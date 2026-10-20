//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

func restoredRetirementFixture(t *testing.T) (*inventoryFixture, sshPreparation, sshStateOwner) {
	t.Helper()
	f, plan, deps := transactionFixture(t)
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal(result, err)
	}
	journal := fixtureJournal(t, f)
	prepared, err := journal.read()
	if err != nil {
		t.Fatal(err)
	}
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256,
		publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	return f, prepared, fixtureOwner(t, f)
}

func retireRestoredFixture(f *inventoryFixture, p sshPreparation, owner sshStateOwner, ops sshProvisionOps) error {
	return retireSSHRestoredTransaction(context.Background(), f.root, os.Geteuid(), owner.Instance, p.PlanSHA256, p.ParserSHA256,
		publicationFixtureParser(f), func() error { return nil }, ops)
}

func TestSSHRestoredRetirementPreservesCustodyAndEnablesNewTransaction(t *testing.T) {
	f, prepared, owner := restoredRetirementFixture(t)
	before, err := collectSSHRollback(f.root, os.Geteuid(), prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := retireRestoredFixture(f, prepared, owner, sshProvisionDefaults()); err != nil {
			t.Fatal(err)
		}
		after, err := collectSSHRollback(f.root, os.Geteuid(), prepared.Transaction)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("changed restored configuration or retained inodes", err)
		}
	}
	parent, err := openSSHStateParent(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, name := range []string{sshStateName, sshOwnerName} {
		if err := sshChildAbsent(parent, name); err != nil {
			t.Fatal("left active transaction state", err)
		}
	}
	if err := checkSSHRestoredRetirements(f.root, parent, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	next := f.plan()
	if next.summary.PlanSHA256 == prepared.PlanSHA256 {
		t.Fatal("restored metadata and retained entries require a new approval")
	}
	deps := transactionFixtureDependencies(f)
	if _, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), prepared.PlanSHA256, deps); err == nil {
		t.Fatal("reused previous plan approval")
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), next.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal("cannot publish separately approved transaction", result, err)
	}
	if fixtureOwner(t, f).Instance == owner.Instance || result.Transaction == prepared.Transaction {
		t.Fatal("reused retired ownership")
	}
	if err := checkSSHRestoredRetirements(f.root, parent, os.Geteuid()); err != nil {
		t.Fatal("new active policy corrupted retired history", err)
	}
	result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), next.summary.PlanSHA256,
		deps.parserDigest, deps.run, deps.checkParser, sshPublicationDefaults())
	if err != nil || !result.Restored {
		t.Fatal("cannot restore second transaction", result, err)
	}
	if err := checkSSHRestoredRetirements(f.root, parent, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRestoredRetirementResumesDurabilityAndRenameFailures(t *testing.T) {
	for failure := 1; failure <= 7; failure++ {
		t.Run(fmt.Sprintf("sync-%d", failure), func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			count := 0
			ops := sshProvisionDefaults()
			ops.sync = func(file *os.File) error {
				count++
				if count == failure {
					return unix.EIO
				}
				return file.Sync()
			}
			if err := retireRestoredFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) || count != failure {
				t.Fatal("ignored durability error", count, err)
			}
			if failure > 1 && failure < 6 {
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
					t.Fatal("provisioned through incomplete retirement")
				}
			}
			if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
				t.Fatal("cannot explicitly resume", err)
			}
		})
	}
	for failure := 1; failure <= 2; failure++ {
		for _, moved := range []bool{false, true} {
			t.Run(fmt.Sprintf("rename-%d-moved-%t", failure, moved), func(t *testing.T) {
				f, p, owner := restoredRetirementFixture(t)
				count := 0
				ops := sshProvisionDefaults()
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					count++
					if count == failure {
						if moved {
							if err := unix.Renameat2(a, b, c, d, flags); err != nil {
								return err
							}
						}
						return unix.EIO
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
				if err := retireRestoredFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) {
					t.Fatal(err)
				}
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
					t.Fatal("provisioned before explicit completion")
				}
				if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
					t.Fatal("cannot recover interrupted rename", err)
				}
			})
		}
	}
}

func TestSSHRestoredRetirementRejectsDriftAndConflictingEvidence(t *testing.T) {
	for _, scenario := range []string{"main", "selection", "include", "new include", "main stage", "drop stage",
		"removed stage", "drop-in", "unknown", "abort", "terminal", "missing phase", "owner", "hardlink",
		"archive collision", "receipt collision", "completion collision", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			mainStage, _ := sshMainStagePath(p.Transaction)
			dropStage, _ := sshDropStagePath(p.Transaction)
			switch scenario {
			case "main":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "include":
				f.write("/etc/ssh/sshd_config.d/admin.conf", "MaxSessions 13\n")
			case "new include":
				f.write("/etc/ssh/sshd_config.d/another.conf", "MaxSessions 14\n")
			case "main stage":
				f.write(mainStage, "# replaced main candidate\n")
			case "drop stage":
				f.write(dropStage, "# replaced policy candidate\n")
			case "removed stage":
				if err := os.Remove(f.path(dropStage)); err != nil {
					t.Fatal(err)
				}
			case "drop-in":
				f.write(DropInPath, "# unrelated replacement\n")
			case "unknown":
				f.write(sshJournalDirectory+"/unknown.json", "{}")
			case "abort":
				f.write(sshJournalDirectory+"/"+sshPreparationAbortName, "{}")
			case "terminal":
				f.write(sshJournalDirectory+"/"+sshRollbackName(2, true), "{}")
			case "missing phase":
				if err := os.Remove(f.path(sshJournalDirectory + "/" + sshPublicationName(2, true))); err != nil {
					t.Fatal(err)
				}
			case "owner":
				f.write(sshStateParent+"/"+sshOwnerName, "{}")
			case "hardlink":
				if err := os.Link(f.path(dropStage), f.path("/etc/ssh/candidate-alias")); err != nil {
					t.Fatal(err)
				}
			case "archive collision":
				if err := os.Mkdir(f.path(sshStateParent+"/"+sshRestoredPrefix+owner.Instance), 0700); err != nil {
					t.Fatal(err)
				}
			case "receipt collision", "completion collision":
				suffix := ".owner.json"
				if scenario == "completion collision" {
					suffix = ".complete.json"
				}
				f.write(sshStateParent+"/"+sshRestoredPrefix+owner.Instance+suffix, "{}")
			case "symlink":
				if err := os.Symlink(f.path("/etc/ssh"), f.path(sshStateParent+"/"+sshRestoredPrefix+owner.Instance)); err != nil {
					t.Fatal(err)
				}
			}
			before := fixtureMainImage(t, f)
			if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("accepted altered or conflicting state")
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("retirement changed SSH configuration")
			}
		})
	}
}

func TestSSHRestoredRetirementAfterEveryInterruptedPublication(t *testing.T) {
	for step := 1; step <= 3; step++ {
		for _, moved := range []bool{false, true} {
			t.Run(fmt.Sprintf("step-%d-moved-%t", step, moved), func(t *testing.T) {
				f, plan, before, main, drop := preparationFixture(t)
				p := fixturePreparation(t, plan, before, main, drop)
				journal := fixtureJournal(t, f)
				if err := journal.write(p); err != nil {
					t.Fatal(err)
				}
				ops := sshPublicationDefaults()
				count := 0
				ops.link = func(a int, b string, c int, d string, flags int) error {
					count++
					if count == step {
						if moved {
							if err := unix.Linkat(a, b, c, d, flags); err != nil {
								return err
							}
						}
						return unix.EIO
					}
					return unix.Linkat(a, b, c, d, flags)
				}
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					count++
					if count == step {
						if moved {
							if err := unix.Renameat2(a, b, c, d, flags); err != nil {
								return err
							}
						}
						return unix.EIO
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
				if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
					publicationFixtureParser(f), func() error { return nil }, ops); !errors.Is(err, unix.EIO) {
					t.Fatal(err)
				}
				if err := errors.Join(journal.Close(), main.Close(), drop.Close()); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				if err := rollbackSSHConfiguration(context.Background(), journal, p.PlanSHA256,
					publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
					t.Fatal(err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				if err := retireRestoredFixture(f, p, fixtureOwner(t, f), sshProvisionDefaults()); err != nil {
					t.Fatal("cannot retire verified inverse of partial publication", err)
				}
			})
		}
	}
}

func TestSSHRestoredRetirementBlocksProvisioningAfterRetainedDrift(t *testing.T) {
	for _, scenario := range []string{"stage bytes", "stage mode", "stage missing", "stage included",
		"record", "record copied", "completion missing", "unknown", "marker", "owner", "directory mode"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			stage, _ := sshDropStagePath(p.Transaction)
			archive := sshStateParent + "/" + sshRestoredPrefix + owner.Instance
			switch scenario {
			case "stage bytes":
				f.write(stage, "# changed\n")
			case "stage mode":
				if err := f.chmod(stage, 0644); err != nil {
					t.Fatal(err)
				}
			case "stage missing":
				if err := os.Remove(f.path(stage)); err != nil {
					t.Fatal(err)
				}
			case "stage included":
				f.write(MainPath, includeDropIns+"Include "+stage+"\n")
			case "record":
				f.write(archive+"/"+sshRollbackName(2, true), "{}")
			case "record copied":
				replaceRestoredFixtureRecord(t, f, archive+"/"+sshPreparedRecord)
			case "completion missing":
				if err := os.Remove(f.path(archive + ".complete.json")); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				f.write(archive+"/operator-note", "preserve")
			case "marker":
				f.write(archive+"/"+sshMarkerName, "changed")
			case "owner":
				f.write(archive+".owner.json", "{}")
			case "directory mode":
				if err := f.chmod(archive, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("provisioned through damaged or activated retained state")
			}
		})
	}
}

func TestSSHRestoredRetirementPreservesInterruptedStateOnDrift(t *testing.T) {
	for _, scenario := range []string{"main", "selection", "candidate", "record replaced", "owner replaced"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			ops := sshProvisionDefaults()
			count := 0
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				count++
				if count == 2 {
					return unix.EIO
				}
				return unix.Renameat2(a, b, c, d, flags)
			}
			if err := retireRestoredFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) {
				t.Fatal(err)
			}
			switch scenario {
			case "main":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "candidate":
				stage, _ := sshMainStagePath(p.Transaction)
				f.write(stage, "changed")
			case "record replaced", "owner replaced":
				name := sshStateParent + "/" + sshOwnerName
				if scenario == "record replaced" {
					name = sshStateParent + "/" + sshRestoredPrefix + owner.Instance + "/" + sshPreparedRecord
				}
				replaceRestoredFixtureRecord(t, f, name)
			}
			before := fixtureMainImage(t, f)
			if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("accepted drift during interrupted retirement")
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("changed administrator configuration while refusing recovery")
			}
		})
	}
}

func replaceRestoredFixtureRecord(t *testing.T, f *inventoryFixture, name string) {
	t.Helper()
	root, err := os.OpenRoot(f.base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	name = strings.TrimPrefix(name, "/")
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(name, "retained-original"); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRestoredRetirementRequiresExclusiveLocksAndParserStability(t *testing.T) {
	for _, scenario := range []string{"parent lock", "journal lock", "parser mutation", "rename mutation"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			run := publicationFixtureParser(f)
			ops := sshProvisionDefaults()
			switch scenario {
			case "parent lock":
				parent, err := openSSHRetirementParent(f.root, os.Geteuid(), owner.Instance)
				if err != nil {
					t.Fatal(err)
				}
				defer parent.Close()
			case "journal lock":
				journal := fixtureJournal(t, f)
				defer journal.Close()
			case "parser mutation":
				original := run
				run = func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
					f.write(MainPath, includeDropIns+"Port 2223\n")
					return original(ctx, image, mode, access)
				}
			case "rename mutation":
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					err := unix.Renameat2(a, b, c, d, flags)
					f.write(MainPath, includeDropIns+"Port 2223\n")
					return err
				}
			}
			if err := retireSSHRestoredTransaction(context.Background(), f.root, os.Geteuid(), owner.Instance,
				p.PlanSHA256, p.ParserSHA256, run, func() error { return nil }, ops); err == nil {
				t.Fatal("ignored concurrent use or mutation")
			}
		})
	}
}

func TestSSHRestoredRetirementReceiptRejectsNoncanonicalAndUnboundedRecords(t *testing.T) {
	f, p, owner := restoredRetirementFixture(t)
	if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.path(sshStateParent + "/" + sshRestoredPrefix + owner.Instance + ".intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeSSHRestoredRetirement(data, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range [][]byte{nil, []byte("{}"), append(data, '\n'), append([]byte(`{"unknown":1,`), data[1:]...),
		[]byte(strings.Repeat(" ", maxSSHOwnerBytes+1)), append([]byte(`{"schema":1,`), data[1:]...)} {
		if _, err := decodeSSHRestoredRetirement(encoded, os.Geteuid()); err == nil {
			t.Fatal("accepted noncanonical or oversized receipt")
		}
	}
	for _, scenario := range []string{"schema", "missing terminal", "abort", "digest", "owner mode", "instance"} {
		t.Run(scenario, func(t *testing.T) {
			copy, err := decodeSSHRestoredRetirement(data, os.Geteuid())
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "schema":
				copy.Schema = 2
			case "missing terminal":
				delete(copy.Files, sshRollbackName(2, true))
			case "abort":
				copy.Files[sshPreparationAbortName] = strings.Repeat("a", 64)
			case "digest":
				copy.Files[sshPreparedRecord] = ""
			case "owner mode":
				copy.Owner.Mode |= 0004
			case "instance":
				copy.Instance = strings.Repeat("d", 64)
			}
			encoded, err := json.Marshal(copy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeSSHRestoredRetirement(encoded, os.Geteuid()); err == nil {
				t.Fatal("accepted invalid typed receipt", r.Instance)
			}
		})
	}
}

func TestSSHRestoredRetirementRejectsPublishedOrIncompleteRollback(t *testing.T) {
	for _, state := range []string{"published", "partial rollback", "aborted"} {
		t.Run(state, func(t *testing.T) {
			var f *inventoryFixture
			var p sshPreparation
			if state == "aborted" {
				f, p, _ = abortedRetirementFixture(t)
			} else {
				var journal *sshJournal
				f, _, p, journal = completedPublicationFixture(t)
				if state == "partial rollback" {
					ops := sshPublicationDefaults()
					ops.rename = func(int, string, int, string, uint) error { return unix.EIO }
					if err := rollbackSSHConfiguration(context.Background(), journal, p.PlanSHA256,
						publicationFixtureParser(f), func() error { return nil }, ops); err == nil {
						t.Fatal("missing fixture failure")
					}
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := retireRestoredFixture(f, p, fixtureOwner(t, f), sshProvisionDefaults()); err == nil {
				t.Fatal("retired non-restored transaction")
			}
		})
	}
}

func TestSSHRestoredRetirementReadOnlyHistoryCannotMutate(t *testing.T) {
	f, p, owner := restoredRetirementFixture(t)
	if err := retireRestoredFixture(f, p, owner, sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	parent, err := openSSHStateParent(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	receipt, err := readSSHPrivateChild(parent, sshRestoredPrefix+owner.Instance+".intent.json", os.Geteuid(), maxSSHOwnerBytes)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decodeSSHRestoredRetirement(receipt.data, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openSSHRetainedDirectory(parent, r.name(""))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	journal := &sshJournal{root: f.root, directory: directory, uid: os.Geteuid(),
		retained: &sshRetainedJournal{parent: parent, record: r, completed: true}}
	plan, _, err := inspectSSHRestoredHistory(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.writeRecord(sshPreparationAbortName, []byte("{}")); err == nil {
		t.Fatal("wrote into retained journal")
	}
	if err := rollbackSSHConfiguration(context.Background(), journal, p.PlanSHA256,
		publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err == nil {
		t.Fatal("replayed rollback from retained journal")
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, &sshAnonymousStage{}, &sshAnonymousStage{},
		publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err == nil {
		t.Fatal("published from retained journal")
	}
	if err := checkSSHRestoredRetirements(f.root, parent, os.Geteuid()); err != nil {
		t.Fatal("mutator changed retained evidence", err)
	}
}

func TestSSHRestoredRetirementRejectsChangedAuthorizationAndParser(t *testing.T) {
	for _, scenario := range []string{"plan", "parser", "instance", "parser check", "syntax", "effective", "context", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := restoredRetirementFixture(t)
			ctx := context.Background()
			run := publicationFixtureParser(f)
			check := func() error { return nil }
			switch scenario {
			case "plan":
				p.PlanSHA256 = strings.Repeat("d", 64)
			case "parser":
				p.ParserSHA256 = strings.Repeat("d", 64)
			case "instance":
				owner.Instance = strings.Repeat("d", 64)
			case "parser check":
				check = func() error { return unix.EIO }
			case "syntax", "effective", "context":
				original := run
				run = func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
					if (scenario == "syntax" && mode == "syntax") || (scenario == "effective" && mode == "effective") ||
						(scenario == "context" && access != "") {
						return nil, unix.EIO
					}
					return original(ctx, image, mode, access)
				}
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			}
			if err := retireSSHRestoredTransaction(ctx, f.root, os.Geteuid(), owner.Instance, p.PlanSHA256, p.ParserSHA256, run, check, sshProvisionDefaults()); err == nil {
				t.Fatal("retired without current verified authorization")
			}
		})
	}
}
