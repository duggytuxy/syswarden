//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

func abortedRetirementFixture(t *testing.T) (*inventoryFixture, sshPreparation, sshStateOwner) {
	t.Helper()
	f, _, prepared := interruptedPreparationFixture(t)
	result, err := recoverPreparationFixture(f, prepared)
	if err != nil || !result.Aborted {
		t.Fatal(result, err)
	}
	return f, prepared, fixtureOwner(t, f)
}

func retireAbortedFixture(f *inventoryFixture, p sshPreparation, owner sshStateOwner, ops sshProvisionOps) error {
	return retireSSHAbortedPreparation(context.Background(), f.root, os.Geteuid(), owner.Instance, p.PlanSHA256, p.ParserSHA256,
		preparationAbortFixtureParser, func() error { return nil }, ops)
}

func TestSSHAbortedRetirementPreservesEvidenceAndAllowsFreshTransaction(t *testing.T) {
	f, p, owner := abortedRetirementFixture(t)
	before := fixtureMainImage(t, f)
	journal := fixtureJournal(t, f)
	hashes, _, _, err := observeSSHAbortedFiles(journal.directory, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
			t.Fatal("retirement changed the SSH main file")
		}
	}
	parent, err := openSSHStateParent(f.root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, name := range []string{sshStateName, sshOwnerName} {
		if err := sshChildAbsent(parent, name); err != nil {
			t.Fatal("left active retired storage", err)
		}
	}
	image, err := readSSHPrivateChild(parent, sshAbortedPrefix+owner.Instance+".intent.json", os.Geteuid(), maxSSHOwnerBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := decodeSSHAbortedRetirement(image.data, os.Geteuid())
	if err != nil || !reflect.DeepEqual(receipt.Files, hashes) {
		t.Fatal("lost exact retained identities", err)
	}
	if err := checkSSHAbortedRetirements(parent, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	plan := f.plan()
	deps := transactionFixtureDependencies(f)
	deps.run = func(_ context.Context, image *parserImage, mode, _ string) ([]byte, error) {
		if mode == "syntax" {
			return nil, nil
		}
		value := "yes"
		_, live := os.Stat(f.path(DropInPath))
		if (image != nil && len(image.files) == 3) || (image == nil && live == nil) {
			value = "no"
		}
		return []byte("port 2222\nauthenticationmethods publickey\nallowtcpforwarding " + value + "\n"), nil
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err != nil || !result.Published {
		t.Fatal("cannot begin a separately verified new transaction", result, err)
	}
	if fixtureOwner(t, f).Instance == owner.Instance || result.Transaction == p.Transaction {
		t.Fatal("reused retired identity")
	}
	if err := checkSSHAbortedRetirements(parent, os.Geteuid()); err != nil {
		t.Fatal("new transaction changed retired evidence", err)
	}
}

func TestSSHAbortedRetirementResumesEveryDurabilityFailure(t *testing.T) {
	for failure := 1; failure <= 7; failure++ {
		t.Run(fmt.Sprintf("sync-%d", failure), func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			before := fixtureMainImage(t, f)
			count := 0
			ops := sshProvisionDefaults()
			ops.sync = func(file *os.File) error {
				count++
				if count == failure {
					return unix.EIO
				}
				return file.Sync()
			}
			err := retireAbortedFixture(f, p, owner, ops)
			if !errors.Is(err, unix.EIO) || count != failure {
				t.Fatal("ignored or missed sync failure", count, err)
			}
			// Before the complete record is visible, normal provisioning must not
			// interpret the now-absent active names as a fresh installation.
			if failure > 1 && failure < 6 {
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
					t.Fatal("provisioned through pending retirement")
				}
			}
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err != nil {
				t.Fatal("cannot resume exact retirement", err)
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("changed original SSH configuration")
			}
		})
	}
}

func TestSSHAbortedRetirementResumesFailedOrAmbiguousRenames(t *testing.T) {
	for _, moveAfterError := range []bool{false, true} {
		for failure := 1; failure <= 2; failure++ {
			t.Run(fmt.Sprintf("rename-%d-moved-%t", failure, moveAfterError), func(t *testing.T) {
				f, p, owner := abortedRetirementFixture(t)
				count := 0
				ops := sshProvisionDefaults()
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					count++
					if count == failure {
						if moveAfterError {
							if err := unix.Renameat2(a, b, c, d, flags); err != nil {
								return err
							}
						}
						return unix.EIO
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
				if err := retireAbortedFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) {
					t.Fatal(err)
				}
				if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
					t.Fatal("used incomplete retirement")
				}
				if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSSHAbortedRetirementRejectsChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"main", "selection", "intent", "include", "new include", "stage", "drop-in", "unknown", "publication", "terminal", "mode", "hardlink", "owner", "archive collision", "receipt collision", "completion collision"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			switch scenario {
			case "main":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "intent":
				f.write(IntentPath, strings.Replace(validIntentJSON, "forwarding", "cis", 1))
			case "include":
				f.write("/etc/ssh/sshd_config.d/admin.conf", "MaxSessions 13\n")
			case "new include":
				f.write("/etc/ssh/sshd_config.d/another.conf", "MaxSessions 14\n")
			case "stage":
				name, _ := sshMainStagePath(p.Transaction)
				f.write(name, "unexpected")
			case "drop-in":
				f.write(DropInPath, string(p.DropIn.Data))
			case "unknown":
				f.write(sshJournalDirectory+"/administrator-note", "keep")
			case "publication":
				f.write(sshJournalDirectory+"/"+sshPublicationName(1, false), "{}")
			case "terminal":
				f.write(sshJournalDirectory+"/"+sshPreparationAbortName, "{}")
			case "mode":
				if err := f.chmod(sshJournalDirectory+"/"+sshPreparedRecord, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(sshJournalDirectory+"/"+sshPreparedRecord), f.path("/copy")); err != nil {
					t.Fatal(err)
				}
			case "owner":
				f.write(sshStateParent+"/"+sshOwnerName, "{}")
			case "archive collision":
				f.write(sshStateParent+"/"+sshAbortedPrefix+owner.Instance+"/operator-note", "keep")
			case "receipt collision":
				f.write(sshStateParent+"/"+sshAbortedPrefix+owner.Instance+".owner.json", "keep")
			case "completion collision":
				f.write(sshStateParent+"/"+sshAbortedPrefix+owner.Instance+".complete.json", "keep")
			}
			before := fixtureMainImage(t, f)
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("accepted changed evidence")
			}
			if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
				t.Fatal("mutated SSH configuration")
			}
			if _, err := os.Lstat(f.path(sshStateParent + "/" + sshAbortedPrefix + owner.Instance + ".intent.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("wrote intent despite unsafe evidence", err)
			}
		})
	}
}

func TestSSHAbortedRetirementRequiresApprovalParserAndLocks(t *testing.T) {
	for _, scenario := range []string{"approval", "parser digest", "instance", "parser identity", "parser error", "effective", "context", "parent lock", "journal lock"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			instance, approved, parser := owner.Instance, p.PlanSHA256, p.ParserSHA256
			check := func() error { return nil }
			run := preparationAbortFixtureParser
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "approval":
				approved = strings.Repeat("b", 64)
			case "parser digest":
				parser = strings.Repeat("b", 64)
			case "instance":
				instance = strings.Repeat("b", 64)
			case "parser identity":
				check = func() error { return unix.EIO }
			case "parser error":
				run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "effective":
				run = func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
					if mode == "effective" && image == nil {
						return []byte("port 2223\nallowtcpforwarding yes\n"), nil
					}
					return preparationAbortFixtureParser(ctx, image, mode, access)
				}
			case "context":
				cancel()
			case "parent lock":
				parent, err := openSSHRetirementParent(f.root, os.Geteuid(), owner.Instance)
				if err != nil {
					t.Fatal(err)
				}
				defer parent.Close()
			case "journal lock":
				journal := fixtureJournal(t, f)
				defer journal.Close()
			}
			if err := retireSSHAbortedPreparation(ctx, f.root, os.Geteuid(), instance, approved, parser, run, check, sshProvisionDefaults()); err == nil {
				t.Fatal("accepted invalid authorization or dependency")
			}
			if _, err := os.Lstat(f.path(sshStateParent + "/" + sshAbortedPrefix + owner.Instance + ".intent.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created intent after failed prerequisite", err)
			}
		})
	}
}

func TestSSHAbortedRetirementRechecksDuringParserAndMutations(t *testing.T) {
	for _, at := range []string{"parser", "intent sync", "directory rename", "owner rename"} {
		t.Run(at, func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			changed := false
			mutate := func() {
				if !changed {
					changed = true
					f.write("/etc/ssh/sshd_config.d/admin.conf", "MaxSessions 15\n")
				}
			}
			run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if at == "parser" {
					mutate()
				}
				return preparationAbortFixtureParser(ctx, image, mode, access)
			}
			ops := sshProvisionDefaults()
			ops.sync = func(file *os.File) error {
				if at == "intent sync" {
					mutate()
				}
				return file.Sync()
			}
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				err := unix.Renameat2(a, b, c, d, flags)
				if (at == "directory rename" && b == sshStateName) || (at == "owner rename" && b == sshOwnerName) {
					mutate()
				}
				return err
			}
			if err := retireSSHAbortedPreparation(context.Background(), f.root, os.Geteuid(), owner.Instance, p.PlanSHA256, p.ParserSHA256, run, func() error { return nil }, ops); err == nil || !changed {
				t.Fatal("missed concurrent input change", err)
			}
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("resumed after input drift")
			}
		})
	}
}

func TestSSHAbortedRetirementDoesNotRetirePublishedOrUnabortedState(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			f, plan, deps := transactionFixture(t)
			var p sshPreparation
			if published {
				if _, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps); err != nil {
					t.Fatal(err)
				}
				journal := fixtureJournal(t, f)
				var err error
				p, err = journal.read()
				if err != nil {
					t.Fatal(err)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				f, _, p = interruptedPreparationFixture(t)
			}
			owner := fixtureOwner(t, f)
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("retired nonterminal preparation")
			}
		})
	}
}

func TestSSHAbortedRetirementBlocksDamagedArchivesAndOrphans(t *testing.T) {
	for _, scenario := range []string{"unknown prefix", "missing completion", "changed prepared", "owner copy", "directory symlink"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err != nil {
				t.Fatal(err)
			}
			base := sshStateParent + "/" + sshAbortedPrefix + owner.Instance
			switch scenario {
			case "unknown prefix":
				f.write(sshStateParent+"/"+sshAbortedPrefix+"unknown", "retain")
			case "missing completion":
				if err := os.Remove(f.path(base + ".complete.json")); err != nil {
					t.Fatal(err)
				}
			case "changed prepared":
				f.write(base+"/"+sshPreparedRecord, "{}")
			case "owner copy":
				data, err := os.ReadFile(f.path(base + ".owner.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.path(base+".owner.json"), f.path(base+".saved")); err != nil {
					t.Fatal(err)
				}
				f.write(base+".owner.json", string(data))
			case "directory symlink":
				if err := os.Rename(f.path(base), f.path(base+".saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.path(base+".saved"), f.path(base)); err != nil {
					t.Fatal(err)
				}
			}
			if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err == nil {
				t.Fatal("provisioned through damaged retained evidence")
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created active state despite incomplete custody", err)
			}
		})
	}
}

func TestSSHAbortedRetirementVisibleCompletionRequiresParentSyncBeforeReuse(t *testing.T) {
	f, p, owner := abortedRetirementFixture(t)
	ops := sshProvisionDefaults()
	calls := 0
	ops.sync = func(file *os.File) error {
		calls++
		if calls == 7 {
			return unix.EIO
		}
		return file.Sync()
	}
	if err := retireAbortedFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	// The completed custody may be reverified, but new state must establish
	// parent durability before publishing a new independent ownership receipt.
	syncs := 0
	ops = sshProvisionDefaults()
	ops.sync = func(file *os.File) error { syncs++; return unix.EIO }
	if err := provisionSSHState(f.root, os.Geteuid(), ops); !errors.Is(err, unix.EIO) || syncs != 1 {
		t.Fatal("ignored durability failure", syncs, err)
	}
	if _, err := os.Lstat(f.path(sshStateParent + "/" + sshOwnerName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published new ownership before sync", err)
	}
}

func TestSSHAbortedRetirementRejectsRecordReplacementWhileResuming(t *testing.T) {
	for _, scenario := range []string{"intent", "terminal", "owner", "archive", "complete"} {
		t.Run(scenario, func(t *testing.T) {
			f, p, owner := abortedRetirementFixture(t)
			ops := sshProvisionDefaults()
			moves := 0
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				moves++
				if moves == 2 {
					return unix.EIO
				}
				return unix.Renameat2(a, b, c, d, flags)
			}
			if err := retireAbortedFixture(f, p, owner, ops); !errors.Is(err, unix.EIO) {
				t.Fatal(err)
			}
			base := sshStateParent + "/" + sshAbortedPrefix + owner.Instance
			switch scenario {
			case "intent":
				f.write(base+".intent.json", "{}")
			case "terminal":
				f.write(base+"/"+sshPreparationAbortName, "{}")
			case "owner":
				f.write(sshStateParent+"/"+sshOwnerName, "{}")
			case "archive":
				f.write(base+"/unrelated", "retain")
			case "complete":
				data, err := os.ReadFile(f.path(base + ".intent.json"))
				if err != nil {
					t.Fatal(err)
				}
				f.write(base+".complete.json", string(data))
			}
			if err := retireAbortedFixture(f, p, owner, sshProvisionDefaults()); err == nil {
				t.Fatal("accepted replaced or premature records")
			}
			if _, err := os.Lstat(f.path(sshStateParent + "/" + sshOwnerName)); err != nil {
				t.Fatal("moved the remaining owner despite ambiguity", err)
			}
		})
	}
}
