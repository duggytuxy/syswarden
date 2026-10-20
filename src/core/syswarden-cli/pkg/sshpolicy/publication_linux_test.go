//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func publicationFixtureParser(f *inventoryFixture) sshParserRun {
	return func(_ context.Context, image *parserImage, mode, _ string) ([]byte, error) {
		if mode == "syntax" {
			return nil, nil
		}
		value := "yes"
		_, live := os.Stat(f.path(DropInPath))
		if (image != nil && len(image.files) == 2) || (image == nil && live == nil) {
			value = "no"
		}
		return []byte("port 2222\nauthenticationmethods publickey\nallowtcpforwarding " + value + "\n"), nil
	}
}

func TestSSHPublicationRetainsOriginalAndReopensExactCompletedState(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
		publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fixtureMainImage(t, f).data, plan.main) {
		t.Fatal("published wrong main bytes")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(main.Close(), drop.Close()); err != nil {
		t.Fatal(err)
	}
	reopened := fixtureJournal(t, f)
	position, err := inspectSSHPublication(reopened)
	if err != nil || position != (sshPublicationPosition{3, "complete"}) {
		t.Fatal("cannot recover completed configuration publication", position, err)
	}
	stage, _ := sshMainStagePath(record.Transaction)
	snapshot, err := stableSSHPublication(f.root, os.Geteuid(), stage)
	if err != nil || !matchesSSHRecovery(snapshot, stage, record.MainBefore) ||
		!matchesSSHRecovery(snapshot, MainPath, record.MainAfter) ||
		!matchesSSHRecovery(snapshot, DropInPath, record.DropIn) {
		t.Fatal("lost exact original or candidate inodes", err)
	}
	if got := snapshot.Files[stage]; !bytes.Equal(got, before.data) {
		t.Fatal("lost private recovery bytes")
	}
	if err := reopened.requireNoPublicationRecords(); err == nil {
		t.Fatal("allowed blind duplicate publication")
	}
	for step := 1; step <= 3; step++ {
		for _, done := range []bool{false, true} {
			state, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPublicationName(step, done)))
			if err != nil || state.Mode().Perm() != 0600 {
				t.Fatal("phase evidence is not private", err)
			}
		}
	}
}

func TestSSHPublicationInterruptionAtEveryDurabilityBoundary(t *testing.T) {
	for step := 1; step <= 3; step++ {
		for _, boundary := range []string{"intent", "mutation", "directory sync", "completion"} {
			t.Run(fmt.Sprintf("%d/%s", step, boundary), func(t *testing.T) {
				f, plan, before, main, drop := preparationFixture(t)
				record := fixturePreparation(t, plan, before, main, drop)
				journal := fixtureJournal(t, f)
				if err := journal.write(record); err != nil {
					t.Fatal(err)
				}
				ops := sshPublicationDefaults()
				phaseWrites, mutations, syncs := 0, 0, 0
				journal.syncDirectory = func(dir *os.File) error {
					phaseWrites++
					if (boundary == "intent" && phaseWrites == step*2-1) ||
						(boundary == "completion" && phaseWrites == step*2) {
						return unix.EIO
					}
					return dir.Sync()
				}
				ops.link = func(a int, b string, c int, d string, flags int) error {
					mutations++
					if boundary == "mutation" && mutations == step {
						return unix.EIO
					}
					return unix.Linkat(a, b, c, d, flags)
				}
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					mutations++
					if boundary == "mutation" && mutations == step {
						return unix.EIO
					}
					return unix.Renameat2(a, b, c, d, flags)
				}
				ops.sync = func(dir *os.File) error {
					syncs++
					if boundary == "directory sync" && syncs == step {
						return unix.EIO
					}
					return dir.Sync()
				}
				err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
					publicationFixtureParser(f), func() error { return nil }, ops)
				if err == nil || !journal.poisoned {
					t.Fatal("claimed successful publication after injected failure")
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				if err := errors.Join(main.Close(), drop.Close()); err != nil {
					t.Fatal(err)
				}
				reopened := fixtureJournal(t, f)
				position, err := inspectSSHPublication(reopened)
				state := "before"
				if boundary == "directory sync" {
					state = "after"
				} else if boundary == "completion" {
					state = "complete"
				}
				if err != nil || position != (sshPublicationPosition{step, state}) {
					t.Fatal("wrong interrupted position", position, err)
				}
				// A reopened observation does not repair or finish any operation.
				if syncs > step || mutations > step {
					t.Fatal("continued after uncertainty")
				}
			})
		}
	}
}

func TestSSHPublicationPreservesForeignFileAtReservedName(t *testing.T) {
	for _, step := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			f, plan, before, main, drop := preparationFixture(t)
			record := fixturePreparation(t, plan, before, main, drop)
			journal := fixtureJournal(t, f)
			if err := journal.write(record); err != nil {
				t.Fatal(err)
			}
			stage, _ := sshMainStagePath(record.Transaction)
			ops := sshPublicationDefaults()
			links := 0
			foreign := []byte("# administrator-owned fixture\n")
			ops.link = func(a int, b string, c int, d string, flags int) error {
				links++
				if links == step {
					name := stage
					if step == 2 {
						name = DropInPath
					}
					if err := os.WriteFile(f.path(name), foreign, 0600); err != nil {
						return err
					}
				}
				return unix.Linkat(a, b, c, d, flags)
			}
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				// An external writer can race after the final observation.
				// Exchange must retain that file and report disagreement.
				if err := os.Rename(f.path(MainPath), f.path(MainPath+".administrator-copy")); err != nil {
					return err
				}
				if err := os.WriteFile(f.path(MainPath), foreign, 0600); err != nil {
					return err
				}
				return unix.Renameat2(a, b, c, d, flags)
			}
			if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
				publicationFixtureParser(f), func() error { return nil }, ops); err == nil {
				t.Fatal("claimed success after administrator race")
			}
			name := stage
			if step == 2 {
				name = DropInPath
			}
			got, err := os.ReadFile(f.path(name))
			if err != nil || !bytes.Equal(got, foreign) {
				t.Fatal("lost foreign configuration", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := inspectSSHPublication(fixtureJournal(t, f)); err == nil {
				t.Fatal("adopted foreign file after reopen")
			}
		})
	}
}

func TestSSHPublicationRefusesChangedInputsAndInvalidPrerequisites(t *testing.T) {
	for _, scenario := range []string{"plan", "stage", "main", "intent", "parser", "cancelled", "preexisting phase"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, before, main, drop := preparationFixture(t)
			record := fixturePreparation(t, plan, before, main, drop)
			journal := fixtureJournal(t, f)
			if err := journal.write(record); err != nil {
				t.Fatal(err)
			}
			run := publicationFixtureParser(f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "plan":
				plan.summary.PlanSHA256 = strings.Repeat("b", 64)
			case "stage":
				if _, err := main.file.WriteAt([]byte("#"), 0); err != nil {
					t.Fatal(err)
				}
			case "main":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "intent":
				f.write(IntentPath, validIntentJSON+"\n")
			case "parser":
				run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "cancelled":
				cancel()
			case "preexisting phase":
				f.write(sshJournalDirectory+"/"+sshPublicationName(2, true), "{}")
			}
			if err := publishSSHConfiguration(ctx, journal, plan, main, drop, run,
				func() error { return nil }, sshPublicationDefaults()); err == nil {
				t.Fatal("accepted changed input")
			}
			if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("published despite invalid prerequisite")
			}
		})
	}
}

func TestSSHPublicationReopenRefusesChangedConfigurationAndEvidence(t *testing.T) {
	for _, scenario := range []string{"same bytes new inode", "main mode", "drop bytes", "unrelated entry", "missing phase", "extra JSON", "phase identity", "phase chain", "null files", "null nodes", "record hardlink"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, before, main, drop := preparationFixture(t)
			record := fixturePreparation(t, plan, before, main, drop)
			journal := fixtureJournal(t, f)
			if err := journal.write(record); err != nil {
				t.Fatal(err)
			}
			if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
				publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
				t.Fatal(err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			name := sshJournalDirectory + "/" + sshPublicationName(2, false)
			switch scenario {
			case "same bytes new inode":
				if err := os.Rename(f.path(DropInPath), f.path(DropInPath+".retained")); err != nil {
					t.Fatal(err)
				}
				f.write(DropInPath, string(record.DropIn.Data))
			case "main mode":
				if err := f.chmod(MainPath, 0640); err != nil {
					t.Fatal(err)
				}
			case "drop bytes":
				f.write(DropInPath, "# modified policy\n")
			case "unrelated entry":
				f.write("/etc/ssh/sshd_config.d/operator.conf", "Port 2223\n")
			case "missing phase":
				if err := os.Remove(f.path(name)); err != nil {
					t.Fatal(err)
				}
			case "extra JSON":
				data, err := os.ReadFile(f.path(name))
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, string(data)+"\n")
			case "phase identity", "phase chain", "null files", "null nodes":
				data, err := os.ReadFile(f.path(name))
				if err != nil {
					t.Fatal(err)
				}
				var phase sshPublicationRecord
				if err := json.Unmarshal(data, &phase); err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "phase identity":
					phase.Transaction = strings.Repeat("b", 64)
				case "phase chain":
					phase.Before.Files[MainPath] = []byte("Port 2223\n")
				case "null files":
					phase.Before.Files = nil
				case "null nodes":
					phase.Before.Nodes = nil
				}
				data, err = json.Marshal(phase)
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, string(data))
			case "record hardlink":
				if err := os.Link(f.path(name), f.path(name+".alias")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectSSHPublication(fixtureJournal(t, f)); err == nil {
				t.Fatal("accepted altered configuration or phase evidence")
			}
		})
	}
}

func TestSSHPublicationRejectsPostPublicationParserDisagreement(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	baseline := publicationFixtureParser(f)
	run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
		if image == nil && mode == "effective" && fixtureMainImage(t, f).state.ino == record.MainAfter.Inode {
			return []byte("port 2223\nallowtcpforwarding no\n"), nil
		}
		return baseline(ctx, image, mode, access)
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
		run, func() error { return nil }, sshPublicationDefaults()); err == nil || !journal.poisoned {
		t.Fatal("claimed verified publication after live parser disagreement")
	}
	stage, _ := sshMainStagePath(record.Transaction)
	got, err := os.ReadFile(f.path(stage))
	if err != nil || !reflect.DeepEqual(got, before.data) {
		t.Fatal("discarded recovery data after parser disagreement", err)
	}
}

func TestSSHPublicationBoundsIncludeRecoveryStageBeforeAnyNamedWrite(t *testing.T) {
	f, plan, before, main, drop := preparationFixtureWithMain(t,
		includeDropIns+strings.Repeat("# fixture\n", 60000))
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop,
		publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); !errors.Is(err, ErrInventoryBounds) {
		t.Fatal("did not bound the complete publication inventory", err)
	}
	stage, _ := sshMainStagePath(record.Transaction)
	for _, name := range []string{stage, DropInPath, sshJournalDirectory + "/" + sshPublicationName(1, false)} {
		if _, err := os.Lstat(f.path(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("published before accounting for recovery bounds", err)
		}
	}
}
