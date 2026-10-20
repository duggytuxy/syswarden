//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func completedPublicationFixture(t *testing.T) (*inventoryFixture, migrationPlan, sshPreparation, *sshJournal) {
	t.Helper()
	f, plan, before, main, drop := preparationFixture(t)
	prepared := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(prepared); err != nil {
		t.Fatal(err)
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(journal.Close(), main.Close(), drop.Close()); err != nil {
		t.Fatal(err)
	}
	return f, plan, prepared, fixtureJournal(t, f)
}

func assertSSHRestored(t *testing.T, f *inventoryFixture, prepared sshPreparation, journal *sshJournal) {
	t.Helper()
	snapshot, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil || !matchesSSHRecovery(snapshot, MainPath, prepared.MainBefore) || snapshot.Nodes[DropInPath] != (sshStoredStamp{}) {
		t.Fatal("original identity or drop-in absence not restored", err)
	}
	position, err := inspectSSHRollback(journal)
	if err != nil || position != (sshPublicationPosition{2, "complete"}) {
		t.Fatal("rollback evidence cannot be reopened", position, err)
	}
	if _, err := inspectSSHPublication(journal); err == nil {
		t.Fatal("forward inspector ignored rollback")
	}
	if got := fixtureMainImage(t, f); !bytes.Equal(got.data, prepared.MainBefore.Data) {
		t.Fatal("lost original bytes")
	}
}

func TestSSHRollbackRestoresOriginalAndRetainsCandidates(t *testing.T) {
	f, plan, prepared, journal := completedPublicationFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
			t.Fatal(err)
		}
		assertSSHRestored(t, f, prepared, journal)
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		journal = fixtureJournal(t, f)
	}
	snapshot, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	mainStage, _ := sshMainStagePath(prepared.Transaction)
	dropStage, _ := sshDropStagePath(prepared.Transaction)
	if !matchesSSHRecovery(snapshot, mainStage, prepared.MainAfter) || !matchesSSHRecovery(snapshot, dropStage, prepared.DropIn) {
		t.Fatal("discarded candidate recovery data")
	}
}

func TestSSHRollbackFromEveryPublicationBoundary(t *testing.T) {
	for step := 1; step <= 3; step++ {
		for _, boundary := range []string{"intent", "mutation", "sync", "completion"} {
			t.Run(fmt.Sprintf("%d/%s", step, boundary), func(t *testing.T) {
				f, plan, before, main, drop := preparationFixture(t)
				prepared := fixturePreparation(t, plan, before, main, drop)
				journal := fixtureJournal(t, f)
				if err := journal.write(prepared); err != nil {
					t.Fatal(err)
				}
				ops := sshPublicationDefaults()
				writes, mutations, syncs := 0, 0, 0
				journal.syncDirectory = func(dir *os.File) error {
					writes++
					if (boundary == "intent" && writes == step*2-1) || (boundary == "completion" && writes == step*2) {
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
					if boundary == "sync" && syncs == step {
						return unix.EIO
					}
					return dir.Sync()
				}
				if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop, publicationFixtureParser(f), func() error { return nil }, ops); err == nil {
					t.Fatal("missing injected failure")
				}
				if err := errors.Join(journal.Close(), main.Close(), drop.Close()); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
					t.Fatal(err)
				}
				assertSSHRestored(t, f, prepared, journal)
			})
		}
	}
}

func TestSSHRollbackResumesEveryDurabilityBoundary(t *testing.T) {
	for step := 1; step <= 2; step++ {
		for _, boundary := range []string{"start", "intent", "mutation", "sync", "completion"} {
			t.Run(fmt.Sprintf("%d/%s", step, boundary), func(t *testing.T) {
				f, plan, prepared, journal := completedPublicationFixture(t)
				ops := sshPublicationDefaults()
				failed := false
				mutations := 0
				justRenamed := false
				exists := func(name string) bool { _, err := os.Stat(f.path(sshJournalDirectory + "/" + name)); return err == nil }
				journal.syncDirectory = func(dir *os.File) error {
					if !failed && ((boundary == "start" && exists(sshRollbackStartName)) || (boundary == "intent" && exists(sshRollbackName(step, false)) && !exists(sshRollbackName(step, true))) || (boundary == "completion" && exists(sshRollbackName(step, true)))) {
						failed = true
						return unix.EIO
					}
					return dir.Sync()
				}
				ops.rename = func(a int, b string, c int, d string, flags uint) error {
					mutations++
					if boundary == "mutation" && mutations == step {
						failed = true
						return unix.EIO
					}
					err := unix.Renameat2(a, b, c, d, flags)
					if err == nil {
						justRenamed = true
					}
					return err
				}
				ops.sync = func(dir *os.File) error {
					if boundary == "sync" && justRenamed && mutations == step && !failed {
						failed = true
						return unix.EIO
					}
					return dir.Sync()
				}
				err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, ops)
				if err == nil || !failed || !journal.poisoned {
					t.Fatal("claimed success after injected rollback failure", err, failed)
				}
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				journal = fixtureJournal(t, f)
				if _, err := inspectSSHRollback(journal); err != nil {
					t.Fatal("cannot inspect interrupted rollback", err)
				}
				if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
					t.Fatal("cannot explicitly resume rollback", err)
				}
				assertSSHRestored(t, f, prepared, journal)
			})
		}
	}
}

func TestSSHRollbackPreservesChangedAdministratorInputs(t *testing.T) {
	for _, scenario := range []string{"main", "drop-in", "same-byte replacement", "mode", "include member", "intent", "wrong approval", "parser", "cancelled", "reserved collision"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, prepared, journal := completedPublicationFixture(t)
			approved := plan.summary.PlanSHA256
			run := publicationFixtureParser(f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "main":
				f.write(MainPath, "# administrator main\n")
			case "drop-in":
				f.write(DropInPath, "# administrator policy\n")
			case "same-byte replacement":
				if err := os.Rename(f.path(MainPath), f.path(MainPath+".admin")); err != nil {
					t.Fatal(err)
				}
				f.write(MainPath, string(prepared.MainAfter.Data))
			case "mode":
				if err := os.Chmod(f.path(MainPath), 0640); err != nil { // #nosec G302 -- Intentional permission mutation in a disposable fixture; rollback must reject it.
					t.Fatal(err)
				}
			case "include member":
				f.write("/etc/ssh/sshd_config.d/20-administrator.conf", "MaxSessions 12\n")
			case "intent":
				f.write(IntentPath, validIntentJSON+"\n")
			case "wrong approval":
				approved = strings.Repeat("b", 64)
			case "parser":
				run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "cancelled":
				cancel()
			case "reserved collision":
				stage, _ := sshDropStagePath(prepared.Transaction)
				f.write(stage, "# retained administrator bytes\n")
			}
			before, err := stableSSHRollback(journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			if err := rollbackSSHConfiguration(ctx, journal, approved, run, func() error { return nil }, sshPublicationDefaults()); err == nil {
				t.Fatal("accepted unreviewed inputs")
			}
			after, err := stableSSHRollback(journal, prepared.Transaction)
			if err != nil {
				t.Fatal(err)
			}
			left, _ := json.Marshal(before)
			right, _ := json.Marshal(after)
			if !bytes.Equal(left, right) {
				t.Fatal("changed rejected administrator configuration")
			}
			if err := journal.requireNoRollbackRecords(); err != nil {
				t.Fatal("wrote premature rollback evidence", err)
			}
		})
	}
}

func TestSSHRollbackRetainsForeignRacedFiles(t *testing.T) {
	for _, scenario := range []string{"main exchange", "drop source", "drop destination"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, prepared, journal := completedPublicationFixture(t)
			ops := sshPublicationDefaults()
			calls := 0
			foreign := []byte("# concurrently maintained administrator file\n")
			mainStage, _ := sshMainStagePath(prepared.Transaction)
			dropStage, _ := sshDropStagePath(prepared.Transaction)
			retained := mainStage
			ops.rename = func(a int, b string, c int, d string, flags uint) error {
				calls++
				name := ""
				if scenario == "main exchange" && calls == 1 {
					name = MainPath
				}
				if scenario == "drop source" && calls == 2 {
					name = DropInPath
					retained = dropStage
				}
				if scenario == "drop destination" && calls == 2 {
					name = dropStage
					retained = dropStage
				}
				if name != "" {
					if err := os.WriteFile(f.path(name), foreign, 0600); err != nil {
						return err
					}
				}
				return unix.Renameat2(a, b, c, d, flags)
			}
			if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, ops); err == nil {
				t.Fatal("accepted concurrent writer")
			}
			got, err := os.ReadFile(f.path(retained))
			if err != nil || !bytes.Equal(got, foreign) {
				t.Fatal("lost administrator bytes", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			journal = fixtureJournal(t, f)
			if _, err := inspectSSHRollback(journal); err == nil {
				t.Fatal("adopted raced file")
			}
			if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err == nil {
				t.Fatal("blindly resumed raced state")
			}
		})
	}
}

func TestSSHRollbackRefusesMalformedOrContradictoryEvidence(t *testing.T) {
	for _, scenario := range []string{"start extra field", "start wrong applied", "missing intent", "modified completion", "hardlink", "missing start"} {
		t.Run(scenario, func(t *testing.T) {
			f, plan, _, journal := completedPublicationFixture(t)
			if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err != nil {
				t.Fatal(err)
			}
			name := sshJournalDirectory + "/" + sshRollbackStartName
			switch scenario {
			case "start extra field":
				data, err := os.ReadFile(f.path(name))
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, strings.TrimSuffix(string(data), "}")+",\"extra\":1}")
			case "start wrong applied":
				data, err := os.ReadFile(f.path(name))
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, strings.Replace(string(data), "\"publication_steps_observed\":3", "\"publication_steps_observed\":2", 1))
			case "missing intent":
				if err := os.Remove(f.path(sshJournalDirectory + "/" + sshRollbackName(1, false))); err != nil {
					t.Fatal(err)
				}
			case "modified completion":
				f.write(sshJournalDirectory+"/"+sshRollbackName(1, true), "{}")
			case "hardlink":
				if err := os.Link(f.path(name), f.path(name+".linked")); err != nil {
					t.Fatal(err)
				}
			case "missing start":
				if err := os.Remove(f.path(name)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := inspectSSHRollback(journal); err == nil {
				t.Fatal("accepted damaged rollback history")
			}
		})
	}
}

func TestSSHRollbackRequiresSuccessfulLiveVerificationAfterReversal(t *testing.T) {
	f, plan, prepared, journal := completedPublicationFixture(t)
	originalRun := publicationFixtureParser(f)
	run := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
		if image == nil {
			return nil, unix.EIO
		}
		return originalRun(ctx, image, mode, access)
	}
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, run, func() error { return nil }, sshPublicationDefaults()); err == nil || !journal.poisoned {
		t.Fatal("claimed access recovery after parser failure")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	assertSSHRestored(t, f, prepared, journal)
	// Configuration-position inspection can succeed while parser verification
	// has failed. A successful explicit resume must verify the live parser anew.
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, originalRun, func() error { return nil }, sshPublicationDefaults()); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRollbackRejectsAdministratorChangeBeforeResume(t *testing.T) {
	f, plan, _, journal := completedPublicationFixture(t)
	ops := sshPublicationDefaults()
	calls := 0
	ops.rename = func(a int, b string, c int, d string, flags uint) error {
		calls++
		if calls == 2 {
			return unix.EIO
		}
		return unix.Renameat2(a, b, c, d, flags)
	}
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, ops); err == nil {
		t.Fatal("missing interrupted rollback")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	foreign := "# administrator changed access after interruption\n"
	f.write(MainPath, foreign)
	if err := rollbackSSHConfiguration(context.Background(), journal, plan.summary.PlanSHA256, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err == nil {
		t.Fatal("overrode a later administrator change")
	}
	got, err := os.ReadFile(f.path(MainPath))
	if err != nil || string(got) != foreign {
		t.Fatal("lost later administrator configuration", err)
	}
}

func TestSSHPreparationExcludesRollbackRetentionFromIncludes(t *testing.T) {
	f, _, before, main, drop := preparationFixture(t)
	// A negative Include that can later consume the retained policy must fail
	// during preparation, before publishing any transaction configuration.
	f.write("/etc/ssh/sshd_config.d/20-admin.conf", "Include /etc/ssh/sshd_config.d/.syswarden-ssh-drop-*\n")
	plan := f.plan()
	if _, err := prepareSSHRecord(plan, plan.summary.PlanSHA256, strings.Repeat("a", 64), before, main, drop, os.Geteuid()); err == nil || !strings.Contains(err.Error(), "transaction stage") {
		t.Fatal("allowed rollback retention in an Include graph or failed for the wrong reason", err)
	}
}

func TestSSHForwardPublicationRefusesRollbackEvidence(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	prepared := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(prepared); err != nil {
		t.Fatal(err)
	}
	f.write(sshJournalDirectory+"/"+sshRollbackStartName, "{}")
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop, publicationFixtureParser(f), func() error { return nil }, sshPublicationDefaults()); err == nil {
		t.Fatal("forward publication ignored rollback evidence")
	}
	stage, _ := sshMainStagePath(prepared.Transaction)
	if _, err := os.Lstat(f.path(stage)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("published a stage despite rollback evidence", err)
	}
}
