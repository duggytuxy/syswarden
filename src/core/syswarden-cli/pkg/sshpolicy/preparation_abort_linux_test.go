//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"syswarden-cli/pkg/sshselection"
	"testing"

	"golang.org/x/sys/unix"
)

func preparationAbortFixtureParser(_ context.Context, _ *parserImage, mode, _ string) ([]byte, error) {
	if mode == "syntax" {
		return nil, nil
	}
	return []byte("port 2222\nauthenticationmethods publickey\nallowtcpforwarding yes\n"), nil
}

func interruptedPreparationFixture(t *testing.T) (*inventoryFixture, migrationPlan, sshPreparation) {
	t.Helper()
	f, _, _ := transactionFixture(t)
	f.write("/etc/ssh/sshd_config.d/admin.conf", "MaxSessions 12\n")
	plan := f.plan()
	if err := provisionSSHState(f.root, os.Geteuid(), sshProvisionDefaults()); err != nil {
		t.Fatal(err)
	}
	before := fixtureMainImage(t, f)
	attrs := map[string][]byte{}
	if label, exists := before.attrs["security.selinux"]; exists {
		attrs["security.selinux"] = label
	}
	main, drop, err := stageSSHTransaction(f.root, os.Geteuid(), plan, attrs)
	if err != nil {
		t.Fatal(err)
	}
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(main.Close(), drop.Close(), journal.Close()); err != nil {
		t.Fatal(err)
	}
	return f, plan, record
}

func recoverPreparationFixture(f *inventoryFixture, record sshPreparation) (sshTransactionResult, error) {
	return recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), record.PlanSHA256,
		record.ParserSHA256, preparationAbortFixtureParser, func() error { return nil }, sshPublicationDefaults())
}

func TestSSHPreparationAbortRetainsOriginalAndTerminalEvidence(t *testing.T) {
	f, plan, record := interruptedPreparationFixture(t)
	before := fixtureMainImage(t, f)
	prepared, err := os.ReadFile(f.path(sshJournalDirectory + "/" + sshPreparedRecord))
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := recoverPreparationFixture(f, record)
		if err != nil || !result.Aborted || result.Restored || result.Published ||
			result.RecoveryRequired || result.Verification.RuntimeActivated || result.Transaction != record.Transaction {
			t.Fatal("preparation abort did not preserve its exact outcome", result, err)
		}
		if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
			t.Fatal("abort rewrote the original main file")
		}
		if current, err := os.ReadFile(f.path(sshJournalDirectory + "/" + sshPreparedRecord)); err != nil || !bytes.Equal(current, prepared) {
			t.Fatal("preparation evidence was rewritten", err)
		}
		if _, err := os.Lstat(f.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("abort left an active policy")
		}
	}
	journal := fixtureJournal(t, f)
	data, err := journal.readRecord(sshPreparationAbortName)
	if err != nil {
		t.Fatal(err)
	}
	var terminal sshPreparationAbort
	if err := json.Unmarshal(data, &terminal); err != nil || terminal.Prepared != digestBytes(prepared) ||
		terminal.Transaction != record.Transaction || terminal.Schema != 1 {
		t.Fatal("terminal record does not bind the exact preparation", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	// Aborting is not journal retirement or authorization to publish again.
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, transactionFixtureDependencies(f))
	if err == nil || result.Published {
		t.Fatal("reused aborted evidence as a fresh transaction")
	}
}

func TestSSHPreparationAbortRejectsChangedInputsAndMixedHistory(t *testing.T) {
	for _, scenario := range []string{
		"main", "include", "selection", "intent", "new include", "main mode",
		"main stage", "drop stage", "drop-in", "unknown record", "late phase",
		"rollback", "invalid terminal", "prepared mode", "prepared link", "identical main replacement",
	} {
		t.Run(scenario, func(t *testing.T) {
			f, _, record := interruptedPreparationFixture(t)
			switch scenario {
			case "main":
				f.write(MainPath, includeDropIns+"Port 2223\n")
			case "include":
				f.write("/etc/ssh/sshd_config.d/admin.conf", "MaxSessions 15\n")
			case "selection":
				f.write(sshselection.Path, "[ssh]\nhardening = \"disabled\"\n")
			case "intent":
				f.write(IntentPath, strings.Replace(validIntentJSON, "forwarding", "cis", 1))
			case "new include":
				f.write("/etc/ssh/sshd_config.d/new.conf", "PermitTTY no\n")
			case "main mode":
				if err := f.chmod(MainPath, 0644); err != nil {
					t.Fatal(err)
				}
			case "identical main replacement":
				original := fixtureMainImage(t, f)
				f.write("/etc/ssh/replacement", string(original.data))
				if err := os.Rename(f.path("/etc/ssh/replacement"), f.path(MainPath)); err != nil {
					t.Fatal(err)
				}
			case "main stage":
				name, _ := sshMainStagePath(record.Transaction)
				f.write(name, string(record.MainAfter.Data))
			case "drop stage":
				name, _ := sshDropStagePath(record.Transaction)
				f.write(name, string(record.DropIn.Data))
			case "drop-in":
				f.write(DropInPath, string(record.DropIn.Data))
			case "unknown record":
				f.write(sshJournalDirectory+"/operator-note", "retained evidence\n")
			case "late phase":
				f.write(sshJournalDirectory+"/"+sshPublicationName(3, true), "{}")
			case "rollback":
				f.write(sshJournalDirectory+"/"+sshRollbackStartName, "{}")
			case "invalid terminal":
				f.write(sshJournalDirectory+"/"+sshPreparationAbortName, "{}")
			case "prepared mode":
				if err := f.chmod(sshJournalDirectory+"/"+sshPreparedRecord, 0644); err != nil {
					t.Fatal(err)
				}
			case "prepared link":
				if err := os.Link(f.path(sshJournalDirectory+"/"+sshPreparedRecord), f.path("/extra-preparation")); err != nil {
					t.Fatal(err)
				}
			}
			current := fixtureMainImage(t, f)
			result, err := recoverPreparationFixture(f, record)
			if err == nil || result.Aborted || result.Restored || result.Published {
				t.Fatal("accepted changed or ambiguous evidence", result, err)
			}
			if !reflect.DeepEqual(current, fixtureMainImage(t, f)) {
				t.Fatal("recovery changed the observed main file")
			}
			if scenario != "invalid terminal" {
				if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("created terminal evidence despite changed inputs")
				}
			}
		})
	}
}

func TestSSHPreparationAbortRequiresOriginalApprovalAndParser(t *testing.T) {
	for _, scenario := range []string{"approval", "parser digest", "parser identity", "syntax", "effective", "context"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, record := interruptedPreparationFixture(t)
			approved, parser := record.PlanSHA256, record.ParserSHA256
			check := func() error { return nil }
			run := preparationAbortFixtureParser
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch scenario {
			case "approval":
				approved = strings.Repeat("b", 64)
			case "parser digest":
				parser = strings.Repeat("b", 64)
			case "parser identity":
				check = func() error { return unix.EIO }
			case "syntax":
				run = func(context.Context, *parserImage, string, string) ([]byte, error) { return nil, unix.EIO }
			case "effective":
				run = func(_ context.Context, image *parserImage, mode, _ string) ([]byte, error) {
					if mode == "syntax" {
						return nil, nil
					}
					if image == nil {
						return []byte("port 2223\nallowtcpforwarding yes\n"), nil
					}
					return []byte("port 2222\nallowtcpforwarding yes\n"), nil
				}
			case "context":
				cancel()
			}
			result, err := recoverSSHTransaction(ctx, f.root, os.Geteuid(), approved, parser, run, check, sshPublicationDefaults())
			if err == nil || result.Aborted {
				t.Fatal("accepted unverified recovery", result, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recorded unverified abort")
			}
		})
	}
}

func TestSSHPreparationAbortChecksChangesDuringParser(t *testing.T) {
	for _, scenario := range []string{"main", "selection", "journal", "prepared", "parser error"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, record := interruptedPreparationFixture(t)
			run := preparationAbortFixtureParser
			called := false
			mutate := func(ctx context.Context, image *parserImage, mode, access string) ([]byte, error) {
				if !called {
					called = true
					switch scenario {
					case "main":
						f.write(MainPath, includeDropIns+"Port 2223\n")
					case "selection":
						f.write(sshselection.Path, "[ssh]\nhardening = \"cis\"\n")
					case "journal":
						f.write(sshJournalDirectory+"/unexpected", "keep\n")
					case "prepared":
						f.write(sshJournalDirectory+"/"+sshPreparedRecord, "{}")
					case "parser error":
						f.write(sshJournalDirectory+"/unexpected", "keep\n")
						return nil, unix.EIO
					}
				}
				return run(ctx, image, mode, access)
			}
			result, err := recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), record.PlanSHA256,
				record.ParserSHA256, mutate, func() error { return nil }, sshPublicationDefaults())
			if !called || err == nil || result.Aborted {
				t.Fatal("missed a change during parser verification", result, err)
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recorded an abort over concurrently changed inputs")
			}
		})
	}
}

func TestSSHPreparationAbortRepairsUncertainSyncWithoutReplacingEvidence(t *testing.T) {
	f, _, record := interruptedPreparationFixture(t)
	journal := fixtureJournal(t, f)
	journal.syncDirectory = func(*os.File) error { return unix.EIO }
	if err := abortSSHPreparation(context.Background(), journal, record, preparationAbortFixtureParser, func() error { return nil }); err == nil || !journal.poisoned {
		t.Fatal("claimed durability despite failed sync")
	}
	terminal, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName))
	if err != nil {
		t.Fatal("missing retained uncertain terminal evidence", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal = fixtureJournal(t, f)
	// Exercise recovery after a caller has already enumerated the directory.
	if _, err := journal.directory.Readdirnames(-1); err != nil {
		t.Fatal(err)
	}
	syncs := 0
	journal.syncDirectory = func(file *os.File) error { syncs++; return file.Sync() }
	if err := abortSSHPreparation(context.Background(), journal, record, preparationAbortFixtureParser, func() error { return nil }); err != nil || syncs != 1 {
		t.Fatal("did not repair the retained terminal record's durability", err, syncs)
	}
	after, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName))
	if err != nil || !os.SameFile(terminal, after) {
		t.Fatal("replaced terminal evidence during retry", err)
	}
}

func TestSSHPreparationAbortPreventsPublicationAndMixedRollback(t *testing.T) {
	f, plan, before, main, drop := preparationFixture(t)
	record := fixturePreparation(t, plan, before, main, drop)
	journal := fixtureJournal(t, f)
	if err := journal.write(record); err != nil {
		t.Fatal(err)
	}
	run, check := preparationAbortFixtureParser, func() error { return nil }
	if err := abortSSHPreparation(context.Background(), journal, record, run, check); err != nil {
		t.Fatal(err)
	}
	if err := publishSSHConfiguration(context.Background(), journal, plan, main, drop, run, check, sshPublicationDefaults()); err == nil {
		t.Fatal("published after terminal abort")
	}
	// Even a mixed journal with a first publication intent must not choose
	// rollback and ignore the terminal abort.
	if err := journal.writeRecord(sshPublicationName(1, false), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectSSHPublication(journal); err == nil {
		t.Fatal("accepted mixed abort and publication history")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := recoverPreparationFixture(f, record); err == nil || result.Restored || result.Aborted {
		t.Fatal("accepted mixed terminal evidence", result, err)
	}
}

func TestSSHPreparationAbortRejectsChangesDuringDurabilityRepair(t *testing.T) {
	for _, scenario := range []string{"main", "selection", "phase", "terminal", "prepared"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, record := interruptedPreparationFixture(t)
			journal := fixtureJournal(t, f)
			journal.syncDirectory = func(file *os.File) error {
				switch scenario {
				case "main":
					f.write(MainPath, includeDropIns+"Port 2223\n")
				case "selection":
					f.write(sshselection.Path, "[ssh]\nhardening = \"cis\"\n")
				case "phase":
					f.write(sshJournalDirectory+"/"+sshPublicationName(1, false), "{}")
				case "terminal":
					f.write(sshJournalDirectory+"/"+sshPreparationAbortName, "{}")
				case "prepared":
					f.write(sshJournalDirectory+"/"+sshPreparedRecord, "{}")
				}
				return file.Sync()
			}
			if err := abortSSHPreparation(context.Background(), journal, record, preparationAbortFixtureParser,
				func() error { return nil }); err == nil || !journal.poisoned {
				t.Fatal("claimed success after a change during terminal sync")
			}
			if _, err := os.Lstat(f.path(sshJournalDirectory + "/" + sshPreparationAbortName)); err != nil {
				t.Fatal("removed uncertain evidence", err)
			}
		})
	}
}

func TestSSHPreparationAbortRejectsModifiedTerminalRecordOnRetry(t *testing.T) {
	for _, scenario := range []string{"unknown key", "whitespace", "original", "mode", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			f, _, record := interruptedPreparationFixture(t)
			if _, err := recoverPreparationFixture(f, record); err != nil {
				t.Fatal(err)
			}
			name := sshJournalDirectory + "/" + sshPreparationAbortName
			raw, err := os.ReadFile(f.path(name))
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unknown key":
				f.write(name, strings.TrimSuffix(string(raw), "}")+",\"extra\":true}")
			case "whitespace":
				f.write(name, string(raw)+"\n")
			case "original":
				var terminal sshPreparationAbort
				if err := json.Unmarshal(raw, &terminal); err != nil {
					t.Fatal(err)
				}
				terminal.Original.Files[MainPath] = []byte("Port 2223\n")
				data, err := json.Marshal(terminal)
				if err != nil {
					t.Fatal(err)
				}
				f.write(name, string(data))
			case "mode":
				if err := f.chmod(name, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				f.write("/terminal-copy", string(raw))
				if err := os.Remove(f.path(name)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.path("/terminal-copy"), f.path(name)); err != nil {
					t.Fatal(err)
				}
			}
			if result, err := recoverPreparationFixture(f, record); err == nil || result.Aborted {
				t.Fatal("accepted a modified terminal record", result, err)
			}
		})
	}
}

func TestSSHTransactionRecoversInterruptionBeforeFirstPublicationIntent(t *testing.T) {
	f, plan, deps := transactionFixture(t)
	before := fixtureMainImage(t, f)
	deps.checkParser = func() error {
		_, err := os.Stat(f.path(sshJournalDirectory + "/" + sshPreparedRecord))
		if err == nil {
			return unix.EIO
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	result, err := executeSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256, deps)
	if err == nil || !result.RecoveryRequired || result.Published || result.Transaction == "" {
		t.Fatal("wrong result for interruption after preparation", result, err)
	}
	result, err = recoverSSHTransaction(context.Background(), f.root, os.Geteuid(), plan.summary.PlanSHA256,
		deps.parserDigest, deps.run, func() error { return nil }, sshPublicationDefaults())
	if err != nil || !result.Aborted || result.Restored || result.RecoveryRequired {
		t.Fatal("cannot resolve exact preparation-only interruption", result, err)
	}
	if !reflect.DeepEqual(before, fixtureMainImage(t, f)) {
		t.Fatal("changed original configuration while aborting")
	}
}
