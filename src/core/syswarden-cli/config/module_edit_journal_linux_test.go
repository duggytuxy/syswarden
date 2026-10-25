//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func exerciseReviewedJournal(t *testing.T, root, boundary string, stop func()) error {
	t.Helper()
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	proposal := prepareProfileProposal(t, edit)
	state := proposal.state
	journal := newModuleEditJournal(state)
	journal.persisted = func(phase string) {
		if phase == boundary {
			stop()
		}
	}
	ops := defaultConfigReplacementOps()
	ops.hooks = journal.hooks()
	rename := ops.rename
	ops.rename = func(root *os.Root, from, to string, exchange bool) error {
		if err := rename(root, from, to, exchange); err != nil {
			return err
		}
		if boundary == "exchanged" {
			stop()
		}
		return nil
	}
	remove := ops.remove
	ops.remove = func(root *os.Root, name string) error {
		if err := remove(root, name); err != nil {
			return err
		}
		if boundary == "removed_original" {
			stop()
		}
		return nil
	}
	pre := func() error { return state.snapshot.revalidate(state.root, false, nil) }
	post := func() error {
		if boundary == "rolled_back" || boundary == "rollback_record_unknown" {
			return errors.New("injected post-publication refusal")
		}
		return state.snapshot.revalidateTarget(state.root, state.target, state.content)
	}
	switch boundary {
	case "prepare_record_unknown":
		ops.hooks.prepare = func(stage string, candidate *secureFileIdentity) error {
			if err := journal.prepare(stage, candidate); err != nil {
				return err
			}
			return errors.New("injected unknown prepared-record result")
		}
	case "commit_record_unknown":
		ops.hooks.commit = func() error {
			if err := journal.transition("committed"); err != nil {
				return err
			}
			return errors.New("injected unknown committed-record result")
		}
	case "rollback_record_unknown":
		ops.hooks.rollback = func() error {
			if err := journal.transition("rolled_back"); err != nil {
				return err
			}
			return errors.New("injected unknown rollback-record result")
		}
	}
	return replaceSecureConfigFileUsing(state.target.directory(root), state.target.name, state.content, state.snapshot.identity(state.target), pre, nil, post, ops)
}

func TestModuleEditJournalCrashChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_EDIT_CRASH_CHILD") != "1" {
		return
	}
	root, boundary := os.Getenv("SYSWARDEN_EDIT_CRASH_ROOT"), os.Getenv("SYSWARDEN_EDIT_CRASH_BOUNDARY")
	if err := exerciseReviewedJournal(t, root, boundary, func() { os.Exit(77) }); err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash boundary was not reached")
}

func TestModuleEditJournalSurvivesAbruptProcessExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, missing := range []bool{false, true} {
		kind := "replace"
		if missing {
			kind = "create"
		}
		for _, boundary := range []string{"prepared", "exchanged", "committed", "rolled_back", "removed_original"} {
			if missing && boundary == "removed_original" {
				continue
			}
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				root, _ := initializedUserModule(t)
				if missing {
					root = historicalOrdinaryEditRoot(t)
					if err := os.Remove(filepath.Join(root, "modules", userModuleName)); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				// #nosec G204 -- Runs only this test executable from os.Executable with a fixed test selector; fixture paths are passed as environment data, never shell code.
				child := exec.CommandContext(ctx, executable, "-test.run=^TestModuleEditJournalCrashChild$", "-test.count=1")
				child.Env = append(os.Environ(), "SYSWARDEN_EDIT_CRASH_CHILD=1", "SYSWARDEN_EDIT_CRASH_ROOT="+root, "SYSWARDEN_EDIT_CRASH_BOUNDARY="+boundary)
				output, err := child.CombinedOutput()
				var exited *exec.ExitError
				if !errors.As(err, &exited) || exited.ExitCode() != 77 {
					t.Fatalf("child did not exit at boundary: %v %s", err, output)
				}
				observed, err := ObserveModuleEdit(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				expected := map[string]string{"prepared": "prepared", "exchanged": "published_pending", "committed": "committed_cleanup", "rolled_back": "rolled_back_cleanup", "removed_original": "committed_cleanup"}[boundary]
				if observed.State != expected || observed.InputsChanged {
					t.Fatalf("incorrect crash observation: %+v", observed)
				}
				if err := RefusePendingModuleEdit(root); err == nil {
					t.Fatal("crash evidence did not block reuse")
				}
				before := intentFixtureFiles(t, root)
				if _, err := BeginUserModuleEdit(context.Background(), root); err == nil {
					t.Fatal("opened a new edit over unresolved intent")
				}
				if _, err := ValidateModularConfig(root); err == nil {
					t.Fatal("validated unresolved live publication as complete")
				}
				if err := ParseConfig(root); err == nil {
					t.Fatal("loaded unresolved publication")
				}
				if err := EnsureDefaults(root); err == nil {
					t.Fatal("filled defaults across unresolved publication")
				}
				if err := InitializeDefaults(root); err == nil {
					t.Fatal("initialized across unresolved publication")
				}
				migrator := &Migrator{SourcePath: filepath.Join(root, "missing-legacy"), OutputDir: root}
				if err := migrator.Run(); err == nil || !strings.Contains(err.Error(), "edit publication") {
					t.Fatalf("migration did not hit edit barrier first: %v", err)
				}
				if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) {
					t.Fatal("blocked operation altered recovery data")
				}
				plan, err := PrepareModuleEditRecovery(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				if err := plan.Apply(context.Background(), plan.Review().ApprovalID, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				completed, err := ObserveModuleEdit(context.Background(), root)
				if err != nil || completed.State != "none" {
					t.Fatalf("fresh process evidence could not be recovered: %+v %v", completed, err)
				}
			})
		}
	}
}

func TestModuleEditJournalRetainsPairsOnUnknownRecordOutcomes(t *testing.T) {
	for boundary, expected := range map[string]string{"prepare_record_unknown": "prepared", "commit_record_unknown": "committed_cleanup", "rollback_record_unknown": "rolled_back_cleanup"} {
		t.Run(boundary, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			if err := exerciseReviewedJournal(t, root, boundary, func() { t.Fatal("unexpected crash callback") }); err == nil {
				t.Fatal("unknown record result reported success")
			}
			observed, err := observeModuleEdit(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if observed.observation.State != expected {
				t.Fatalf("unexpected retained pair: %+v", observed.observation)
			}
			if _, err := os.Stat(filepath.Join(root, "modules", observed.intent.Stage)); err != nil {
				t.Fatal("uncertain outcome discarded a retained data file")
			}
		})
	}
}

func TestModuleEditJournalSuccessfulPublicationLeavesNoIntentOrStage(t *testing.T) {
	root, edit, _, _ := proposalFixture(t)
	proposal := prepareProfileProposal(t, edit)
	if err := proposal.Publish(context.Background(), proposal.Review().ApprovalID, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	observed, err := ObserveModuleEdit(context.Background(), root)
	if err != nil || observed.State != "none" {
		t.Fatalf("publication retained unresolved evidence: %+v %v", observed, err)
	}
	actual, err := ReadUserModule(root)
	if err != nil || !bytes.Equal(actual, proposal.state.content) {
		t.Fatal("published bytes differ")
	}
	entries, err := os.ReadDir(filepath.Join(root, "modules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+userModuleName+".tmp-") {
			t.Fatal("completed publication retained a stage")
		}
	}
}

func TestModuleEditBarrierTreatsEveryExistingEvidenceAsUnresolved(t *testing.T) {
	for _, kind := range []string{"invalid", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			path := filepath.Join(root, moduleEditIntentName)
			switch kind {
			case "invalid":
				if err := writeModuleFixture(path, []byte("not JSON"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			}
			if err := RefusePendingModuleEdit(root); err == nil {
				t.Fatal("unsafe evidence did not block reuse")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("barrier removed evidence")
			}
		})
	}
	absent := filepath.Join(t.TempDir(), "absent")
	if err := RefusePendingModuleEdit(absent); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(absent); !os.IsNotExist(err) {
		t.Fatal("barrier created missing root")
	}
}

func TestModuleEditJournalDetectsInPlaceRecordRestoration(t *testing.T) {
	root, _ := initializedUserModule(t)
	edit, err := BeginUserModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	proposal := prepareProfileProposal(t, edit)
	journal := newModuleEditJournal(proposal.state)
	ops := defaultConfigReplacementOps()
	ops.hooks = journal.hooks()
	journal.persisted = func(phase string) {
		if phase != "prepared" {
			return
		}
		path := filepath.Join(root, moduleEditIntentName)
		raw, err := readModuleFixture(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeModuleFixture(path, append(bytes.Clone(raw), ' '), 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeModuleFixture(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
			t.Fatal(err)
		}
	}
	if err := replaceSecureConfigFileUsing(filepath.Join(root, "modules"), userModuleName, proposal.state.content, proposal.state.snapshot.user, nil, nil, nil, ops); err == nil {
		t.Fatal("in-place record rewrite went undetected")
	}
	observed, err := ObserveModuleEdit(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if observed.State != "prepared" {
		t.Fatalf("record rewrite reached live publication: %+v", observed)
	}
}
