//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func recoveryFixture(t *testing.T, phase string, missing bool) (string, *moduleEditIntent, []byte) {
	t.Helper()
	root, intent := moduleIntentFixture(t, missing)
	original, err := readModuleFixture(filepath.Join(root, "modules", userModuleName))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	switch phase {
	case "published_pending":
		exchangeIntentFixture(t, root, intent, false)
	case "committed_cleanup":
		exchangeIntentFixture(t, root, intent, false)
		intent.State = "committed"
	case "rolled_back_cleanup":
		intent.State = "rolled_back"
	case "prepared":
	default:
		t.Fatal("unknown fixture phase")
	}
	writeIntentFixture(t, root, intent)
	return root, intent, original
}

func TestModuleEditRecoveryHandlesEachSupportedPairWithoutActivation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		kind := "replace"
		if missing {
			kind = "create"
		}
		for _, phase := range []string{"prepared", "published_pending", "committed_cleanup", "rolled_back_cleanup"} {
			t.Run(kind+"/"+phase, func(t *testing.T) {
				root, intent, original := recoveryFixture(t, phase, missing)
				global, load := GlobalConfig, CurrentLoadState()
				plan, err := PrepareModuleEditRecovery(context.Background(), root)
				if err != nil {
					t.Fatal(err)
				}
				review := plan.Review()
				if review.Target != intent.Target || review.State != phase || len(review.ApprovalID) != 64 || review.Action == "" {
					t.Fatalf("incomplete review: %+v", review)
				}
				calls := 0
				if err := plan.Apply(context.Background(), review.ApprovalID, func() error { calls++; return nil }); err != nil {
					t.Fatal(err)
				}
				if calls < 2 {
					t.Fatal("recovery did not repeat lifecycle preflight")
				}
				observed, err := ObserveModuleEdit(context.Background(), root)
				if err != nil || observed.State != "none" {
					t.Fatalf("recovery left unresolved intent: %+v %v", observed, err)
				}
				live, err := readModuleFixture(filepath.Join(root, "modules", userModuleName))
				if phase == "committed_cleanup" {
					if err != nil || !bytes.Contains(live, []byte("Reviewed")) {
						t.Fatal("committed candidate was not preserved")
					}
				} else if missing {
					if !os.IsNotExist(err) {
						t.Fatal("recovery did not restore original absence")
					}
				} else if err != nil || !bytes.Equal(live, original) {
					t.Fatal("recovery did not restore exact original bytes")
				}
				if _, err := os.Lstat(filepath.Join(root, "modules", intent.Stage)); !os.IsNotExist(err) {
					t.Fatal("recovery left its proven disposable stage")
				}
				if GlobalConfig != global || CurrentLoadState() != load {
					t.Fatal("file recovery changed runtime configuration")
				}
				if err := plan.Apply(context.Background(), review.ApprovalID, func() error { t.Fatal("reused approval reached preflight"); return nil }); err == nil {
					t.Fatal("replayed recovery approval")
				}
			})
		}
	}
}

func TestModuleEditRecoveryPreservesAdministratorChangesPresentAtReview(t *testing.T) {
	for _, phase := range []string{"prepared", "published_pending", "rolled_back_cleanup", "committed_cleanup"} {
		t.Run(phase, func(t *testing.T) {
			root, _, _ := recoveryFixture(t, phase, false)
			path := filepath.Join(root, "modules", "zz-admin.toml")
			content := []byte("# administrator-owned concurrent choice\n")
			if err := writeModuleFixture(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PrepareModuleEditRecovery(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if !plan.Review().InputsChanged {
				t.Fatal("review omitted changed administrator inputs")
			}
			if err := plan.Apply(context.Background(), plan.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := readModuleFixture(path)
			if err != nil || !bytes.Equal(raw, content) || !os.SameFile(before, after) {
				t.Fatal("recovery changed unrelated administrator input")
			}
		})
	}
}

func TestModuleEditRecoveryRejectsStaleOrUnapprovedPlansWithoutWrites(t *testing.T) {
	for _, fault := range []string{"approval", "expired", "canceled", "missing_preflight", "preflight", "target_replaced", "input_added", "intent_replaced", "late_input_change"} {
		t.Run(fault, func(t *testing.T) {
			root, _, _ := recoveryFixture(t, "published_pending", false)
			plan, err := PrepareModuleEditRecovery(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			approval := plan.Review().ApprovalID
			ctx := context.Background()
			preflight := func() error { return nil }
			switch fault {
			case "approval":
				approval = "yes"
			case "expired":
				plan.state.review.ExpiresAt = time.Now().Add(-time.Second)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing_preflight":
				preflight = nil
			case "preflight":
				preflight = func() error { return errors.New("pending firewall recovery") }
			case "target_replaced":
				path := filepath.Join(root, "modules", userModuleName)
				raw, err := readModuleFixture(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".admin-saved"); err != nil {
					t.Fatal(err)
				}
				if err := writeModuleFixture(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "input_added":
				if err := writeModuleFixture(filepath.Join(root, "modules", "zz-admin.toml"), []byte("# later\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "intent_replaced":
				path := filepath.Join(root, moduleEditIntentName)
				raw, err := readModuleFixture(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := writeModuleFixture(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "late_input_change":
				preflight = func() error {
					return writeModuleFixture(filepath.Join(root, "modules", "zz-admin.toml"), []byte("# late administrator edit\n"), 0600)
				}
			}
			before := intentFixtureFiles(t, root)
			if err := plan.Apply(ctx, approval, preflight); err == nil {
				t.Fatal("unsafe recovery was accepted")
			}
			after := intentFixtureFiles(t, root)
			if fault == "late_input_change" {
				delete(after, filepath.Join(root, "modules", "zz-admin.toml"))
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("refused recovery mutated files")
			}
		})
	}
}

func TestModuleEditRecoveryRetainsAmbiguousAndChangedCommittedEvidence(t *testing.T) {
	for _, fault := range []string{"missing_original", "edited_original", "changed_committed_inputs"} {
		t.Run(fault, func(t *testing.T) {
			phase := "published_pending"
			if fault == "changed_committed_inputs" {
				phase = "committed_cleanup"
			}
			root, intent, _ := recoveryFixture(t, phase, false)
			switch fault {
			case "missing_original":
				if err := os.Remove(filepath.Join(root, "modules", intent.Stage)); err != nil {
					t.Fatal(err)
				}
			case "edited_original":
				if err := writeModuleFixture(filepath.Join(root, "modules", intent.Stage), []byte("# changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed_committed_inputs":
				if err := writeModuleFixture(filepath.Join(root, "modules", "zz-admin.toml"), []byte("[invalid TOML\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := intentFixtureFiles(t, root)
			if _, err := PrepareModuleEditRecovery(context.Background(), root); err == nil {
				t.Fatal("ambiguous recovery acquired authority")
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) {
				t.Fatal("ambiguous recovery changed evidence")
			}
		})
	}
}

func TestModuleEditRecoveryCanResumeAfterItsOwnInterruptedCleanup(t *testing.T) {
	for _, boundary := range []string{"after_restore", "after_candidate_cleanup"} {
		t.Run(boundary, func(t *testing.T) {
			root, intent, original := recoveryFixture(t, "published_pending", false)
			plan, err := PrepareModuleEditRecovery(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			refusal := errors.New("injected lifecycle barrier during recovery")
			guard := func() error {
				observed, err := ObserveModuleEdit(context.Background(), root)
				if err != nil {
					return err
				}
				if boundary == "after_restore" && observed.State == "prepared" {
					return refusal
				}
				if boundary == "after_candidate_cleanup" && observed.State == "rolled_back_cleanup" {
					if _, err := os.Lstat(filepath.Join(root, "modules", intent.Stage)); os.IsNotExist(err) {
						return refusal
					}
				}
				return nil
			}
			if err := plan.Apply(context.Background(), plan.Review().ApprovalID, guard); !errors.Is(err, refusal) {
				t.Fatalf("recovery did not stop at selected boundary: %v", err)
			}
			live, err := ReadUserModule(root)
			if err != nil || !bytes.Equal(live, original) {
				t.Fatal("interrupted recovery lost the original")
			}
			if err := RefusePendingModuleEdit(root); err == nil {
				t.Fatal("interrupted recovery lost its barrier")
			}
			retry, err := PrepareModuleEditRecovery(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if err := retry.Apply(context.Background(), retry.Review().ApprovalID, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if err := RefusePendingModuleEdit(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}
