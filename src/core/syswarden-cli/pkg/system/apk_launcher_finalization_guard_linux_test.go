//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPKLauncherFinalizationGuardRejectsPublishedOnlyLineage(t *testing.T) {
	fixture, factory := apkTerminalCompleteFixture(t)
	authority, err := inspectAPKTerminalFixture(t.Context(), fixture, factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishAPKExecutionLauncherLineage(t.Context(), authority); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	err = preflightAPKLauncherRemovalAt(t.Context(), fixture.services.hostRoot)
	if err == nil || !strings.Contains(err.Error(), "not terminally finalized") {
		t.Fatalf("published-only execution lineage was not refused at finalization boundary: %v", err)
	}
}

func TestAPKLauncherFinalizationGuardRequiresExactFinalState(t *testing.T) {
	for _, mutation := range []string{"none", "missing-finalizing", "missing-closed", "closed-binding", "closed-identity", "pending-closed", "unresolved", "pre-dispatch-refused", "terminal-unresolved", "missing-finalized", "different-finalized", "noncanonical", "active-hook", "gate", "quarantine", "missing-gate-proof", "parent", "record-identity", "late-terminal-unresolved", "handoff"} {
		t.Run(mutation, func(t *testing.T) {
			fixture, factory := apkTerminalCompleteFixture(t)
			authority, err := inspectAPKTerminalFixture(t.Context(), fixture, factory)
			if err != nil {
				t.Fatal(err)
			}
			reference, err := authority.launcherReference(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := authority.Close(); err != nil {
				t.Fatal(err)
			}
			if err := finalizeAPKTransitionWith(t.Context(), reference.PlanSHA256, fixture.candidate.keys, fixture.candidate.attestInstalled, fixture.services, factory); err != nil {
				t.Fatal(err)
			}
			store, err := openAPKLauncherLifecycleStore(t.Context(), fixture.services.hostRoot, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := store.close(); err != nil {
					t.Error(err)
				}
			}()
			h := &apkLauncherLifecycleRemoval{store: store, reference: reference}
			if mutation == "record-identity" || mutation == "late-terminal-unresolved" || mutation == "closed-identity" {
				if err := h.attestExecutionFinalization(); err != nil {
					t.Fatal(err)
				}
			}
			finalized := filepath.Join(fixture.review.Directory, "terminal-finalized.json")
			write := func(path string, raw []byte, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, raw, mode); err != nil {
					t.Fatal(err)
				} // #nosec G306 -- exact test-owned evidence and hook modes
			}
			var retained string
			switch mutation {
			case "missing-finalizing":
				if err := os.Remove(filepath.Join(fixture.review.Directory, "terminal-finalizing.json")); err != nil {
					t.Fatal(err)
				}
			case "missing-closed":
				if err := os.Remove(filepath.Join(fixture.review.Directory, "terminal-closed.json")); err != nil {
					t.Fatal(err)
				}
			case "closed-binding":
				path := filepath.Join(fixture.review.Directory, "terminal-closed.json")
				raw := freshAPKAtomicRead(t, path)
				write(path, []byte(strings.Replace(string(raw), reference.ReceiptSHA256, strings.Repeat("a", 64), 1)), 0600)
			case "closed-identity":
				path := filepath.Join(fixture.review.Directory, "terminal-closed.json")
				raw := freshAPKAtomicRead(t, path)
				if err := os.Rename(path, path+".held"); err != nil {
					t.Fatal(err)
				}
				write(path, raw, 0600)
			case "pending-closed":
				write(filepath.Join(fixture.review.Directory, "terminal-closed.pending"), []byte("{}\n"), 0600)
			case "unresolved", "pre-dispatch-refused", "terminal-unresolved":
				write(filepath.Join(fixture.review.Directory, mutation+".json"), []byte("{}\n"), 0600)
			case "late-terminal-unresolved":
				write(filepath.Join(fixture.review.Directory, "terminal-unresolved.json"), []byte("{}\n"), 0600)
			case "missing-finalized":
				if err := os.Remove(finalized); err != nil {
					t.Fatal(err)
				}
			case "different-finalized":
				raw := freshAPKAtomicRead(t, finalized)
				write(finalized, []byte(strings.Replace(string(raw), reference.ReceiptSHA256, strings.Repeat("a", 64), 1)), 0600)
			case "noncanonical":
				write(finalized, append(freshAPKAtomicRead(t, finalized), ' '), 0600)
			case "active-hook":
				body, err := apkTransitionGateBytes(reference.PlanSHA256)
				if err != nil {
					t.Fatal(err)
				}
				retained = filepath.Join(fixture.services.root, "active-hook")
				write(retained, body, 0700)
			case "gate":
				body, err := apkTransitionGateBytes(reference.PlanSHA256)
				if err != nil {
					t.Fatal(err)
				}
				retained = filepath.Join(fixture.services.hostRoot, apkTransitionGateDirectory, apkTransitionGateName)
				write(retained, body, 0755)
			case "quarantine":
				var record apkTerminalGateRetirement
				if err := decodeAPKTransitionJSON(freshAPKAtomicRead(t, filepath.Join(fixture.review.Directory, "terminal-retire-gate.json")), &record); err != nil {
					t.Fatal(err)
				}
				retained = filepath.Join(fixture.services.hostRoot, apkTransitionGateDirectory, record.Quarantine)
				write(retained, []byte("administrator recovery entry\n"), 0600)
			case "missing-gate-proof":
				if err := os.Remove(filepath.Join(fixture.review.Directory, "terminal-retire-gate.json")); err != nil {
					t.Fatal(err)
				}
			case "parent":
				parent := filepath.Join(fixture.services.hostRoot, apkTransitionGateDirectory)
				if err := os.Rename(parent, parent+".held"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(parent, 0755); err != nil {
					t.Fatal(err)
				} // #nosec G301 -- deliberate safe parent replacement
			case "record-identity":
				raw := freshAPKAtomicRead(t, finalized)
				if err := os.Rename(finalized, finalized+".held"); err != nil {
					t.Fatal(err)
				}
				write(finalized, raw, 0600)
			case "handoff":
				path := filepath.Join(fixture.review.Directory, "native-handoff.json")
				write(path, append(freshAPKAtomicRead(t, path), ' '), 0600)
			}
			err = h.attestExecutionFinalization()
			if mutation == "none" && err != nil {
				t.Fatal(err)
			}
			if mutation != "none" && err == nil {
				t.Fatal("incomplete or changed finalization accepted")
			}
			if retained != "" {
				if _, err := os.Lstat(retained); errors.Is(err, os.ErrNotExist) {
					t.Fatal("refusal removed a retained recovery entry")
				} else if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
