//go:build linux

package system

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture models a completed native operation with inert payloads. Real
// consecutive signed APK operations remain separate native validation evidence.
func apkRepeatedTransferFixture(t *testing.T) (*apkExecutionTestFixture, *apkLauncherTransferProposal) {
	t.Helper()
	f, factory := apkTerminalCompleteFixtureWithSetup(t, func(candidate *authenticatedAPKCandidate, services *apkTransitionServices) {
		apkTransferFixtureSource(t, candidate, services, false)
	})
	if err := finalizeAPKTransitionWith(t.Context(), f.review.PlanSHA256, f.candidate.keys, f.candidate.attestInstalled, f.services, factory); err != nil {
		t.Fatal(err)
	}
	h, err := inspectAPKLauncherLifecycleRemovalAt(t.Context(), f.services.hostRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := h.close(); err != nil {
			t.Error(err)
		}
	}()
	records, err := parseAPKLauncherRegistrations(freshAPKAtomicRead(t, filepath.Join(f.services.hostRoot, "lib/apk/db/installed")))
	if err != nil {
		t.Fatal(err)
	}
	record := records[f.candidate.target.packageName]
	native := apkLauncherNativeRecord{Name: f.candidate.target.packageName, Version: f.candidate.version, Checksum: record.checksum, RecordSHA256: apkTransitionDigest([]byte(record.raw))}
	previous, err := captureAPKLauncherPreviousExecution(h, native)
	if err != nil {
		t.Fatal(err)
	}
	proposal := *h.transfer
	proposal.Schema, proposal.Purpose = apkLauncherRepeatedTransferSchema, "same-identity-execution-ownership-transfer"
	proposal.Previous, proposal.Native = previous, native
	proposal.Lineage, err = h.store.captureLineageProposal()
	if err != nil {
		t.Fatal(err)
	}
	return f, &proposal
}

func TestAPKLauncherRepeatedTransferBindsClosedPredecessor(t *testing.T) {
	for _, mutation := range []string{"none", "depth", "excess-depth", "native-checksum", "original-native", "reference", "missing-closure", "changed-closure", "replaced-closure", "missing-ack", "unexpected-publication", "retirement-debt", "publication-identity", "record-order", "ancestor-origin", "cancelled"} {
		t.Run(mutation, func(t *testing.T) {
			f, proposal := apkRepeatedTransferFixture(t)
			ctx := t.Context()
			root, err := os.OpenRoot(f.review.Directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			switch mutation {
			case "depth":
				proposal.Previous.Depth++
			case "excess-depth":
				proposal.Previous.Depth = maximumAPKLauncherTransferDepth + 1
			case "native-checksum":
				proposal.Native.Checksum = apkRetentionFixtureChecksum
			case "original-native":
				proposal.Previous.OriginalNative.Version = "v5.02.0"
			case "reference":
				proposal.Previous.Reference.ReceiptSHA256 = strings.Repeat("a", 64)
			case "missing-closure":
				if err := root.Remove("terminal-closed.json"); err != nil {
					t.Fatal(err)
				}
			case "changed-closure":
				if err := root.WriteFile("terminal-closed.json", []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "replaced-closure":
				raw, err := root.ReadFile("terminal-closed.json")
				if err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("terminal-closed.json", "terminal-closed.held"); err != nil {
					t.Fatal(err)
				}
				if err := root.WriteFile("terminal-closed.json", raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-ack":
				if err := root.Remove("native-hook-post-commit.json"); err != nil {
					t.Fatal(err)
				}
			case "unexpected-publication":
				freshAPKFixtureWrite(t, f.services.hostRoot, filepath.Join(strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "fresh-"+f.review.PlanSHA256, "unexpected.json"), []byte("{}\n"), 0600)
			case "retirement-debt":
				if err := os.Mkdir(filepath.Join(f.services.hostRoot, strings.TrimPrefix(apkLauncherLifecycleRoot, "/"), "transfer-removal-"+f.review.PlanSHA256), 0700); err != nil {
					t.Fatal(err)
				}
			case "publication-identity":
				proposal.Previous.Publication[0].Identity.Inode++
			case "record-order":
				proposal.Previous.Execution[0], proposal.Previous.Execution[1] = proposal.Previous.Execution[1], proposal.Previous.Execution[0]
			case "ancestor-origin":
				proposal.Records[0].SHA256 = strings.Repeat("b", 64)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			source, err := openAPKLauncherTransferSource(ctx, f.services.hostRoot, proposal, strings.Repeat("c", 64), "")
			if source != nil {
				err = errors.Join(err, source.close())
			}
			if mutation == "none" && err != nil {
				t.Fatal(err)
			}
			if mutation != "none" && err == nil {
				t.Fatal("changed predecessor evidence accepted")
			}
			if f.calls != 1 {
				t.Fatal("verification replayed native execution")
			}
		})
	}
}

func TestAPKLauncherFinalizationAllowsOnlyBoundSuccessor(t *testing.T) {
	for _, mutation := range []string{"none", "exact", "wrong-successor", "same-execution", "invalid-successor", "unsafe-mode", "own-quarantine", "late-debt", "historical-default"} {
		t.Run(mutation, func(t *testing.T) {
			f, proposal := apkRepeatedTransferFixture(t)
			store, err := openAPKLauncherLifecycleReadOnlyStore(t.Context(), f.services.hostRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := store.close(); err != nil {
					t.Error(err)
				}
			}()
			guard := &apkLauncherLifecycleRemoval{store: store, currentReference: proposal.Previous.Reference}
			successor := strings.Repeat("c", 64)
			body, err := apkTransitionGateBytes(successor)
			if err != nil {
				t.Fatal(err)
			}
			if mutation != "none" {
				freshAPKFixtureWrite(t, f.services.hostRoot, filepath.Join(strings.TrimPrefix(apkTransitionRoot, "/"), "active-hook"), body, 0700)
				freshAPKFixtureWrite(t, f.services.hostRoot, filepath.Join(apkTransitionGateDirectory, apkTransitionGateName), body, 0755)
			}
			switch mutation {
			case "wrong-successor":
				successor = strings.Repeat("d", 64)
			case "same-execution":
				successor = f.review.PlanSHA256
			case "invalid-successor":
				successor = "invalid"
			case "unsafe-mode":
				if err := store.anchor.Chmod(filepath.Join(apkTransitionGateDirectory, apkTransitionGateName), 0777); err != nil {
					t.Fatal(err)
				}
			case "own-quarantine":
				var q apkTerminalGateRetirement
				if err := decodeAPKTransitionJSON(freshAPKAtomicRead(t, filepath.Join(f.review.Directory, "terminal-retire-gate.json")), &q); err != nil {
					t.Fatal(err)
				}
				freshAPKFixtureWrite(t, f.services.hostRoot, filepath.Join(apkTransitionGateDirectory, q.Quarantine), []byte("retained recovery\n"), 0600)
			case "late-debt":
				freshAPKFixtureWrite(t, f.services.hostRoot, filepath.Join(strings.TrimPrefix(apkTransitionRoot, "/"), "execution-"+f.review.PlanSHA256, "terminal-unresolved.json"), []byte("{}\n"), 0600)
			case "historical-default":
				successor = ""
			}
			err = guard.attestExecutionFinalizationForSuccessor(successor)
			if (mutation == "none" || mutation == "exact") && err != nil {
				t.Fatal(err)
			}
			if mutation != "none" && mutation != "exact" && err == nil {
				t.Fatal("unbound successor or unresolved recovery accepted")
			}
		})
	}
}

func TestAPKLauncherRepeatedTransferNativeClosureAndCycle(t *testing.T) {
	f, proposal := apkRepeatedTransferFixture(t)
	directory, err := openExistingPinnedServiceDirectory(f.review.Directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	_, raw, err := readAPKLauncherPreviousRecords(directory, apkLauncherPreviousExecutionNames, proposal.Previous.Execution)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"none", "native-child.json", "native-result.json", "completed.json", "resources-closed.json", "post-attestation.json", "observed-host-snapshot.json", "native-hook-pre-commit.json", "native-hook-pre-upgrade.json", "native-hook-post-upgrade.json", "native-hook-post-commit.json"} {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string][]byte, len(raw))
			for key, value := range raw {
				changed[key] = append([]byte(nil), value...)
			}
			if strings.HasPrefix(name, "native-hook-") {
				changed[name] = append(changed[name], ' ')
			} else if name != "none" {
				changed[name] = []byte("{}\n")
			}
			err := attestAPKLauncherPreviousNative(changed, proposal.Native)
			if name == "none" && err != nil {
				t.Fatal(err)
			}
			if name != "none" && err == nil {
				t.Fatal("incomplete or substituted native closure accepted")
			}
		})
	}
	store, err := openAPKLauncherLifecycleReadOnlyStore(t.Context(), f.services.hostRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.close(); err != nil {
			t.Error(err)
		}
	}()
	if err := verifyAPKLauncherPreviousExecution(store, proposal, strings.Repeat("c", 64), map[string]bool{proposal.Previous.Reference.PlanSHA256: true}); err == nil {
		t.Fatal("cyclic ancestry accepted")
	}
}
