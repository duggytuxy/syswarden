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

func originalRuntimeFixture(t *testing.T, descriptor bool) (string, string, *apkOriginalPayloadProposal, string) {
	t.Helper()
	base := t.TempDir()
	host := filepath.Join(base, "host")
	executionParent := filepath.Join(base, "custody")
	execution := filepath.Join(executionParent, "execution")
	for _, name := range []string{host, filepath.Join(host, "opt"), filepath.Join(host, "opt/syswarden"), filepath.Join(host, "opt/syswarden/bin"), executionParent, execution} {
		if err := os.Mkdir(name, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(execution, 0700); err != nil { // #nosec G302 -- private temporary custody is a directory and requires search permission0700
		t.Fatal(err)
	}
	for _, name := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"} {
		mode := os.FileMode(0750)
		if name == "signatures.json" {
			mode = 0640
		}
		if err := os.WriteFile(filepath.Join(host, "opt/syswarden", name), []byte("original inert "+name+"\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if descriptor {
		raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(apkTransitionDigest([]byte("original inert bin/syswarden-cli\n")), apkTransitionDigest([]byte("original inert bin/syswarden-core\n"))))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(host, "opt/syswarden/activation-contract-v1.json"), raw, 0644); err != nil { // #nosec G306 -- fixed temporary descriptor models the public native0644 member
			t.Fatal(err)
		}
	}
	proposal, err := captureAPKOriginalPayloadProposalAt(t.Context(), host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := apkExecutionJSON(proposal)
	if err != nil {
		t.Fatal(err)
	}
	return host, execution, proposal, apkTransitionDigest(raw)
}

func TestAPKOriginalRuntimeRetainsCompleteBytesAndNeverAuthorizesReplay(t *testing.T) {
	for _, descriptor := range []bool{false, true} {
		t.Run(map[bool]string{false: "historical", true: "descriptor"}[descriptor], func(t *testing.T) {
			host, execution, _, _ := originalRuntimeFixture(t, descriptor)
			admin := filepath.Join(host, "opt/syswarden/admin-data")
			if err := os.WriteFile(admin, []byte("administrator data\n"), 0600); err != nil {
				t.Fatal(err)
			}
			// Administrator data is preserved but never imported into owned custody.
			proposal, err := captureAPKOriginalPayloadProposalAt(t.Context(), host)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := apkExecutionJSON(proposal)
			digest := apkTransitionDigest(raw)
			custody, err := retainAPKOriginalPayloadAt(t.Context(), host, execution, proposal, digest)
			if err != nil {
				t.Fatal(err)
			}
			defer custody.Close()
			if err := custody.RevalidateSource(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := custody.RevalidateRetained(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, entry := range proposal.Files {
				got, err := os.ReadFile(filepath.Join(execution, "original-runtime", entry.Path)) // #nosec G304 -- captured proposal contains only this fixture fixed runtime members under its private custody root
				if err != nil {
					t.Fatal(err)
				}
				if apkTransitionDigest(got) != entry.SHA256 {
					t.Fatal("wrong retained bytes", entry.Path)
				}
			}
			if _, err := os.Lstat(filepath.Join(execution, "original-runtime/admin-data")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			before, err := os.ReadFile(admin) // #nosec G304 -- fixed administrator-data fixture path inside the temporary host root
			if err != nil || string(before) != "administrator data\n" {
				t.Fatal("administrator bytes changed", err)
			}
			if _, err := retainAPKOriginalPayloadAt(t.Context(), host, execution, proposal, digest); err == nil {
				t.Fatal("replayed retained custody")
			}
			if err := os.WriteFile(filepath.Join(host, "opt/syswarden/bin/syswarden-core"), []byte("new candidate\n"), 0750); err != nil { // #nosec G306 -- fixed temporary core fixture models executable candidate replacement
				t.Fatal(err)
			}
			if err := custody.RevalidateSource(t.Context()); err == nil {
				t.Fatal("accepted changed source")
			}
			if err := custody.RevalidateRetained(t.Context()); err != nil {
				t.Fatal("retained old runtime invalid after source replacement", err)
			}
		})
	}
}

func TestAPKOriginalRuntimeRefusesDriftBeforeRetention(t *testing.T) {
	for _, mutation := range []string{"cli", "core", "tui", "signatures", "mode", "symlink", "hardlink", "descriptor", "digest", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			host, execution, proposal, digest := originalRuntimeFixture(t, true)
			path := filepath.Join(host, "opt/syswarden/bin/syswarden-cli")
			ctx := t.Context()
			switch mutation {
			case "cli", "core", "tui":
				path = filepath.Join(host, "opt/syswarden/bin/syswarden-"+mutation)
				if err := os.WriteFile(path, []byte("changed"), 0750); err != nil { // #nosec G306 -- closed mutation table selects only this temporary fixture runtime files with executable0750 metadata
					t.Fatal(err)
				}
			case "signatures":
				if err := os.WriteFile(filepath.Join(host, "opt/syswarden/signatures.json"), []byte("changed"), 0640); err != nil { // #nosec G306 -- fixed temporary signatures fixture intentionally corrupts native0640 payload bytes
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0777); err != nil { // #nosec G302 -- private temporary source is deliberately made writable to verify refusal
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "descriptor":
				if err := os.WriteFile(filepath.Join(host, "opt/syswarden/activation-contract-v1.json"), []byte("changed"), 0644); err != nil { // #nosec G306 -- fixed temporary descriptor is deliberately corrupted with native0644 metadata
					t.Fatal(err)
				}
			case "digest":
				digest = strings.Repeat("a", 64)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if custody, err := retainAPKOriginalPayloadAt(ctx, host, execution, proposal, digest); err == nil || custody != nil {
				t.Fatal("accepted drift", err)
			}
			entries, err := os.ReadDir(execution)
			if err != nil || len(entries) != 0 {
				t.Fatal("retention wrote before approval validation", err)
			}
		})
	}
}

func TestAPKOriginalRuntimeRefusesRetainedMutationAndClosedCustody(t *testing.T) {
	for _, mutation := range []string{"bytes", "mode", "link", "parent", "execution-link", "ancestor-link", "receipt", "receipt-replacement", "receipt-metadata-aba", "unrelated", "cancel", "close"} {
		t.Run(mutation, func(t *testing.T) {
			host, execution, proposal, digest := originalRuntimeFixture(t, false)
			custody, err := retainAPKOriginalPayloadAt(t.Context(), host, execution, proposal, digest)
			if err != nil {
				t.Fatal(err)
			}
			defer custody.Close()
			path := filepath.Join(execution, "original-runtime/bin/syswarden-tui")
			ctx := t.Context()
			switch mutation {
			case "bytes":
				err = os.WriteFile(path, []byte("changed"), 0750) // #nosec G306 -- private temporary retained runtime bytes are deliberately corrupted
			case "mode":
				err = os.Chmod(path, 0777) // #nosec G302 -- private temporary retained source mode is deliberately unsafe to verify refusal
			case "link":
				err = os.Link(path, path+".extra")
			case "parent":
				err = os.Rename(filepath.Join(execution, "original-runtime"), filepath.Join(execution, "moved"))
			case "execution-link":
				err = os.Rename(execution, execution+"-moved")
				if err == nil {
					err = os.Symlink(execution+"-moved", execution)
				}
			case "ancestor-link":
				parent := filepath.Dir(execution)
				err = os.Rename(parent, parent+"-moved")
				if err == nil {
					err = os.Symlink(parent+"-moved", parent)
				}
			case "receipt-replacement":
				path := filepath.Join(execution, "original-runtime.json")
				var raw []byte
				raw, err = os.ReadFile(path) // #nosec G304 -- fixed original-runtime.json record inside this test private execution directory
				if err == nil {
					err = os.Rename(path, path+".original")
				}
				if err == nil {
					err = os.WriteFile(path, raw, 0600) // #nosec G703 -- fixed original-runtime.json record inside this test private execution directory is replaced with the same inert bytes
				}
			case "receipt-metadata-aba":
				path := filepath.Join(execution, "original-runtime.json")
				err = os.Chmod(path, 0640) // #nosec G302 -- private temporary receipt deliberately has unsafe group-readable metadata
				if err == nil {
					err = os.Chmod(path, 0600)
				}
			case "receipt":
				err = os.WriteFile(filepath.Join(execution, "original-runtime.json"), []byte("changed"), 0600)
			case "unrelated":
				err = os.WriteFile(filepath.Join(execution, "original-runtime/unrelated"), []byte("data"), 0600)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "close":
				err = custody.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := custody.RevalidateRetained(ctx); err == nil {
				t.Fatal("accepted retained mutation")
			}
		})
	}
}

func TestAPKOriginalRuntimeBindingRequiresAuthenticatedPair(t *testing.T) {
	_, _, proposal, _ := originalRuntimeFixture(t, false)
	expected, err := apkOriginalExpected(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAPKOriginalRuntime(proposal, expected["bin/syswarden-cli"], expected["bin/syswarden-core"]); err != nil {
		t.Fatal(err)
	}
	if err := bindAPKOriginalRuntime(proposal, expected["bin/syswarden-cli"], strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted foreign core")
	}
	if _, err := captureAPKOriginalPayloadProposalAt(nil, "/"); err == nil { //nolint:staticcheck // SA1012: Deliberate invalid input verifies rejection before opening host resources.
		t.Fatal("accepted nil context")
	}
}

func TestAPKOriginalRuntimeCompleteSnapshotRejectsEarlierLeafDrift(t *testing.T) {
	for _, changed := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json", "activation-contract-v1.json"} {
		t.Run(changed, func(t *testing.T) {
			host, _, proposal, _ := originalRuntimeFixture(t, true)
			directory, err := openExistingPinnedServiceDirectory(filepath.Join(host, "opt/syswarden"))
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			expected, err := apkOriginalExpected(proposal)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := inspectBoundPayload(directory, expected, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := attestBoundPayloadLeaves(directory.root, snapshot); err != nil {
				t.Fatal(err)
			}
			// Model a write to an earlier leaf after the later-file hash completes.
			// No directory entry changes, so parent-only checks cannot catch it.
			file, err := directory.root.OpenFile(changed, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.WriteAt([]byte("changed"), 0)
			if err := errors.Join(writeErr, file.Close()); err != nil {
				t.Fatal(err)
			}
			if err := attestBoundPayloadLeaves(directory.root, snapshot); err == nil {
				t.Fatal("accepted mixed-time payload snapshot")
			}
		})
	}
}
