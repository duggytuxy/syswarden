//go:build linux

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeActivationDescriptorRemovalRequiresExactDerivedBytes(t *testing.T) {
	for _, outcome := range []string{"historical-absent", "legacy-v1", "exact", "changed-contract", "changed-core-hash", "writable", "symlink"} {
		t.Run(outcome, func(t *testing.T) {
			base, root, expected := standalonePayloadFixture(t)
			name := "syswarden/" + filepath.Base(nativeActivationDescriptorPath)
			raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(expected["bin/syswarden-cli"], expected["bin/syswarden-core"]))
			if err != nil {
				t.Fatal(err)
			}
			switch outcome {
			case "legacy-v1":
				raw, err = canonicalNativeActivationDescriptor(nativeActivationLegacyDescriptorFor(expected["bin/syswarden-cli"], expected["bin/syswarden-core"]))
				if err != nil {
					t.Fatal(err)
				}
			case "changed-contract":
				raw = bytes.ReplaceAll(raw, []byte("approval-v1"), []byte("approval-v9"))
			case "changed-core-hash":
				raw = bytes.ReplaceAll(raw, []byte(expected["bin/syswarden-core"]), []byte(expected["bin/syswarden-cli"]))
			}
			if outcome != "historical-absent" {
				if err := root.WriteFile(name, raw, 0644); err != nil { // #nosec G306 -- test-owned fixture models the native descriptor mode
					t.Fatal(err)
				}
			}
			if outcome == "writable" {
				if err := root.Chmod(name, 0664); err != nil { // #nosec G302 -- deliberate unsafe descriptor rejection fixture
					t.Fatal(err)
				}
			}
			if outcome == "symlink" {
				if err := root.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("signatures.json", filepath.Join(base, name)); err != nil {
					t.Fatal(err)
				}
			}
			directory, err := openExistingPinnedServiceDirectory(filepath.Join(base, "syswarden"))
			if err != nil {
				t.Fatal(err)
			}
			defer directory.close()
			snapshot, err := inspectStandalonePayload(directory, expected)
			wantValid := outcome == "historical-absent" || outcome == "legacy-v1" || outcome == "exact"
			if (err == nil) != wantValid {
				t.Fatalf("ownership outcome %s: %v", outcome, err)
			}
			if outcome == "exact" && len(snapshot.content[filepath.Base(nativeActivationDescriptorPath)]) != 64 {
				t.Fatal("descriptor was not bound in retirement snapshot")
			}
		})
	}
}

func TestNativeActivationDescriptorAPKRecoveryPreservesExactBytes(t *testing.T) {
	base, root, expected := standalonePayloadFixture(t)
	raw, err := canonicalNativeActivationDescriptor(nativeActivationDescriptorFor(expected["bin/syswarden-cli"], expected["bin/syswarden-core"]))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(nativeActivationDescriptorPath)
	if err := root.WriteFile("syswarden/"+name, raw, 0644); err != nil { // #nosec G306 -- exact test-owned package descriptor fixture
		t.Fatal(err)
	}
	backup, err := preserveAPKPayload(filepath.Join(base, "syswarden"), filepath.Join(base, "backups"), expected, nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(filepath.Join(backup, name)) // #nosec G304 -- backup is returned by the test-owned private recovery fixture
	if err != nil || !bytes.Equal(actual, raw) {
		t.Fatalf("descriptor recovery changed bytes: %v", err)
	}
}
