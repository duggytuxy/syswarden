//go:build linux

package system

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func nativePublicationExclusionFixture(t *testing.T) (string, NativeActivationCandidate) {
	t.Helper()
	host := t.TempDir()
	entries := nativeActivationTestPayload(t)
	for _, entry := range entries {
		target := filepath.Join(host, entry.name)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		} // #nosec G301 -- protected test-owned native ancestry
		mode := os.FileMode(0644)
		if entry.mode == 0750 {
			mode = 0750
		} else if entry.mode != 0644 {
			t.Fatal("unexpected native fixture mode")
		}
		if err := os.WriteFile(target, entry.payload, mode); err != nil {
			t.Fatal(err)
		} // #nosec G304 G306 -- exact native payload in the test-owned root
		if err := os.Chmod(target, mode); err != nil {
			t.Fatal(err)
		} // #nosec G302 -- exact package metadata in the test-owned root
	}
	candidate, err := parseNativeActivationDescriptor(entries[2].payload)
	if err != nil {
		t.Fatal(err)
	}
	return host, candidate
}

func TestNativePublicationExclusionRequiresBothExactRuntimeContracts(t *testing.T) {
	for _, outcome := range []string{"current", "legacy-source", "legacy-candidate", "missing-source", "changed-cli", "changed-core", "changed-descriptor", "writable-descriptor", "symlink-descriptor", "canceled", "nil-context"} {
		t.Run(outcome, func(t *testing.T) {
			host, candidate := nativePublicationExclusionFixture(t)
			legacyRaw, err := canonicalNativeActivationDescriptor(nativeActivationLegacyDescriptorFor(candidate.Review().CLISHA256, candidate.Review().CoreSHA256))
			if err != nil {
				t.Fatal(err)
			}
			descriptor := filepath.Join(host, nativeActivationDescriptorPath)
			ctx := t.Context()
			switch outcome {
			case "legacy-source":
				if err := os.WriteFile(descriptor, legacyRaw, 0600); err != nil {
					t.Fatal(err)
				} // #nosec G304 -- deliberate test-owned legacy source substitution
			case "legacy-candidate":
				candidate, err = parseNativeActivationDescriptor(legacyRaw)
				if err != nil {
					t.Fatal(err)
				}
			case "missing-source":
				if err := os.Remove(descriptor); err != nil {
					t.Fatal(err)
				}
			case "changed-cli", "changed-core", "changed-descriptor":
				target := descriptor
				if outcome == "changed-cli" {
					target = filepath.Join(host, qualificationPackageCLIPath)
				}
				if outcome == "changed-core" {
					target = filepath.Join(host, nativeActivationCorePath)
				}
				if err := os.WriteFile(target, []byte("changed\n"), 0600); err != nil {
					t.Fatal(err)
				} // #nosec G304 -- deliberate mutation of test-owned native input
			case "writable-descriptor":
				if err := os.Chmod(descriptor, 0664); err != nil {
					t.Fatal(err)
				} // #nosec G302 -- deliberate unsafe metadata rejection fixture
			case "symlink-descriptor":
				if err := os.Remove(descriptor); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("bin/syswarden-cli", descriptor); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-context":
				ctx = nil
			}
			observation, err := captureNativePublicationExclusionAt(ctx, host, candidate)
			if (err == nil) != (outcome == "current") {
				t.Fatalf("capture outcome: %v", err)
			}
			if outcome == "current" {
				if observation.source != candidate || observation.runtime.CLI.SHA256 != candidate.Review().CLISHA256 {
					t.Fatal("source runtime identity was not bound")
				}
				if err := observation.Revalidate(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else if observation != nil {
				t.Fatal("failed capture returned an observation")
			}
		})
	}
}

func TestNativePublicationExclusionRefusesReplacementAfterCapture(t *testing.T) {
	for _, name := range []string{qualificationPackageCLIPath, nativeActivationCorePath, nativeActivationDescriptorPath} {
		t.Run(name, func(t *testing.T) {
			host, candidate := nativePublicationExclusionFixture(t)
			observation, err := captureNativePublicationExclusionAt(t.Context(), host, candidate)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(host, name)
			original, err := os.Open(path) // #nosec G304 -- exact test-owned native file; the retained descriptor prevents inode reuse
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = original.Close() }()
			raw, err := io.ReadAll(original)
			if err != nil {
				t.Fatal(err)
			}
			info, err := original.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, info.Mode().Perm()); err != nil {
				t.Fatal(err)
			} // #nosec G304 G306 G703 -- closed native-path test matrix under TempDir; replacement preserves exact fixture bytes and mode
			if err := observation.Revalidate(t.Context()); err == nil {
				t.Fatal("same-byte replacement accepted")
			}
		})
	}
	if err := (*nativePublicationExclusionObservation)(nil).Revalidate(t.Context()); err == nil {
		t.Fatal("nil observation accepted")
	}
}
