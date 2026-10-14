//go:build linux

package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rhelOperatorRetentionFixture(t *testing.T) (string, string, string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	uid, gid := testRHELPackageOwnedOwner(t, root)
	for _, path := range append(append([]string{}, rhelPackageOwnedRuntimeDirectories...), "/var/backups") {
		if err := os.MkdirAll(filepath.Join(root, strings.TrimPrefix(path, "/")), 0750); err != nil {
			t.Fatal(err)
		}
	}
	installTestRHELPackageOwnedProductSkeleton(t, root)
	if err := os.WriteFile(filepath.Join(root, "var/lib/syswarden", removalTombstoneName), []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(root, "etc/syswarden/config/modules/70-operator.toml")
	if err := os.WriteFile(custom, []byte("[core]\nlog_level = \"info\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "etc/syswarden/config")
	plan, err := inspectOperatorConfigurationRetention(directory)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := OperatorConfigurationRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, record, err := applyOperatorConfigurationRetention(directory, filepath.Join(root, "var/backups"), digest, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	return root, custom, record, uid, gid
}

func TestRHELPackageOwnedErasePreservesReviewedOperatorEdits(t *testing.T) {
	root, custom, _, uid, gid := rhelOperatorRetentionFixture(t)
	if err := os.WriteFile(custom, []byte("[core]\nlog_level = \"warn\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(custom)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
	for attempt := 0; attempt < 2; attempt++ {
		if err := prepareRHELPackageOwnedRuntimeForEraseAt(root, marker, uid, gid, testSuccessfulRHELPackagePayloadAttestation); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(custom)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
			t.Fatal("operator file changed", err)
		}
	}
	if err := attestRHELPackageOwnedProductFilesAt(func(path string) string { return filepath.Join(root, strings.TrimPrefix(path, "/")) }, uid, gid); err != nil {
		t.Fatal("RPM payload was not preserved", err)
	}
}

func TestRHELPackageOwnedEraseRejectsUnreviewedAndChangingConfiguration(t *testing.T) {
	for _, kind := range []string{"unknown", "late unknown", "mode", "link", "record"} {
		t.Run(kind, func(t *testing.T) {
			root, custom, record, uid, gid := rhelOperatorRetentionFixture(t)
			marker := filepath.Join(root, "var/lib/.syswarden-rhelpo-erase-ready-v1")
			mutate := func() {
				var err error
				switch kind {
				case "unknown", "late unknown":
					err = os.WriteFile(filepath.Join(filepath.Dir(custom), "71-unreviewed.toml"), []byte("[core]\nlog_level = \"warn\"\n"), 0600)
				case "mode":
					err = os.Chmod(custom, 0666) // #nosec G302 -- adversarial private fixture verifies rejection of writable administrator configuration
				case "link":
					err = os.Link(custom, filepath.Join(root, "outside"))
				case "record":
					err = os.WriteFile(record, []byte("modified retention authority\n"), 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			attest := func() error {
				calls++
				if kind == "late unknown" && calls == 3 {
					mutate()
				}
				return nil
			}
			if kind != "late unknown" {
				mutate()
			}
			if err := prepareRHELPackageOwnedRuntimeForEraseAt(root, marker, uid, gid, attest); err == nil {
				t.Fatal("unverified state authorized RPM erase")
			}
			if _, err := os.Lstat(marker); !os.IsNotExist(err) {
				t.Fatal("erase marker published after refusal", err)
			}
			if _, err := os.Lstat(custom); err != nil {
				t.Fatal("refusal removed operator configuration", err)
			}
		})
	}
}
