//go:build linux

package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func legacyLogRetentionFixture(t *testing.T) (string, string, *os.Root) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, path := range []string{"log", "log/syswarden", "backups"} {
		if err := root.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"core.log", "waf.json"} {
		if err := root.WriteFile("log/syswarden/"+name, []byte("Private fixture content must never be printed.\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(base, "log"), filepath.Join(base, "backups"), root
}

func inspectLegacyLogFixture(t *testing.T, parent string) (LegacyLogRetentionPlan, string) {
	t.Helper()
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(parent, "syswarden"))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	_, plan, err := inspectLegacyProductLogDirectory(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, digest
}

func TestLegacyLogRetentionRequiresReviewedUnchangedPlanAndKeepsOriginalInodes(t *testing.T) {
	parent, backups, root := legacyLogRetentionFixture(t)
	plan, digest := inspectLegacyLogFixture(t, parent)
	wire, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte("Private fixture content")) {
		t.Fatal("plan exposed raw log contents")
	}
	before, err := root.Lstat("log/syswarden/core.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyLegacyLogRetention(parent, backups, strings.Repeat("0", 64), func() error { return nil }, unix.Renameat2); err == nil {
		t.Fatal("different plan was accepted")
	}
	if _, err := root.Lstat("backups/syswarden-retired-v1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unreviewed plan created backup state", err)
	}
	applied, backup, err := applyLegacyLogRetention(parent, backups, digest, func() error { return nil }, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := LegacyLogRetentionPlanSHA256(applied)
	if err != nil || actual != digest {
		t.Fatal("applied plan changed", err)
	}
	if _, err := root.Lstat("log/syswarden"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("active legacy logs remain", err)
	}
	relative, err := filepath.Rel(filepath.Dir(parent), backup)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := root.Lstat(relative + "/core.log")
	if err != nil || !os.SameFile(before, saved) {
		t.Fatal("original inode was not retained", err)
	}
	content, err := root.ReadFile(relative + "/core.log")
	if err != nil || string(content) != "Private fixture content must never be printed.\n" {
		t.Fatal("original log bytes changed", err)
	}
	again, againPath, err := applyLegacyLogRetention(parent, backups, digest, func() error { return nil }, unix.Renameat2)
	if err != nil || againPath != backup {
		t.Fatal("completed private retention did not resume", err)
	}
	actual, err = LegacyLogRetentionPlanSHA256(again)
	if err != nil || actual != digest {
		t.Fatal("retry selected another plan", err)
	}
	if err := root.WriteFile(relative+"/core.log", []byte("Changed retained evidence.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyLegacyLogRetention(parent, backups, digest, func() error { return nil }, unix.Renameat2); err == nil {
		t.Fatal("modified retained evidence was accepted")
	}
}

func TestLegacyLogRetentionPreservesChangedSharedAndUnrelatedFiles(t *testing.T) {
	for _, kind := range []string{"changed-before-apply", "changed-during-apply", "additional-file", "shared-file", "copied-origin", "invalid-digest", "guard"} {
		t.Run(kind, func(t *testing.T) {
			parent, backups, root := legacyLogRetentionFixture(t)
			_, digest := inspectLegacyLogFixture(t, parent)
			switch kind {
			case "changed-before-apply":
				if err := root.WriteFile("log/syswarden/core.log", []byte("Administrator change.\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "additional-file":
				if err := root.WriteFile("log/syswarden/administrator.conf", []byte("Keep this configuration.\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "shared-file":
				if err := root.Link("log/syswarden/core.log", "administrator-link"); err != nil {
					t.Fatal(err)
				}
			case "copied-origin":
				file, err := root.Open("log/syswarden/core.log")
				if err != nil {
					t.Fatal(err)
				}
				err = unix.Fsetxattr(int(file.Fd()), productLogOriginAttribute, []byte("unproven origin"), unix.XATTR_CREATE)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "invalid-digest":
				digest = strings.Repeat("A", 64)
			}
			checks := 0
			guard := func() error {
				checks++
				if kind == "guard" {
					return errors.New("producer is still active")
				}
				if kind == "changed-during-apply" && checks == 3 {
					return root.WriteFile("log/syswarden/core.log", []byte("Concurrent administrator change.\n"), 0600)
				}
				return nil
			}
			if _, _, err := applyLegacyLogRetention(parent, backups, digest, guard, unix.Renameat2); err == nil {
				t.Fatal("unreviewed inventory was retained")
			}
			if _, err := root.Lstat("log/syswarden/core.log"); err != nil {
				t.Fatal("unreviewed file lost its active location", err)
			}
		})
	}
}
