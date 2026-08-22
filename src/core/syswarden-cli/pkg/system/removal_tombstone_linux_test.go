//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRemovalTombstonePath(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	return filepath.Join(t.TempDir(), "syswarden", removalTombstoneName), uint32(os.Geteuid()), uint32(os.Getegid())
}

func TestRemovalTombstoneGrammarAndAtomicIdempotentPublication_SW2_FWBACKEND_001(t *testing.T) {
	if len(RemovalTombstoneRecord) != 39 || strings.ContainsAny(RemovalTombstoneRecord, "\r\x00") ||
		RemovalTombstoneRecord != "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n" {
		t.Fatalf("unexpected removal tombstone grammar: %q", RemovalTombstoneRecord)
	}
	path, uid, gid := testRemovalTombstonePath(t)
	present, err := inspectRemovalTombstoneAt(path, uid, gid)
	if err != nil || present {
		t.Fatalf("inspect absent state directory: present=%t err=%v", present, err)
	}
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatalf("idempotent exact publication: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != RemovalTombstoneRecord || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("published tombstone content=%q mode=%04o", content, info.Mode().Perm())
	}
	present, err = inspectRemovalTombstoneAt(path, uid, gid)
	if err != nil || !present {
		t.Fatalf("inspect exact tombstone: present=%t err=%v", present, err)
	}
}

func TestRemovalTombstoneRejectsModifiedHardlinkedAndSymlinkedEvidence_SW2_FWBACKEND_001(t *testing.T) {
	t.Run("modified record", func(t *testing.T) {
		path, uid, gid := testRemovalTombstonePath(t)
		if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		modified := "SYSWARDEN_REMOVAL_V1\nstate=xn-progress\n"
		if len(modified) != len(RemovalTombstoneRecord) {
			t.Fatalf("test record length = %d", len(modified))
		}
		if err := os.WriteFile(path, []byte(modified), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ensureRemovalTombstoneAt(path, uid, gid); err == nil {
			t.Fatal("modified existing record was accepted")
		}
		content, err := os.ReadFile(path)
		if err != nil || string(content) != modified {
			t.Fatalf("modified evidence was overwritten: content=%q err=%v", content, err)
		}
		present, err := inspectRemovalTombstoneAt(path, uid, gid)
		if err == nil || !present {
			t.Fatalf("modified evidence inspection: present=%t err=%v", present, err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path, uid, gid := testRemovalTombstonePath(t)
		if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(filepath.Dir(path), "operator-link")); err != nil {
			t.Fatal(err)
		}
		present, err := inspectRemovalTombstoneAt(path, uid, gid)
		if err == nil || !present {
			t.Fatalf("hardlinked evidence inspection: present=%t err=%v", present, err)
		}
	})

	t.Run("symlinked state root", func(t *testing.T) {
		root := t.TempDir()
		operator := filepath.Join(root, "operator")
		if err := os.Mkdir(operator, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(operator, "keep")
		if err := os.WriteFile(marker, []byte("operator"), 0600); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(root, "syswarden")
		if err := os.Symlink(operator, state); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(state, removalTombstoneName)
		if err := ensureRemovalTombstoneAt(path, uint32(os.Geteuid()), uint32(os.Getegid())); err == nil {
			t.Fatal("symlinked state root was accepted")
		}
		present, inspectErr := inspectRemovalTombstoneAt(
			path, uint32(os.Geteuid()), uint32(os.Getegid()),
		)
		if inspectErr == nil || !present {
			t.Fatalf("symlinked state root inspection: present=%t err=%v", present, inspectErr)
		}
		content, err := os.ReadFile(marker)
		if err != nil || string(content) != "operator" {
			t.Fatalf("operator target changed: content=%q err=%v", content, err)
		}
	})
}

func TestRemovalTombstoneFinalizationRequiresAbsentExecutablesAndEmptyState_SW2_FWBACKEND_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(filepath.Dir(filepath.Dir(path)), "syswarden-cli")
	if err := os.WriteFile(executable, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err == nil ||
		!strings.Contains(err.Error(), "executable path remains") {
		t.Fatalf("present executable finalization = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("executable refusal lost evidence: %v", err)
	}
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	residual := filepath.Join(filepath.Dir(path), "operator-neighbor")
	if err := os.WriteFile(residual, []byte("preserve until explicit cleanup"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err == nil ||
		!strings.Contains(err.Error(), "residual") {
		t.Fatalf("residual finalization = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("residual refusal lost evidence: %v", err)
	}
	if err := os.Remove(residual); err != nil {
		t.Fatal(err)
	}
	if err := finalizeRemovalTombstoneAt(path, uid, gid, []string{executable}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory remains after finalization: %v", err)
	}
}
