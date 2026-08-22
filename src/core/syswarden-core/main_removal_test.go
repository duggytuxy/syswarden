package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCoreRemovalTombstoneStartupGuard_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	missingPath := filepath.Join(root, "missing", "removal-in-progress-v1")
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	present, err := inspectCoreRemovalTombstone(missingPath, uid, gid)
	if err != nil || present {
		t.Fatalf("absent state directory: present=%t err=%v", present, err)
	}

	state := filepath.Join(root, "syswarden")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "removal-in-progress-v1")

	present, err = inspectCoreRemovalTombstone(path, uid, gid)
	if err != nil || present {
		t.Fatalf("absent tombstone: present=%t err=%v", present, err)
	}
	if err := os.WriteFile(path, []byte(coreRemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = inspectCoreRemovalTombstone(path, uid, gid)
	if err != nil || !present {
		t.Fatalf("exact tombstone: present=%t err=%v", present, err)
	}
	if err := os.WriteFile(path, []byte("modified\n"), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = inspectCoreRemovalTombstone(path, uid, gid)
	if err == nil || !present {
		t.Fatalf("modified tombstone: present=%t err=%v", present, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "operator"), path); err != nil {
		t.Fatal(err)
	}
	present, err = inspectCoreRemovalTombstone(path, uid, gid)
	if err == nil || !present {
		t.Fatalf("symlink tombstone: present=%t err=%v", present, err)
	}

	target := filepath.Join(root, "operator-state")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	linkedState := filepath.Join(root, "linked-state")
	if err := os.Symlink(target, linkedState); err != nil {
		t.Fatal(err)
	}
	present, err = inspectCoreRemovalTombstone(
		filepath.Join(linkedState, "removal-in-progress-v1"), uid, gid,
	)
	if err == nil || !present {
		t.Fatalf("symlink state directory: present=%t err=%v", present, err)
	}
}

func TestCoreRemovalGuardRunsBeforeRuntimeFilesystemMutation_SW2_FWBACKEND_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	guard := strings.Index(content, "inspectCoreRemovalTombstone(coreRemovalTombstonePath")
	firstMutation := strings.Index(content, `os.MkdirAll("/var/log/syswarden"`)
	if guard < 0 || firstMutation < 0 || guard >= firstMutation {
		t.Fatalf("core startup guard ordering is not fail-closed: guard=%d mutation=%d", guard, firstMutation)
	}
}
