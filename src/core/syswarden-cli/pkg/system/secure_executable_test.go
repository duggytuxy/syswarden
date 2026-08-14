package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteExecutableAtomicallyIsPrivateUntilComplete(t *testing.T) {
	directory := t.TempDir()
	victimPath := filepath.Join(directory, "operator-owned")
	if err := os.WriteFile(victimPath, []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executablePath := filepath.Join(directory, "syswarden")
	if err := os.Symlink(filepath.Base(victimPath), executablePath); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if err := writeExecutableAtomically(directory, "syswarden", []byte("#!/bin/sh\nexit 0\n")); err != nil {
		t.Fatalf("writeExecutableAtomically() error = %v", err)
	}
	victim, err := root.ReadFile("operator-owned")
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "preserve\n" {
		t.Fatalf("executable replacement followed destination symlink: %q", victim)
	}
	info, err := root.Lstat("syswarden")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0755 {
		t.Fatalf("executable mode = %v, want regular 0755", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".syswarden.tmp-") {
			t.Fatalf("temporary executable was not removed: %s", entry.Name())
		}
	}
}

func TestWriteExecutableAtomicallyCleansUpAfterRenameFailure(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "syswarden"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeExecutableAtomically(directory, "syswarden", []byte("#!/bin/sh\n")); err == nil {
		t.Fatal("writeExecutableAtomically() accepted a directory destination")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "syswarden" || !entries[0].IsDir() {
		t.Fatalf("failed executable replacement left artifacts: %#v", entries)
	}
}
