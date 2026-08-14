package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsurePrivateDirectoryRestrictsExistingDirectories(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "wireguard")
	if err := os.Mkdir(privatePath, 0700); err != nil {
		t.Fatal(err)
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rootHandle.Close() })
	privateDirectory, err := rootHandle.Open("wireguard")
	if err != nil {
		t.Fatal(err)
	}
	if err := privateDirectory.Chmod(0755); err != nil {
		_ = privateDirectory.Close()
		t.Fatal(err)
	}
	if err := privateDirectory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(root, "wireguard"); err != nil {
		t.Fatalf("ensurePrivateDirectory() error = %v", err)
	}
	if err := ensurePrivateDirectory(root, "wireguard/clients"); err != nil {
		t.Fatalf("ensurePrivateDirectory() child error = %v", err)
	}
	for _, path := range []string{privatePath, filepath.Join(privatePath, "clients")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("private directory %s mode = %v, want directory 0700", path, info.Mode())
		}
	}
}

func TestEnsurePrivateDirectoryRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideRoot, err := os.OpenRoot(outside)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outsideRoot.Close() })
	outsideDirectory, err := outsideRoot.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	if err := outsideDirectory.Chmod(0755); err != nil {
		_ = outsideDirectory.Close()
		t.Fatal(err)
	}
	if err := outsideDirectory.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "wireguard")); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDirectory(root, "wireguard"); err == nil {
		t.Fatal("ensurePrivateDirectory() accepted a symlink")
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("symlink target mode changed to %#o", info.Mode().Perm())
	}
	for _, relative := range []string{"../escape", "/absolute", "."} {
		if err := ensurePrivateDirectory(root, relative); err == nil {
			t.Errorf("ensurePrivateDirectory() accepted %q", relative)
		}
	}
}
