package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateConfigTokenIsAtomicAndPrivate(t *testing.T) {
	directory := t.TempDir()
	victimPath := filepath.Join(directory, "operator-owned.toml")
	if err := os.WriteFile(victimPath, []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "99-user.toml")
	if err := os.Symlink(filepath.Base(victimPath), tokenPath); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if err := updateConfigTokenInDirectory(directory, "0123456789abcdef"); err == nil {
		t.Fatal("updateConfigTokenInDirectory() accepted a symbolic-link token file")
	}
	victim, err := root.ReadFile("operator-owned.toml")
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "preserve\n" {
		t.Fatalf("token update followed destination symlink: %q", victim)
	}
	info, err := root.Lstat("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("failed token update replaced destination symlink: %v", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".99-user.toml.tmp-") {
			t.Fatalf("temporary token file was not removed: %s", entry.Name())
		}
	}
}

func TestUpdateConfigTokenCreatesPrivateFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "modules")
	if err := updateConfigTokenInDirectory(directory, "new-token"); err != nil {
		t.Fatalf("updateConfigTokenInDirectory() error = %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, "99-user.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("new token file mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestUpdateConfigTokenReplacesRegularFilePrivately(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("99-user.toml", []byte("[user]\nwebtui_password = \"old\"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := updateConfigTokenInDirectory(directory, "replacement"); err != nil {
		t.Fatal(err)
	}
	content, err := root.ReadFile("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `webtui_password = "replacement"`) || strings.Contains(string(content), `"old"`) {
		t.Fatalf("updated token file content = %q", content)
	}
	info, err := root.Lstat("99-user.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("updated token file mode = %v, want regular 0600", info.Mode())
	}
}

func TestUpdateConfigTokenDoesNotReplaceUnreadableFileKind(t *testing.T) {
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "99-user.toml")
	if err := os.Mkdir(tokenPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := updateConfigTokenInDirectory(directory, "new-token"); err == nil {
		t.Fatal("updateConfigTokenInDirectory() replaced a directory token path")
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatalf("failed token update changed destination kind: %v", info.Mode())
	}
}
