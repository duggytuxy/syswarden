//go:build linux

package network

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestResolveWAAPLogFilesRequiresRealRegularFiles_SW_CFG_002(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	first := filepath.Join(root, "access.log")
	second := filepath.Join(root, "audit.log")
	if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resolved, rejected := resolveWAAPLogFiles([]string{
		first,
		filepath.Join(root, "*.log"),
	})
	if len(rejected) != 0 {
		t.Fatalf("regular files were rejected: %v", rejected)
	}
	want := []string{first, second}
	if !reflect.DeepEqual(resolved, want) {
		t.Fatalf("resolved files = %#v, want %#v", resolved, want)
	}

	missing := filepath.Join(root, "missing.log")
	directory := filepath.Join(root, "directory.log")
	symlink := filepath.Join(root, "symlink.log")
	fifo := filepath.Join(root, "stream.log")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, symlink); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []string{missing, directory, symlink, fifo} {
		candidate := candidate
		t.Run(filepath.Base(candidate), func(t *testing.T) {
			resolved, rejected := resolveWAAPLogFiles([]string{candidate})
			if len(resolved) != 0 {
				t.Fatalf("unsafe path resolved as a log: %#v", resolved)
			}
			if len(rejected) == 0 {
				t.Fatal("unsafe path was not rejected")
			}
		})
	}

	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("resolution mutated the missing path: %v", err)
	}
}

func TestResolveWAAPLogFilesRejectsNonCanonicalPatterns_SW_CFG_002(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		"relative.log",
		"/var/log/../log/auth.log",
		"/var/log/auth.log\n/var/log/messages",
	} {
		resolved, rejected := resolveWAAPLogFiles([]string{pattern})
		if len(resolved) != 0 || len(rejected) != 1 {
			t.Fatalf("pattern %q: resolved=%#v rejected=%v", pattern, resolved, rejected)
		}
		if !strings.Contains(rejected[0].Error(), "absolute canonical path") {
			t.Fatalf("pattern %q returned unexpected error: %v", pattern, rejected[0])
		}
	}
}
