//go:build linux

package network

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/viper"
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

func TestDiscoverWAAPLogsByInstalledLayout(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []string
	}{
		{"debian-rsyslog", []string{"auth.log", "syslog"}},
		{"redhat-rsyslog", []string{"secure", "messages"}},
		{"bunkerweb-debian", []string{"bunkerweb/access.log", "bunkerweb/error.log", "bunkerweb/modsec_audit.log", "auth.log", "syslog"}},
		{"existing-web-layouts", []string{"nginx/access.log", "nginx/error.log", "apache2/access.log", "httpd/access_log", "caddy/access.log", "traefik/access.log", "lighttpd/access.log"}},
		{"no-log-files", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			var want []string
			for _, name := range tc.files {
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("test\n"), 0600); err != nil {
					t.Fatal(err)
				}
				want = append(want, path)
			}
			// A present web directory must not select nonexistent log files.
			if err := os.MkdirAll(filepath.Join(root, "nginx"), 0700); err != nil {
				t.Fatal(err)
			}
			sort.Strings(want)
			got := discoverLogsIn(root)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("discovered = %v, want %v", got, want)
			}
			resolved, rejected := resolveWAAPLogFiles(got)
			if len(rejected) != 0 || len(resolved) != len(want) {
				t.Fatalf("resolved = %v, rejected = %v", resolved, rejected)
			}
		})
	}
}

func TestDiscoverWAAPLogsPreservesUnsafeMatchRejection(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(root, "absent"), filepath.Join(root, "auth.log")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "syslog"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "messages"), 0700); err != nil {
		t.Fatal(err)
	}
	paths := discoverLogsIn(root)
	resolved, rejected := resolveWAAPLogFiles(paths)
	if len(paths) != 3 || len(resolved) != 0 || len(rejected) != 3 {
		t.Fatalf("paths = %v, resolved = %v, rejected = %v", paths, resolved, rejected)
	}
}

func TestLoadWAAPConfigPreservesExplicitLogPaths(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	root := t.TempDir()
	bf := filepath.Join(root, "custom.log")
	mod := filepath.Join(root, "modsec", "*.log")
	viper.Set("waap.bruteforce_logs", bf)
	viper.Set("waap.modsec_logs", mod)
	cfg := loadWAAPConfig()
	if want := []string{bf, mod}; !reflect.DeepEqual(cfg.Logs, want) {
		t.Fatalf("explicit paths = %v, want %v", cfg.Logs, want)
	}
	// Explicit missing paths remain diagnostic errors, not optional defaults.
	resolved, rejected := resolveWAAPLogFiles(cfg.Logs)
	if len(resolved) != 0 || len(rejected) != 2 {
		t.Fatalf("resolved = %v, rejected = %v", resolved, rejected)
	}
}
