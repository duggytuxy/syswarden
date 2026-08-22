package system

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateCronWorkIsModeLockedAndIgnoresHostileTMPDIR(t *testing.T) {
	if privateCronWorkRoot != "/var/tmp" {
		t.Fatalf("production private cron work root = %q", privateCronWorkRoot)
	}
	hostileTmp := filepath.Join(t.TempDir(), "attacker-controlled-tmp")
	if err := os.Mkdir(hostileTmp, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", hostileTmp)
	command := exec.Command("/bin/sh", "-c", "exit 0")
	fixedRoot := filepath.Join(t.TempDir(), "fixed-root")
	if err := os.Mkdir(fixedRoot, 0700); err != nil {
		t.Fatal(err)
	}
	workPath, err := preparePrivateCronWorkAt(fixedRoot, command)
	if err != nil {
		t.Fatalf("prepare private cron work: %v", err)
	}
	t.Cleanup(func() {
		if _, statErr := os.Lstat(workPath); errors.Is(statErr, os.ErrNotExist) {
			return
		}
		if err := removePrivateCronWork(workPath); err != nil {
			t.Errorf("cleanup private cron work: %v", err)
		}
	})
	if filepath.Dir(workPath) != fixedRoot ||
		!strings.HasPrefix(filepath.Base(workPath), "syswarden-cron.") {
		t.Fatalf("unexpected private cron work path: %q", workPath)
	}
	if strings.HasPrefix(workPath, hostileTmp+string(os.PathSeparator)) {
		t.Fatalf("hostile TMPDIR controlled cron work path: %q", workPath)
	}
	cachePath := filepath.Join(workPath, "cache")
	for _, path := range []string{workPath, cachePath} {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatalf("inspect private cron directory %q: %v", path, statErr)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			t.Fatalf("private cron directory %q has type/mode %v", path, info.Mode())
		}
	}
	xdgCount := 0
	for _, variable := range command.Environ() {
		if strings.HasPrefix(variable, "XDG_CACHE_HOME=") {
			xdgCount++
			if variable != "XDG_CACHE_HOME="+cachePath {
				t.Fatalf("unexpected private cron cache environment: %q", variable)
			}
		}
	}
	if xdgCount != 1 {
		t.Fatalf("private cron cache environment count = %d, want 1", xdgCount)
	}
	if err := removePrivateCronWork(workPath); err != nil {
		t.Fatalf("remove private cron work: %v", err)
	}
	if _, statErr := os.Lstat(workPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("private cron work remains: %v", statErr)
	}
}
