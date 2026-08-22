//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDedicatedRemovalTreeRefusesSymlinkAndPropagatesDeletionError_SW2_FWBACKEND_001(t *testing.T) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	t.Run("symlink root", func(t *testing.T) {
		parent := t.TempDir()
		operator := filepath.Join(parent, "operator")
		if err := os.Mkdir(operator, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(operator, "keep")
		if err := os.WriteFile(marker, []byte("operator"), 0600); err != nil {
			t.Fatal(err)
		}
		product := filepath.Join(parent, "syswarden")
		if err := os.Symlink(operator, product); err != nil {
			t.Fatal(err)
		}
		if err := removeDedicatedRemovalTreeAt(
			product, uid, gid,
			func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
		); err == nil {
			t.Fatal("symlinked product root was removed")
		}
		if content, err := os.ReadFile(marker); err != nil || string(content) != "operator" {
			t.Fatalf("operator target changed: content=%q err=%v", content, err)
		}
	})

	t.Run("operator error", func(t *testing.T) {
		product := filepath.Join(t.TempDir(), "syswarden")
		if err := os.Mkdir(product, 0700); err != nil {
			t.Fatal(err)
		}
		sentinel := errors.New("synthetic removal failure")
		err := removeDedicatedRemovalTreeAt(product, uid, gid, func(*os.Root, string, string) error { return sentinel })
		if err == nil || !errors.Is(err, sentinel) {
			t.Fatalf("removal error = %v", err)
		}
		if _, err := os.Lstat(product); err != nil {
			t.Fatalf("failed removal lost product root: %v", err)
		}
	})
}

func TestExactProductSymlinkRemovalPreservesLookalikes_SW2_FWBACKEND_001(t *testing.T) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	parent := t.TempDir()
	expected := "/opt/syswarden/bin/syswarden-cli"

	regular := filepath.Join(parent, "regular")
	if err := os.WriteFile(regular, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeExactProductSymlinkAt(regular, expected, uid, gid); err == nil {
		t.Fatal("lookalike regular file was accepted")
	}
	if content, err := os.ReadFile(regular); err != nil || string(content) != "operator" {
		t.Fatalf("lookalike regular file changed: content=%q err=%v", content, err)
	}

	wrong := filepath.Join(parent, "wrong")
	if err := os.Symlink("/opt/operator/bin/syswarden-cli", wrong); err != nil {
		t.Fatal(err)
	}
	if err := removeExactProductSymlinkAt(wrong, expected, uid, gid); err == nil {
		t.Fatal("wrong symlink target was accepted")
	}
	if target, err := os.Readlink(wrong); err != nil || target != "/opt/operator/bin/syswarden-cli" {
		t.Fatalf("wrong symlink changed: target=%q err=%v", target, err)
	}

	exact := filepath.Join(parent, "exact")
	if err := os.Symlink(expected, exact); err != nil {
		t.Fatal(err)
	}
	if err := removeExactProductSymlinkAt(exact, expected, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(exact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact product symlink remains: %v", err)
	}
}

func TestRemovalStateFailureRetainsExactTombstoneEvidence_SW2_FWBACKEND_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	stateEntry := filepath.Join(filepath.Dir(path), "data")
	if err := os.WriteFile(stateEntry, []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("synthetic state removal error")
	err := removeRemovalStateContentsAt(
		filepath.Dir(path), uid, gid,
		func(_ *os.Root, _ string, candidate string) error {
			if candidate != stateEntry {
				t.Fatalf("unexpected state removal target %s", candidate)
			}
			return sentinel
		},
	)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("state removal error = %v", err)
	}
	present, inspectErr := inspectRemovalTombstoneAt(path, uid, gid)
	if inspectErr != nil || !present {
		t.Fatalf("failure lost tombstone: present=%t err=%v", present, inspectErr)
	}
	if content, readErr := os.ReadFile(stateEntry); readErr != nil || string(content) != "state" {
		t.Fatalf("failed target changed: content=%q err=%v", content, readErr)
	}
}

func TestExactRuntimeSocketRemovalRefusesRegularLookalike_SW2_FWBACKEND_001(t *testing.T) {
	uid := uint32(os.Geteuid())
	gid := uint32(os.Getegid())
	parent := t.TempDir()
	lookalike := filepath.Join(parent, "lookalike.sock")
	if err := os.WriteFile(lookalike, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeExactRuntimeSocketAt(lookalike, uid, gid); err == nil {
		t.Fatal("regular socket lookalike was accepted")
	}
	if content, err := os.ReadFile(lookalike); err != nil || string(content) != "operator" {
		t.Fatalf("socket lookalike changed: content=%q err=%v", content, err)
	}

}

func TestUninstallTailHasNoAmbientCronProfileOrIgnoredRemovalMutation_SW2_FWBACKEND_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "uninstall_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	for _, forbidden := range []string{
		`exec.Command("crontab"`,
		`exec.Command("chattr"`,
		`"/etc/cron.allow"`,
		`os.RemoveAll(`,
		`_ = os.Remove(`,
		`systemctl", "restart", "rsyslog`,
	} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("uninstall tail contains forbidden mutation %q", forbidden)
		}
	}
	success := strings.Index(content, `fmt.Println("[SUCCESS]`)
	finalize := strings.Index(content, "FinalizeRemovalTombstone()")
	if success < 0 || finalize < 0 || success <= finalize {
		t.Fatalf("success can be printed before finalization: success=%d finalize=%d", success, finalize)
	}
}
