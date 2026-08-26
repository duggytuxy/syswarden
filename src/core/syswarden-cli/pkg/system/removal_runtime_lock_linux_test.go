//go:build linux

package system

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func writeFirewallRuntimeLockFixture(t *testing.T, path string, mode os.FileMode, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestRemovePreparedFirewallRuntimeLockRemovesOnlyExactUnlockedArtifact_SW2_PKG_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-firewall.lock")
	writeFirewallRuntimeLockFixture(t, path, 0600, nil)

	reattestCalls := 0
	var warnings bytes.Buffer
	err := removePreparedFirewallRuntimeLockAt(
		path,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error {
			reattestCalls++
			return nil
		},
		&warnings,
	)
	if err != nil {
		t.Fatalf("remove exact runtime lock: %v", err)
	}
	if reattestCalls != 2 {
		t.Fatalf("runtime lock reattestations = %d, want 2", reattestCalls)
	}
	if warnings.Len() != 0 {
		t.Fatalf("unexpected runtime lock warning: %s", warnings.String())
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime lock remained after exact removal: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("runtime lock quarantine remained: %v", entries)
	}
}

func TestRemovePreparedFirewallRuntimeLockPreservesUnsafeArtifacts_SW2_PKG_001(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		build func(*testing.T, string)
		uid   uint32
		gid   uint32
	}{
		{
			name: "symlink",
			build: func(t *testing.T, path string) {
				t.Helper()
				target := filepath.Join(filepath.Dir(path), "operator-target")
				writeFirewallRuntimeLockFixture(t, target, 0600, nil)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-empty",
			build: func(t *testing.T, path string) {
				writeFirewallRuntimeLockFixture(t, path, 0600, []byte("operator"))
			},
		},
		{
			name: "wrong-mode",
			build: func(t *testing.T, path string) {
				writeFirewallRuntimeLockFixture(t, path, 0640, nil)
			},
		},
		{
			name: "hard-linked",
			build: func(t *testing.T, path string) {
				writeFirewallRuntimeLockFixture(t, path, 0600, nil)
				if err := os.Link(path, filepath.Join(filepath.Dir(path), "operator-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			build: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-owner-attestation",
			build: func(t *testing.T, path string) {
				writeFirewallRuntimeLockFixture(t, path, 0600, nil)
			},
			uid: uint32(os.Geteuid()) + 1,
			gid: uint32(os.Getegid()),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "syswarden-firewall.lock")
			testCase.build(t, path)
			uid := testCase.uid
			gid := testCase.gid
			if testCase.name != "wrong-owner-attestation" {
				uid = uint32(os.Geteuid())
				gid = uint32(os.Getegid())
			}
			reattestCalls := 0
			var warnings bytes.Buffer
			if err := removePreparedFirewallRuntimeLockAt(
				path, uid, gid, func() error { reattestCalls++; return nil }, &warnings,
			); err != nil {
				t.Fatalf("unsafe runtime lock preservation: %v", err)
			}
			if reattestCalls != 0 {
				t.Fatalf("unsafe runtime lock reached reattestation: %d", reattestCalls)
			}
			if !strings.Contains(warnings.String(), "Preserving ambiguous SysWarden firewall runtime lock") {
				t.Fatalf("unsafe runtime lock warning = %q", warnings.String())
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("unsafe runtime lock was not preserved: %v", err)
			}
		})
	}
}

func TestRemovePreparedFirewallRuntimeLockRejectsBusyArtifact_SW2_PKG_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-firewall.lock")
	writeFirewallRuntimeLockFixture(t, path, 0600, nil)
	lock, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN) //nolint:errcheck -- best-effort test cleanup

	var warnings bytes.Buffer
	err = removePreparedFirewallRuntimeLockAt(
		path,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error { t.Fatal("busy lock reached process reattestation"); return nil },
		&warnings,
	)
	if err == nil || !strings.Contains(err.Error(), "held by another process") {
		t.Fatalf("busy runtime lock result = %v", err)
	}
	if !strings.Contains(warnings.String(), "Preserving ambiguous") {
		t.Fatalf("busy runtime lock warning = %q", warnings.String())
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("busy runtime lock was not preserved: %v", err)
	}
}

func TestRemovePreparedFirewallRuntimeLockRestoresOnFinalReattestationFailure_SW2_PKG_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-firewall.lock")
	writeFirewallRuntimeLockFixture(t, path, 0600, nil)
	sentinel := errors.New("synthetic process reattestation drift")
	reattestCalls := 0
	var warnings bytes.Buffer
	err := removePreparedFirewallRuntimeLockAt(
		path,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error {
			reattestCalls++
			if reattestCalls == 2 {
				return sentinel
			}
			return nil
		},
		&warnings,
	)
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("final runtime lock reattestation result = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("runtime lock was not restored after reattestation drift: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("unexpected artifacts after runtime lock restoration: %v", entries)
	}
	if !strings.Contains(warnings.String(), "Preserving ambiguous") {
		t.Fatalf("restored runtime lock warning = %q", warnings.String())
	}
}

func TestRemovePreparedFirewallRuntimeLockPreservesQuarantineWhenPathIsRecreated_SW2_PKG_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-firewall.lock")
	writeFirewallRuntimeLockFixture(t, path, 0600, nil)
	reattestCalls := 0
	var warnings bytes.Buffer
	err := removePreparedFirewallRuntimeLockAt(
		path,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error {
			reattestCalls++
			if reattestCalls == 2 {
				writeFirewallRuntimeLockFixture(t, path, 0600, []byte("new-owner"))
			}
			return nil
		},
		&warnings,
	)
	if err == nil || !strings.Contains(err.Error(), "recreated") {
		t.Fatalf("recreated runtime lock result = %v", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "new-owner" {
		t.Fatalf("recreated runtime lock was changed: content=%q err=%v", content, readErr)
	}
	entries, readDirErr := os.ReadDir(directory)
	if readDirErr != nil {
		t.Fatal(readDirErr)
	}
	if len(entries) != 2 {
		t.Fatalf("original quarantine was not preserved beside recreated path: %v", entries)
	}
	quarantineFound := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".syswarden-firewall-lock-removal-") {
			quarantineFound = true
		}
	}
	if !quarantineFound || !strings.Contains(warnings.String(), "Preserving ambiguous") {
		t.Fatalf("recreated path preservation evidence: entries=%v warning=%q", entries, warnings.String())
	}
}

func TestRemovePreparedFirewallRuntimeLockDoesNothingWhenAbsent_SW2_PKG_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syswarden-firewall.lock")
	reattestCalls := 0
	if err := removePreparedFirewallRuntimeLockAt(
		path,
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error { reattestCalls++; return nil },
		ioDiscardForRuntimeLockTest{},
	); err != nil {
		t.Fatalf("absent runtime lock removal: %v", err)
	}
	if reattestCalls != 0 {
		t.Fatalf("absent runtime lock triggered reattestation: %d", reattestCalls)
	}
}

func TestRemovePreparedFirewallRuntimeLockRejectsFilesystemRoot_SW2_PKG_001(t *testing.T) {
	err := removePreparedFirewallRuntimeLockAt(
		string(filepath.Separator),
		uint32(os.Geteuid()),
		uint32(os.Getegid()),
		func() error { return nil },
		ioDiscardForRuntimeLockTest{},
	)
	if err == nil || !strings.Contains(err.Error(), "not clean and absolute") {
		t.Fatalf("filesystem-root runtime lock path result = %v", err)
	}
}

type ioDiscardForRuntimeLockTest struct{}

func (ioDiscardForRuntimeLockTest) Write(content []byte) (int, error) { return len(content), nil }
