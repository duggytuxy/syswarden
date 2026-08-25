//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeRemovalMountInfo(mountPoints ...string) []byte {
	var rendered strings.Builder
	for index, mountPoint := range mountPoints {
		fmt.Fprintf(
			&rendered,
			"%d 0 0:%d / %s rw - ext4 /dev/fake rw\n",
			index+1,
			index+1,
			mountPoint,
		)
	}
	return []byte(rendered.String())
}

func TestDedicatedRemovalTreeRefusesSymlinkAndPropagatesDeletionError_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
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
		if content, err := os.ReadFile(marker); err != nil || string(content) != "operator" { // #nosec G304 -- marker is confined to the private adversarial fixture root
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

func TestDedicatedRemovalTreeMountPreflightPreservesEveryByteAndAllowsRetry_SW2_PKG_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	product := filepath.Join(t.TempDir(), "syswarden")
	nested := filepath.Join(product, "nested")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(nested, "operator-data")
	if err := os.WriteFile(marker, []byte("preserve exactly"), 0600); err != nil {
		t.Fatal(err)
	}
	operatorCalls := 0
	removeAll := func(root *os.Root, name string, _ string) error {
		operatorCalls++
		return root.RemoveAll(name)
	}
	err := removeDedicatedRemovalTreeAtUsingMountInfo(
		product,
		uid,
		gid,
		removeAll,
		func() ([]byte, error) { return fakeRemovalMountInfo("/", nested), nil },
	)
	if err == nil || !strings.Contains(err.Error(), "mount boundary") {
		t.Fatalf("nested mount preflight error = %v", err)
	}
	if operatorCalls != 0 {
		t.Fatalf("nested mount preflight invoked %d destructive operators", operatorCalls)
	}
	if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "preserve exactly" {
		t.Fatalf("nested mount preflight changed marker = %q, %v", got, readErr)
	}
	err = removeDedicatedRemovalTreeAtUsingMountInfo(
		product,
		uid,
		gid,
		removeAll,
		func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil },
	)
	if err != nil {
		t.Fatalf("mount-free retry: %v", err)
	}
	if operatorCalls != 1 {
		t.Fatalf("mount-free retry destructive operator calls = %d", operatorCalls)
	}
	if _, statErr := os.Lstat(product); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("mount-free retry left product tree: %v", statErr)
	}
}

func TestExactProductSymlinkRemovalPreservesLookalikes_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	parent := t.TempDir()
	expected := "/opt/syswarden/bin/syswarden-cli"

	regular := filepath.Join(parent, "regular")
	if err := os.WriteFile(regular, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeExactProductSymlinkAt(regular, expected, uid, gid); err == nil {
		t.Fatal("lookalike regular file was accepted")
	}
	if content, err := os.ReadFile(regular); err != nil || string(content) != "operator" { // #nosec G304 -- regular is confined to the private lookalike fixture root
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
	if content, readErr := os.ReadFile(stateEntry); readErr != nil || string(content) != "state" { // #nosec G304 -- stateEntry is confined to the private removal-state fixture root
		t.Fatalf("failed target changed: content=%q err=%v", content, readErr)
	}
}

func TestRemovalStateMountPreflightPreservesTombstoneAndDataUntilRetry_SW2_PKG_001(t *testing.T) {
	path, uid, gid := testRemovalTombstonePath(t)
	if err := ensureRemovalTombstoneAt(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(path)
	stateEntry := filepath.Join(directory, "data")
	if err := os.Mkdir(stateEntry, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(stateEntry, "operator-data")
	if err := os.WriteFile(marker, []byte("preserve exactly"), 0600); err != nil {
		t.Fatal(err)
	}
	operatorCalls := 0
	removeAll := func(root *os.Root, name string, _ string) error {
		operatorCalls++
		return root.RemoveAll(name)
	}
	err := removeRemovalStateContentsAtUsingMountInfo(
		directory,
		uid,
		gid,
		removeAll,
		func() ([]byte, error) { return fakeRemovalMountInfo("/", filepath.Join(stateEntry, "nested")), nil },
	)
	if err == nil || !strings.Contains(err.Error(), "mount boundary") {
		t.Fatalf("state mount preflight error = %v", err)
	}
	if operatorCalls != 0 {
		t.Fatalf("state mount preflight invoked %d destructive operators", operatorCalls)
	}
	if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "preserve exactly" {
		t.Fatalf("state mount preflight changed marker = %q, %v", got, readErr)
	}
	if present, inspectErr := inspectRemovalTombstoneAt(path, uid, gid); inspectErr != nil || !present {
		t.Fatalf("state mount preflight lost tombstone: %t, %v", present, inspectErr)
	}
	err = removeRemovalStateContentsAtUsingMountInfo(
		directory,
		uid,
		gid,
		removeAll,
		func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil },
	)
	if err != nil {
		t.Fatalf("state mount-free retry: %v", err)
	}
	if operatorCalls != 1 {
		t.Fatalf("state mount-free retry destructive operator calls = %d", operatorCalls)
	}
	if _, statErr := os.Lstat(stateEntry); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("state mount-free retry left data: %v", statErr)
	}
	if present, inspectErr := inspectRemovalTombstoneAt(path, uid, gid); inspectErr != nil || !present {
		t.Fatalf("state retry lost tombstone: %t, %v", present, inspectErr)
	}
}

func TestHostRemovalMountPreflightChecksAllRootsInOneSnapshot_SW2_PKG_001(t *testing.T) {
	roots := []string{
		"/opt/syswarden",
		"/etc/syswarden",
		"/var/log/syswarden",
		"/var/lib/syswarden",
	}
	readCalls := 0
	err := preflightRemovalMountBoundariesAt(
		roots,
		func() ([]byte, error) {
			readCalls++
			return fakeRemovalMountInfo("/", "/var/lib/syswarden/operator-bind"), nil
		},
	)
	if err == nil || !strings.Contains(err.Error(), "/var/lib/syswarden/operator-bind") {
		t.Fatalf("four-root mount preflight error = %v", err)
	}
	if readCalls != 1 {
		t.Fatalf("four-root mount preflight snapshots = %d, want 1", readCalls)
	}
}

func TestExactRuntimeSocketRemovalRefusesRegularLookalike_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	parent := t.TempDir()
	lookalike := filepath.Join(parent, "lookalike.sock")
	if err := os.WriteFile(lookalike, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeExactRuntimeSocketAt(lookalike, uid, gid); err == nil {
		t.Fatal("regular socket lookalike was accepted")
	}
	if content, err := os.ReadFile(lookalike); err != nil || string(content) != "operator" { // #nosec G304 -- lookalike is confined to the private socket fixture root
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
