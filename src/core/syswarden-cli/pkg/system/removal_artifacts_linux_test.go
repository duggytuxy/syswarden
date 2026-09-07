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

	"golang.org/x/sys/unix"
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
	if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "preserve exactly" { // #nosec G304 -- marker is confined to the private nested-mount fixture root
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

func TestSharedParentDedicatedRemovalSupportsUbuntuLayoutAndPreservesSiblings_SW2_PKG_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	sharedParent := filepath.Join(t.TempDir(), "var-log")
	if err := os.Mkdir(sharedParent, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sharedParent, 0775); err != nil { // #nosec G302 -- reproduces the supported shared /var/log mode
		t.Fatal(err)
	}
	product := filepath.Join(sharedParent, "syswarden")
	if err := os.Mkdir(product, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(product, "product.log"), []byte("product"), 0600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(sharedParent, "operator.log")
	if err := os.WriteFile(sibling, []byte("preserve exactly"), 0640); err != nil { // #nosec G306 -- reproduces a typical shared log sibling mode
		t.Fatal(err)
	}
	siblingBefore, err := os.Lstat(sibling)
	if err != nil {
		t.Fatal(err)
	}
	parentBefore, err := os.Lstat(sharedParent)
	if err != nil {
		t.Fatal(err)
	}
	unlinks := 0
	remove := func() error {
		return removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
			product,
			uid,
			gid,
			uid,
			func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
			func(fd int, name string, flags int) error {
				unlinks++
				return unix.Unlinkat(fd, name, flags)
			},
			func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil },
			sharedRemovalRaceHooks{},
		)
	}
	if err := remove(); err != nil {
		t.Fatalf("shared-parent removal: %v", err)
	}
	if err := remove(); err != nil {
		t.Fatalf("idempotent shared-parent retry: %v", err)
	}
	if unlinks != 1 {
		t.Fatalf("shared-parent rmdir calls = %d, want 1", unlinks)
	}
	if _, err := os.Lstat(product); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("product log root remains: %v", err)
	}
	if got, err := os.ReadFile(sibling); err != nil || string(got) != "preserve exactly" { // #nosec G304 -- sibling is confined to the private fixture
		t.Fatalf("operator sibling changed: content=%q error=%v", got, err)
	}
	siblingAfter, err := os.Lstat(sibling)
	if err != nil || !os.SameFile(siblingBefore, siblingAfter) || siblingBefore.Mode() != siblingAfter.Mode() {
		t.Fatalf("operator sibling identity changed: %v", err)
	}
	parentAfter, err := os.Lstat(sharedParent)
	if err != nil || !os.SameFile(parentBefore, parentAfter) || parentBefore.Mode() != parentAfter.Mode() {
		t.Fatalf("shared parent identity changed: %v", err)
	}
}

func TestSharedParentDedicatedRemovalRejectsUnsafeStateAndRaces_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	newFixture := func(t *testing.T) (string, string) {
		t.Helper()
		parent := filepath.Join(t.TempDir(), "var-log")
		if err := os.Mkdir(parent, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0775); err != nil { // #nosec G302 -- reproduces the supported shared /var/log mode
			t.Fatal(err)
		}
		product := filepath.Join(parent, "syswarden")
		if err := os.Mkdir(product, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(product, "product.log"), []byte("product"), 0600); err != nil {
			t.Fatal(err)
		}
		return parent, product
	}
	run := func(product string, hooks sharedRemovalRaceHooks, readMountInfo removalMountInfoReader) error {
		return removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
			product,
			uid,
			gid,
			uid,
			func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
			unix.Unlinkat,
			readMountInfo,
			hooks,
		)
	}

	t.Run("world-writable parent", func(t *testing.T) {
		parent, product := newFixture(t)
		if err := os.Chmod(parent, 0777); err != nil { // #nosec G302 -- adversarial fixture must be world-writable
			t.Fatal(err)
		}
		if err := run(product, sharedRemovalRaceHooks{}, func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil }); err == nil {
			t.Fatal("world-writable shared parent was accepted")
		}
		if got, err := os.ReadFile(filepath.Join(product, "product.log")); err != nil || string(got) != "product" { // #nosec G304 -- fixture path
			t.Fatalf("unsafe-parent refusal changed product bytes: %q, %v", got, err)
		}
	})

	t.Run("unsafe target", func(t *testing.T) {
		_, product := newFixture(t)
		if err := os.Chmod(product, 0770); err != nil { // #nosec G302 -- adversarial fixture must be group-writable
			t.Fatal(err)
		}
		if err := run(product, sharedRemovalRaceHooks{}, func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil }); err == nil {
			t.Fatal("group-writable product root was accepted")
		}
	})

	t.Run("nested mount", func(t *testing.T) {
		_, product := newFixture(t)
		calls := 0
		err := removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
			product,
			uid,
			gid,
			uid,
			func(*os.Root, string, string) error { calls++; return nil },
			func(int, string, int) error { calls++; return nil },
			func() ([]byte, error) { return fakeRemovalMountInfo("/", filepath.Join(product, "nested")), nil },
			sharedRemovalRaceHooks{},
		)
		if err == nil || !strings.Contains(err.Error(), "mount boundary") || calls != 0 {
			t.Fatalf("nested-mount refusal = %v, destructive calls = %d", err, calls)
		}
	})

	t.Run("replacement before final rmdir", func(t *testing.T) {
		parent, product := newFixture(t)
		displaced := filepath.Join(parent, "syswarden-displaced")
		replacementMarker := filepath.Join(product, "operator-data")
		err := run(
			product,
			sharedRemovalRaceHooks{beforeFinalUnlink: func() {
				if renameErr := os.Rename(product, displaced); renameErr != nil {
					t.Fatalf("displace pinned product root: %v", renameErr)
				}
				if mkdirErr := os.Mkdir(product, 0750); mkdirErr != nil {
					t.Fatalf("publish replacement root: %v", mkdirErr)
				}
				if writeErr := os.WriteFile(replacementMarker, []byte("operator"), 0600); writeErr != nil {
					t.Fatalf("publish replacement marker: %v", writeErr)
				}
			}},
			func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil },
		)
		if err == nil || !strings.Contains(err.Error(), "changed at final boundary") {
			t.Fatalf("replacement race error = %v", err)
		}
		if got, readErr := os.ReadFile(replacementMarker); readErr != nil || string(got) != "operator" { // #nosec G304 -- fixture path
			t.Fatalf("replacement bytes changed: %q, %v", got, readErr)
		}
		if entries, readErr := os.ReadDir(displaced); readErr != nil || len(entries) != 0 {
			t.Fatalf("pinned product root was not boundedly emptied: entries=%v error=%v", entries, readErr)
		}
	})

	t.Run("replacement at final rmdir", func(t *testing.T) {
		parent, product := newFixture(t)
		displaced := filepath.Join(parent, "syswarden-displaced")
		replacement := filepath.Join(parent, "syswarden")
		err := removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
			product,
			uid,
			gid,
			uid,
			func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
			func(fd int, name string, flags int) error {
				if renameErr := os.Rename(product, displaced); renameErr != nil {
					t.Fatalf("displace product at final rmdir: %v", renameErr)
				}
				if mkdirErr := os.Mkdir(replacement, 0750); mkdirErr != nil {
					t.Fatalf("publish empty replacement at final rmdir: %v", mkdirErr)
				}
				return unix.Unlinkat(fd, name, flags)
			},
			func() ([]byte, error) { return fakeRemovalMountInfo("/"), nil },
			sharedRemovalRaceHooks{},
		)
		if err == nil || !strings.Contains(err.Error(), "was not the directory removed") {
			t.Fatalf("final-rmdir replacement race error = %v", err)
		}
		if entries, readErr := os.ReadDir(displaced); readErr != nil || len(entries) != 0 {
			t.Fatalf("original pinned product root was not preserved empty: entries=%v error=%v", entries, readErr)
		}
	})
}

func TestStrictDedicatedRemovalStillRejectsGroupWritableParent_SW2_FWBACKEND_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0775); err != nil { // #nosec G302 -- verifies strict removal rejects a group-writable parent
		t.Fatal(err)
	}
	product := filepath.Join(parent, "syswarden")
	if err := os.Mkdir(product, 0750); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := removeDedicatedRemovalTreeAt(product, uid, gid, func(*os.Root, string, string) error {
		calls++
		return nil
	})
	if err == nil || calls != 0 {
		t.Fatalf("strict group-writable-parent refusal = %v, destructive calls = %d", err, calls)
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
	if err := preflightExactProductSymlinkAt(regular, expected, uid, gid); err == nil {
		t.Fatal("preflight accepted a regular link lookalike")
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
	if err := preflightExactProductSymlinkAt(wrong, expected, uid, gid); err == nil {
		t.Fatal("preflight accepted an unexpected product link target")
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
	if err := preflightExactProductSymlinkAt(exact, expected, uid, gid); err != nil {
		t.Fatalf("preflight exact product symlink: %v", err)
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
	if got, readErr := os.ReadFile(marker); readErr != nil || string(got) != "preserve exactly" { // #nosec G304 -- marker is confined to the private removal-state mount fixture root
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

func TestPackageRemovalRuntimeSocketUsesExactRootOwnedPath_SW2_PKG_001(t *testing.T) {
	sentinel := errors.New("synthetic exact-socket refusal")
	calls := 0
	err := removeExactRuntimeSocketForPackageRemovalUsing(
		func(path string, uid, gid uint32) error {
			calls++
			if path != "/run/syswarden.sock" || uid != 0 || gid != 0 {
				t.Fatalf("package-removal socket target = %q uid %d gid %d", path, uid, gid)
			}
			return sentinel
		},
	)
	if calls != 1 || !errors.Is(err, sentinel) {
		t.Fatalf("package-removal exact socket delegation = calls %d error %v", calls, err)
	}
	if err := removeExactRuntimeSocketForPackageRemovalUsing(nil); err == nil {
		t.Fatal("package-removal socket cleanup accepted a nil exact remover")
	}
}

func TestOfflinePackageRemovalSocketAbsenceAttestationIsReadOnlyAndFailClosed_SW2_PKG_001(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	parent := t.TempDir()
	path := filepath.Join(parent, "syswarden.sock")
	if err := attestRuntimeSocketAbsentAt(path, uid, gid); err != nil {
		t.Fatalf("attest absent runtime socket: %v", err)
	}
	operatorBytes := []byte("operator-owned lookalike")
	if err := os.WriteFile(path, operatorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := attestRuntimeSocketAbsentAt(path, uid, gid); err == nil ||
		!strings.Contains(err.Error(), "teardown target remains") {
		t.Fatalf("present runtime target attestation = %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(operatorBytes) { // #nosec G304 -- path is confined to the private offline-attestation fixture root
		t.Fatalf("offline socket attestation mutated target: bytes=%q error=%v", got, err)
	}
	if err := attestRuntimeSocketAbsentAt("relative.sock", uid, gid); err == nil {
		t.Fatal("offline socket attestation accepted a relative path")
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
		`removeExactRuntimeSocketAt(`,
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
	preflight := strings.Index(content, "preflightHostProductRemovalArtifacts()")
	start := strings.Index(content, `fmt.Println("[WARN] Starting verified SysWarden host removal...")`)
	logRemoval := strings.Index(content, "removeDedicatedProductLogTree()")
	configRemoval := strings.Index(content, `removeDedicatedRemovalTree("/etc/syswarden")`)
	tuiLinkRemoval := strings.Index(content, `"/usr/local/bin/syswarden-tui", "/opt/syswarden/bin/syswarden-tui"`)
	cliLinkRemoval := strings.Index(content, `"/usr/local/bin/syswarden", "/opt/syswarden/bin/syswarden-cli"`)
	executableRemoval := strings.Index(content, `removeDedicatedRemovalTree("/opt/syswarden")`)
	if preflight < 0 || start < 0 || logRemoval < 0 || configRemoval < 0 || tuiLinkRemoval < 0 ||
		cliLinkRemoval < 0 || executableRemoval < 0 || preflight >= start || start >= logRemoval ||
		logRemoval >= configRemoval || configRemoval >= tuiLinkRemoval || tuiLinkRemoval >= cliLinkRemoval ||
		cliLinkRemoval >= executableRemoval {
		t.Fatalf(
			"unsafe uninstall ordering: preflight=%d start=%d log=%d config=%d tui-link=%d cli-link=%d executable=%d",
			preflight, start, logRemoval, configRemoval, tuiLinkRemoval, cliLinkRemoval, executableRemoval,
		)
	}
	if strings.Contains(content, `removeDedicatedRemovalTree("/var/log/syswarden")`) {
		t.Fatal("uninstall tail uses the strict parent remover for the shared log root")
	}
}
