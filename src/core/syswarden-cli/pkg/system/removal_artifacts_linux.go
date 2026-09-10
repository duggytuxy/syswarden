//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type removalTreeOperator func(*os.Root, string, string) error

type sharedRemovalRaceHooks struct {
	afterTargetSnapshot func()
	afterTargetPinned   func()
	beforeFinalUnlink   func()
}

func normalizeSharedRemovalRaceHooks(hooks sharedRemovalRaceHooks) sharedRemovalRaceHooks {
	if hooks.afterTargetSnapshot == nil {
		hooks.afterTargetSnapshot = func() {}
	}
	if hooks.afterTargetPinned == nil {
		hooks.afterTargetPinned = func() {}
	}
	if hooks.beforeFinalUnlink == nil {
		hooks.beforeFinalUnlink = func() {}
	}
	return hooks
}

// openPinnedSharedRemovalParent pins a root-owned parent whose group may be
// allowed to create directory entries. It is intentionally separate from the
// strict service-directory contract: distro-managed /var/log is commonly
// root:syslog and group-writable. Callers must therefore delete only through a
// separately pinned and identity-attested child, never recursively by name
// from this parent.
func openPinnedSharedRemovalParent(path string, expectedUID uint32) (*pinnedServiceDirectory, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("shared removal parent is not clean and absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect shared removal parent %s: %w", path, err)
	}
	beforeIdentity, identityErr := exactRemovalArtifactIdentity(before)
	if identityErr != nil || !safeSharedRemovalParent(before, beforeIdentity, expectedUID) {
		return nil, errors.Join(fmt.Errorf("refusing unsafe shared removal parent %s", path), identityErr)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("pin shared removal parent %s: %w", path, err)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) // #nosec G304 -- fixed production path and private test fixtures are identity attested
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open shared removal parent %s without following links: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		_ = root.Close()
		return nil, fmt.Errorf("pin shared removal parent %s", path)
	}
	rootInfo, rootErr := root.Stat(".")
	rootIdentity, rootIdentityErr := exactRemovalArtifactIdentity(rootInfo)
	fdInfo, fdErr := file.Stat()
	fdIdentity, fdIdentityErr := exactRemovalArtifactIdentity(fdInfo)
	after, afterErr := os.Lstat(path)
	afterIdentity, afterIdentityErr := exactRemovalArtifactIdentity(after)
	if rootErr != nil || rootIdentityErr != nil || fdErr != nil || fdIdentityErr != nil ||
		afterErr != nil || afterIdentityErr != nil ||
		!safeSharedRemovalParent(rootInfo, rootIdentity, expectedUID) ||
		!safeSharedRemovalParent(fdInfo, fdIdentity, expectedUID) ||
		!safeSharedRemovalParent(after, afterIdentity, expectedUID) ||
		!samePinnedRemovalDirectoryIdentity(beforeIdentity, rootIdentity) ||
		!samePinnedRemovalDirectoryIdentity(rootIdentity, fdIdentity) ||
		!samePinnedRemovalDirectoryIdentity(fdIdentity, afterIdentity) {
		_ = file.Close()
		_ = root.Close()
		return nil, errors.Join(
			fmt.Errorf("shared removal parent changed while pinning %s", path),
			rootErr, rootIdentityErr, fdErr, fdIdentityErr, afterErr, afterIdentityErr,
		)
	}
	return &pinnedServiceDirectory{root: root, file: file, fd: fd}, nil
}

func safeSharedRemovalParent(info os.FileInfo, identity removalArtifactIdentity, expectedUID uint32) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() &&
		info.Mode().Perm()&0002 == 0 && identity.uid == expectedUID
}

type pinnedSharedRemovalTree struct {
	parent   *pinnedServiceDirectory
	root     *os.Root
	name     string
	identity removalArtifactIdentity
	absent   bool
}

func (tree *pinnedSharedRemovalTree) close() {
	if tree == nil {
		return
	}
	if tree.root != nil {
		_ = tree.root.Close()
	}
	if tree.parent != nil {
		tree.parent.close()
	}
}

func samePinnedRemovalDirectoryIdentity(left, right removalArtifactIdentity) bool {
	return left.dev == right.dev && left.ino == right.ino && left.mode == right.mode &&
		left.uid == right.uid && left.gid == right.gid
}

func openPinnedSharedRemovalTree(
	path string,
	targetUID uint32,
	targetGID uint32,
	parentUID uint32,
	hooks sharedRemovalRaceHooks,
) (*pinnedSharedRemovalTree, error) {
	hooks = normalizeSharedRemovalRaceHooks(hooks)
	parentPath := filepath.Dir(path)
	parent, err := openPinnedSharedRemovalParent(parentPath, parentUID)
	if err != nil {
		return nil, err
	}
	tree := &pinnedSharedRemovalTree{parent: parent, name: filepath.Base(path)}
	before, err := parent.root.Lstat(tree.name)
	if errors.Is(err, os.ErrNotExist) {
		tree.absent = true
		return tree, nil
	}
	if err != nil {
		tree.close()
		return nil, fmt.Errorf("inspect shared-parent removal root %s: %w", path, err)
	}
	beforeIdentity, identityErr := exactRemovalArtifactIdentity(before)
	if identityErr != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() ||
		before.Mode().Perm()&0022 != 0 || beforeIdentity.uid != targetUID || beforeIdentity.gid != targetGID {
		tree.close()
		return nil, errors.Join(fmt.Errorf("refusing unsafe shared-parent removal root %s", path), identityErr)
	}
	hooks.afterTargetSnapshot()
	targetRoot, err := parent.root.OpenRoot(tree.name)
	if err != nil {
		tree.close()
		return nil, fmt.Errorf("pin shared-parent removal root %s: %w", path, err)
	}
	opened, openedErr := targetRoot.Stat(".")
	openedIdentity, openedIdentityErr := exactRemovalArtifactIdentity(opened)
	current, currentErr := parent.root.Lstat(tree.name)
	currentIdentity, currentIdentityErr := exactRemovalArtifactIdentity(current)
	if openedErr != nil || openedIdentityErr != nil || currentErr != nil || currentIdentityErr != nil ||
		beforeIdentity != openedIdentity || openedIdentity != currentIdentity {
		_ = targetRoot.Close()
		tree.close()
		return nil, errors.Join(
			fmt.Errorf("shared-parent removal root %s changed while pinning", path),
			openedErr, openedIdentityErr, currentErr, currentIdentityErr,
		)
	}
	tree.root = targetRoot
	tree.identity = openedIdentity
	hooks.afterTargetPinned()
	return tree, nil
}

func readBoundedSharedRemovalEntries(root *os.Root) ([]os.DirEntry, error) {
	if root == nil {
		return nil, fmt.Errorf("shared-parent removal root is unavailable")
	}
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := file.ReadDir(maximumRemovalStateEntries + 1)
	closeErr := file.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(fmt.Errorf("inventory shared-parent removal root"), readErr, closeErr)
	}
	if len(entries) > maximumRemovalStateEntries {
		return nil, fmt.Errorf("shared-parent removal root exceeds %d entries", maximumRemovalStateEntries)
	}
	return entries, nil
}

type sharedRemovalUnlink func(int, string, int) error

func removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
	path string,
	targetUID uint32,
	targetGID uint32,
	parentUID uint32,
	removeAll removalTreeOperator,
	unlink sharedRemovalUnlink,
	readMountInfo removalMountInfoReader,
	hooks sharedRemovalRaceHooks,
) error {
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("shared-parent removal root %q is not safe", path)
	}
	if removeAll == nil || unlink == nil {
		return fmt.Errorf("shared-parent removal operator is unavailable")
	}
	if err := preflightRemovalMountBoundariesAt([]string{path}, readMountInfo); err != nil {
		return err
	}
	tree, err := openPinnedSharedRemovalTree(path, targetUID, targetGID, parentUID, hooks)
	if err != nil {
		return err
	}
	defer tree.close()
	if tree.absent {
		return nil
	}

	entries, err := readBoundedSharedRemovalEntries(tree.root)
	if err != nil {
		return fmt.Errorf("inventory shared-parent product root %s: %w", path, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
			return fmt.Errorf("refusing invalid shared-parent product entry %q", name)
		}
		candidate := filepath.Join(path, name)
		if err := removeAll(tree.root, name, candidate); err != nil {
			return fmt.Errorf("remove shared-parent product entry %s: %w", candidate, err)
		}
		if _, err := tree.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return fmt.Errorf("verify shared-parent product entry absence %s: %w", candidate, err)
			}
			return fmt.Errorf("shared-parent product entry remains after removal: %s", candidate)
		}
	}
	confirmedEntries, err := readBoundedSharedRemovalEntries(tree.root)
	if err != nil {
		return fmt.Errorf("verify shared-parent product root inventory %s: %w", path, err)
	}
	if len(confirmedEntries) != 0 {
		return fmt.Errorf("shared-parent product root is not empty after removal: %s", path)
	}
	opened, err := tree.root.Stat(".")
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	current, currentErr := tree.parent.root.Lstat(tree.name)
	currentIdentity, currentIdentityErr := exactRemovalArtifactIdentity(current)
	if err != nil || identityErr != nil || currentErr != nil || currentIdentityErr != nil ||
		!samePinnedRemovalDirectoryIdentity(tree.identity, openedIdentity) ||
		!samePinnedRemovalDirectoryIdentity(openedIdentity, currentIdentity) {
		return errors.Join(
			fmt.Errorf("shared-parent removal root %s changed before final removal", path),
			err, identityErr, currentErr, currentIdentityErr,
		)
	}
	hooks = normalizeSharedRemovalRaceHooks(hooks)
	hooks.beforeFinalUnlink()
	current, currentErr = tree.parent.root.Lstat(tree.name)
	currentIdentity, currentIdentityErr = exactRemovalArtifactIdentity(current)
	if currentErr != nil || currentIdentityErr != nil ||
		!samePinnedRemovalDirectoryIdentity(tree.identity, currentIdentity) {
		return errors.Join(
			fmt.Errorf("shared-parent removal root %s changed at final boundary", path),
			currentErr, currentIdentityErr,
		)
	}
	// The shared parent may be group-writable. Never recurse from it: a final
	// rmdir can at worst reject a raced non-empty replacement and cannot erase
	// any replacement contents.
	if err := unlink(tree.parent.fd, tree.name, unix.AT_REMOVEDIR); err != nil {
		return fmt.Errorf("remove empty shared-parent product root %s: %w", path, err)
	}
	unlinked, unlinkedErr := tree.root.Stat(".")
	unlinkedIdentity, unlinkedIdentityErr := exactRemovalArtifactIdentity(unlinked)
	if unlinkedErr != nil || unlinkedIdentityErr != nil ||
		!samePinnedRemovalDirectoryIdentity(tree.identity, unlinkedIdentity) || unlinkedIdentity.nlink != 0 {
		return errors.Join(
			fmt.Errorf("shared-parent product root %s was not the directory removed at the final boundary", path),
			unlinkedErr, unlinkedIdentityErr,
		)
	}
	if err := tree.parent.sync(); err != nil {
		return fmt.Errorf("sync shared-parent product root removal %s: %w", path, err)
	}
	if _, err := tree.parent.root.Lstat(tree.name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify shared-parent product root absence %s: %w", path, err)
	}
	return fmt.Errorf("shared-parent product root remains after removal: %s", path)
}

func removeDedicatedProductLogTree() error {
	const path = "/var/log/syswarden"
	return removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
		path,
		0,
		0,
		0,
		func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
		unix.Unlinkat,
		readProcRemovalMountInfo,
		sharedRemovalRaceHooks{},
	)
}

func preflightDedicatedRemovalTree(path string) error {
	sentinel := errors.New("dedicated removal preflight boundary")
	err := removeDedicatedRemovalTreeAt(
		path,
		0,
		0,
		func(*os.Root, string, string) error { return sentinel },
	)
	if errors.Is(err, sentinel) {
		return nil
	}
	return err
}

func preflightDedicatedProductLogTree() error {
	sentinel := errors.New("shared-parent removal preflight boundary")
	err := removeDedicatedRemovalTreeFromSharedParentAtUsingMountInfo(
		"/var/log/syswarden",
		0,
		0,
		0,
		func(*os.Root, string, string) error { return sentinel },
		func(int, string, int) error { return sentinel },
		readProcRemovalMountInfo,
		sharedRemovalRaceHooks{},
	)
	if errors.Is(err, sentinel) {
		return nil
	}
	return err
}

func preflightHostProductRemovalArtifacts() error {
	for _, path := range []string{"/opt/syswarden", "/etc/syswarden"} {
		if err := preflightDedicatedRemovalTree(path); err != nil {
			return fmt.Errorf("preflight dedicated product root %s: %w", path, err)
		}
	}
	if err := preflightDedicatedProductLogTree(); err != nil {
		return fmt.Errorf("preflight shared product log root: %w", err)
	}
	for _, link := range []struct {
		path   string
		target string
	}{
		{"/usr/local/bin/syswarden", "/opt/syswarden/bin/syswarden-cli"},
		{"/usr/local/bin/syswarden-tui", "/opt/syswarden/bin/syswarden-tui"},
	} {
		if err := preflightExactProductSymlinkAt(link.path, link.target, 0, 0); err != nil {
			return fmt.Errorf("preflight exact product link %s: %w", link.path, err)
		}
	}
	return nil
}

func openAttestedRemovalParent(
	path string,
	expectedUID uint32,
	expectedGID uint32,
) (*pinnedServiceDirectory, error) {
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil {
		return nil, fmt.Errorf("inspect removal parent %s: %w", parentPath, err)
	}
	if parent.Mode()&os.ModeSymlink != 0 || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 ||
		!removalArtifactOwnedBy(parent, expectedUID, expectedGID) {
		return nil, fmt.Errorf("refusing unsafe removal parent %s", parentPath)
	}
	directory, err := openPinnedServiceDirectory(parentPath)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.root.Stat(".")
	if statErr != nil || !os.SameFile(parent, opened) {
		directory.close()
		return nil, errors.Join(fmt.Errorf("removal parent changed while pinning %s", parentPath), statErr)
	}
	return directory, nil
}

func removeDedicatedRemovalTreeAt(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	removeAll removalTreeOperator,
) error {
	return removeDedicatedRemovalTreeAtUsingMountInfo(
		path, expectedUID, expectedGID, removeAll, readProcRemovalMountInfo,
	)
}

func removeDedicatedRemovalTreeAtUsingMountInfo(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	removeAll removalTreeOperator,
	readMountInfo removalMountInfoReader,
) error {
	if removeAll == nil {
		return fmt.Errorf("dedicated removal operator is unavailable")
	}
	if path == "" || path == "/" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("dedicated removal root %q is not safe", path)
	}
	if err := preflightRemovalMountBoundariesAt([]string{path}, readMountInfo); err != nil {
		return err
	}
	parent, err := openAttestedRemovalParent(path, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer parent.close()
	name := filepath.Base(path)
	before, err := parent.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0022 != 0 ||
		!removalArtifactOwnedBy(before, expectedUID, expectedGID) {
		return fmt.Errorf("refusing unsafe dedicated removal root %s", path)
	}
	confirmed, err := parent.root.Lstat(name)
	if err != nil || !os.SameFile(before, confirmed) || before.Mode() != confirmed.Mode() {
		return errors.Join(fmt.Errorf("dedicated removal root %s changed before deletion", path), err)
	}
	if err := removeAll(parent.root, name, path); err != nil {
		return fmt.Errorf("remove dedicated product root %s: %w", path, err)
	}
	if _, err := parent.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify dedicated product root absence %s: %w", path, err)
	}
	return fmt.Errorf("dedicated product root remains after removal: %s", path)
}

func removeDedicatedRemovalTree(path string) error {
	return removeDedicatedRemovalTreeAt(
		path, 0, 0,
		func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
	)
}

type attestedProductSymlink struct {
	parent *pinnedServiceDirectory
	name   string
	absent bool
}

func openAttestedProductSymlink(
	path string,
	expectedTarget string,
	expectedUID uint32,
	expectedGID uint32,
) (*attestedProductSymlink, error) {
	if path == "" || expectedTarget == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!filepath.IsAbs(expectedTarget) || filepath.Clean(expectedTarget) != expectedTarget {
		return nil, fmt.Errorf("product symlink removal request is not clean and absolute")
	}
	parent, err := openAttestedRemovalParent(path, expectedUID, expectedGID)
	if err != nil {
		return nil, err
	}
	link := &attestedProductSymlink{parent: parent, name: filepath.Base(path)}
	before, err := parent.root.Lstat(link.name)
	if errors.Is(err, os.ErrNotExist) {
		link.absent = true
		return link, nil
	}
	if err != nil {
		parent.close()
		return nil, fmt.Errorf("inspect product symlink %s: %w", path, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 {
		parent.close()
		return nil, fmt.Errorf("refusing non-attributable product link %s", path)
	}
	target, err := parent.root.Readlink(link.name)
	if err != nil || target != expectedTarget {
		parent.close()
		return nil, errors.Join(fmt.Errorf("refusing unexpected product link target %q for %s", target, path), err)
	}
	after, err := parent.root.Lstat(link.name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		parent.close()
		return nil, errors.Join(fmt.Errorf("product link %s changed during attestation", path), err)
	}
	return link, nil
}

func preflightExactProductSymlinkAt(
	path string,
	expectedTarget string,
	expectedUID uint32,
	expectedGID uint32,
) error {
	link, err := openAttestedProductSymlink(path, expectedTarget, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	link.parent.close()
	return nil
}

func removeExactProductSymlinkAt(
	path string,
	expectedTarget string,
	expectedUID uint32,
	expectedGID uint32,
) error {
	link, err := openAttestedProductSymlink(path, expectedTarget, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer link.parent.close()
	if link.absent {
		return nil
	}
	if err := link.parent.root.Remove(link.name); err != nil {
		return fmt.Errorf("remove exact product link %s: %w", path, err)
	}
	if _, err := link.parent.root.Lstat(link.name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify product link absence %s: %w", path, err)
	}
	return fmt.Errorf("product link remains after removal: %s", path)
}

func removeExactRuntimeSocketAt(path string, expectedUID, expectedGID uint32) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("runtime socket removal path is not clean and absolute")
	}
	parent, err := openAttestedRemovalParent(path, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer parent.close()
	name := filepath.Base(path)
	before, err := parent.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect runtime socket %s: %w", path, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || before.Mode()&os.ModeSocket == 0 ||
		stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 {
		return fmt.Errorf("refusing non-attributable runtime socket %s", path)
	}
	confirmed, err := parent.root.Lstat(name)
	if err != nil || !os.SameFile(before, confirmed) || before.Mode() != confirmed.Mode() {
		return errors.Join(fmt.Errorf("runtime socket %s changed during attestation", path), err)
	}
	if err := parent.root.Remove(name); err != nil {
		return fmt.Errorf("remove exact runtime socket %s: %w", path, err)
	}
	if _, err := parent.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify runtime socket absence %s: %w", path, err)
	}
	return fmt.Errorf("runtime socket remains after removal: %s", path)
}

// RemoveExactRuntimeSocketForPackageRemoval removes only the root-owned,
// single-link Unix socket used by the stopped SysWarden core. Package removal
// calls this only after every rsyslog producer has been restarted without the
// SysWarden bridge and before the matching SELinux policy is removed.
func RemoveExactRuntimeSocketForPackageRemoval() error {
	return removeExactRuntimeSocketForPackageRemovalUsing(removeExactRuntimeSocketAt)
}

func removeExactRuntimeSocketForPackageRemovalUsing(
	remove func(string, uint32, uint32) error,
) error {
	if remove == nil {
		return fmt.Errorf("runtime socket removal operator is unavailable")
	}
	for _, path := range []string{"/run/syswarden.sock", "/run/syswarden-control.sock"} {
		if err := remove(path, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

// AttestRuntimeSocketAbsentForPackageRemoval provides the read-only half of the
// exact socket contract. It is used only to accept an already-complete removal
// retry while the service-manager runtime is offline.
func AttestRuntimeSocketAbsentForPackageRemoval() error {
	for _, path := range []string{"/run/syswarden.sock", "/run/syswarden-control.sock"} {
		if err := attestRuntimeSocketAbsentAt(path, 0, 0); err != nil {
			return err
		}
	}
	return nil
}

func attestRuntimeSocketAbsentAt(path string, expectedUID, expectedGID uint32) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("runtime socket absence path is not clean and absolute")
	}
	parent, err := openAttestedRemovalParent(path, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer parent.close()
	if _, err := parent.root.Lstat(filepath.Base(path)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("attest runtime socket absence %s: %w", path, err)
	}
	return fmt.Errorf("runtime socket teardown target remains at %s", path)
}

func removeRemovalStateContentsAt(
	directoryPath string,
	expectedUID uint32,
	expectedGID uint32,
	removeAll removalTreeOperator,
) error {
	return removeRemovalStateContentsAtUsingMountInfo(
		directoryPath, expectedUID, expectedGID, removeAll, readProcRemovalMountInfo,
	)
}

func removeRemovalStateContentsAtUsingMountInfo(
	directoryPath string,
	expectedUID uint32,
	expectedGID uint32,
	removeAll removalTreeOperator,
	readMountInfo removalMountInfoReader,
) error {
	if removeAll == nil {
		return fmt.Errorf("removal state operator is unavailable")
	}
	if err := preflightRemovalMountBoundariesAt([]string{directoryPath}, readMountInfo); err != nil {
		return err
	}
	directory, err := openExistingRemovalStateDirectory(directoryPath, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
		return err
	}
	entries, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		return fmt.Errorf("inventory product state before removal: %w", err)
	}
	for _, entry := range entries {
		if entry.Name() == removalTombstoneName {
			continue
		}
		if entry.Name() == "" || filepath.Base(entry.Name()) != entry.Name() || entry.Name() == "." || entry.Name() == ".." {
			return fmt.Errorf("refusing invalid product state entry %q", entry.Name())
		}
		path := filepath.Join(directoryPath, entry.Name())
		if err := removeAll(directory.root, entry.Name(), path); err != nil {
			return fmt.Errorf("remove product state entry %s: %w", path, err)
		}
		if _, err := directory.root.Lstat(entry.Name()); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return fmt.Errorf("verify product state entry absence %s: %w", path, err)
			}
			return fmt.Errorf("product state entry remains after removal: %s", path)
		}
	}
	if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
		return fmt.Errorf("reattest retained removal tombstone: %w", err)
	}
	confirmed, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		return fmt.Errorf("verify product state inventory: %w", err)
	}
	if len(confirmed) != 1 || confirmed[0].Name() != removalTombstoneName {
		return fmt.Errorf("product state residual remains beside removal tombstone")
	}
	return nil
}

func removeRemovalStateContents() error {
	return removeRemovalStateContentsAt(
		filepath.Dir(RemovalTombstonePath), 0, 0,
		func(root *os.Root, name string, _ string) error { return root.RemoveAll(name) },
	)
}
