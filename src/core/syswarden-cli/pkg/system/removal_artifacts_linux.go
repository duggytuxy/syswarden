//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type removalTreeOperator func(*os.Root, string, string) error

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

func removeExactProductSymlinkAt(
	path string,
	expectedTarget string,
	expectedUID uint32,
	expectedGID uint32,
) error {
	if path == "" || expectedTarget == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		!filepath.IsAbs(expectedTarget) || filepath.Clean(expectedTarget) != expectedTarget {
		return fmt.Errorf("product symlink removal request is not clean and absolute")
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
		return fmt.Errorf("inspect product symlink %s: %w", path, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 {
		return fmt.Errorf("refusing non-attributable product link %s", path)
	}
	target, err := parent.root.Readlink(name)
	if err != nil || target != expectedTarget {
		return errors.Join(fmt.Errorf("refusing unexpected product link target %q for %s", target, path), err)
	}
	after, err := parent.root.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return errors.Join(fmt.Errorf("product link %s changed during attestation", path), err)
	}
	if err := parent.root.Remove(name); err != nil {
		return fmt.Errorf("remove exact product link %s: %w", path, err)
	}
	if _, err := parent.root.Lstat(name); errors.Is(err, os.ErrNotExist) {
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
