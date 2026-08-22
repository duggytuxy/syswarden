//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const (
	RemovalTombstonePath   = "/var/lib/syswarden/removal-in-progress-v1"
	RemovalTombstoneRecord = "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"

	removalTombstoneName       = "removal-in-progress-v1"
	maximumRemovalStateEntries = 131072
)

func removalArtifactOwnedBy(info os.FileInfo, expectedUID, expectedGID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == expectedUID && stat.Gid == expectedGID
}

func attestRemovalTombstone(
	directory *pinnedServiceDirectory,
	expectedUID uint32,
	expectedGID uint32,
) (os.FileInfo, error) {
	if directory == nil || directory.root == nil {
		return nil, fmt.Errorf("removal tombstone directory is unavailable")
	}
	before, err := directory.root.Lstat(removalTombstoneName)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm() != 0600 || stat.Uid != expectedUID || stat.Gid != expectedGID || stat.Nlink != 1 ||
		before.Size() != int64(len(RemovalTombstoneRecord)) {
		return nil, fmt.Errorf("refusing unsafe or modified removal tombstone")
	}
	file, err := directory.root.Open(removalTombstoneName)
	if err != nil {
		return nil, fmt.Errorf("open removal tombstone: %w", err)
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(RemovalTombstoneRecord)+1)))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) {
		return nil, errors.Join(
			fmt.Errorf("removal tombstone changed while reading"),
			statErr,
			readErr,
			closeErr,
		)
	}
	after, err := directory.root.Lstat(removalTombstoneName)
	if err != nil || !os.SameFile(opened, after) || opened.Mode() != after.Mode() ||
		string(content) != RemovalTombstoneRecord {
		return nil, errors.Join(fmt.Errorf("removal tombstone changed during attestation"), err)
	}
	return after, nil
}

func openExistingRemovalStateDirectory(path string, expectedUID, expectedGID uint32) (*pinnedServiceDirectory, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("removal state directory is not clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 ||
		!removalArtifactOwnedBy(info, expectedUID, expectedGID) {
		return nil, fmt.Errorf("refusing unsafe removal state directory %s", path)
	}
	directory, err := openPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.root.Stat(".")
	if statErr != nil || !os.SameFile(info, opened) {
		directory.close()
		return nil, errors.Join(fmt.Errorf("removal state directory changed while pinning"), statErr)
	}
	return directory, nil
}

func ensureRemovalTombstoneAt(path string, expectedUID, expectedGID uint32) error {
	if filepath.Base(path) != removalTombstoneName || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("removal tombstone path is not the fixed clean absolute path")
	}
	directoryPath := filepath.Dir(path)
	if err := ensureServiceDirectory(directoryPath, 0750); err != nil {
		return fmt.Errorf("prepare removal state directory: %w", err)
	}
	if _, err := publishExactServiceFile(path, RemovalTombstoneRecord, 0600); err != nil {
		return fmt.Errorf("publish removal tombstone atomically: %w", err)
	}
	directory, err := openExistingRemovalStateDirectory(directoryPath, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
		return fmt.Errorf("attest published removal tombstone: %w", err)
	}
	return nil
}

func inspectRemovalTombstoneAt(path string, expectedUID, expectedGID uint32) (bool, error) {
	if filepath.Base(path) != removalTombstoneName || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false, fmt.Errorf("removal tombstone path is not the fixed clean absolute path")
	}
	directoryPath := filepath.Dir(path)
	if _, err := os.Lstat(directoryPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, fmt.Errorf("inspect removal state directory: %w", err)
	}
	directory, err := openExistingRemovalStateDirectory(directoryPath, expectedUID, expectedGID)
	if err != nil {
		return true, err
	}
	defer directory.close()
	if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

// BeginRemoval publishes the durable host-removal barrier. An exact existing
// record makes the operation resumable; any modified record fails closed.
func BeginRemoval() error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("removal preparation must be executed as root")
	}
	return ensureRemovalTombstoneAt(RemovalTombstonePath, 0, 0)
}

// InspectRemovalTombstone reports whether the durable removal barrier exists.
// A present but unsafe or modified record is reported as present with an error.
func InspectRemovalTombstone() (bool, error) {
	return inspectRemovalTombstoneAt(RemovalTombstonePath, 0, 0)
}

// RequireRemovalTombstone prevents the destructive host tail from being
// invoked without the durable barrier created by BeginRemoval.
func RequireRemovalTombstone() error {
	present, err := InspectRemovalTombstone()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("removal tombstone is absent")
	}
	return nil
}

func verifyRemovalExecutablesAbsent(paths []string) error {
	for _, path := range paths {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("removal executable path %q is not clean and absolute", path)
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return fmt.Errorf("verify removal executable absence %s: %w", path, err)
		}
		return fmt.Errorf("removal executable path remains present: %s", path)
	}
	return nil
}

func restoreRemovalTombstone(path string, expectedUID, expectedGID uint32, cause error) error {
	restoreErr := ensureRemovalTombstoneAt(path, expectedUID, expectedGID)
	if restoreErr != nil {
		return errors.Join(cause, fmt.Errorf("restore removal tombstone after finalization failure: %w", restoreErr))
	}
	return cause
}

func readBoundedRemovalDirectory(directory *pinnedServiceDirectory) ([]os.DirEntry, error) {
	if directory == nil || directory.root == nil {
		return nil, fmt.Errorf("removal state directory is unavailable")
	}
	before, err := directory.root.Stat(".")
	if err != nil {
		return nil, err
	}
	file, err := directory.root.Open(".")
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	entries, readErr := file.ReadDir(maximumRemovalStateEntries + 1)
	closeErr := file.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	after, afterErr := directory.root.Stat(".")
	if statErr != nil || readErr != nil || closeErr != nil || afterErr != nil ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		return nil, errors.Join(
			fmt.Errorf("removal state directory changed during inventory"),
			statErr,
			readErr,
			closeErr,
			afterErr,
		)
	}
	if len(entries) > maximumRemovalStateEntries {
		return nil, fmt.Errorf("removal state directory exceeds %d entries", maximumRemovalStateEntries)
	}
	return entries, nil
}

func finalizeRemovalTombstoneAt(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	executablePaths []string,
) error {
	if err := verifyRemovalExecutablesAbsent(executablePaths); err != nil {
		return err
	}
	directoryPath := filepath.Dir(path)
	directory, err := openExistingRemovalStateDirectory(directoryPath, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	stateInfo, err := directory.root.Stat(".")
	if err != nil {
		directory.close()
		return fmt.Errorf("attest removal state directory before finalization: %w", err)
	}
	if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
		directory.close()
		return err
	}
	entries, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		directory.close()
		return fmt.Errorf("inventory removal state directory: %w", err)
	}
	if len(entries) != 1 || entries[0].Name() != removalTombstoneName {
		directory.close()
		return fmt.Errorf("removal state directory contains residual entries")
	}
	if err := directory.root.Remove(removalTombstoneName); err != nil {
		directory.close()
		return fmt.Errorf("remove exact removal tombstone: %w", err)
	}
	if err := directory.sync(); err != nil {
		directory.close()
		return restoreRemovalTombstone(
			path, expectedUID, expectedGID,
			fmt.Errorf("sync removal tombstone deletion: %w", err),
		)
	}
	directory.close()

	parent, err := openPinnedServiceDirectory(filepath.Dir(directoryPath))
	if err != nil {
		return restoreRemovalTombstone(path, expectedUID, expectedGID, err)
	}
	defer parent.close()
	current, err := parent.root.Lstat(filepath.Base(directoryPath))
	if err != nil || !os.SameFile(stateInfo, current) {
		return restoreRemovalTombstone(
			path, expectedUID, expectedGID,
			errors.Join(fmt.Errorf("removal state directory changed before final deletion"), err),
		)
	}
	if err := parent.root.Remove(filepath.Base(directoryPath)); err != nil {
		return restoreRemovalTombstone(
			path, expectedUID, expectedGID,
			fmt.Errorf("remove empty removal state directory: %w", err),
		)
	}
	if err := parent.sync(); err != nil {
		return restoreRemovalTombstone(
			path, expectedUID, expectedGID,
			fmt.Errorf("sync removal state directory deletion: %w", err),
		)
	}
	if _, err := os.Lstat(directoryPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return restoreRemovalTombstone(
			path, expectedUID, expectedGID,
			fmt.Errorf("verify removal state directory absence: %w", err),
		)
	}
	return restoreRemovalTombstone(
		path, expectedUID, expectedGID,
		fmt.Errorf("removal state directory remains after deletion"),
	)
}

// FinalizeRemovalTombstone removes the barrier only after all product binary
// paths and every other entry in the product state root are absent.
func FinalizeRemovalTombstone() error {
	return finalizeRemovalTombstoneAt(
		RemovalTombstonePath,
		0,
		0,
		[]string{
			"/opt/syswarden/bin/syswarden-cli",
			"/opt/syswarden/bin/syswarden-core",
			"/opt/syswarden/bin/syswarden-tui",
		},
	)
}
