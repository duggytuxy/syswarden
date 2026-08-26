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

const (
	RemovalTombstonePath    = "/var/lib/syswarden/removal-in-progress-v1"
	RemovalTombstoneRecord  = "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
	RemovalFinalizingPath   = "/var/lib/.syswarden-removal-finalizing-v1"
	RemovalFinalizingRecord = RemovalTombstoneRecord

	removalTombstoneName       = "removal-in-progress-v1"
	removalFinalizingName      = ".syswarden-removal-finalizing-v1"
	maximumRemovalStateEntries = 131072
)

type removalArtifactIdentity struct {
	dev, ino, nlink uint64
	size            int64
	mode, uid, gid  uint32
	mtime, ctime    syscall.Timespec
}

func exactRemovalArtifactIdentity(info os.FileInfo) (removalArtifactIdentity, error) {
	if info == nil {
		return removalArtifactIdentity{}, fmt.Errorf("removal artifact metadata is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return removalArtifactIdentity{}, fmt.Errorf("removal artifact has unsupported metadata")
	}
	return removalArtifactIdentity{
		dev:   uint64(stat.Dev),
		ino:   uint64(stat.Ino),
		nlink: uint64(stat.Nlink),
		size:  stat.Size,
		mode:  stat.Mode,
		uid:   stat.Uid,
		gid:   stat.Gid,
		mtime: stat.Mtim,
		ctime: stat.Ctim,
	}, nil
}

func sameMovedRemovalArtifactIdentity(left, right removalArtifactIdentity) bool {
	left.ctime = syscall.Timespec{}
	right.ctime = syscall.Timespec{}
	return left == right
}

func removalArtifactOwnedBy(info os.FileInfo, expectedUID, expectedGID uint32) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == expectedUID && stat.Gid == expectedGID
}

func attestRemovalTombstone(
	directory *pinnedServiceDirectory,
	expectedUID uint32,
	expectedGID uint32,
) (os.FileInfo, error) {
	return attestExactRemovalRecord(
		directory,
		removalTombstoneName,
		RemovalTombstoneRecord,
		expectedUID,
		expectedGID,
	)
}

func attestExactRemovalRecord(
	directory *pinnedServiceDirectory,
	name, record string,
	expectedUID uint32,
	expectedGID uint32,
) (os.FileInfo, error) {
	return attestExactRemovalRecordUsing(
		directory, name, record, expectedUID, expectedGID, func() {},
	)
}

func attestExactRemovalRecordUsing(
	directory *pinnedServiceDirectory,
	name, record string,
	expectedUID uint32,
	expectedGID uint32,
	afterInitialSnapshot func(),
) (os.FileInfo, error) {
	if directory == nil || directory.root == nil {
		return nil, fmt.Errorf("removal record directory is unavailable")
	}
	if afterInitialSnapshot == nil {
		return nil, fmt.Errorf("removal record attestation boundary is unavailable")
	}
	before, err := directory.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	beforeIdentity, err := exactRemovalArtifactIdentity(before)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode().Perm() != 0600 || beforeIdentity.uid != expectedUID || beforeIdentity.gid != expectedGID ||
		beforeIdentity.nlink != 1 || beforeIdentity.size != int64(len(record)) {
		return nil, fmt.Errorf("refusing unsafe or modified removal record %s", name)
	}
	afterInitialSnapshot()
	file, err := directory.root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open removal record %s: %w", name, err)
	}
	opened, statErr := file.Stat()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(record)+1)))
	closeErr := file.Close()
	if statErr != nil || identityErr != nil || readErr != nil || closeErr != nil ||
		beforeIdentity != openedIdentity {
		return nil, errors.Join(
			fmt.Errorf("removal record %s changed while reading", name),
			statErr,
			identityErr,
			readErr,
			closeErr,
		)
	}
	after, err := directory.root.Lstat(name)
	afterIdentity, afterIdentityErr := exactRemovalArtifactIdentity(after)
	if err != nil || afterIdentityErr != nil || openedIdentity != afterIdentity || string(content) != record {
		return nil, errors.Join(
			fmt.Errorf("removal record %s changed during attestation", name),
			err,
			afterIdentityErr,
		)
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
	beforeIdentity, err := exactRemovalArtifactIdentity(info)
	if err != nil {
		return nil, err
	}
	directory, err := openPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	opened, statErr := directory.root.Stat(".")
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	if statErr != nil || identityErr != nil || beforeIdentity != openedIdentity {
		directory.close()
		return nil, errors.Join(
			fmt.Errorf("removal state directory changed while pinning"), statErr, identityErr,
		)
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

func removalFinalizingPathFor(tombstonePath string) string {
	return filepath.Join(filepath.Dir(filepath.Dir(tombstonePath)), removalFinalizingName)
}

func ensureRemovalFinalizingAt(path string, expectedUID, expectedGID uint32) error {
	if filepath.Base(path) != removalFinalizingName || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("removal finalizing path is not the fixed clean absolute path")
	}
	if _, err := publishExactServiceFile(path, RemovalFinalizingRecord, 0600); err != nil {
		return fmt.Errorf("publish removal finalizing barrier atomically: %w", err)
	}
	directory, err := openPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := attestExactRemovalRecord(
		directory, removalFinalizingName, RemovalFinalizingRecord, expectedUID, expectedGID,
	); err != nil {
		return fmt.Errorf("attest removal finalizing barrier: %w", err)
	}
	return nil
}

func inspectRemovalFinalizingAt(path string, expectedUID, expectedGID uint32) (bool, error) {
	if filepath.Base(path) != removalFinalizingName || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false, fmt.Errorf("removal finalizing path is not the fixed clean absolute path")
	}
	parentPath := filepath.Dir(path)
	if _, err := os.Lstat(parentPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, fmt.Errorf("inspect removal finalizing parent: %w", err)
	}
	directory, err := openPinnedServiceDirectory(parentPath)
	if err != nil {
		return true, err
	}
	defer directory.close()
	if _, err := attestExactRemovalRecord(
		directory, removalFinalizingName, RemovalFinalizingRecord, expectedUID, expectedGID,
	); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return true, err
	}
	return true, nil
}

func removeRemovalFinalizingAt(path string, expectedUID, expectedGID uint32) error {
	directory, err := openPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.close()
	if _, err := attestExactRemovalRecord(
		directory, removalFinalizingName, RemovalFinalizingRecord, expectedUID, expectedGID,
	); err != nil {
		return err
	}
	if err := directory.root.Remove(removalFinalizingName); err != nil {
		return fmt.Errorf("remove exact removal finalizing barrier: %w", err)
	}
	if err := directory.sync(); err != nil {
		return restoreRemovalFinalizing(
			path, expectedUID, expectedGID,
			fmt.Errorf("sync removal finalizing barrier deletion: %w", err),
		)
	}
	if _, err := directory.root.Lstat(removalFinalizingName); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return restoreRemovalFinalizing(
			path, expectedUID, expectedGID,
			fmt.Errorf("verify removal finalizing barrier absence: %w", err),
		)
	}
	return restoreRemovalFinalizing(
		path, expectedUID, expectedGID,
		fmt.Errorf("removal finalizing barrier remains after deletion"),
	)
}

func restoreRemovalFinalizing(path string, expectedUID, expectedGID uint32, cause error) error {
	return errors.Join(
		cause,
		func() error {
			if err := ensureRemovalFinalizingAt(path, expectedUID, expectedGID); err != nil {
				return fmt.Errorf("restore removal finalizing barrier: %w", err)
			}
			return nil
		}(),
	)
}

func transitionRemovalTombstoneToFinalizing(
	directory *pinnedServiceDirectory,
	finalizingPath string,
	expectedUID uint32,
	expectedGID uint32,
	faultPoint func(string),
) error {
	if directory == nil || directory.root == nil || faultPoint == nil {
		return fmt.Errorf("removal finalizing transition is unavailable")
	}
	tombstone, err := attestRemovalTombstone(directory, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	tombstoneIdentity, err := exactRemovalArtifactIdentity(tombstone)
	if err != nil {
		return err
	}
	finalizingDirectory, err := openPinnedServiceDirectory(filepath.Dir(finalizingPath))
	if err != nil {
		return err
	}
	defer finalizingDirectory.close()
	if _, err := finalizingDirectory.root.Lstat(removalFinalizingName); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("inspect removal finalizing barrier before transition: %w", err)
		}
		return fmt.Errorf("removal finalizing barrier appeared concurrently")
	}
	if err := unix.Renameat2(
		directory.fd,
		removalTombstoneName,
		finalizingDirectory.fd,
		removalFinalizingName,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("move removal tombstone to external finalizing barrier: %w", err)
	}
	faultPoint("after-finalizing-rename")
	finalizing, err := attestExactRemovalRecord(
		finalizingDirectory,
		removalFinalizingName,
		RemovalFinalizingRecord,
		expectedUID,
		expectedGID,
	)
	finalizingIdentity, identityErr := exactRemovalArtifactIdentity(finalizing)
	if err != nil || identityErr != nil ||
		!sameMovedRemovalArtifactIdentity(tombstoneIdentity, finalizingIdentity) {
		return errors.Join(
			fmt.Errorf("external removal finalizing barrier failed moved-identity attestation"),
			err,
			identityErr,
		)
	}
	if err := finalizingDirectory.sync(); err != nil {
		return fmt.Errorf("sync external removal finalizing barrier publication: %w", err)
	}
	if err := directory.sync(); err != nil {
		return fmt.Errorf("sync internal removal tombstone retirement: %w", err)
	}
	return nil
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
	return inspectRemovalBarrierAt(RemovalTombstonePath, RemovalFinalizingPath, 0, 0)
}

func inspectRemovalBarrierAt(
	tombstonePath string,
	finalizingPath string,
	expectedUID uint32,
	expectedGID uint32,
) (bool, error) {
	return inspectRemovalBarrierAtUsing(
		tombstonePath, finalizingPath, expectedUID, expectedGID, func() error { return nil },
	)
}

func inspectRemovalBarrierAtUsing(
	tombstonePath string,
	finalizingPath string,
	expectedUID uint32,
	expectedGID uint32,
	afterInternalInspection func() error,
) (bool, error) {
	if afterInternalInspection == nil {
		return true, fmt.Errorf("removal barrier inspection boundary is unavailable")
	}
	// The finalization transition is one atomic rename from the internal source
	// to the external destination. Reading the source first guarantees that the
	// two observations cannot both miss that rename.
	tombstone, err := inspectRemovalTombstoneAt(tombstonePath, expectedUID, expectedGID)
	if err != nil {
		return true, err
	}
	if err := afterInternalInspection(); err != nil {
		return true, fmt.Errorf("removal barrier inspection boundary: %w", err)
	}
	finalizing, err := inspectRemovalFinalizingAt(finalizingPath, expectedUID, expectedGID)
	if err != nil {
		return true, err
	}
	return tombstone || finalizing, nil
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

func readBoundedRemovalDirectory(directory *pinnedServiceDirectory) ([]os.DirEntry, error) {
	if directory == nil || directory.root == nil {
		return nil, fmt.Errorf("removal state directory is unavailable")
	}
	before, err := directory.root.Stat(".")
	if err != nil {
		return nil, err
	}
	beforeIdentity, err := exactRemovalArtifactIdentity(before)
	if err != nil {
		return nil, err
	}
	file, err := directory.root.Open(".")
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	openedIdentity, openedIdentityErr := exactRemovalArtifactIdentity(opened)
	entries, readErr := file.ReadDir(maximumRemovalStateEntries + 1)
	closeErr := file.Close()
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	after, afterErr := directory.root.Stat(".")
	afterIdentity, afterIdentityErr := exactRemovalArtifactIdentity(after)
	if statErr != nil || openedIdentityErr != nil || readErr != nil || closeErr != nil || afterErr != nil ||
		afterIdentityErr != nil || beforeIdentity != openedIdentity || openedIdentity != afterIdentity {
		return nil, errors.Join(
			fmt.Errorf("removal state directory changed during inventory"),
			statErr,
			openedIdentityErr,
			readErr,
			closeErr,
			afterErr,
			afterIdentityErr,
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
	return finalizeRemovalTombstoneAtUsing(
		path, expectedUID, expectedGID, executablePaths, func(string) {},
	)
}

func finalizeRemovalTombstoneAtUsing(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	executablePaths []string,
	faultPoint func(string),
) error {
	if faultPoint == nil {
		return fmt.Errorf("removal finalization fault boundary is unavailable")
	}
	if err := verifyRemovalExecutablesAbsent(executablePaths); err != nil {
		return err
	}
	directoryPath := filepath.Dir(path)
	finalizingPath := removalFinalizingPathFor(path)
	finalizing, err := inspectRemovalFinalizingAt(finalizingPath, expectedUID, expectedGID)
	if err != nil {
		return fmt.Errorf("inspect removal finalizing barrier: %w", err)
	}
	if _, err := os.Lstat(directoryPath); errors.Is(err, os.ErrNotExist) {
		if !finalizing {
			return fmt.Errorf("removal state directory and finalizing barrier are absent")
		}
		return removeRemovalFinalizingAt(finalizingPath, expectedUID, expectedGID)
	} else if err != nil {
		return fmt.Errorf("inspect removal state directory before finalization: %w", err)
	}
	directory, err := openExistingRemovalStateDirectory(directoryPath, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	entries, err := readBoundedRemovalDirectory(directory)
	if err != nil {
		directory.close()
		return fmt.Errorf("inventory removal state directory: %w", err)
	}
	tombstonePresent := len(entries) == 1 && entries[0].Name() == removalTombstoneName
	if (!finalizing && !tombstonePresent) ||
		(finalizing && len(entries) != 0 && !tombstonePresent) {
		directory.close()
		return fmt.Errorf("removal state directory contains residual entries")
	}
	if tombstonePresent {
		if _, err := attestRemovalTombstone(directory, expectedUID, expectedGID); err != nil {
			directory.close()
			return err
		}
	}
	if !finalizing {
		if err := transitionRemovalTombstoneToFinalizing(
			directory,
			finalizingPath,
			expectedUID,
			expectedGID,
			faultPoint,
		); err != nil {
			directory.close()
			return err
		}
		tombstonePresent = false
	}
	faultPoint("after-finalizing-barrier")
	if tombstonePresent {
		if err := directory.root.Remove(removalTombstoneName); err != nil {
			directory.close()
			return fmt.Errorf("remove exact removal tombstone: %w", err)
		}
	}
	if err := directory.sync(); err != nil {
		directory.close()
		return fmt.Errorf("sync removal tombstone deletion: %w", err)
	}
	faultPoint("after-internal-tombstone")
	stateInfo, err := directory.root.Stat(".")
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode().Perm()&0022 != 0 ||
		!removalArtifactOwnedBy(stateInfo, expectedUID, expectedGID) {
		directory.close()
		return errors.Join(fmt.Errorf("reattest safe removal state root before final deletion"), err)
	}
	stateIdentity, err := exactRemovalArtifactIdentity(stateInfo)
	if err != nil {
		directory.close()
		return err
	}
	directory.close()
	faultPoint("before-state-root-recheck")

	parent, err := openPinnedServiceDirectory(filepath.Dir(directoryPath))
	if err != nil {
		return err
	}
	defer parent.close()
	current, err := parent.root.Lstat(filepath.Base(directoryPath))
	currentIdentity, identityErr := exactRemovalArtifactIdentity(current)
	if err != nil || identityErr != nil || stateIdentity != currentIdentity {
		return errors.Join(
			fmt.Errorf("removal state directory changed before final deletion"), err, identityErr,
		)
	}
	if err := parent.root.Remove(filepath.Base(directoryPath)); err != nil {
		return fmt.Errorf("remove empty removal state directory: %w", err)
	}
	if err := parent.sync(); err != nil {
		return fmt.Errorf("sync removal state directory deletion: %w", err)
	}
	faultPoint("after-state-directory")
	if _, err := os.Lstat(directoryPath); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("verify removal state directory absence: %w", err)
		}
		return fmt.Errorf("removal state directory remains after deletion")
	}
	return removeRemovalFinalizingAt(finalizingPath, expectedUID, expectedGID)
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
