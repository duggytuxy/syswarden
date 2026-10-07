//go:build linux

package system

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"syswarden-cli/pkg/runtimehistory"

	"golang.org/x/sys/unix"
)

const runtimeHistoryName = "runtime-lifecycle"

type retainedDirectorySnapshot struct {
	directory removalArtifactIdentity
	files     map[string]removalArtifactIdentity
	content   map[string][]byte
	digest    string
}

func attestRuntimeHistoryContents(content map[string][]byte) (string, error) {
	snapshot, err := runtimehistory.DecodeQuiescent(content["state.json"], content["anchor.json"], content["intent.slot"])
	if err != nil {
		return "", err
	}
	return snapshot.StateSHA256, nil
}

func inspectRuntimeHistory(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
	result := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	info, err := directory.root.Stat(".")
	if err != nil {
		return result, err
	}
	result.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !serviceFileOwnedByCurrentUser(info) {
		return result, fmt.Errorf("runtime history directory must be private and owner controlled")
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	if err != nil {
		return result, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"anchor.json", "intent.slot", "state.json"}) {
		return result, fmt.Errorf("runtime history contains missing, additional or pending artifacts; preserve it for verified recovery")
	}
	for _, name := range names {
		before, err := directory.root.Lstat(name)
		if err != nil {
			return result, err
		}
		if before.Mode().Perm() != 0600 {
			return result, fmt.Errorf("runtime history file is not private")
		}
		limit := int64(4096)
		if name == "state.json" {
			limit = runtimehistory.MaximumStateBytes
		}
		content, err := readRetirementCandidateBounded(directory, name, before, limit)
		if err != nil {
			return result, err
		}
		result.files[name], err = exactRemovalArtifactIdentity(before)
		if err != nil {
			return result, err
		}
		result.content[name] = content
	}
	result.digest, err = attestRuntimeHistoryContents(result.content)
	if err != nil {
		return result, err
	}
	after, err := directory.root.Stat(".")
	actual, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != result.directory {
		return result, fmt.Errorf("runtime history inventory changed during inspection")
	}
	return result, nil
}

func sameRetainedDirectorySnapshot(left, right retainedDirectorySnapshot, moved bool) bool {
	sameDirectory := left.directory == right.directory
	if moved {
		sameDirectory = sameMovedRemovalArtifactIdentity(left.directory, right.directory)
	}
	if !sameDirectory || left.digest != right.digest || len(left.files) != len(right.files) {
		return false
	}
	for name, identity := range left.files {
		if right.files[name] != identity || !bytes.Equal(left.content[name], right.content[name]) {
			return false
		}
	}
	return true
}

// RetireRuntimeHistoryForRemoval preserves the complete original inode tree
// after independently verified kernel absence. It never creates missing
// history, rewrites consumed intent or accepts an outstanding mutation.
func RetireRuntimeHistoryForRemoval(verifyRuntimeAbsent func() error) error {
	if verifyRuntimeAbsent == nil {
		return fmt.Errorf("runtime history retirement requires independent kernel absence verification")
	}
	guard := func() error {
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		if err := preflightHostRemovalMountBoundaries(); err != nil {
			return err
		}
		root, err := os.OpenRoot("/")
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()
		for _, path := range []string{"/var/lib/syswarden/runtime-lifecycle/state.json", "/var/backups/syswarden-retired-v1/runtime-history"} {
			if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
				return err
			}
		}
		if err := ReattestFirewallStatePreparedForRemoval(); err != nil {
			return err
		}
		return verifyRuntimeAbsent()
	}
	backup, err := retireRuntimeHistory("/var/lib/syswarden", "/var/backups", guard, unix.Renameat2)
	if err == nil && backup != "" {
		fmt.Printf("[INFO] Retained exact quiescent runtime history in private recovery backup: %s\n", backup)
	}
	return err
}

func retireRuntimeHistory(parentPath, backupParentPath string, guard func() error, rename serviceArtifactRename) (string, error) {
	return retireAttestedDirectory(parentPath, runtimeHistoryName, backupParentPath, "runtime-history", guard, inspectRuntimeHistory, rename)
}
func retireAttestedDirectory(parentPath, sourceName, backupParentPath, backupKind string, guard func() error, inspect func(*pinnedServiceDirectory) (retainedDirectorySnapshot, error), rename serviceArtifactRename) (string, error) {
	if guard == nil || rename == nil || inspect == nil || filepath.Base(sourceName) != sourceName || sourceName == "." || sourceName == ".." || sourceName == "" || backupKind != "runtime-history" && backupKind != "product-logs" && backupKind != "legacy-logs" && backupKind != "legacy-lists" && backupKind != "legacy-ui" && backupKind != "generated-lists" && backupKind != "ui-snapshots" && backupKind != "standalone-payload" {
		return "", fmt.Errorf("owned directory retirement requires complete guards")
	}
	if err := guard(); err != nil {
		return "", err
	}

	parentInfo, err := os.Lstat(parentPath)
	if err != nil {
		return "", err
	}
	owner, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int64(owner.Uid) != int64(os.Geteuid()) {
		return "", fmt.Errorf("owned directory parent has an unexpected owner")
	}
	parent, err := openPinnedSharedRemovalParent(parentPath, owner.Uid)
	if err != nil {
		return "", err
	}
	defer parent.close()
	named, err := parent.root.Lstat(sourceName)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(parentPath, sourceName))
	if err != nil {
		return "", err
	}
	defer directory.close()
	// The caller quiesces writers. This lease also excludes cooperating stores.
	if err := syscall.Flock(directory.fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", fmt.Errorf("owned directory still has an active owner: %w", err)
	}
	defer func() { _ = syscall.Flock(directory.fd, syscall.LOCK_UN) }()
	before, err := inspect(directory)
	if err != nil {
		return "", err
	}
	namedIdentity, err := exactRemovalArtifactIdentity(named)
	if err != nil || namedIdentity != before.directory {
		return "", fmt.Errorf("owned directory directory changed while opening")
	}
	backupParent, err := openExistingPinnedServiceDirectory(backupParentPath)
	if err != nil {
		return "", err
	}
	defer backupParent.close()
	const backupRootName = "syswarden-retired-v1"
	if err := backupParent.root.Mkdir(backupRootName, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	backupPath := filepath.Join(backupParentPath, backupRootName)
	backupRoot, err := openExistingPinnedServiceDirectory(backupPath)
	if err != nil {
		return "", err
	}
	defer backupRoot.close()
	backupInfo, err := backupRoot.root.Stat(".")
	backupIdentity, identityErr := exactRemovalArtifactIdentity(backupInfo)
	if err != nil || identityErr != nil || backupInfo.Mode().Perm() != 0700 || backupIdentity.dev != before.directory.dev {
		return "", fmt.Errorf("owned directory backup must be private and on the same filesystem")
	}
	if err := backupParent.sync(); err != nil {
		return "", err
	}
	name := retainedDirectoryBackupName(backupKind, before)
	if err := guard(); err != nil {
		return "", err
	}
	checked, err := inspect(directory)
	if err != nil || !sameRetainedDirectorySnapshot(before, checked, false) {
		return "", errors.Join(fmt.Errorf("owned directory changed before retirement"), err)
	}
	current, err := parent.root.Lstat(sourceName)
	currentIdentity, identityErr := exactRemovalArtifactIdentity(current)
	if err != nil || identityErr != nil || currentIdentity != before.directory {
		return "", fmt.Errorf("owned directory path changed before retirement")
	}

	for path, pinned := range map[string]*pinnedServiceDirectory{parentPath: parent, backupParentPath: backupParent, backupPath: backupRoot} {
		if err := attestRetainedDirectoryParent(path, pinned, path == parentPath); err != nil {
			return "", err
		}
	}
	if err := rename(parent.fd, sourceName, backupRoot.fd, name, unix.RENAME_NOREPLACE); err != nil {
		return "", fmt.Errorf("retain owned directory without replacing any backup: %w", err)
	}
	moved, inspectErr := inspect(directory)
	saved, statErr := backupRoot.root.Lstat(name)
	savedIdentity, savedErr := exactRemovalArtifactIdentity(saved)
	if inspectErr != nil || statErr != nil || savedErr != nil || !sameRetainedDirectorySnapshot(before, moved, true) || savedIdentity != moved.directory {
		restoreErr := rename(backupRoot.fd, name, parent.fd, sourceName, unix.RENAME_NOREPLACE)
		return "", errors.Join(fmt.Errorf("owned directory changed during retirement; all bytes remain retained"), inspectErr, statErr, savedErr, restoreErr, parent.sync(), backupRoot.sync())
	}
	if err := errors.Join(backupRoot.sync(), parent.sync()); err != nil {
		return "", err
	}
	if _, err := parent.root.Lstat(sourceName); !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("owned directory reappeared after retirement")
	}

	if err := guard(); err != nil {
		return "", err
	}
	for path, pinned := range map[string]*pinnedServiceDirectory{parentPath: parent, backupParentPath: backupParent, backupPath: backupRoot} {
		if err := attestRetainedDirectoryParent(path, pinned, path == parentPath); err != nil {
			return "", err
		}
	}
	return filepath.Join(backupPath, name), nil
}

func runtimeHistoryBackupName(snapshot retainedDirectorySnapshot) string {
	return retainedDirectoryBackupName("runtime-history", snapshot)
}

func attestRetainedDirectoryParent(path string, directory *pinnedServiceDirectory, shared bool) error {
	named, err := os.Lstat(path)
	opened, openErr := directory.file.Stat()
	left, leftErr := exactRemovalArtifactIdentity(named)
	right, rightErr := exactRemovalArtifactIdentity(opened)
	unsafe := err != nil || openErr != nil || leftErr != nil || rightErr != nil
	if !unsafe {
		unsafe = !samePinnedRemovalDirectoryIdentity(left, right) || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || int64(left.uid) != int64(os.Geteuid()) || named.Mode().Perm()&0002 != 0
		if !shared {
			unsafe = unsafe || named.Mode().Perm()&0022 != 0 || !serviceFileOwnedByCurrentUser(named)
		}
	}
	if unsafe {
		return fmt.Errorf("runtime retirement parent changed identity: %s", path)
	}
	return nil
}

func retainedDirectoryBackupName(kind string, snapshot retainedDirectorySnapshot) string {
	return fmt.Sprintf("%s-%s-%x-%x", kind, snapshot.digest, snapshot.directory.dev, snapshot.directory.ino)
}
