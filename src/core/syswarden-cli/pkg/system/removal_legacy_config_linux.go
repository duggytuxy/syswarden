//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"syswarden-cli/config"

	"golang.org/x/sys/unix"
)

const legacyConfigDirectory = "/opt/syswarden"
const legacyConfigRetentionSchema = "syswarden-inactive-legacy-config-retention-v1"
const legacyConfigRetentionAuthority = "explicit-operator-confirmation-of-inactive-backup-with-no-other-consumer"

// These names bound the review surface; they confer no ownership. The active
// flat configuration and unfinished migration sources are deliberately excluded.
var inactiveLegacyConfigNames = []string{
	"syswarden-auto.conf.bak",
	"syswarden-auto.conf.migrated",
	"syswarden-auto.conf.migration_backup.migrated",
}

func inactiveLegacyConfigPath(path string) bool {
	return filepath.Dir(path) == legacyConfigDirectory && slices.Contains(inactiveLegacyConfigNames, filepath.Base(path))
}

func legacyConfigRetentionGuard() error {
	if err := config.CheckModularRetirementState("/etc/syswarden/config"); err != nil {
		return err
	}
	return legacyRetentionGuard(legacyRetentionProfile{directory: legacyConfigDirectory, backupKind: "legacy-config"})
}

func inspectLegacyConfigFile(directory *pinnedServiceDirectory, name string, syncData bool) (LegacyLogRetentionPlan, error) {
	plan := LegacyLogRetentionPlan{Schema: legacyConfigRetentionSchema, Directory: legacyConfigDirectory, Authority: legacyConfigRetentionAuthority}
	if !slices.Contains(inactiveLegacyConfigNames, name) {
		return plan, fmt.Errorf("unsupported inactive legacy configuration backup")
	}
	info, err := directory.root.Stat(".")
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if err != nil || identityErr != nil {
		return plan, errors.Join(err, identityErr)
	}
	plan.Identity = legacyLogPlanIdentity(identity)
	before, err := directory.root.Lstat(name)
	if err != nil {
		return plan, err
	}
	content, err := readRetirementCandidateBounded(directory, name, before, 1<<20)
	if err != nil || before.Mode().Perm() != 0600 {
		return plan, fmt.Errorf("inactive configuration backup requires an exclusive private bounded regular file: %q", name)
	}
	fileIdentity, err := exactRemovalArtifactIdentity(before)
	if err != nil || fileIdentity.dev != identity.dev {
		return plan, fmt.Errorf("inactive configuration backup crosses its directory filesystem")
	}
	if syncData {
		file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return plan, err
		}
		opened, statErr := file.Stat()
		openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
		if statErr != nil || identityErr != nil || openedIdentity != fileIdentity {
			_ = file.Close()
			return plan, fmt.Errorf("inactive configuration changed before synchronization")
		}
		if err := errors.Join(file.Sync(), file.Close()); err != nil {
			return plan, err
		}
		after, err := directory.root.Lstat(name)
		actual, identityErr := exactRemovalArtifactIdentity(after)
		if err != nil || identityErr != nil || actual != fileIdentity {
			return plan, fmt.Errorf("inactive configuration changed during synchronization")
		}
	}
	plan.Files = []LegacyLogRetentionFile{{Path: filepath.Join(legacyConfigDirectory, name), Identity: legacyLogPlanIdentity(fileIdentity), Size: fileIdentity.size, Modified: fileIdentity.mtime, Changed: fileIdentity.ctime, SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}}
	return plan, nil
}

// Review one backup at a time. Other product payload and administrator files
// remain untouched, including another inactive backup requiring its own review.
func inspectLegacyConfigRetention(directory *pinnedServiceDirectory) (LegacyLogRetentionPlan, error) {
	for _, name := range inactiveLegacyConfigNames {
		plan, err := inspectLegacyConfigFile(directory, name, false)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return plan, err
	}
	return LegacyLogRetentionPlan{}, fmt.Errorf("no supported inactive legacy configuration backup requires retention")
}

func InspectLegacyConfigRetention() (LegacyLogRetentionPlan, error) {
	if err := legacyConfigRetentionGuard(); err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	directory, err := openExistingPinnedServiceDirectory(legacyConfigDirectory)
	if err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	defer directory.close()
	plan, err := inspectLegacyConfigRetention(directory)
	if err != nil {
		return plan, err
	}
	return plan, errors.Join(attestRetainedDirectoryParent(legacyConfigDirectory, directory, false), legacyConfigRetentionGuard())
}

func ApplyLegacyConfigRetention(expected string) (LegacyLogRetentionPlan, string, error) {
	return applyLegacyConfigRetention(legacyConfigDirectory, "/var/backups", expected, legacyConfigRetentionGuard, unix.Renameat2)
}

func applyLegacyConfigRetention(directoryPath, backupParentPath, expected string, guard func() error, rename serviceArtifactRename) (LegacyLogRetentionPlan, string, error) {
	var plan LegacyLogRetentionPlan
	if len(expected) != 64 || strings.Trim(expected, "0123456789abcdef") != "" || guard == nil || rename == nil {
		return plan, "", fmt.Errorf("inactive configuration retention requires the exact reviewed lowercase SHA-256 and complete guards")
	}
	if err := guard(); err != nil {
		return plan, "", err
	}
	directory, err := openExistingPinnedServiceDirectory(directoryPath)
	if err != nil {
		return plan, "", err
	}
	defer directory.close()
	if err := unix.Flock(directory.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return plan, "", err
	}
	defer func() { _ = unix.Flock(directory.fd, unix.LOCK_UN) }()
	rootPath := filepath.Join(backupParentPath, "syswarden-retired-v1")
	backupPath := filepath.Join(rootPath, "legacy-config-"+expected)
	if saved, err := openExistingPinnedServiceDirectory(backupPath); err == nil {
		defer saved.close()
		return finishLegacyConfigRetention(directoryPath, directory, backupPath, saved, expected, guard, rename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return plan, "", err
	}
	plan, err = inspectLegacyConfigRetention(directory)
	if err != nil {
		return plan, "", err
	}
	digest, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil || digest != expected {
		return plan, "", fmt.Errorf("inactive configuration backup changed since review; inspect a new plan")
	}
	parent, err := openExistingPinnedServiceDirectory(backupParentPath)
	if err != nil {
		return plan, "", err
	}
	defer parent.close()
	if err := parent.root.Mkdir("syswarden-retired-v1", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return plan, "", err
	}
	root, err := openExistingPinnedServiceDirectory(rootPath)
	if err != nil {
		return plan, "", err
	}
	defer root.close()
	if err := attestLegacyConfigBackup(rootPath, root, plan.Identity.Device); err != nil {
		return plan, "", err
	}
	if err := root.root.Mkdir(filepath.Base(backupPath), 0700); err != nil {
		return plan, "", err
	}
	saved, err := openExistingPinnedServiceDirectory(backupPath)
	if err != nil {
		return plan, "", err
	}
	defer saved.close()
	wire, err := json.Marshal(plan)
	if err != nil {
		return plan, "", err
	}
	file, err := saved.root.OpenFile("plan.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return plan, "", err
	}
	_, writeErr := file.Write(wire)
	if err := errors.Join(writeErr, file.Sync(), file.Close(), saved.sync(), root.sync(), parent.sync()); err != nil {
		return plan, "", err
	}
	return finishLegacyConfigRetention(directoryPath, directory, backupPath, saved, expected, guard, rename)
}

func attestLegacyConfigBackup(path string, directory *pinnedServiceDirectory, device uint64) error {
	info, err := directory.root.Stat(".")
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if err != nil || identityErr != nil || info.Mode().Perm() != 0700 || identity.dev != device {
		return fmt.Errorf("inactive configuration backup must be private and on the original filesystem")
	}
	return attestRetainedDirectoryParent(path, directory, false)
}

func finishLegacyConfigRetention(directoryPath string, directory *pinnedServiceDirectory, backupPath string, saved *pinnedServiceDirectory, expected string, guard func() error, rename serviceArtifactRename) (LegacyLogRetentionPlan, string, error) {
	var plan LegacyLogRetentionPlan
	before, err := saved.root.Lstat("plan.json")
	if err != nil {
		return plan, "", err
	}
	wire, err := readRetirementCandidateBounded(saved, "plan.json", before, 16<<10)
	if err != nil || before.Mode().Perm() != 0600 || json.Unmarshal(wire, &plan) != nil {
		return plan, "", fmt.Errorf("inactive configuration backup lacks its exact private plan")
	}
	canonical, err := json.Marshal(plan)
	digest, digestErr := LegacyLogRetentionPlanSHA256(plan)
	if err != nil || digestErr != nil || string(canonical) != string(wire) || digest != expected ||
		plan.Schema != legacyConfigRetentionSchema || plan.Directory != legacyConfigDirectory || plan.Authority != legacyConfigRetentionAuthority ||
		len(plan.Files) != 1 || !inactiveLegacyConfigPath(plan.Files[0].Path) || plan.Files[0].CreationProvenance {
		return plan, "", fmt.Errorf("inactive configuration backup plan differs from the reviewed inventory")
	}
	name := filepath.Base(plan.Files[0].Path)
	inspect := func() (bool, error) {
		rootPath := filepath.Dir(backupPath)
		root, err := openExistingPinnedServiceDirectory(rootPath)
		if err != nil {
			return false, err
		}
		defer root.close()
		if err := errors.Join(attestLegacyConfigBackup(rootPath, root, plan.Identity.Device), attestLegacyConfigBackup(backupPath, saved, plan.Identity.Device), attestRetainedDirectoryParent(directoryPath, directory, false)); err != nil {
			return false, err
		}
		entries, err := readBoundedSharedRemovalEntries(saved.root)
		if err != nil || len(entries) < 1 || len(entries) > 2 {
			return false, fmt.Errorf("inactive configuration backup inventory changed")
		}
		archived := false
		for _, entry := range entries {
			if entry.Name() == name {
				archived = true
			} else if entry.Name() != "plan.json" {
				return false, fmt.Errorf("unrecognized inactive configuration backup entry")
			}
		}
		currentWire, err := readRetirementCandidateBounded(saved, "plan.json", before, 16<<10)
		if err != nil || string(currentWire) != string(wire) {
			return false, fmt.Errorf("inactive configuration plan changed during retention")
		}
		info, err := directory.root.Stat(".")
		id, identityErr := exactRemovalArtifactIdentity(info)
		if err != nil || identityErr != nil || legacyLogPlanIdentity(id) != plan.Identity {
			return false, fmt.Errorf("inactive configuration directory changed since review")
		}
		selected := directory
		if archived {
			if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return false, fmt.Errorf("inactive configuration source reappeared; preserve both copies for review")
			}
			selected = saved
		}
		actual, err := inspectLegacyConfigFile(selected, name, true)
		if err != nil {
			return false, err
		}
		if archived {
			// Same-inode rename changes ctime, but must preserve every other
			// reviewed field, including bytes, mtime, owner and permissions.
			actual.Files[0].Changed = plan.Files[0].Changed
		}
		if actual.Files[0] != plan.Files[0] {
			return false, fmt.Errorf("inactive configuration changed; retain all bytes for review")
		}
		return archived, nil
	}
	if err := guard(); err != nil {
		return plan, "", err
	}
	complete, err := inspect()
	if err != nil {
		return plan, "", err
	}
	if !complete {
		if err := rename(directory.fd, name, saved.fd, name, unix.RENAME_NOREPLACE); err != nil {
			return plan, "", err
		}
		complete, err = inspect()
		if err != nil || !complete {
			// Never overwrite a concurrently recreated source. A displaced
			// update remains at its original path when safe, or in the private
			// backup when both paths now exist. No bytes are deleted.
			restoreErr := rename(saved.fd, name, directory.fd, name, unix.RENAME_NOREPLACE)
			return plan, "", errors.Join(fmt.Errorf("inactive configuration changed during retention"), err, restoreErr, directory.sync(), saved.sync())
		}
	}
	if err := errors.Join(directory.sync(), saved.sync(), guard()); err != nil {
		return plan, "", err
	}
	complete, err = inspect()
	if err != nil || !complete {
		return plan, "", errors.Join(fmt.Errorf("inactive configuration retention verification failed"), err)
	}
	return plan, backupPath, nil
}
