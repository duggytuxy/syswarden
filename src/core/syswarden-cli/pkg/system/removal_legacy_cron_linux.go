//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/pkg/platformpaths"
	"time"

	"golang.org/x/sys/unix"
)

const legacyCronSpool = "/var/spool/cron/crontabs"

type LegacyCronRetirementPlan struct {
	Schema             string                     `json:"schema"`
	Directory          string                     `json:"directory"`
	DirectoryIdentity  LegacyLogRetentionIdentity `json:"directory_identity"`
	Original           LegacyLogRetentionFile     `json:"original"`
	ReplacementSHA256  string                     `json:"replacement_sha256"`
	RemovedLines       []int                      `json:"removed_lines"`
	StopsProduct       bool                       `json:"stops_product_services"`
	PreservesOtherJobs bool                       `json:"preserves_other_records_byte_for_byte"`
}

func LegacyCronRetirementPlanSHA256(plan LegacyCronRetirementPlan) (string, error) {
	wire, err := json.Marshal(plan)
	return fmt.Sprintf("%x", sha256.Sum256(wire)), err
}

func readLegacyCronFile(directory *pinnedServiceDirectory, name string, uid uint32) (removalArtifactIdentity, []byte, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return removalArtifactIdentity{}, nil, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 ||
		before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || identity.uid != uid || identity.nlink != 1 || identity.size < 0 || identity.size > 1<<20 {
		return identity, nil, fmt.Errorf("legacy root cron requires an exclusive private bounded regular file")
	}
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identity, nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	actual, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || actual != identity {
		return identity, nil, fmt.Errorf("legacy root cron changed while opening")
	}
	if _, err := readLegacyCronSecurityLabel(file); err != nil {
		return identity, nil, err
	}
	content, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || int64(len(content)) != identity.size || strings.ContainsRune(string(content), '\x00') {
		return identity, nil, fmt.Errorf("legacy root cron content changed or is invalid")
	}
	after, err := directory.root.Lstat(name)
	actual, identityErr = exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != identity {
		return identity, nil, fmt.Errorf("legacy root cron changed during inspection")
	}
	return identity, content, nil
}

func readLegacyCronSecurityLabel(file *os.File) ([]byte, error) {
	var names [1024]byte
	size, err := unix.Flistxattr(int(file.Fd()), names[:])
	if errors.Is(err, unix.ENOTSUP) || err == nil && size == 0 {
		return nil, nil
	}
	if err != nil || string(names[:size]) != "security.selinux\x00" {
		return nil, fmt.Errorf("root cron extended attributes require separate preservation review")
	}
	var label [4096]byte
	size, err = unix.Fgetxattr(int(file.Fd()), "security.selinux", label[:])
	if err != nil || size == 0 {
		return nil, fmt.Errorf("root cron security label is unavailable")
	}
	return append([]byte(nil), label[:size]...), nil
}

func legacyCronSecurityLabelAt(directory *pinnedServiceDirectory, name string) ([]byte, error) {
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return readLegacyCronSecurityLabel(file)
}

func inspectLegacyCronDirectory(directory *pinnedServiceDirectory, uid uint32) (LegacyCronRetirementPlan, []byte, error) {
	plan := LegacyCronRetirementPlan{Schema: "syswarden-legacy-root-cron-retirement-v1", Directory: legacyCronSpool, StopsProduct: true, PreservesOtherJobs: true}
	info, err := directory.root.Stat(".")
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if err != nil || identityErr != nil || !safeSharedRemovalParent(info, identity, uid) {
		return plan, nil, fmt.Errorf("root cron spool is not a trusted shared directory")
	}
	plan.DirectoryIdentity = legacyLogPlanIdentity(identity)
	original, content, err := readLegacyCronFile(directory, "root", uid)
	if err != nil {
		return plan, nil, err
	}
	for index, line := range strings.Split(string(content), "\n") {
		if platformpaths.IsManagedCronLine(line) {
			plan.RemovedLines = append(plan.RemovedLines, index+1)
		}
	}
	if len(plan.RemovedLines) == 0 {
		return plan, nil, fmt.Errorf("no exact historical generated root cron records require retirement")
	}
	replacement, err := platformpaths.ReconcileCronRecords(string(content), platformpaths.IsManagedCronLine, "")
	if err != nil {
		return plan, nil, err
	}
	plan.Original = LegacyLogRetentionFile{Path: legacyCronSpool + "/root", Identity: legacyLogPlanIdentity(original), Size: original.size, Modified: original.mtime, Changed: original.ctime, SHA256: fmt.Sprintf("%x", sha256.Sum256(content))}
	plan.ReplacementSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(replacement)))
	return plan, []byte(replacement), nil
}

// This explicit operator recovery is separate from package maintainer scripts.
// Ordinary remove/purge remains read-only toward the shared root crontab. The
// original inode is retained privately, and only complete historical records
// selected in the reviewed plan are omitted from the replacement.
func legacyCronProviderGuard() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("legacy cron recovery requires root")
	}
	evidence, err := InspectRuntimeCronDProvider()
	if err != nil {
		return err
	}
	if evidence.Manager != "systemd" || evidence.Unit != "cron.service" || evidence.Daemon != "/usr/sbin/cron" {
		return fmt.Errorf("legacy cron recovery requires the verified Debian cron provider")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, path := range []string{legacyCronSpool, "/var/backups/syswarden-retired-v1/legacy-cron"} {
		if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, nil); err != nil {
			return err
		}
	}
	return nil
}

func InspectLegacyCronRetirement() (LegacyCronRetirementPlan, error) {
	if err := legacyCronProviderGuard(); err != nil {
		return LegacyCronRetirementPlan{}, err
	}
	directory, err := openPinnedSharedRemovalParent(legacyCronSpool, 0)
	if err != nil {
		return LegacyCronRetirementPlan{}, err
	}
	defer directory.close()
	plan, _, err := inspectLegacyCronDirectory(directory, 0)
	if err != nil {
		return plan, err
	}
	return plan, legacyCronProviderGuard()
}

func ApplyLegacyCronRetirement(expected string) (LegacyCronRetirementPlan, string, error) {
	if err := legacyCronProviderGuard(); err != nil {
		return LegacyCronRetirementPlan{}, "", err
	}
	prepare := func() error {
		if err := BeginRemoval(); err != nil {
			return err
		}
		return PrepareFirewallStateForRemoval()
	}
	guard := func() error {
		if err := legacyCronProviderGuard(); err != nil {
			return err
		}
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	return applyLegacyCronRetirement(legacyCronSpool, "/var/backups", expected, 0, prepare, guard, unix.Renameat2)
}

func applyLegacyCronRetirement(spoolPath, backupParentPath, expected string, uid uint32, prepare, guard func() error, rename serviceArtifactRename) (LegacyCronRetirementPlan, string, error) {
	var empty LegacyCronRetirementPlan
	if len(expected) != 64 || strings.Trim(expected, "0123456789abcdef") != "" || prepare == nil || guard == nil || rename == nil {
		return empty, "", fmt.Errorf("legacy cron retirement requires the exact reviewed digest and complete guards")
	}
	spool, err := openPinnedSharedRemovalParent(spoolPath, uid)
	if err != nil {
		return empty, "", err
	}
	defer spool.close()
	if err := unix.Flock(spool.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return empty, "", err
	}
	defer func() { _ = unix.Flock(spool.fd, unix.LOCK_UN) }()
	backupPath := filepath.Join(backupParentPath, "syswarden-retired-v1", "legacy-cron-"+expected)
	// Recover only a complete, digest-bound private plan. A partial stage is
	// retained for inspection; it never authorizes a guessed overwrite.
	if saved, err := openExistingPinnedServiceDirectory(backupPath); err == nil {
		defer saved.close()
		return finishLegacyCronRetirement(spoolPath, spool, backupPath, saved, expected, uid, prepare, guard, rename)
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, "", err
	}
	plan, replacement, err := inspectLegacyCronDirectory(spool, uid)
	if err != nil {
		return plan, "", err
	}
	digest, err := LegacyCronRetirementPlanSHA256(plan)
	if err != nil || digest != expected {
		return plan, "", fmt.Errorf("root cron changed since review; inspect a new plan")
	}
	parent, err := openExistingPinnedServiceDirectory(backupParentPath)
	if err != nil {
		return plan, "", err
	}
	defer parent.close()
	if err := parent.root.Mkdir("syswarden-retired-v1", 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return plan, "", err
	}
	root, err := openExistingPinnedServiceDirectory(filepath.Join(backupParentPath, "syswarden-retired-v1"))
	if err != nil {
		return plan, "", err
	}
	defer root.close()
	info, err := root.root.Stat(".")
	identity, identityErr := exactRemovalArtifactIdentity(info)
	if err != nil || identityErr != nil || info.Mode().Perm() != 0700 || identity.dev != plan.DirectoryIdentity.Device {
		return plan, "", fmt.Errorf("legacy cron backup must be private and on the same filesystem")
	}
	if err := root.root.Mkdir("legacy-cron-"+expected, 0700); err != nil {
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
	label, err := legacyCronSecurityLabelAt(spool, "root")
	if err != nil {
		return plan, "", err
	}
	for name, content := range map[string][]byte{"plan.json": wire, "root-crontab": replacement} {
		file, err := saved.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return plan, "", err
		}
		_, writeErr := file.Write(content)
		if name == "root-crontab" && writeErr == nil {
			writeErr = file.Chown(int(plan.Original.Identity.UID), int(plan.Original.Identity.GID))
			if writeErr == nil {
				stageLabel, labelErr := readLegacyCronSecurityLabel(file)
				writeErr = labelErr
				if labelErr == nil && !bytes.Equal(stageLabel, label) {
					if len(label) == 0 {
						writeErr = fmt.Errorf("root cron replacement inherited a different security label")
					} else {
						writeErr = unix.Fsetxattr(int(file.Fd()), "security.selinux", label, 0)
					}
				}
			}
			if writeErr == nil {
				// Cron compares second-resolution timestamps. Make the stage
				// observably different even when preparation is very fast.
				stamp := time.Now().Unix()
				if stamp == plan.Original.Modified.Sec {
					stamp++
				}
				writeErr = unix.Futimes(int(file.Fd()), []unix.Timeval{{Sec: stamp}, {Sec: stamp}})
			}
		}
		if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
			return plan, "", err
		}
	}
	if err := errors.Join(saved.sync(), root.sync(), parent.sync()); err != nil {
		return plan, "", err
	}
	return finishLegacyCronRetirement(spoolPath, spool, backupPath, saved, expected, uid, prepare, guard, rename)
}

func finishLegacyCronRetirement(spoolPath string, spool *pinnedServiceDirectory, backupPath string, saved *pinnedServiceDirectory, expected string, uid uint32, prepare, guard func() error, rename serviceArtifactRename) (LegacyCronRetirementPlan, string, error) {
	var plan LegacyCronRetirementPlan
	privateInfo, err := saved.root.Stat(".")
	if err != nil || privateInfo.Mode().Perm() != 0700 {
		return plan, "", fmt.Errorf("legacy cron backup directory is not private")
	}
	_, wire, err := readLegacyCronFile(saved, "plan.json", uid)
	if err != nil || json.Unmarshal(wire, &plan) != nil {
		return plan, "", fmt.Errorf("legacy cron backup lacks its exact private plan")
	}
	canonical, err := json.Marshal(plan)
	digest, digestErr := LegacyCronRetirementPlanSHA256(plan)
	if err != nil || digestErr != nil || string(wire) != string(canonical) || digest != expected || plan.Schema != "syswarden-legacy-root-cron-retirement-v1" || plan.Directory != legacyCronSpool || !plan.StopsProduct || !plan.PreservesOtherJobs || len(plan.RemovedLines) == 0 {
		return plan, "", fmt.Errorf("legacy cron backup plan differs from the reviewed inventory")
	}
	inspect := func() (bool, error) {
		backupRootPath := filepath.Dir(backupPath)
		backupRoot, err := openExistingPinnedServiceDirectory(backupRootPath)
		if err != nil {
			return false, err
		}
		defer backupRoot.close()
		for path, pinned := range map[string]*pinnedServiceDirectory{backupRootPath: backupRoot, backupPath: saved} {
			info, err := pinned.root.Stat(".")
			identity, identityErr := exactRemovalArtifactIdentity(info)
			if err != nil || identityErr != nil || info.Mode().Perm() != 0700 || identity.uid != uid || identity.dev != plan.DirectoryIdentity.Device {
				return false, fmt.Errorf("legacy cron backup ancestry is not private or on the original filesystem")
			}
			if err := attestRetainedDirectoryParent(path, pinned, false); err != nil {
				return false, err
			}
		}
		directory, err := saved.root.Open(".")
		if err != nil {
			return false, err
		}
		names, readErr := directory.Readdirnames(3)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) != 2 ||
			!(names[0] == "plan.json" && names[1] == "root-crontab" || names[1] == "plan.json" && names[0] == "root-crontab") {
			return false, fmt.Errorf("legacy cron backup inventory changed")
		}
		for path, pinned := range map[string]*pinnedServiceDirectory{spoolPath: spool, backupPath: saved} {
			if err := attestRetainedDirectoryParent(path, pinned, path == spoolPath); err != nil {
				return false, err
			}
		}
		spoolInfo, err := spool.root.Stat(".")
		identity, identityErr := exactRemovalArtifactIdentity(spoolInfo)
		if err != nil || identityErr != nil || legacyLogPlanIdentity(identity) != plan.DirectoryIdentity {
			return false, fmt.Errorf("root cron spool changed since review")
		}
		active, content, err := readLegacyCronFile(spool, "root", uid)
		if err != nil {
			return false, err
		}
		retained, original, err := readLegacyCronFile(saved, "root-crontab", uid)
		if err != nil {
			return false, err
		}
		activeLabel, activeErr := legacyCronSecurityLabelAt(spool, "root")
		retainedLabel, retainedErr := legacyCronSecurityLabelAt(saved, "root-crontab")
		if activeErr != nil || retainedErr != nil || !bytes.Equal(activeLabel, retainedLabel) {
			return false, fmt.Errorf("root cron security label differs from the retained original")
		}
		activeHash, retainedHash := fmt.Sprintf("%x", sha256.Sum256(content)), fmt.Sprintf("%x", sha256.Sum256(original))
		originalMatches := func(identity removalArtifactIdentity) bool {
			return legacyLogPlanIdentity(identity) == plan.Original.Identity && identity.size == plan.Original.Size && identity.mtime == plan.Original.Modified
		}
		metadataMatches := active.uid == plan.Original.Identity.UID && active.gid == plan.Original.Identity.GID && retained.uid == active.uid && retained.gid == active.gid
		if metadataMatches && activeHash == plan.ReplacementSHA256 && retainedHash == plan.Original.SHA256 && originalMatches(retained) {
			filtered, err := platformpaths.ReconcileCronRecords(string(original), platformpaths.IsManagedCronLine, "")
			return true, errors.Join(err, cronReplacementMismatch(filtered, content))
		}
		if !metadataMatches || activeHash != plan.Original.SHA256 || retainedHash != plan.ReplacementSHA256 || !originalMatches(active) || active.ctime != plan.Original.Changed {
			return false, fmt.Errorf("root cron or retained stage changed; both are preserved for review")
		}
		filtered, err := platformpaths.ReconcileCronRecords(string(content), platformpaths.IsManagedCronLine, "")
		return false, errors.Join(err, cronReplacementMismatch(filtered, original))
	}
	complete, err := inspect()
	if err != nil {
		return plan, "", err
	}
	if err := prepare(); err != nil {
		return plan, "", err
	}
	if err := guard(); err != nil {
		return plan, "", err
	}
	confirmed, err := inspect()
	if err != nil || confirmed != complete {
		return plan, "", fmt.Errorf("root cron state changed before retention")
	}
	if !complete {
		stage, stageContent, err := readLegacyCronFile(saved, "root-crontab", uid)
		if err != nil {
			return plan, "", err
		}
		if err := rename(spool.fd, "root", saved.fd, "root-crontab", unix.RENAME_EXCHANGE); err != nil {
			return plan, "", err
		}
		complete, err = inspect()
		if err != nil || !complete {
			active, content, readErr := readLegacyCronFile(spool, "root", uid)
			// Restore a displaced administrator update only while the active
			// path still names our unchanged replacement inode. A later edit
			// must remain untouched, with both current versions retained.
			if readErr == nil && legacyLogPlanIdentity(active) == legacyLogPlanIdentity(stage) &&
				active.size == stage.size && active.mtime == stage.mtime && string(content) == string(stageContent) {
				restoreErr := rename(spool.fd, "root", saved.fd, "root-crontab", unix.RENAME_EXCHANGE)
				return plan, "", errors.Join(fmt.Errorf("root cron changed during exchange; original active state was restored when unchanged"), err, restoreErr, spool.sync(), saved.sync())
			}
			return plan, "", errors.Join(fmt.Errorf("root cron changed during exchange; retain both active and private files for review"), err, readErr)
		}
	}
	if err := errors.Join(spool.sync(), saved.sync(), guard()); err != nil {
		return plan, "", err
	}
	complete, err = inspect()
	if err != nil || !complete {
		return plan, "", errors.Join(fmt.Errorf("root cron retirement verification failed"), err)
	}
	return plan, backupPath, nil
}

func cronReplacementMismatch(expected string, actual []byte) error {
	if expected != string(actual) {
		return fmt.Errorf("root cron replacement changes unrelated records")
	}
	return nil
}
