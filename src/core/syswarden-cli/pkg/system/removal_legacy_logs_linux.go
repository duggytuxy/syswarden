//go:build linux

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maximumLegacyLogRetentionBytes = 512 << 20

type LegacyLogRetentionIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

type LegacyLogRetentionFile struct {
	Path               string                     `json:"path"`
	Identity           LegacyLogRetentionIdentity `json:"identity"`
	Size               int64                      `json:"size"`
	Modified           syscall.Timespec           `json:"modified"`
	Changed            syscall.Timespec           `json:"changed"`
	SHA256             string                     `json:"sha256"`
	CreationProvenance bool                       `json:"creation_provenance"`
}

type LegacyLogRetentionPlan struct {
	Schema    string                     `json:"schema"`
	Directory string                     `json:"directory"`
	Identity  LegacyLogRetentionIdentity `json:"directory_identity"`
	Authority string                     `json:"authority"`
	Files     []LegacyLogRetentionFile   `json:"files"`
}

func legacyLogPlanIdentity(identity removalArtifactIdentity) LegacyLogRetentionIdentity {
	return LegacyLogRetentionIdentity{Device: identity.dev, Inode: identity.ino, Mode: identity.mode, UID: identity.uid, GID: identity.gid}
}

func LegacyLogRetentionPlanSHA256(plan LegacyLogRetentionPlan) (string, error) {
	wire, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(wire)), nil
}

// Inspection never claims that an unmarked log is product-owned. Applying the
// displayed digest explicitly confirms retention of this exact inventory as
// legacy product logs. Originals are moved intact to a private backup, never
// deleted or assigned a new creation marker. Other applications' files must
// not be selected, even if they occupy a familiar product filename.
func inspectLegacyProductLogDirectory(directory *pinnedServiceDirectory, syncData bool) (retainedDirectorySnapshot, LegacyLogRetentionPlan, error) {
	return inspectLegacyDataDirectory(directory, syncData, legacyLogsProfile())
}

func inspectLegacyDataDirectory(directory *pinnedServiceDirectory, syncData bool, profile legacyRetentionProfile) (retainedDirectorySnapshot, LegacyLogRetentionPlan, error) {
	snapshot := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	plan := LegacyLogRetentionPlan{Schema: profile.schema, Directory: profile.directory, Authority: profile.authority}
	info, err := directory.root.Stat(".")
	if err != nil {
		return snapshot, plan, err
	}
	snapshot.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || !slices.Contains([]os.FileMode{0700, 0750}, info.Mode().Perm()) || !serviceFileOwnedByCurrentUser(info) {
		return snapshot, plan, fmt.Errorf("legacy data directory must be private and owner controlled")
	}
	plan.Identity = legacyLogPlanIdentity(snapshot.directory)
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	if err != nil {
		return snapshot, plan, err
	}
	if len(entries) == 0 || len(entries) > len(profile.names) {
		return snapshot, plan, fmt.Errorf("legacy data inventory is empty or includes unrelated entries")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	unmarked := 0
	for _, name := range names {
		kind, allowed := profile.names[name]
		if !allowed {
			return snapshot, plan, fmt.Errorf("unrecognized legacy data entry must remain untouched: %q", name)
		}
		identity, digest, proven, err := profile.inspect(directory, name, kind, syncData)
		if err != nil {
			return snapshot, plan, err
		}
		if !proven {
			unmarked++
		}
		snapshot.files[name] = identity
		snapshot.content[name] = []byte(digest)
		plan.Files = append(plan.Files, LegacyLogRetentionFile{Path: filepath.Join(plan.Directory, name), Identity: legacyLogPlanIdentity(identity), Size: identity.size, Modified: identity.mtime, Changed: identity.ctime, SHA256: digest, CreationProvenance: proven})
	}
	if unmarked == 0 {
		return snapshot, plan, fmt.Errorf("no unmarked legacy data requires confirmation; retry the original removal command")
	}
	after, err := directory.root.Stat(".")
	identity, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || identity != snapshot.directory {
		return snapshot, plan, fmt.Errorf("legacy data inventory changed during inspection")
	}
	snapshot.digest, err = LegacyLogRetentionPlanSHA256(plan)
	return snapshot, plan, err
}

func inspectLegacyProductLogFile(directory *pinnedServiceDirectory, name, kind string, syncData bool) (removalArtifactIdentity, string, bool, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return removalArtifactIdentity{}, "", false, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !serviceFileOwnedByCurrentUser(before) || identity.nlink != 1 || identity.size < 0 || identity.size > maximumLegacyLogRetentionBytes {
		return identity, "", false, fmt.Errorf("legacy log must be a bounded exclusive private regular file")
	}
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identity, "", false, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	actual, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || actual != identity {
		return identity, "", false, fmt.Errorf("legacy log changed while opening")
	}
	var marker [256]byte
	_, originErr := unix.Fgetxattr(int(file.Fd()), productLogOriginAttribute, marker[:])
	proven := originErr == nil
	if proven {
		checked, _, err := inspectCreatedProductLog(directory, name, kind, false)
		if err != nil || checked != identity {
			return identity, "", false, fmt.Errorf("legacy retention cannot override a modified creation marker")
		}
	} else if !errors.Is(originErr, unix.ENODATA) && !errors.Is(originErr, unix.ENOTSUP) {
		return identity, "", false, originErr
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maximumLegacyLogRetentionBytes+1))
	if err != nil || size != identity.size {
		return identity, "", false, fmt.Errorf("legacy log changed during bounded hashing")
	}
	if syncData {
		if err := file.Sync(); err != nil {
			return identity, "", false, err
		}
	}
	after, err := directory.root.Lstat(name)
	actual, identityErr = exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != identity {
		return identity, "", false, fmt.Errorf("legacy log changed during inspection")
	}
	return identity, fmt.Sprintf("%x", hash.Sum(nil)), proven, nil
}

func legacyLogRetentionGuard() error { return legacyRetentionGuard(legacyLogsProfile()) }

func legacyRetentionGuard(profile legacyRetentionProfile) error {
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("legacy data retention requires an existing removal barrier from the original removal attempt: %w", err)
	}
	if err := preflightHostRemovalMountBoundaries(); err != nil {
		return err
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	for _, path := range []string{profile.directory, filepath.Join("/var/backups/syswarden-retired-v1", profile.backupKind)} {
		if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, nil); err != nil {
			return err
		}
	}
	return ReattestFirewallStatePreparedForRemoval()
}

func InspectLegacyLogRetention() (LegacyLogRetentionPlan, error) {
	return inspectLegacyRetention(legacyLogsProfile())
}

func inspectLegacyRetention(profile legacyRetentionProfile) (LegacyLogRetentionPlan, error) {
	if err := legacyRetentionGuard(profile); err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	directory, err := openExistingPinnedServiceDirectory(profile.directory)
	if err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	defer directory.close()
	_, plan, err := inspectLegacyDataDirectory(directory, false, profile)
	if err != nil {
		return plan, err
	}
	return plan, legacyRetentionGuard(profile)
}

func ApplyLegacyLogRetention(expected string) (LegacyLogRetentionPlan, string, error) {
	return applyLegacyLogRetention("/var/log", "/var/backups", expected, legacyLogRetentionGuard, unix.Renameat2)
}

func applyLegacyLogRetention(parentPath, backupParentPath, expected string, guard func() error, rename serviceArtifactRename) (LegacyLogRetentionPlan, string, error) {
	return applyLegacyRetention(parentPath, backupParentPath, expected, guard, rename, legacyLogsProfile())
}

func applyLegacyRetention(parentPath, backupParentPath, expected string, guard func() error, rename serviceArtifactRename, profile legacyRetentionProfile) (LegacyLogRetentionPlan, string, error) {
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != expected {
		return LegacyLogRetentionPlan{}, "", fmt.Errorf("legacy retention requires the exact lowercase plan SHA-256 from a reviewed dry run")
	}
	if guard == nil || rename == nil {
		return LegacyLogRetentionPlan{}, "", fmt.Errorf("legacy retention guards are incomplete")
	}
	if err := guard(); err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(parentPath, filepath.Base(profile.directory)))
	if errors.Is(err, fs.ErrNotExist) {
		return attestCompletedLegacyRetention(backupParentPath, expected, guard, profile)
	}
	if err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	_, plan, err := inspectLegacyDataDirectory(directory, false, profile)
	directory.close()
	if err != nil {
		return plan, "", err
	}
	actual, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil || actual != expected {
		return plan, "", fmt.Errorf("legacy data retention plan changed; repeat the read-only inspection")
	}
	inspect := func(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
		snapshot, _, err := inspectLegacyDataDirectory(directory, true, profile)
		if err != nil {
			return snapshot, err
		}
		if snapshot.digest != expected {
			return snapshot, fmt.Errorf("legacy data retention plan changed before completion")
		}
		return snapshot, nil
	}
	backup, err := retireAttestedDirectory(parentPath, filepath.Base(profile.directory), backupParentPath, profile.backupKind, guard, inspect, rename)
	return plan, backup, err
}

func attestCompletedLegacyLogRetention(backupParentPath, expected string, guard func() error) (LegacyLogRetentionPlan, string, error) {
	return attestCompletedLegacyRetention(backupParentPath, expected, guard, legacyLogsProfile())
}

func attestCompletedLegacyRetention(backupParentPath, expected string, guard func() error, profile legacyRetentionProfile) (LegacyLogRetentionPlan, string, error) {
	rootPath := filepath.Join(backupParentPath, "syswarden-retired-v1")
	root, err := openExistingPinnedServiceDirectory(rootPath)
	if err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	defer root.close()
	info, err := root.root.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return LegacyLogRetentionPlan{}, "", fmt.Errorf("legacy data backup root is not private")
	}
	entries, err := readBoundedSharedRemovalEntries(root.root)
	if err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	prefix := profile.backupKind + "-" + expected + "-"
	selected := ""
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			if selected != "" {
				return LegacyLogRetentionPlan{}, "", fmt.Errorf("legacy data recovery has multiple matching backups")
			}
			selected = entry.Name()
		}
	}
	if selected == "" {
		return LegacyLogRetentionPlan{}, "", fmt.Errorf("active data is absent but no exact backup binds the reviewed retention plan")
	}
	path := filepath.Join(rootPath, selected)
	saved, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return LegacyLogRetentionPlan{}, "", err
	}
	defer saved.close()
	snapshot, plan, err := inspectLegacyDataDirectory(saved, false, profile)
	if err != nil || snapshot.digest != expected || retainedDirectoryBackupName(profile.backupKind, snapshot) != selected {
		return plan, "", fmt.Errorf("retained legacy data backup does not bind the reviewed plan")
	}
	if err := guard(); err != nil {
		return plan, "", err
	}
	again, _, err := inspectLegacyDataDirectory(saved, false, profile)
	if err != nil || !sameRetainedDirectorySnapshot(snapshot, again, false) {
		return plan, "", fmt.Errorf("retained legacy data backup changed during recovery")
	}
	return plan, path, nil
}
