//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const haRetentionDirectory = "/var/lib/syswarden/ha"

func haRetentionProfile() legacyRetentionProfile {
	return legacyRetentionProfile{
		directory: haRetentionDirectory, backupKind: "ha-state",
		inspectDirectory: inspectHAStateRetention,
	}
}

// These fixed producer paths bound an explicit archival review, not ownership.
// Custom TLS paths, secrets, unrelated files and incomplete temporary files
// are never selected by a name prefix or a recursive directory deletion.
func haRetentionLimit(name string) (int64, bool) {
	switch name {
	case "server.crt", "server.key":
		return 1 << 20, true
	case "bans.json", "replication-v2.json", "replication-v2.wal.json", "replication-v2.json.head.wal.json", "fence/native-sync-fence-epochs.json":
		return 16 << 20, true
	case "replication-v2.json.anchor.json":
		return 4096, true
	case "replication-v2.json.instance.lock", "fence/native-sync-fence.lock":
		return 0, true
	case "fence/native-sync-fence.json":
		return 64 << 10, true
	default:
		return 0, false
	}
}

func inspectHAStateRetention(directory *pinnedServiceDirectory, syncData bool) (retainedDirectorySnapshot, LegacyLogRetentionPlan, error) {
	snapshot := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	plan := LegacyLogRetentionPlan{
		Schema: "syswarden-ha-state-retention-v1", Directory: haRetentionDirectory,
		Authority: "explicit-operator-confirmation-of-exclusive-inactive-ha-state-with-no-other-consumer-or-producer",
	}
	info, err := directory.root.Stat(".")
	if err != nil {
		return snapshot, plan, err
	}
	snapshot.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !serviceFileOwnedByCurrentUser(info) {
		return snapshot, plan, fmt.Errorf("HA retention requires a private owner-controlled directory")
	}
	plan.Identity = legacyLogPlanIdentity(snapshot.directory)
	var walk func(*os.Root, string) error
	walk = func(root *os.Root, prefix string) error {
		entries, err := readBoundedSharedRemovalEntries(root)
		if err != nil {
			return err
		}
		if len(entries) > 11 {
			return fmt.Errorf("HA retention inventory exceeds its bound")
		}
		slices.SortFunc(entries, func(left, right os.DirEntry) int {
			if left.Name() < right.Name() {
				return -1
			}
			if left.Name() > right.Name() {
				return 1
			}
			return 0
		})
		for _, entry := range entries {
			name := entry.Name()
			relative := prefix + name
			before, err := root.Lstat(name)
			if err != nil {
				return err
			}
			identity, err := exactRemovalArtifactIdentity(before)
			if err != nil || identity.dev != snapshot.directory.dev || !serviceFileOwnedByCurrentUser(before) || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
				return fmt.Errorf("unsafe HA retention entry %q", relative)
			}
			record := LegacyLogRetentionFile{Path: filepath.Join(haRetentionDirectory, relative), Identity: legacyLogPlanIdentity(identity), Size: identity.size, Modified: identity.mtime, Changed: identity.ctime}
			if relative == "fence" {
				if !before.IsDir() || before.Mode().Perm() != 0700 {
					return fmt.Errorf("HA fence must be a private real directory")
				}
				child, err := root.OpenRoot(name)
				if err != nil {
					return err
				}
				opened, statErr := child.Stat(".")
				actual, identityErr := exactRemovalArtifactIdentity(opened)
				if statErr != nil || identityErr != nil || actual != identity {
					_ = child.Close()
					return fmt.Errorf("HA fence directory changed while opening")
				}
				err = walk(child, "fence/")
				closeErr := child.Close()
				if err != nil || closeErr != nil {
					return errors.Join(err, closeErr)
				}
				record.Type = "directory"
				snapshot.content[relative] = nil
			} else {
				limit, allowed := haRetentionLimit(relative)
				if !allowed || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || identity.nlink != 1 || identity.size < 0 || identity.size > limit {
					return fmt.Errorf("HA retention requires an allowed exclusive private bounded file: %q", relative)
				}
				content, err := readRetirementCandidateBounded(&pinnedServiceDirectory{root: root}, name, before, max(limit, 1))
				if err != nil {
					return err
				}
				if syncData {
					file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
					if err != nil {
						return err
					}
					opened, statErr := file.Stat()
					actual, identityErr := exactRemovalArtifactIdentity(opened)
					if statErr != nil || identityErr != nil || actual != identity {
						_ = file.Close()
						return fmt.Errorf("HA file changed before synchronization")
					}
					if err := errors.Join(file.Sync(), file.Close()); err != nil {
						return err
					}
				}
				record.Type, record.SHA256 = "file", fmt.Sprintf("%x", sha256.Sum256(content))
				snapshot.content[relative] = []byte(record.SHA256)
			}
			snapshot.files[relative] = identity
			plan.Files = append(plan.Files, record)
		}
		return nil
	}
	if err := walk(directory.root, ""); err != nil {
		return snapshot, plan, err
	}
	if len(plan.Files) == 0 {
		return snapshot, plan, fmt.Errorf("empty HA state needs separate directory attribution")
	}
	// Recheck every child, including the fence directory: nested additions do
	// not necessarily change the top directory's timestamps.
	for name, expected := range snapshot.files {
		current, err := directory.root.Lstat(name)
		actual, identityErr := exactRemovalArtifactIdentity(current)
		if err != nil || identityErr != nil || actual != expected {
			return snapshot, plan, fmt.Errorf("HA retention inventory changed during inspection")
		}
	}
	after, err := directory.root.Stat(".")
	actual, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != snapshot.directory {
		return snapshot, plan, fmt.Errorf("HA retention directory changed during inspection")
	}
	slices.SortFunc(plan.Files, func(left, right LegacyLogRetentionFile) int {
		if left.Path < right.Path {
			return -1
		}
		if left.Path > right.Path {
			return 1
		}
		return 0
	})
	snapshot.digest, err = LegacyLogRetentionPlanSHA256(plan)
	return snapshot, plan, err
}

func haRetentionGuard(verifyRuntimeAbsent func() error) error {
	if verifyRuntimeAbsent == nil {
		return fmt.Errorf("HA retention requires independent runtime absence verification")
	}
	if err := legacyRetentionGuard(haRetentionProfile()); err != nil {
		return err
	}
	return verifyRuntimeAbsent()
}

func InspectHAStateRetention(verifyRuntimeAbsent func() error) (LegacyLogRetentionPlan, error) {
	guard := func() error { return haRetentionGuard(verifyRuntimeAbsent) }
	if err := guard(); err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	directory, err := openExistingPinnedServiceDirectory(haRetentionDirectory)
	if err != nil {
		return LegacyLogRetentionPlan{}, err
	}
	defer directory.close()
	_, plan, err := inspectHAStateRetention(directory, false)
	if err != nil {
		return plan, err
	}
	return plan, errors.Join(attestRetainedDirectoryParent(haRetentionDirectory, directory, false), guard())
}

func ApplyHAStateRetention(expected string, verifyRuntimeAbsent func() error) (LegacyLogRetentionPlan, string, error) {
	return applyLegacyRetention(filepath.Dir(haRetentionDirectory), "/var/backups", expected,
		func() error { return haRetentionGuard(verifyRuntimeAbsent) }, unix.Renameat2, haRetentionProfile())
}
