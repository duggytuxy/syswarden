//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const productSnapshotOriginAttribute = "user.syswarden.snapshot-origin-v1"

func inspectProductSnapshotDirectory(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
	result := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	info, err := directory.root.Stat(".")
	if err != nil {
		return result, err
	}
	result.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || !slices.Contains([]os.FileMode{0700, 0750}, info.Mode().Perm()) || !serviceFileOwnedByCurrentUser(info) {
		return result, fmt.Errorf("snapshot directory must be private and owner controlled")
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	if err != nil {
		return result, err
	}
	if len(entries) == 0 || len(entries) > 2 {
		return result, fmt.Errorf("snapshot directory has no closed owned inventory; preserve pending or unrelated files for explicit recovery")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	digest := sha256.New()
	for _, name := range names {
		kind := ""
		switch name {
		case "data.json":
			kind = "dashboard"
		case "metrics_24h.json":
			kind = "metrics"
		default:
			return result, fmt.Errorf("unrecognized snapshot entry must remain untouched: %q", name)
		}
		identity, content, err := inspectCreatedProductSnapshot(directory, name, kind, true)
		if err != nil {
			return result, err
		}
		result.files[name], result.content[name] = identity, content
		_, _ = digest.Write([]byte(name + "\x00"))
		contentDigest := sha256.Sum256(content)
		_, _ = digest.Write(contentDigest[:])
	}
	result.digest = fmt.Sprintf("%x", digest.Sum(nil))
	return result, nil
}

func inspectCreatedProductSnapshot(directory *pinnedServiceDirectory, name, kind string, syncData bool) (removalArtifactIdentity, []byte, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return removalArtifactIdentity{}, nil, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || before.Mode().Perm() != 0600 {
		return identity, nil, fmt.Errorf("snapshot must have private metadata")
	}
	content, err := readRetirementCandidateBounded(directory, name, before, 16<<20)
	if err != nil {
		return identity, nil, err
	}
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identity, nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || openedIdentity != identity {
		return identity, nil, fmt.Errorf("snapshot changed while opening")
	}
	var marker [512]byte
	size, err := unix.Fgetxattr(int(file.Fd()), productSnapshotOriginAttribute, marker[:])
	if err != nil {
		return identity, nil, fmt.Errorf("snapshot lacks exact creation provenance; preserve it for explicit recovery: %w", err)
	}
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		return identity, nil, err
	}
	if birth.Mask&unix.STATX_BTIME == 0 || birth.Ino != identity.ino {
		return identity, nil, fmt.Errorf("snapshot creation identity is unavailable")
	}
	expected := fmt.Sprintf("SYSWARDEN_SNAPSHOT_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\nsha256=%x\n", kind, identity.ino, birth.Btime.Sec, birth.Btime.Nsec, sha256.Sum256(content))
	if string(marker[:size]) != expected {
		return identity, nil, fmt.Errorf("snapshot origin does not bind its exact inode and content")
	}
	if syncData {
		if err := file.Sync(); err != nil {
			return identity, nil, err
		}
	}
	after, err := directory.root.Lstat(name)
	afterIdentity, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || afterIdentity != identity {
		return identity, nil, fmt.Errorf("snapshot changed during inspection")
	}
	return identity, content, nil
}

func RetireCreatedUISnapshotsForRemoval() error {
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
		for _, path := range []string{"/var/lib/syswarden/ui/data.json", "/var/backups/syswarden-retired-v1/ui-snapshots"} {
			if _, err := historicalRemovalCandidatePresent(root, path, 0, 0, func() {}); err != nil {
				return err
			}
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	if err := guard(); err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory("/var/lib/syswarden/ui")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	directory.close()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return guard()
	}
	backup, err := retireAttestedDirectory("/var/lib/syswarden", "ui", "/var/backups", "ui-snapshots", guard, inspectProductSnapshotDirectory, unix.Renameat2)
	if err == nil && backup != "" {
		fmt.Printf("[INFO] Retained verified UI snapshots in private recovery backup: %s\n", backup)
	}
	return err
}
