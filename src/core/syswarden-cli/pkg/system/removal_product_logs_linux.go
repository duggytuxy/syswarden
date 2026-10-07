//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

const productLogOriginAttribute = "user.syswarden.log-origin-v1"

// Product logs are mutable append-only data, not operator configuration. Their
// creator records origin only on an exclusively created inode. Existing
// unmarked logs cannot acquire authority merely by being opened for append.
func inspectProductLogDirectory(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
	result := retainedDirectorySnapshot{files: map[string]removalArtifactIdentity{}, content: map[string][]byte{}}
	info, err := directory.root.Stat(".")
	if err != nil {
		return result, err
	}
	result.directory, err = exactRemovalArtifactIdentity(info)
	if err != nil || !info.IsDir() || !slices.Contains([]os.FileMode{0700, 0750}, info.Mode().Perm()) || !serviceFileOwnedByCurrentUser(info) {
		return result, fmt.Errorf("product log directory must be private and owner controlled")
	}
	entries, err := readBoundedSharedRemovalEntries(directory.root)
	if err != nil {
		return result, err
	}
	if len(entries) == 0 || len(entries) > 3 {
		return result, fmt.Errorf("product log directory has no closed owned inventory")
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
		case "core.log":
			kind = "core"
		case "waf.json", "waf.json.1":
			kind = "telemetry"
		default:
			return result, fmt.Errorf("unrecognized log directory entry must be preserved: %q", name)
		}
		identity, marker, err := inspectCreatedProductLog(directory, name, kind, true)
		if err != nil {
			return result, fmt.Errorf("preserve product log %s for explicit recovery: %w", name, err)
		}
		result.files[name], result.content[name] = identity, marker
		_, _ = digest.Write([]byte(name + "\x00"))
		_, _ = digest.Write(marker)
	}
	result.digest = fmt.Sprintf("%x", digest.Sum(nil))
	after, err := directory.root.Stat(".")
	actual, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || actual != result.directory {
		return result, fmt.Errorf("product log inventory changed during inspection")
	}
	return result, nil
}

func inspectCreatedProductLog(directory *pinnedServiceDirectory, name, kind string, syncData bool) (removalArtifactIdentity, []byte, error) {
	before, err := directory.root.Lstat(name)
	if err != nil {
		return removalArtifactIdentity{}, nil, err
	}
	identity, err := exactRemovalArtifactIdentity(before)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !serviceFileOwnedByCurrentUser(before) || identity.nlink != 1 || identity.size < 0 {
		return identity, nil, fmt.Errorf("log is not an exclusive private owned inode")
	}
	file, err := directory.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return identity, nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	if err != nil || identityErr != nil || identity != openedIdentity {
		return identity, nil, fmt.Errorf("log changed while opening")
	}
	var marker [256]byte
	size, err := unix.Fgetxattr(int(file.Fd()), productLogOriginAttribute, marker[:])
	if err != nil {
		return identity, nil, fmt.Errorf("log lacks valid creation provenance: %w", err)
	}
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		return identity, nil, err
	}
	if birth.Mask&unix.STATX_BTIME == 0 || birth.Ino != identity.ino {
		return identity, nil, fmt.Errorf("stable product log creation identity is unavailable")
	}
	expected := fmt.Sprintf("SYSWARDEN_LOG_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\n", kind, identity.ino, birth.Btime.Sec, birth.Btime.Nsec)
	if string(marker[:size]) != expected {
		return identity, nil, fmt.Errorf("log creation provenance does not bind this inode and kind")
	}
	if syncData {
		if err := file.Sync(); err != nil {
			return identity, nil, fmt.Errorf("sync owned log before private retention: %w", err)
		}
	}
	after, err := directory.root.Lstat(name)
	afterIdentity, identityErr := exactRemovalArtifactIdentity(after)
	if err != nil || identityErr != nil || afterIdentity != identity {
		return identity, nil, fmt.Errorf("log changed during origin inspection")
	}
	return identity, append([]byte(nil), marker[:size]...), nil
}

func RetireCreatedProductLogsForRemoval() error {
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
		// The log parent is a shared distro directory and is pinned separately.
		if _, err := historicalRemovalCandidatePresent(root, "/var/backups/syswarden-retired-v1/product-logs", 0, 0, func() {}); err != nil {
			return err
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	if err := guard(); err != nil {
		return err
	}
	// An absent directory or an empty product skeleton needs no file authority.
	// Final directory removal remains an independent empty-only operation.
	parent, err := openExistingPinnedServiceDirectory("/var/log/syswarden")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := readBoundedSharedRemovalEntries(parent.root)
	parent.close()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return guard()
	}
	backup, err := retireAttestedDirectory("/var/log", "syswarden", "/var/backups", "product-logs", guard, inspectProductLogDirectory, unix.Renameat2)
	if err == nil && backup != "" {
		fmt.Printf("[INFO] Retained verified product logs in private recovery backup: %s\n", backup)
	}
	return err
}
