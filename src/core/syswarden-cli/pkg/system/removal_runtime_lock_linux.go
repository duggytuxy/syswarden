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

const firewallRuntimeLockPath = "/run/syswarden-firewall.lock"

func warnPreservedFirewallRuntimeLock(writer io.Writer, path string, reason error) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(
		writer,
		"[WARN] Preserving ambiguous SysWarden firewall runtime lock %s: %v.\n",
		path,
		reason,
	)
}

func attestExactFirewallRuntimeLock(
	directory *pinnedServiceDirectory,
	name string,
	expectedUID uint32,
	expectedGID uint32,
) (os.FileInfo, removalArtifactIdentity, error) {
	if directory == nil || directory.root == nil || name == "" || filepath.Base(name) != name {
		return nil, removalArtifactIdentity{}, fmt.Errorf("runtime lock attestation boundary is invalid")
	}
	info, err := directory.root.Lstat(name)
	if err != nil {
		return nil, removalArtifactIdentity{}, err
	}
	identity, err := exactRemovalArtifactIdentity(info)
	if err != nil {
		return nil, removalArtifactIdentity{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		identity.mode&07777 != 0600 || identity.uid != expectedUID || identity.gid != expectedGID ||
		identity.nlink != 1 || identity.size != 0 {
		return nil, identity, fmt.Errorf(
			"expected a real regular %d:%d 0600 nlink=1 size=0 lock",
			expectedUID,
			expectedGID,
		)
	}
	return info, identity, nil
}

func restoreQuarantinedFirewallRuntimeLock(
	directory *pinnedServiceDirectory,
	name string,
	quarantineName string,
	expected removalArtifactIdentity,
) error {
	_, quarantinedIdentity, err := attestExactFirewallRuntimeLock(
		directory, quarantineName, expected.uid, expected.gid,
	)
	if err != nil || !sameMovedRemovalArtifactIdentity(expected, quarantinedIdentity) {
		return errors.Join(fmt.Errorf("quarantined runtime lock changed before restoration"), err)
	}
	if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("runtime lock path was recreated while its original was quarantined")
		}
		return fmt.Errorf("inspect runtime lock path before restoration: %w", err)
	}
	if err := unix.Renameat2(
		directory.fd, quarantineName, directory.fd, name, unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("restore quarantined runtime lock without replacement: %w", err)
	}
	_, restoredIdentity, inspectErr := attestExactFirewallRuntimeLock(
		directory, name, expected.uid, expected.gid,
	)
	syncErr := directory.sync()
	if inspectErr != nil || !sameMovedRemovalArtifactIdentity(expected, restoredIdentity) || syncErr != nil {
		return errors.Join(
			fmt.Errorf("quarantined runtime lock was not exactly restored"),
			inspectErr,
			syncErr,
		)
	}
	return nil
}

func removePreparedFirewallRuntimeLockAt(
	path string,
	expectedUID uint32,
	expectedGID uint32,
	reattest func() error,
	warnings io.Writer,
) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) || filepath.Dir(path) == path {
		return fmt.Errorf("firewall runtime lock path is not clean and absolute")
	}
	if reattest == nil {
		return fmt.Errorf("firewall runtime lock removal reattestation is unavailable")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect firewall runtime lock: %w", err)
	}

	directory, err := openPinnedServiceDirectory(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("pin firewall runtime lock directory: %w", err)
	}
	defer directory.close()
	name := filepath.Base(path)
	_, expected, err := attestExactFirewallRuntimeLock(directory, name, expectedUID, expectedGID)
	if err != nil {
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return nil
	}

	file, err := directory.root.OpenFile(name, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return fmt.Errorf("open exact firewall runtime lock without following links: %w", err)
	}
	defer file.Close()
	opened, statErr := file.Stat()
	openedIdentity, identityErr := exactRemovalArtifactIdentity(opened)
	if statErr != nil || identityErr != nil || expected != openedIdentity {
		err := errors.Join(
			fmt.Errorf("firewall runtime lock changed while opening"),
			statErr,
			identityErr,
		)
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			err = fmt.Errorf("firewall runtime lock is held by another process")
		} else {
			err = fmt.Errorf("acquire firewall runtime lock without blocking: %w", err)
		}
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return err
	}
	defer func() { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }()

	_, lockedIdentity, err := attestExactFirewallRuntimeLock(directory, name, expectedUID, expectedGID)
	if err != nil || expected != lockedIdentity {
		err = errors.Join(fmt.Errorf("firewall runtime lock changed before exclusive acquisition"), err)
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return err
	}
	if err := reattest(); err != nil {
		err = fmt.Errorf("reattest stopped SysWarden services and processes before runtime lock quarantine: %w", err)
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return err
	}

	var quarantineName string
	for attempt := 0; attempt < 16; attempt++ {
		quarantineName, err = randomServiceArtifactName(".syswarden-firewall-lock-removal-")
		if err != nil {
			return fmt.Errorf("generate firewall runtime lock quarantine: %w", err)
		}
		err = unix.Renameat2(directory.fd, name, directory.fd, quarantineName, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		break
	}
	if err != nil {
		err = fmt.Errorf("quarantine firewall runtime lock atomically: %w", err)
		warnPreservedFirewallRuntimeLock(warnings, path, err)
		return err
	}

	restoreAfterFailure := func(cause error) error {
		restoreErr := restoreQuarantinedFirewallRuntimeLock(directory, name, quarantineName, expected)
		combined := errors.Join(cause, restoreErr)
		warnPreservedFirewallRuntimeLock(warnings, path, combined)
		return combined
	}
	_, movedIdentity, inspectErr := attestExactFirewallRuntimeLock(
		directory, quarantineName, expectedUID, expectedGID,
	)
	_, originalErr := directory.root.Lstat(name)
	syncErr := directory.sync()
	if inspectErr != nil || !sameMovedRemovalArtifactIdentity(expected, movedIdentity) ||
		!errors.Is(originalErr, os.ErrNotExist) || syncErr != nil {
		return restoreAfterFailure(errors.Join(
			fmt.Errorf("firewall runtime lock changed during atomic quarantine"),
			inspectErr,
			originalErr,
			syncErr,
		))
	}
	if err := reattest(); err != nil {
		return restoreAfterFailure(fmt.Errorf(
			"reattest stopped SysWarden services and processes before runtime lock commit: %w", err,
		))
	}
	_, committedIdentity, inspectErr := attestExactFirewallRuntimeLock(
		directory, quarantineName, expectedUID, expectedGID,
	)
	_, originalErr = directory.root.Lstat(name)
	if inspectErr != nil || !sameMovedRemovalArtifactIdentity(expected, committedIdentity) ||
		!errors.Is(originalErr, os.ErrNotExist) {
		return restoreAfterFailure(errors.Join(
			fmt.Errorf("firewall runtime lock changed before removal commit"),
			inspectErr,
			originalErr,
		))
	}
	if err := unix.Unlinkat(directory.fd, quarantineName, 0); err != nil {
		return restoreAfterFailure(fmt.Errorf("remove quarantined firewall runtime lock: %w", err))
	}
	if err := directory.sync(); err != nil {
		return fmt.Errorf("sync firewall runtime lock removal: %w", err)
	}
	if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(fmt.Errorf("firewall runtime lock path reappeared after removal"), err)
	}
	if _, err := directory.root.Lstat(quarantineName); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(fmt.Errorf("firewall runtime lock quarantine remained after removal"), err)
	}
	return nil
}

// RemovePreparedFirewallRuntimeLockForRemoval removes the shared nftables
// runtime lock only after every exact SysWarden mutator has been stopped and
// the durable package-removal barrier is present. Unsafe or unattributable
// objects are never changed.
func RemovePreparedFirewallRuntimeLockForRemoval() error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return fmt.Errorf("firewall runtime lock removal must be executed as root:root")
	}
	if err := RequireRemovalTombstone(); err != nil {
		return fmt.Errorf("firewall runtime lock removal requires the durable removal tombstone: %w", err)
	}
	return removePreparedFirewallRuntimeLockAt(
		firewallRuntimeLockPath,
		0,
		0,
		ReattestFirewallStatePreparedForRemoval,
		os.Stderr,
	)
}
