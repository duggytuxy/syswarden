//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"io/fs"
)

// Some distributions do not create /var/backups. Create only that missing
// child through an attested /var descriptor before any recovery journal or
// source move. Existing shared storage is neither replaced nor chmodded.
// Read-only recovery inspection must never call this applying helper.
func ensureLegacyRetirementBackupParent(host nftPersistenceFilesystem, ops legacyRetirementFileOps) error {
	parent, err := host.openDirectory("/var")
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	before, err := parent.Stat(".")
	if err != nil {
		return err
	}
	childBefore, err := parent.Lstat("backups")
	if errors.Is(err, fs.ErrNotExist) {
		if err := ops.checkpoint("backup-parent-before-create"); err != nil {
			return err
		}
		if err := attestLegacyRetirementDirectory(host, "/var", before); err != nil {
			return err
		}
		// A concurrent creator is not silently adopted during this attempt.
		if err := parent.Mkdir("backups", 0700); err != nil {
			return fmt.Errorf("create missing shared recovery parent: %w", err)
		}
		childBefore, err = parent.Lstat("backups")
		if err != nil || !host.trustedMetadata(childBefore, true) || childBefore.Mode().Perm() != 0700 {
			return errors.Join(fmt.Errorf("new shared recovery parent has unsafe metadata"), err)
		}
		if err := ops.checkpoint("backup-parent-created"); err != nil {
			return err
		}
	}
	if err != nil || !host.trustedMetadata(childBefore, true) {
		return errors.Join(fmt.Errorf("shared recovery parent has unsafe metadata"), err)
	}
	child, err := host.openDirectory("/var/backups")
	if err != nil {
		return err
	}
	defer func() { _ = child.Close() }()
	opened, err := child.Stat(".")
	if err != nil || !sameNFTPersistenceIdentity(childBefore, opened) {
		return fmt.Errorf("shared recovery parent changed while opening")
	}
	childFD, err := child.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = childFD.Close() }()
	parentFD, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = parentFD.Close() }()
	if err := errors.Join(ops.sync(childFD), ops.sync(parentFD)); err != nil {
		return fmt.Errorf("shared recovery parent is not durable: %w", err)
	}
	if err := errors.Join(attestLegacyRetirementDirectory(host, "/var", before), attestLegacyRetirementDirectory(host, "/var/backups", opened)); err != nil {
		return err
	}
	return ops.checkpoint("backup-parent-durable")
}
