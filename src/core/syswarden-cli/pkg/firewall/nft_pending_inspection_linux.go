//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// RefusePendingAuthoritativeTransaction only observes recovery-journal presence.
// It creates no lock or directory, opens no journal payload and runs no command.
// An absence observation is not a lock against a later transaction or approval
// to apply configuration; mutation paths retain their own recovery barriers.
func RefusePendingAuthoritativeTransaction() error {
	root, err := os.OpenRoot("/")
	if err != nil {
		return fmt.Errorf("open firewall inspection root: %w", err)
	}
	defer func() { _ = root.Close() }()
	return refusePendingAuthoritativeTransaction(nftPersistenceFilesystem{root: root})
}

func refusePendingAuthoritativeTransaction(host nftPersistenceFilesystem) error {
	parentPath := filepath.Dir(nftStateDirectory)
	parent, err := host.openDirectory(parentPath)
	if err != nil {
		return fmt.Errorf("inspect firewall state parent without recovery: %w", err)
	}
	defer func() { _ = parent.Close() }()
	parentBefore, err := parent.Stat(".")
	if err != nil {
		return err
	}
	name := filepath.Base(nftStateDirectory)
	namedBefore, err := parent.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if host.afterRead != nil {
			host.afterRead()
		}
		currentParent, err := host.openDirectory(parentPath)
		if err != nil {
			return fmt.Errorf("reinspect absent firewall state parent: %w", err)
		}
		defer func() { _ = currentParent.Close() }()
		parentAfter, err := currentParent.Stat(".")
		if err != nil || !sameNFTPersistenceIdentity(parentBefore, parentAfter) {
			return fmt.Errorf("firewall state parent changed during absence inspection")
		}
		if _, err := currentParent.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("firewall state directory appeared or became unsafe during inspection")
		}
		return nil
	}
	if err != nil || !host.trustedMetadata(namedBefore, true) {
		return fmt.Errorf("firewall state directory is unavailable or unsafe")
	}
	directory, err := parent.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("pin firewall state directory without recovery: %w", err)
	}
	defer func() { _ = directory.Close() }()
	before, err := directory.Stat(".")
	namedAfter, pathErr := parent.Lstat(name)
	if err != nil || pathErr != nil || !sameNFTPersistenceIdentity(namedBefore, before) || !sameNFTPersistenceIdentity(before, namedAfter) {
		return fmt.Errorf("firewall state directory changed while pinning")
	}
	if _, err := directory.Lstat(nftTransactionJournalName); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("inspect firewall recovery journal presence: %w", err)
		}
		return fmt.Errorf("firewall recovery journal is present; complete its existing recovery route before configuration editing")
	}
	if host.afterRead != nil {
		host.afterRead()
	}
	// Reopen the logical path so a detached directory cannot prove absence.
	current, err := host.openDirectory(nftStateDirectory)
	if err != nil {
		return fmt.Errorf("reinspect firewall state directory: %w", err)
	}
	defer func() { _ = current.Close() }()
	after, err := current.Stat(".")
	if err != nil || !sameNFTPersistenceIdentity(before, after) {
		return fmt.Errorf("firewall state directory changed during pending-transaction inspection")
	}
	if _, err := current.Lstat(nftTransactionJournalName); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("reinspect firewall recovery journal presence: %w", err)
		}
		return fmt.Errorf("firewall recovery journal appeared during configuration preflight")
	}
	return nil
}
