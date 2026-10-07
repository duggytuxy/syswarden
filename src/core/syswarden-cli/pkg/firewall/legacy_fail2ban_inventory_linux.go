//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

const (
	legacyFail2banDirectory        = "/etc/fail2ban"
	maximumLegacyFail2banFiles     = 2048
	maximumLegacyFail2banTreeBytes = 32 << 20
	maximumLegacyFail2banTreeDepth = 16
)

type legacyFail2banSource struct {
	path     string
	snapshot nftPersistenceRead
	sha256   [sha256.Size]byte
}

type legacyFail2banDirectorySnapshot struct {
	path     string
	identity os.FileInfo
}

type legacyFail2banInventory struct {
	present     bool
	parent      os.FileInfo
	directories []legacyFail2banDirectorySnapshot
	sources     []legacyFail2banSource
}

// inspectLegacyFail2banInventory captures all files and directory membership,
// including disabled configurations, local overrides and hidden files. It does
// not infer ownership or interpret Fail2ban configuration. A caller must still
// establish the actual service configuration root, external include closure,
// effective settings and live actions before authorizing retirement.
func inspectLegacyFail2banInventory(host nftPersistenceFilesystem) (legacyFail2banInventory, error) {
	var inventory legacyFail2banInventory
	parent, err := host.openDirectory(filepath.Dir(legacyFail2banDirectory))
	if err != nil {
		return inventory, err
	}
	defer func() { _ = parent.Close() }()
	inventory.parent, err = parent.Stat(".")
	if err != nil {
		return inventory, err
	}
	info, err := parent.Lstat(filepath.Base(legacyFail2banDirectory))
	if errors.Is(err, fs.ErrNotExist) {
		// Recheck the logical parent as well as the absent child. Absence in
		// a detached directory is not absence at the configured path.
		if err := attestLegacyRetirementDirectory(host, "/etc", inventory.parent); err != nil {
			return inventory, err
		}
		if _, err := parent.Lstat(filepath.Base(legacyFail2banDirectory)); !errors.Is(err, fs.ErrNotExist) {
			return inventory, fmt.Errorf("Fail2ban configuration appeared during inspection")
		}
		return inventory, nil
	}
	if err != nil || !host.trustedMetadata(info, true) {
		return inventory, errors.Join(fmt.Errorf("Fail2ban configuration root is unavailable or unsafe"), err)
	}
	inventory.present = true
	totalBytes, entries := 0, 0
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		if depth > maximumLegacyFail2banTreeDepth {
			return fmt.Errorf("Fail2ban configuration tree exceeds the depth limit")
		}
		directory, err := host.openDirectory(path)
		if err != nil {
			return err
		}
		defer func() { _ = directory.Close() }()
		before, err := directory.Stat(".")
		if err != nil {
			return err
		}
		file, err := directory.Open(".")
		if err != nil {
			return err
		}
		children, readErr := file.ReadDir(maximumLegacyFail2banFiles + 1)
		closeErr := file.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(children) > maximumLegacyFail2banFiles {
			return fmt.Errorf("Fail2ban configuration directory cannot be enumerated within its limit")
		}
		entries += len(children) + 1
		if entries > maximumLegacyFail2banFiles {
			return fmt.Errorf("Fail2ban configuration tree exceeds the entry limit")
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		inventory.directories = append(inventory.directories, legacyFail2banDirectorySnapshot{path, before})
		for _, child := range children {
			childPath := filepath.Join(path, child.Name())
			if !canonicalNFTPersistencePath(childPath, false) {
				return fmt.Errorf("Fail2ban configuration has an unsupported entry name")
			}
			info, err := directory.Lstat(child.Name())
			if err != nil {
				return err
			}
			if info.IsDir() {
				if err := visit(childPath, depth+1); err != nil {
					return err
				}
				continue
			}
			snapshot, err := host.snapshot(childPath)
			if err != nil {
				return fmt.Errorf("inspect Fail2ban configuration source %q: %w", childPath, err)
			}
			if totalBytes > maximumLegacyFail2banTreeBytes-len(snapshot.content) {
				return fmt.Errorf("Fail2ban configuration tree exceeds the byte limit")
			}
			totalBytes += len(snapshot.content)
			inventory.sources = append(inventory.sources, legacyFail2banSource{childPath, snapshot, sha256.Sum256(snapshot.content)})
		}
		after, err := directory.Stat(".")
		if err != nil || !sameNFTPersistenceIdentity(before, after) {
			return fmt.Errorf("Fail2ban configuration membership changed during inspection")
		}
		return attestLegacyRetirementDirectory(host, path, before)
	}
	if err := visit(legacyFail2banDirectory, 0); err != nil {
		return legacyFail2banInventory{}, err
	}
	// A change to an earlier file while later files were read must also be
	// caught. Reattest every snapshot and directory at the end of inspection.
	for _, source := range inventory.sources {
		current, err := host.snapshot(source.path)
		if err != nil || !sameLegacyFail2banSource(source.snapshot, current) {
			return legacyFail2banInventory{}, fmt.Errorf("Fail2ban configuration source changed during inventory: %q", source.path)
		}
	}
	for _, snapshot := range inventory.directories {
		current, err := host.openDirectory(snapshot.path)
		if err != nil {
			return legacyFail2banInventory{}, err
		}
		info, statErr := current.Stat(".")
		closeErr := current.Close()
		if statErr != nil || closeErr != nil || !sameNFTPersistenceIdentity(snapshot.identity, info) {
			return legacyFail2banInventory{}, fmt.Errorf("Fail2ban configuration directory changed during inventory: %q", snapshot.path)
		}
	}
	if err := attestLegacyRetirementDirectory(host, "/etc", inventory.parent); err != nil {
		return legacyFail2banInventory{}, err
	}
	return inventory, nil
}

func sameLegacyFail2banSource(left, right nftPersistenceRead) bool {
	return sameNFTPersistenceIdentity(left.identity, right.identity) && left.filesystemUUID == right.filesystemUUID &&
		bytes.Equal(left.content, right.content)
}

func sameLegacyFail2banDirectory(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() {
		return false
	}
	a, aOK := left.Sys().(*syscall.Stat_t)
	b, bOK := right.Sys().(*syscall.Stat_t)
	return aOK && bOK && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}

// verifyLegacyFail2banInventoryRetirement permits only the exact, separately
// attested file removals supplied by the caller. Every retained file, override,
// directory and previously absent file must keep its original identity. This
// comparison is for one running transaction, not a persisted reboot receipt.
// It proves filesystem preservation only, not effective or runtime behavior.
func verifyLegacyFail2banInventoryRetirement(before, after legacyFail2banInventory, retiring []nftPersistenceRetiredSource) error {
	if before.present != after.present || !sameLegacyFail2banDirectory(before.parent, after.parent) ||
		len(retiring) > maximumLegacyFail2banFiles || len(before.sources) > maximumLegacyFail2banFiles ||
		len(after.sources) > maximumLegacyFail2banFiles || len(before.directories) != len(after.directories) {
		return fmt.Errorf("Fail2ban configuration root or inventory boundary changed")
	}
	if !before.present {
		if len(before.sources)+len(after.sources)+len(before.directories)+len(after.directories)+len(retiring) != 0 {
			return fmt.Errorf("absent Fail2ban configuration has inconsistent inventory evidence")
		}
		return nil
	}
	sources := make(map[string]legacyFail2banSource, len(before.sources))
	for _, source := range before.sources {
		if _, duplicate := sources[source.path]; duplicate || source.sha256 != sha256.Sum256(source.snapshot.content) || source.snapshot.identity == nil {
			return fmt.Errorf("Fail2ban source inventory is duplicate or unbound")
		}
		sources[source.path] = source
	}
	changedParents := make(map[string]bool)
	for _, retired := range retiring {
		source, found := sources[retired.path]
		if !found || source.sha256 != retired.sha256 {
			return fmt.Errorf("Fail2ban retirement is not bound to a unique inspected source")
		}
		delete(sources, retired.path)
		changedParents[filepath.Dir(retired.path)] = true
	}
	if len(sources) != len(after.sources) {
		return fmt.Errorf("Fail2ban retirement added or removed an unexpected configuration file")
	}
	for _, actual := range after.sources {
		expected, found := sources[actual.path]
		if !found || actual.sha256 != expected.sha256 || !sameLegacyFail2banSource(expected.snapshot, actual.snapshot) {
			return fmt.Errorf("Fail2ban retirement changed a retained configuration file: %q", actual.path)
		}
		delete(sources, actual.path)
	}
	seen := make(map[string]bool)
	for index, expected := range before.directories {
		actual := after.directories[index]
		if expected.path != actual.path || seen[expected.path] || !sameLegacyFail2banDirectory(expected.identity, actual.identity) {
			return fmt.Errorf("Fail2ban retirement changed a configuration directory")
		}
		seen[expected.path] = true
		if !changedParents[expected.path] && !sameNFTPersistenceIdentity(expected.identity, actual.identity) {
			return fmt.Errorf("Fail2ban retirement changed unrelated directory membership")
		}
	}
	if !seen[legacyFail2banDirectory] {
		return fmt.Errorf("Fail2ban inventory does not include its configuration root")
	}
	return nil
}
