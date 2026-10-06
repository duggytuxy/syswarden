//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"
)

const maximumNFTPersistenceDirectoryEntries = 4096

// nftPersistenceFilesystem is read-only. All paths are resolved under the
// pinned root, with symlink and writable-directory checks at each component.
// expectedUID/GID are root in production and the fixture owner in unit tests.
type nftPersistenceFilesystem struct {
	root        *os.Root
	expectedUID uint32
	expectedGID uint32
	afterRead   func()
}

func (host nftPersistenceFilesystem) trustedMetadata(info os.FileInfo, directory bool) bool {
	if info == nil || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID {
		return false
	}
	if directory {
		return info.IsDir()
	}
	return info.Mode().IsRegular() && stat.Nlink == 1 && info.Size() >= 0 && info.Size() <= maximumNFTPersistenceBytes
}

func sameNFTPersistenceIdentity(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() {
		return false
	}
	a, aOK := left.Sys().(*syscall.Stat_t)
	b, bOK := right.Sys().(*syscall.Stat_t)
	return aOK && bOK && a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (host nftPersistenceFilesystem) openDirectory(path string) (*os.Root, error) {
	if host.root == nil || path != "/" && !canonicalNFTPersistencePath(path, false) {
		return nil, fmt.Errorf("invalid nftables persistence directory")
	}
	current, err := host.root.OpenRoot(".")
	if err != nil {
		return nil, fmt.Errorf("open pinned nftables persistence root: %w", err)
	}
	info, err := current.Stat(".")
	if err != nil || !host.trustedMetadata(info, true) {
		_ = current.Close()
		return nil, fmt.Errorf("nftables persistence root has unsafe metadata")
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect nftables persistence directory component %s: %w", component, err)
		}
		if !host.trustedMetadata(before, true) {
			_ = current.Close()
			return nil, fmt.Errorf("nftables persistence directory component is unavailable or unsafe: %s", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open nftables persistence directory component: %w", err)
		}
		opened, statErr := next.Stat(".")
		stillNamed, pathErr := current.Lstat(component)
		closeErr := current.Close()
		if statErr != nil || pathErr != nil || closeErr != nil ||
			!sameNFTPersistenceIdentity(before, opened) || !sameNFTPersistenceIdentity(before, stillNamed) {
			_ = next.Close()
			return nil, fmt.Errorf("nftables persistence directory changed while opening")
		}
		current = next
	}
	return current, nil
}

func (host nftPersistenceFilesystem) read(path string) ([]byte, error) {
	snapshot, err := host.snapshot(path)
	if err != nil {
		return nil, err
	}
	return snapshot.content, nil
}

func (host nftPersistenceFilesystem) snapshot(path string) (nftPersistenceRead, error) {
	if !canonicalNFTPersistencePath(path, false) {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source path is not canonical and absolute")
	}
	directory, err := host.openDirectory(filepath.Dir(path))
	if err != nil {
		return nftPersistenceRead{}, err
	}
	defer func() { _ = directory.Close() }()
	name := filepath.Base(path)
	before, err := directory.Lstat(name)
	if err != nil {
		return nftPersistenceRead{}, fmt.Errorf("inspect nftables persistence source: %w", err)
	}
	if !host.trustedMetadata(before, false) {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source is not a single-link trusted regular file")
	}
	file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nftPersistenceRead{}, fmt.Errorf("open nftables persistence source without following links: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(before, opened) {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source changed while opening")
	}
	filesystemUUID, err := wireguardstate.CaptureFilesystemUUID(file)
	if err != nil {
		return nftPersistenceRead{}, err
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumNFTPersistenceBytes+1))
	if err != nil || len(content) > maximumNFTPersistenceBytes {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source could not be read within its limit")
	}
	if host.afterRead != nil {
		host.afterRead()
	}
	after, statErr := file.Stat()
	afterUUID, uuidErr := wireguardstate.CaptureFilesystemUUID(file)
	stillNamed, pathErr := directory.Lstat(name)
	if statErr != nil || pathErr != nil || uuidErr != nil || filesystemUUID != afterUUID || int64(len(content)) != before.Size() ||
		!sameNFTPersistenceIdentity(before, after) || !sameNFTPersistenceIdentity(before, stillNamed) {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source changed while reading")
	}
	// Reopen the logical parent to detect a directory that was moved after it
	// was pinned. A detached directory must not stand in for the current path.
	currentParent, err := host.openDirectory(filepath.Dir(path))
	if err != nil {
		return nftPersistenceRead{}, err
	}
	defer func() { _ = currentParent.Close() }()
	current, err := currentParent.Lstat(name)
	if err != nil || !sameNFTPersistenceIdentity(before, current) {
		return nftPersistenceRead{}, fmt.Errorf("nftables persistence source path changed while reading")
	}
	return nftPersistenceRead{content: content, identity: after, filesystemUUID: filesystemUUID}, nil
}

func (host nftPersistenceFilesystem) expand(pattern string) ([]string, error) {
	if !canonicalNFTPersistencePath(pattern, true) {
		return nil, fmt.Errorf("nftables persistence wildcard is not canonical and bounded")
	}
	if _, err := matchNFTPersistenceWildcard(pattern, ""); err != nil {
		return nil, err
	}
	directory, err := host.openDirectory(filepath.Dir(pattern))
	if errors.Is(err, fs.ErrNotExist) {
		// Shell wildcard includes may have zero matches, including when the
		// directory does not exist. The graph retains this empty expansion so
		// its continued absence can be checked before any later mutation.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	before, err := directory.Stat(".")
	if err != nil {
		return nil, err
	}
	file, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	entries, err := file.ReadDir(maximumNFTPersistenceDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > maximumNFTPersistenceDirectoryEntries {
		return nil, fmt.Errorf("nftables persistence directory cannot be enumerated within its limit")
	}
	var matches []string
	for _, entry := range entries {
		match, err := matchNFTPersistenceWildcard(filepath.Base(pattern), entry.Name())
		if err != nil {
			return nil, err
		}
		if !match {
			continue
		}
		info, err := directory.Lstat(entry.Name())
		if err != nil || !host.trustedMetadata(info, false) {
			return nil, fmt.Errorf("nftables persistence wildcard includes an unsafe file")
		}
		matches = append(matches, filepath.Join(filepath.Dir(pattern), entry.Name()))
		if len(matches) > maximumNFTPersistenceFiles {
			return nil, fmt.Errorf("nftables persistence wildcard exceeds the file limit")
		}
	}
	after, err := directory.Stat(".")
	if err != nil || !sameNFTPersistenceIdentity(before, after) {
		return nil, fmt.Errorf("nftables persistence directory changed during enumeration")
	}
	sort.Strings(matches)
	return matches, nil
}

func (host nftPersistenceFilesystem) reader() nftPersistenceGraphReader {
	return nftPersistenceGraphReader{read: host.snapshot, expand: host.expand}
}
