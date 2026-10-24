//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type nftOpenRCRuntime struct {
	started bool
	enabled bool
	proofs  map[string]nftPersistenceRead
}

// OpenRC creates root:root runtime directories with either 0755 or 0775.
// This exception never applies to persistent configuration or regular files.
func trustedNFTOpenRCDirectory(host nftPersistenceFilesystem, info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == host.expectedUID && stat.Gid == host.expectedGID &&
		(info.Mode().Perm() == 0755 || info.Mode().Perm() == 0775 || info.Mode().Perm() == 0700)
}

func openNFTOpenRCChild(host nftPersistenceFilesystem, parent *os.Root, name string) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !trustedNFTOpenRCDirectory(host, before) {
		return nil, fmt.Errorf("unsafe OpenRC directory %s", name)
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, openErr := child.Stat(".")
	after, afterErr := parent.Lstat(name)
	if openErr != nil || afterErr != nil || !sameNFTPersistenceIdentity(before, opened) || !sameNFTPersistenceIdentity(before, after) {
		_ = child.Close()
		return nil, fmt.Errorf("OpenRC directory changed while opening")
	}
	return child, nil
}

func readNFTOpenRCRuntimeFile(host nftPersistenceFilesystem, directory *os.Root, name string) (nftPersistenceRead, error) {
	before, err := directory.Lstat(name)
	if err != nil {
		return nftPersistenceRead{}, err
	}
	if !host.trustedMetadata(before, false) {
		return nftPersistenceRead{}, fmt.Errorf("unsafe OpenRC runtime file")
	}
	file, err := directory.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nftPersistenceRead{}, err
	}
	defer func() { _ = file.Close() }()
	opened, statErr := file.Stat()
	if statErr != nil || !sameNFTPersistenceIdentity(before, opened) {
		return nftPersistenceRead{}, fmt.Errorf("OpenRC runtime file changed while opening")
	}
	content, readErr := io.ReadAll(io.LimitReader(file, 65))
	after, afterErr := file.Stat()
	named, namedErr := directory.Lstat(name)
	if readErr != nil || len(content) > 64 || afterErr != nil || namedErr != nil ||
		!sameNFTPersistenceIdentity(before, after) || !sameNFTPersistenceIdentity(before, named) {
		return nftPersistenceRead{}, fmt.Errorf("OpenRC runtime file changed or exceeded its limit")
	}
	// procfs comm has a zero stat size, so content length is checked separately.
	return nftPersistenceRead{content: content, identity: after}, nil
}

func readNFTOpenRCLink(host nftPersistenceFilesystem, directory *os.Root, name string) (nftPersistenceRead, error) {
	before, err := directory.Lstat(name)
	if err != nil {
		return nftPersistenceRead{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != host.expectedUID || stat.Gid != host.expectedGID || stat.Nlink != 1 {
		return nftPersistenceRead{}, fmt.Errorf("unsafe OpenRC nftables state link")
	}
	target, err := directory.Readlink(name)
	after, afterErr := directory.Lstat(name)
	if err != nil || afterErr != nil || !sameNFTPersistenceIdentity(before, after) ||
		(target != "/etc/init.d/nftables" && target != "../../init.d/nftables") {
		return nftPersistenceRead{}, fmt.Errorf("OpenRC nftables state link changed or has an unexpected target")
	}
	return nftPersistenceRead{content: []byte(target), identity: after}, nil
}

func nftOpenRCEntries(directory *os.Root) ([]os.DirEntry, error) {
	file, err := directory.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	entries, err := file.ReadDir(maximumNFTPersistenceDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > maximumNFTPersistenceDirectoryEntries {
		return nil, fmt.Errorf("OpenRC state exceeds its inventory limit")
	}
	return entries, nil
}

func rejectNFTOpenRCPending(host nftPersistenceFilesystem, directory *os.Root, depth int) error {
	if _, err := directory.Lstat("nftables"); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("OpenRC nftables has pending, failed or unsupported runtime state")
	}
	if depth == 0 {
		return nil
	}
	entries, err := nftOpenRCEntries(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		child, err := openNFTOpenRCChild(host, directory, entry.Name())
		if err != nil {
			return err
		}
		err = rejectNFTOpenRCPending(host, child, depth-1)
		_ = child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func captureNFTOpenRCState(host nftPersistenceFilesystem, runtime *os.Root, result *nftOpenRCRuntime) error {
	for _, state := range []string{"started", "starting", "stopping", "inactive", "wasinactive", "failed", "hotplugged", "exclusive", "scheduled", "daemons", "options"} {
		directory, err := openNFTOpenRCChild(host, runtime, state)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if state == "started" {
			proof, linkErr := readNFTOpenRCLink(host, directory, "nftables")
			if linkErr == nil {
				// Runtime links must be absolute; relative runlevel links have a
				// different parent and are accepted only in the persistent tree.
				if string(proof.content) != "/etc/init.d/nftables" {
					linkErr = fmt.Errorf("unsupported OpenRC runtime link")
				} else {
					result.started = true
					result.proofs["started"] = proof
				}
			}
			if !errors.Is(linkErr, fs.ErrNotExist) {
				err = linkErr
			}
		} else {
			depth := 0
			if state == "scheduled" {
				depth = 1
			}
			err = rejectNFTOpenRCPending(host, directory, depth)
		}
		_ = directory.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func captureNFTOpenRCEnablement(host nftPersistenceFilesystem, result *nftOpenRCRuntime) error {
	root, err := host.openDirectory("/etc/runlevels")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	entries, err := nftOpenRCEntries(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		// Custom runlevel aliases could conceal enablement and are not inferred.
		if !entry.IsDir() {
			return fmt.Errorf("OpenRC runlevel inventory contains an unsupported alias")
		}
		directory, err := host.openDirectory(filepath.Join("/etc/runlevels", entry.Name()))
		if err != nil {
			return err
		}
		proof, linkErr := readNFTOpenRCLink(host, directory, "nftables")
		_ = directory.Close()
		if errors.Is(linkErr, fs.ErrNotExist) {
			continue
		}
		if linkErr != nil {
			return linkErr
		}
		result.proofs["runlevel/"+entry.Name()] = proof
		if entry.Name() == "boot" || entry.Name() == "default" {
			result.enabled = true
		}
	}
	return nil
}

func captureNFTOpenRCRuntime(host nftPersistenceFilesystem) (nftOpenRCRuntime, error) {
	result := nftOpenRCRuntime{proofs: make(map[string]nftPersistenceRead)}
	parent, err := host.openDirectory("/run")
	if err != nil {
		return result, err
	}
	defer func() { _ = parent.Close() }()
	runtime, err := openNFTOpenRCChild(host, parent, "openrc")
	if err != nil {
		return result, err
	}
	defer func() { _ = runtime.Close() }()
	for _, marker := range []string{"rc.starting", "rc.stopping"} {
		if _, err := runtime.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
			return result, fmt.Errorf("OpenRC runlevel transition is pending")
		}
	}
	level, err := readNFTOpenRCRuntimeFile(host, runtime, "softlevel")
	if err != nil {
		return result, err
	}
	name := strings.TrimSuffix(string(level.content), "\n")
	if name == "" || name == "shutdown" || name == "reboot" {
		return result, fmt.Errorf("OpenRC is not in a stable runlevel")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.-", r)) {
			return result, fmt.Errorf("unsupported OpenRC runlevel")
		}
	}
	proc, err := host.openDirectory("/proc/1")
	if err != nil {
		return result, err
	}
	comm, err := readNFTOpenRCRuntimeFile(host, proc, "comm")
	_ = proc.Close()
	if err != nil {
		return result, err
	}
	if string(comm.content) != "init\n" && string(comm.content) != "openrc-init\n" {
		return result, fmt.Errorf("PID 1 is not coherent with OpenRC")
	}
	result.proofs["softlevel"], result.proofs["pid1"] = level, comm
	if err := captureNFTOpenRCState(host, runtime, &result); err != nil {
		return result, err
	}
	if err := captureNFTOpenRCEnablement(host, &result); err != nil {
		return result, err
	}
	return result, nil
}

func sameNFTOpenRCRuntime(a, b nftOpenRCRuntime) bool {
	if a.started != b.started || a.enabled != b.enabled || len(a.proofs) != len(b.proofs) {
		return false
	}
	for key, proof := range a.proofs {
		next, exists := b.proofs[key]
		if !exists || !bytes.Equal(proof.content, next.content) || !sameNFTPersistenceIdentity(proof.identity, next.identity) {
			return false
		}
	}
	return true
}
