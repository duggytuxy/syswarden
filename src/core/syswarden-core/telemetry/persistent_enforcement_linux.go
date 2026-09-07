//go:build linux

package telemetry

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	persistentEnforcementIPv4File     = "syswarden_blacklist.ipv4"
	persistentEnforcementIPv6File     = "syswarden_blacklist.ipv6"
	maximumPersistentEnforcementBytes = int64(1024 * 1024)
)

type persistentEnforcementEntry struct {
	canonical string
	prefix    netip.Prefix
}

// persistentEnforcementView is authoritative only when attested is true. An
// unsafe or incomplete read is represented by the zero value and can never
// produce an active or absent enforcement claim.
type persistentEnforcementView struct {
	attested bool
	entries  []persistentEnforcementEntry
}

func (view persistentEnforcementView) contains(raw string) bool {
	if !view.attested {
		return false
	}
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Is4In6() || address.Zone() != "" || address.String() != raw {
		return false
	}
	for _, entry := range view.entries {
		if entry.prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (view persistentEnforcementView) entryCount() int {
	if !view.attested {
		return 0
	}
	return len(view.entries)
}

type persistentEnforcementFileIdentity struct {
	info      fs.FileInfo
	mode      fs.FileMode
	device    uint64
	inode     uint64
	uid       uint32
	gid       uint32
	links     uint64
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

type persistentEnforcementDirectoryIdentity struct {
	info   fs.FileInfo
	mode   fs.FileMode
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

type persistentEnforcementFileSnapshot struct {
	name     string
	present  bool
	identity persistentEnforcementFileIdentity
}

type persistentEnforcementReadHook func(stage, name string)

func collectPersistentEnforcementView(directoryPath string) (persistentEnforcementView, error) {
	return collectPersistentEnforcementViewWithHook(directoryPath, nil)
}

func collectPersistentEnforcementViewWithHook(
	directoryPath string,
	hook persistentEnforcementReadHook,
) (persistentEnforcementView, error) {
	unsafeView := persistentEnforcementView{}
	if !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath {
		return unsafeView, fmt.Errorf("persistent enforcement directory must be absolute and canonical")
	}
	directory, err := openPersistentEnforcementDirectory(directoryPath)
	if err != nil {
		return unsafeView, err
	}
	defer directory.Close()
	directoryInfo, err := directory.Stat(".")
	if err != nil {
		return unsafeView, fmt.Errorf("inspect opened persistent enforcement directory: %w", err)
	}
	directoryIdentity, err := persistentEnforcementDirectoryIdentityFromInfo(directoryInfo)
	if err != nil {
		return unsafeView, err
	}

	lock, err := directory.Open(".")
	if err != nil {
		return unsafeView, fmt.Errorf("open persistent enforcement directory lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		return unsafeView, fmt.Errorf("lock persistent enforcement directory: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	view := persistentEnforcementView{attested: true, entries: []persistentEnforcementEntry{}}
	snapshots := make([]persistentEnforcementFileSnapshot, 0, 2)
	seen := make(map[string]struct{})
	files := []struct {
		name string
		ipv6 bool
	}{
		{name: persistentEnforcementIPv4File, ipv6: false},
		{name: persistentEnforcementIPv6File, ipv6: true},
	}
	for _, expected := range files {
		wire, snapshot, err := readPersistentEnforcementFile(directory, expected.name, hook)
		if err != nil {
			return unsafeView, err
		}
		snapshots = append(snapshots, snapshot)
		entries, err := parsePersistentEnforcementEntries(wire, expected.ipv6, seen)
		if err != nil {
			return unsafeView, fmt.Errorf("validate %s: %w", expected.name, err)
		}
		view.entries = append(view.entries, entries...)
	}
	for _, snapshot := range snapshots {
		if err := reattestPersistentEnforcementFile(directory, snapshot); err != nil {
			return unsafeView, fmt.Errorf("persistent enforcement snapshot changed: %w", err)
		}
	}
	currentDirectoryInfo, err := directory.Stat(".")
	if err != nil {
		return unsafeView, fmt.Errorf("reattest persistent enforcement directory: %w", err)
	}
	currentDirectoryIdentity, err := persistentEnforcementDirectoryIdentityFromInfo(currentDirectoryInfo)
	if err != nil || !samePersistentEnforcementDirectoryIdentity(directoryIdentity, currentDirectoryIdentity) {
		return unsafeView, fmt.Errorf("persistent enforcement directory identity changed during snapshot")
	}
	return view, nil
}

func openPersistentEnforcementDirectory(path string) (*os.Root, error) {
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for persistent enforcement: %w", err)
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "/"), "/") {
		if component == "" {
			continue
		}
		before, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect persistent enforcement directory component %q: %w", component, err)
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, fmt.Errorf("persistent enforcement directory component %q is not a real directory", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open persistent enforcement directory component %q: %w", component, err)
		}
		opened, err := next.Stat(".")
		if err != nil || !opened.IsDir() || !os.SameFile(before, opened) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("persistent enforcement directory component %q changed while opening", component)
		}
		_ = current.Close()
		current = next
	}
	info, err := current.Stat(".")
	if err != nil {
		_ = current.Close()
		return nil, fmt.Errorf("inspect persistent enforcement directory: %w", err)
	}
	if _, err := persistentEnforcementDirectoryIdentityFromInfo(info); err != nil {
		_ = current.Close()
		return nil, err
	}
	return current, nil
}

func readPersistentEnforcementFile(
	directory *os.Root,
	name string,
	hook persistentEnforcementReadHook,
) ([]byte, persistentEnforcementFileSnapshot, error) {
	snapshot := persistentEnforcementFileSnapshot{name: name}
	if name != persistentEnforcementIPv4File && name != persistentEnforcementIPv6File {
		return nil, snapshot, fmt.Errorf("persistent enforcement file name is not approved")
	}
	before, err := directory.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		if hook != nil {
			hook("missing", name)
		}
		return nil, snapshot, fmt.Errorf("persistent enforcement file %s is missing", name)
	}
	if err != nil {
		return nil, snapshot, fmt.Errorf("inspect persistent enforcement file %s: %w", name, err)
	}
	identity, err := persistentEnforcementIdentityFromInfo(before)
	if err != nil {
		return nil, snapshot, fmt.Errorf("unsafe persistent enforcement file %s: %w", name, err)
	}
	file, err := directory.Open(name)
	if err != nil {
		return nil, snapshot, fmt.Errorf("open persistent enforcement file %s: %w", name, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, snapshot, fmt.Errorf("inspect opened persistent enforcement file %s: %w", name, err)
	}
	openedIdentity, err := persistentEnforcementIdentityFromInfo(opened)
	if err != nil || !samePersistentEnforcementIdentity(identity, openedIdentity) {
		return nil, snapshot, fmt.Errorf("persistent enforcement file %s changed while opening", name)
	}
	if hook != nil {
		hook("opened", name)
	}
	wire, err := io.ReadAll(io.LimitReader(file, maximumPersistentEnforcementBytes+1))
	if err != nil {
		return nil, snapshot, fmt.Errorf("read persistent enforcement file %s: %w", name, err)
	}
	if int64(len(wire)) > maximumPersistentEnforcementBytes || int64(len(wire)) != identity.size {
		return nil, snapshot, fmt.Errorf("persistent enforcement file %s size is inconsistent", name)
	}
	if hook != nil {
		hook("read", name)
	}
	afterRead, err := file.Stat()
	if err != nil {
		return nil, snapshot, fmt.Errorf("reattest opened persistent enforcement file %s: %w", name, err)
	}
	afterReadIdentity, err := persistentEnforcementIdentityFromInfo(afterRead)
	if err != nil || !samePersistentEnforcementIdentity(identity, afterReadIdentity) {
		return nil, snapshot, fmt.Errorf("persistent enforcement file %s changed during read", name)
	}
	snapshot.present = true
	snapshot.identity = identity
	if err := reattestPersistentEnforcementFile(directory, snapshot); err != nil {
		return nil, snapshot, err
	}
	return wire, snapshot, nil
}

func persistentEnforcementDirectoryIdentityFromInfo(info fs.FileInfo) (persistentEnforcementDirectoryIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) {
		return persistentEnforcementDirectoryIdentity{}, fmt.Errorf("persistent enforcement directory must be an EUID/EGID-owned real directory without group or world write access")
	}
	return persistentEnforcementDirectoryIdentity{
		info: info, mode: info.Mode(), device: uint64(stat.Dev), inode: stat.Ino, uid: stat.Uid, gid: stat.Gid,
	}, nil
}

func samePersistentEnforcementDirectoryIdentity(left, right persistentEnforcementDirectoryIdentity) bool {
	return os.SameFile(left.info, right.info) && left.mode == right.mode && left.device == right.device &&
		left.inode == right.inode && left.uid == right.uid && left.gid == right.gid
}

func persistentEnforcementIdentityFromInfo(info fs.FileInfo) (persistentEnforcementFileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode() != 0600 || int64(stat.Uid) != int64(os.Geteuid()) ||
		int64(stat.Gid) != int64(os.Getegid()) || stat.Nlink != 1 || info.Size() < 0 || info.Size() > maximumPersistentEnforcementBytes {
		return persistentEnforcementFileIdentity{}, fmt.Errorf("expected an EUID/EGID-owned regular 0600 file with one link and bounded size")
	}
	return persistentEnforcementFileIdentity{
		info: info, mode: info.Mode(), device: uint64(stat.Dev), inode: stat.Ino,
		uid: stat.Uid, gid: stat.Gid, links: stat.Nlink, size: info.Size(),
		mtimeSec: stat.Mtim.Sec, mtimeNsec: stat.Mtim.Nsec,
		ctimeSec: stat.Ctim.Sec, ctimeNsec: stat.Ctim.Nsec,
	}, nil
}

func samePersistentEnforcementIdentity(left, right persistentEnforcementFileIdentity) bool {
	return os.SameFile(left.info, right.info) && left.mode == right.mode && left.device == right.device &&
		left.inode == right.inode && left.uid == right.uid && left.gid == right.gid && left.links == right.links &&
		left.size == right.size && left.mtimeSec == right.mtimeSec && left.mtimeNsec == right.mtimeNsec &&
		left.ctimeSec == right.ctimeSec && left.ctimeNsec == right.ctimeNsec
}

func reattestPersistentEnforcementFile(directory *os.Root, snapshot persistentEnforcementFileSnapshot) error {
	current, err := directory.Lstat(snapshot.name)
	if !snapshot.present {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("persistent enforcement file %s appeared during snapshot", snapshot.name)
	}
	if err != nil {
		return fmt.Errorf("inspect persistent enforcement file %s after read: %w", snapshot.name, err)
	}
	identity, err := persistentEnforcementIdentityFromInfo(current)
	if err != nil || !samePersistentEnforcementIdentity(snapshot.identity, identity) {
		return fmt.Errorf("persistent enforcement file %s identity changed", snapshot.name)
	}
	return nil
}

func parsePersistentEnforcementEntries(
	wire []byte,
	expectIPv6 bool,
	seen map[string]struct{},
) ([]persistentEnforcementEntry, error) {
	if len(wire) == 0 {
		return []persistentEnforcementEntry{}, nil
	}
	if wire[len(wire)-1] != '\n' {
		return nil, fmt.Errorf("persistent enforcement file is not newline terminated")
	}
	lines := strings.Split(string(wire[:len(wire)-1]), "\n")
	entries := make([]persistentEnforcementEntry, 0, len(lines))
	for index, line := range lines {
		if line == "" || strings.TrimSpace(line) != line {
			return nil, fmt.Errorf("line %d is empty or contains surrounding whitespace", index+1)
		}
		entry, semanticIdentity, err := canonicalPersistentEnforcementEntry(line, expectIPv6)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		if _, duplicate := seen[semanticIdentity]; duplicate {
			return nil, fmt.Errorf("line %d duplicates an existing enforcement entry", index+1)
		}
		seen[semanticIdentity] = struct{}{}
		entries = append(entries, entry)
	}
	return entries, nil
}

func canonicalPersistentEnforcementEntry(
	raw string,
	expectIPv6 bool,
) (persistentEnforcementEntry, string, error) {
	if address, err := netip.ParseAddr(raw); err == nil {
		if address.Is4In6() || address.Zone() != "" || address.Is6() != expectIPv6 || address.String() != raw {
			return persistentEnforcementEntry{}, "", fmt.Errorf("address is non-canonical or has the wrong family")
		}
		bits := 32
		if address.Is6() {
			bits = 128
		}
		prefix := netip.PrefixFrom(address, bits)
		return persistentEnforcementEntry{canonical: raw, prefix: prefix}, prefix.String(), nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
		prefix.Addr().Is6() != expectIPv6 || prefix.Masked() != prefix || prefix.String() != raw {
		return persistentEnforcementEntry{}, "", fmt.Errorf("CIDR is non-canonical or has the wrong family")
	}
	return persistentEnforcementEntry{canonical: raw, prefix: prefix}, prefix.String(), nil
}
