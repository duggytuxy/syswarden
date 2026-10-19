//go:build linux

package sshpolicy

import (
	"errors"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

const vendorSSHPath = "/etc/crypto-policies/back-ends/opensshserver.config"

// Only the standard crypto-policies terminal alias is supported. A recognized
// name is not ownership, package provenance or permission to change its policy.
// The target, all ancestors and the link itself are independently inspected.
func vendorTarget(name string) bool {
	const prefix = "/usr/share/crypto-policies/"
	const suffix = "/opensshserver.txt"
	if !safePath(name) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if len(label) == 0 || len(label) > 128 || label[0] == ':' || label[len(label)-1] == ':' || strings.Contains(label, "::") {
		return false
	}
	for _, ch := range label {
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == ':') {
			return false
		}
	}
	return true
}

func (reader *inventoryReader) trustedVendorLink(name string, st unix.Stat_t) bool {
	// Linux symlink permission bits are not a write authority. The pinned,
	// protected parent and exact link owner provide the ordinary-UID boundary.
	return name == vendorSSHPath && st.Mode&unix.S_IFMT == unix.S_IFLNK && st.Mode&07000 == 0 &&
		int64(st.Uid) == int64(reader.uid) && st.Nlink == 1 && st.Size > 0 && st.Size <= 1024
}

func (reader *inventoryReader) readVendorLink(parent *os.File, name string, before unix.Stat_t) ([]byte, bool, error) {
	if !reader.trustedVendorLink(name, before) {
		return nil, false, ErrInventoryUnsafe
	}
	fd, err := unix.Openat(int(parent.Fd()), path.Base(name), unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, errors.Join(ErrInventoryUnsafe, err)
	}
	link := os.NewFile(uintptr(fd), "ssh-inventory-vendor-link")
	defer link.Close()
	var opened, after, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || stamp(before) != stamp(opened) {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	var buffer [1025]byte
	count, err := unix.Readlinkat(fd, "", buffer[:])
	if err != nil || int64(count) != opened.Size || count > 1024 {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	target := string(buffer[:count])
	if !vendorTarget(target) {
		return nil, false, ErrInventoryUnsafe
	}
	// The target is not an allowed alias source, so readFile cannot recurse
	// through another link. Missing targets are errors, not absent Includes.
	content, exists, err := reader.readFile(target)
	if err != nil || !exists {
		return nil, false, errors.Join(ErrInventoryUnsafe, err)
	}
	err = errors.Join(unix.Fstat(fd, &after), unix.Fstatat(int(parent.Fd()), path.Base(name), &named, unix.AT_SYMLINK_NOFOLLOW))
	if err != nil || stamp(opened) != stamp(after) || stamp(after) != stamp(named) {
		return nil, false, errors.Join(ErrInventoryChanged, err)
	}
	if len(reader.state.files) >= MaxFiles || len(content) > MaxBytes-reader.bytes {
		return nil, false, ErrInventoryBounds
	}
	if err := reader.observe(name, stamp(after)); err != nil {
		return nil, false, err
	}
	// Retain both logical Include inputs. This deliberately counts the bytes
	// twice, matching the bounded pure preparer's path/content inventory.
	reader.state.files[name] = content
	reader.state.links[name] = target
	reader.bytes += len(content)
	return content, true, nil
}
