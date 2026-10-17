//go:build linux

package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// TrustedLogAccess is an immutable per-file authorization selected from root-
// controlled configuration. ProducerUID is never inferred from file metadata.
// Keep this contract identical in the independently built CLI and core modules.
type TrustedLogAccess struct {
	AuthorityUID int64
	ProducerUID  *uint32
}

func (access TrustedLogAccess) accepts(uid uint32) bool {
	return int64(uid) == access.AuthorityUID || access.ProducerUID != nil && uid == *access.ProducerUID
}

func (access TrustedLogAccess) ValidateFile(identity unix.Stat_t, allowUnlinked bool) error {
	if identity.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a real regular file")
	}
	if !access.accepts(identity.Uid) {
		return fmt.Errorf("owner UID %d is not an explicitly authorized log producer", identity.Uid)
	}
	if identity.Mode&0022 != 0 {
		return fmt.Errorf("group or other write bits are set")
	}
	if identity.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return fmt.Errorf("special permission bits are set")
	}
	if identity.Nlink != 1 && !(allowUnlinked && identity.Nlink == 0) {
		return fmt.Errorf("log must have one link")
	}
	return nil
}

func (access TrustedLogAccess) validateParent(identity unix.Stat_t, intermediate bool) error {
	if identity.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("log parent is not a directory")
	}
	if identity.Uid != 0 && !access.accepts(identity.Uid) {
		return fmt.Errorf("log parent owner UID %d is not authorized", identity.Uid)
	}
	// A trusted sticky ancestor such as /tmp can contain an owner-controlled
	// private directory. Never accept a writable immediate parent.
	if identity.Mode&0022 != 0 && !(intermediate && identity.Mode&unix.S_ISVTX != 0) {
		return fmt.Errorf("log parent is writable by another identity")
	}
	if identity.Mode&unix.S_ISUID != 0 {
		return fmt.Errorf("log parent has unsafe special permissions")
	}
	return nil
}

// OpenParent pins every ancestor and refuses symbolic links. The caller owns fd.
func (access TrustedLogAccess) OpenParent(path string) (int, string, error) {
	if len(path) > 4096 || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return -1, "", fmt.Errorf("log path must be absolute and canonical")
	}
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for i := -1; i < len(components)-1; i++ {
		if i >= 0 {
			next, openErr := unix.Openat(fd, components[i], unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return -1, "", openErr
			}
			fd = next
		}
		var identity unix.Stat_t
		if err := unix.Fstat(fd, &identity); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
		if err := access.validateParent(identity, i < len(components)-2); err != nil {
			_ = unix.Close(fd)
			return -1, "", err
		}
	}
	return fd, components[len(components)-1], nil
}

// OpenFile returns a verified descriptor in a previously pinned parent.
func (access TrustedLogAccess) OpenFile(parent int, name string) (int, unix.Stat_t, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return -1, unix.Stat_t{}, fmt.Errorf("invalid log basename")
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, unix.Stat_t{}, err
	}
	fail := func(err error) (int, unix.Stat_t, error) { _ = unix.Close(fd); return -1, unix.Stat_t{}, err }
	var opened, linked unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return fail(err)
	}
	if err := access.ValidateFile(opened, false); err != nil {
		return fail(err)
	}
	if err := unix.Fstatat(parent, name, &linked, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	if err := access.ValidateFile(linked, false); err != nil {
		return fail(err)
	}
	if opened.Dev != linked.Dev || opened.Ino != linked.Ino || opened.Mode != linked.Mode || opened.Uid != linked.Uid || opened.Gid != linked.Gid || opened.Nlink != linked.Nlink {
		return fail(fmt.Errorf("log identity changed while opening"))
	}
	return fd, opened, nil
}
