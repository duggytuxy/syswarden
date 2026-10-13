package journal

import (
	"errors"
	"math"
	"net"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const AuthoritySocketName = "authority-v1.sock"

var ErrAuthorityEndpoint = errors.New("unsafe local authority endpoint")

// authoritySocket owns a descriptor-relative endpoint and an independent
// directory lock. Only trusted provisioning chooses its directory and group.
// Client-reachable directories must be distinct from private authority storage.
type authoritySocket struct {
	mu        sync.Mutex
	directory *os.File
	listener  *net.UnixListener
	dirStamp  unix.Stat_t
	entry     unix.Stat_t
	path      string
	bound     bool
	closed    bool
	closeErr  error
}

func noAuthorityACL(get func(string) (int, error)) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		n, err := get(name)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
			continue
		}
		if err != nil || n != 0 {
			return errors.Join(ErrAuthorityEndpoint, err)
		}
	}
	return nil
}
func authoritySocketDirectory(dir *os.File, group uint32) (unix.Stat_t, error) {
	var st unix.Stat_t
	if dir == nil {
		return st, ErrAuthorityEndpoint
	}
	fd := int(dir.Fd())
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&(unix.S_IFMT|07777) != unix.S_IFDIR|0750 || int64(st.Uid) != int64(os.Geteuid()) || st.Gid != group || st.Nlink == 0 {
		return st, errors.Join(ErrAuthorityEndpoint, err)
	}
	err := noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) })
	return st, err
}
func openAuthoritySocket(directory *os.File, group uint32, backlog int) (*authoritySocket, error) {
	if directory == nil || group > math.MaxInt32 || backlog < 1 || backlog > MaxAuthorityPeers {
		return nil, ErrInvalidOptions
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err)
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrAuthorityEndpoint, err, openErr)
	}
	s := &authoritySocket{directory: os.NewFile(uintptr(fd), "authority-socket-directory")}
	fail := func(err error) (*authoritySocket, error) { return nil, errors.Join(err, s.Close()) }
	s.dirStamp, err = authoritySocketDirectory(s.directory, group)
	if err != nil {
		return fail(err)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(errors.Join(ErrLocked, err))
	}
	// Linux bind has no bindat. Resolve the fixed basename through our owned
	// descriptor, not the caller's mutable path or working directory.
	s.path = "/proc/self/fd/" + strconv.Itoa(fd) + "/" + AuthoritySocketName
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	file := os.NewFile(uintptr(socket), "authority-listening-socket")
	defer func() { _ = file.Close() }()
	if err = unix.Bind(socket, &unix.SockaddrUnix{Name: s.path}); err != nil {
		// Existing paths, including stale sockets, are never removed here.
		return fail(err)
	}
	if err = unix.Fstatat(fd, AuthoritySocketName, &s.entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || s.entry.Mode&unix.S_IFMT != unix.S_IFSOCK || s.entry.Uid != s.dirStamp.Uid || s.entry.Nlink != 1 {
		// Without a proven inode, preserve the entry for separate inspection.
		return fail(errors.Join(ErrAuthorityEndpoint, err))
	}
	s.bound = true
	if err = unix.Fchownat(fd, AuthoritySocketName, -1, int(group), unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	s.entry.Gid = group
	if err = unix.Fchmodat(fd, AuthoritySocketName, 0660, 0); err != nil {
		return fail(err)
	}
	s.entry.Mode = unix.S_IFSOCK | 0660
	if err = s.attestLocked(); err != nil {
		return fail(err)
	}
	// No accept is possible until final permissions and ownership are proven.
	if err = unix.Listen(socket, backlog); err != nil {
		return fail(err)
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return fail(err)
	}
	l, ok := listener.(*net.UnixListener)
	if !ok {
		return fail(errors.Join(ErrAuthorityEndpoint, listener.Close()))
	}
	l.SetUnlinkOnClose(false)
	s.listener = l
	if err = s.attestLocked(); err != nil {
		return fail(err)
	}
	return s, nil
}
func (s *authoritySocket) attestLocked() error {
	if s.closed || !s.bound {
		return ErrClosed
	}
	dir, err := authoritySocketDirectory(s.directory, s.dirStamp.Gid)
	if err != nil || dir.Dev != s.dirStamp.Dev || dir.Ino != s.dirStamp.Ino {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	var entry unix.Stat_t
	if err = unix.Fstatat(int(s.directory.Fd()), AuthoritySocketName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || entry.Mode&(unix.S_IFMT|07777) != unix.S_IFSOCK|0660 || entry.Uid != dir.Uid || entry.Gid != dir.Gid || entry.Nlink != 1 || entry.Dev != s.entry.Dev || entry.Ino != s.entry.Ino {
		return errors.Join(ErrAuthorityEndpoint, err)
	}
	return noAuthorityACL(func(name string) (int, error) { return unix.Lgetxattr(s.path, name, nil) })
}
func (s *authoritySocket) Attest() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attestLocked()
}

// Close never uses Go's automatic pathname unlink. A changed or unprovable entry
// is retained, even on startup failure; it must not be silently reclaimed later.
func (s *authoritySocket) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	if s.listener != nil {
		s.closeErr = s.listener.Close()
	}
	if s.bound {
		dir, err := authoritySocketDirectory(s.directory, s.dirStamp.Gid)
		var entry unix.Stat_t
		if err == nil {
			err = unix.Fstatat(int(s.directory.Fd()), AuthoritySocketName, &entry, unix.AT_SYMLINK_NOFOLLOW)
		}
		if err == nil {
			err = noAuthorityACL(func(name string) (int, error) { return unix.Lgetxattr(s.path, name, nil) })
		}
		if err != nil || dir.Dev != s.dirStamp.Dev || dir.Ino != s.dirStamp.Ino || entry.Mode != s.entry.Mode || entry.Gid != s.entry.Gid || entry.Uid != s.entry.Uid || entry.Dev != s.entry.Dev || entry.Ino != s.entry.Ino || entry.Nlink != 1 {
			s.closeErr = errors.Join(s.closeErr, ErrAuthorityEndpoint, err)
		} else {
			s.closeErr = errors.Join(s.closeErr, unix.Unlinkat(int(s.directory.Fd()), AuthoritySocketName, 0))
		}
	}
	if s.directory != nil {
		s.closeErr = errors.Join(s.closeErr, s.directory.Close())
	}
	s.closed = true
	return s.closeErr
}
