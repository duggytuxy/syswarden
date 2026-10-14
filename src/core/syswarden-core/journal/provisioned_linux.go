package journal

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

func authorityLayoutNames() [5]string {
	return [5]string{"policy", "custody", "anchors", "journal", "endpoint-pin"}
}

// authorityLayout owns an independent root lease and five fixed child directory
// references. Child leases belong to the actual authority and endpoint handles.
// It neither creates provisioning nor discovers trust from directory contents.
type authorityLayout struct {
	mu       sync.Mutex
	root     *os.File
	dirs     [5]*os.File
	stamps   [6]unix.Stat_t
	closed   bool
	closeErr error
}

func layoutDirectory(dir *os.File) (unix.Stat_t, error) {
	var st unix.Stat_t
	if dir == nil {
		return st, ErrUnsafeStorage
	}
	fd := int(dir.Fd())
	if err := unix.Fstat(fd, &st); err != nil || !privateDirectory(st) {
		return st, errors.Join(ErrUnsafeStorage, err)
	}
	if err := noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) }); err != nil {
		return st, errors.Join(ErrUnsafeStorage, err)
	}
	return st, nil
}

func openAuthorityLayout(directory *os.File) (*authorityLayout, error) {
	root, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	l := &authorityLayout{root: root}
	fail := func(err error) (*authorityLayout, error) { return nil, errors.Join(err, l.close()) }
	l.stamps[0], err = layoutDirectory(root)
	if err != nil {
		return fail(err)
	}
	for i, name := range authorityLayoutNames() {
		fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(errors.Join(ErrUnsafeStorage, err))
		}
		l.dirs[i] = os.NewFile(uintptr(fd), "authority-layout-"+name)
		l.stamps[i+1], err = layoutDirectory(l.dirs[i])
		if err != nil || l.stamps[i+1].Dev != l.stamps[0].Dev {
			return fail(errors.Join(ErrUnsafeStorage, err))
		}
		for j := 0; j <= i; j++ {
			if l.stamps[j].Dev == l.stamps[i+1].Dev && l.stamps[j].Ino == l.stamps[i+1].Ino {
				return fail(ErrUnsafeStorage)
			}
		}
	}
	if err := l.attest(); err != nil {
		return fail(err)
	}
	return l, nil
}

func sameLayoutDirectory(current, expected unix.Stat_t) bool {
	return current.Dev == expected.Dev && current.Ino == expected.Ino && current.Gid == expected.Gid
}

func (l *authorityLayout) attest() error {
	if l == nil {
		return nil // The original explicit-descriptor server has no layout owner.
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	root, err := layoutDirectory(l.root)
	if err != nil || !sameLayoutDirectory(root, l.stamps[0]) {
		return errors.Join(ErrUnsafeStorage, err)
	}
	for i, name := range authorityLayoutNames() {
		st, err := layoutDirectory(l.dirs[i])
		if err != nil || !sameLayoutDirectory(st, l.stamps[i+1]) {
			return errors.Join(ErrUnsafeStorage, err)
		}
		var entry unix.Stat_t
		if err := unix.Fstatat(int(l.root.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateDirectory(entry) || !sameLayoutDirectory(entry, st) {
			return errors.Join(ErrUnsafeStorage, err)
		}
	}
	return nil
}

func (l *authorityLayout) close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.closeErr
	}
	for _, dir := range l.dirs {
		if dir != nil {
			l.closeErr = errors.Join(l.closeErr, dir.Close())
		}
	}
	l.closeErr = errors.Join(l.closeErr, l.root.Close())
	l.closed = true
	return l.closeErr
}

// OpenProvisionedAuthorityServer opens the existing server from one trusted,
// service-owned 0700 state directory and a separately provisioned endpoint.
// The state directory must already contain five distinct same-filesystem 0700
// children: policy, custody, anchors, journal and endpoint-pin. ACLs are refused.
// All five per-resource descriptors in c must be nil; conflicting startup input
// is rejected rather than ignored. Independent roots, enrollment, authorizers,
// limits and the endpoint directory/group are still explicit trusted inputs.
// It creates no directories, accounts, grants or enrollment. The existing server
// creates only its owned socket, receipt and private pin after validation.
func OpenProvisionedAuthorityServer(directory *os.File, c AuthorityServerConfig) (*LocalAuthorityServer, error) {
	if c.Authority.PolicyDirectory != nil || c.Authority.CustodyDirectory != nil || c.Authority.AnchorDirectory != nil || c.Authority.JournalDirectory != nil || c.PinDirectory != nil {
		return nil, ErrInvalidOptions
	}
	l, err := openAuthorityLayout(directory)
	if err != nil {
		return nil, err
	}
	c.Authority.PolicyDirectory, c.Authority.CustodyDirectory = l.dirs[0], l.dirs[1]
	c.Authority.AnchorDirectory, c.Authority.JournalDirectory = l.dirs[2], l.dirs[3]
	c.PinDirectory = l.dirs[4]
	s, err := OpenLocalAuthorityServer(c)
	if err != nil {
		return nil, errors.Join(err, l.close())
	}
	s.layout = l
	if err := l.attest(); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}
