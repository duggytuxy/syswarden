package journal

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var ErrAuthorityRuntimeInputs = errors.New("invalid protected authority runtime directories")

// OpenAuthorityRuntimeDirectories acquires existing fixed state and endpoint
// children from separately trusted root-owned parents. The state parent must be
// 0700 and the endpoint parent 0755; both require GID 0 and no ACL. Exact service
// and client identities come only from the independently pinned launch record.
// The caller retains all inputs and owns both returned readable CLOEXEC handles.
// Failure returns neither handle. No directory, lease, socket or account is
// created, repaired or removed. This is not approval or initial path discovery:
// trusted provisioning must protect parent ancestry, namespace and digest origin.
func OpenAuthorityRuntimeDirectories(stateParent, endpointParent, launch *os.File, launchDigest string) (*os.File, *os.File, error) {
	if stateParent == nil || endpointParent == nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	c, err := LoadAuthorityLaunch(launch, launchDigest)
	if err != nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	stateRaw, err := stateParent.SyscallConn()
	if err != nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	endpointRaw, err := endpointParent.SyscallConn()
	if err != nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	var state, endpoint *os.File
	operation := ErrAuthorityRuntimeInputs
	var endpointControl error
	err = stateRaw.Control(func(sfd uintptr) {
		endpointControl = endpointRaw.Control(func(efd uintptr) {
			state, endpoint, operation = openAuthorityRuntimeDirectories(int(sfd), int(efd), c)
		})
	})
	fail := func() (*os.File, *os.File, error) {
		if state != nil {
			_ = state.Close()
		}
		if endpoint != nil {
			_ = endpoint.Close()
		}
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	if err != nil || endpointControl != nil || operation != nil {
		return fail()
	}
	// A held named record can still change. Require the same independently
	// approved bytes after acquisition; sealing and deployment freshness are separate.
	if _, err := LoadAuthorityLaunch(launch, launchDigest); err != nil {
		return fail()
	}
	return state, endpoint, nil
}

func openAuthorityRuntimeDirectories(stateParent, endpointParent int, c AuthorityLaunch) (_ *os.File, _ *os.File, result error) {
	sp, err := attestAuthorityRuntimeDirectory(stateParent, 0, 0, 0700)
	if err != nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	ep, err := attestAuthorityRuntimeDirectory(endpointParent, 0, 0, 0755)
	if err != nil || sameAuthorityRuntimeObject(sp, ep) {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	var state, endpoint *os.File
	defer func() {
		if result != nil {
			if state != nil {
				_ = state.Close()
			}
			if endpoint != nil {
				_ = endpoint.Close()
			}
		}
	}()
	state, ss, err := openAuthorityRuntimeDirectory(stateParent, "state", c.ServiceUID, c.ServiceGID, 0700)
	if err != nil {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	endpoint, es, err := openAuthorityRuntimeDirectory(endpointParent, "endpoint", c.ServiceUID, c.EndpointGID, 0750)
	if err != nil || sameAuthorityRuntimeObject(ss, es) {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	spAfter, err := attestAuthorityRuntimeDirectory(stateParent, 0, 0, 0700)
	if err != nil || !sameStamp(sp, spAfter) {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	epAfter, err := attestAuthorityRuntimeDirectory(endpointParent, 0, 0, 0755)
	if err != nil || !sameStamp(ep, epAfter) {
		return nil, nil, ErrAuthorityRuntimeInputs
	}
	for _, item := range []struct {
		parent int
		name   string
		file   *os.File
		stamp  unix.Stat_t
	}{{stateParent, "state", state, ss}, {endpointParent, "endpoint", endpoint, es}} {
		// Recheck both metadata and the exact entry before transferring ownership.
		if !authorityInputStillBound(item.parent, item.name, item.file, item.stamp) {
			return nil, nil, ErrAuthorityRuntimeInputs
		}
		if noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(int(item.file.Fd()), name, nil) }) != nil {
			return nil, nil, ErrAuthorityRuntimeInputs
		}
	}
	return state, endpoint, nil
}

func sameAuthorityRuntimeObject(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func validAuthorityRuntimeDirectory(st unix.Stat_t, uid, gid, mode uint32) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFDIR|mode && st.Uid == uid && st.Gid == gid && st.Nlink > 0
}

func attestAuthorityRuntimeDirectory(fd int, uid, gid, mode uint32) (unix.Stat_t, error) {
	var st unix.Stat_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return st, ErrAuthorityRuntimeInputs
	}
	if unix.Fstat(fd, &st) != nil || !validAuthorityRuntimeDirectory(st, uid, gid, mode) {
		return st, ErrAuthorityRuntimeInputs
	}
	if noAuthorityACL(func(name string) (int, error) { return unix.Fgetxattr(fd, name, nil) }) != nil {
		return st, ErrAuthorityRuntimeInputs
	}
	return st, nil
}

func openAuthorityRuntimeDirectory(parent int, name string, uid, gid, mode uint32) (*os.File, unix.Stat_t, error) {
	var before unix.Stat_t
	if unix.Fstatat(parent, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || !validAuthorityRuntimeDirectory(before, uid, gid, mode) {
		return nil, before, ErrAuthorityRuntimeInputs
	}
	fd, err := openAuthorityRuntimeDirectoryFD(parent, name, unix.Openat2)
	if err != nil {
		return nil, before, ErrAuthorityRuntimeInputs
	}
	file := os.NewFile(uintptr(fd), "authority-runtime-"+name)
	after, err := attestAuthorityRuntimeDirectory(fd, uid, gid, mode)
	if err != nil || !sameStamp(before, after) {
		_ = file.Close()
		return nil, before, ErrAuthorityRuntimeInputs
	}
	return file, after, nil
}

func openAuthorityRuntimeDirectoryFD(parent int, name string, open func(int, string, *unix.OpenHow) (int, error)) (int, error) {
	if parent < 0 || (name != "state" && name != "endpoint") || open == nil {
		return -1, ErrAuthorityRuntimeInputs
	}
	return open(parent, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}
