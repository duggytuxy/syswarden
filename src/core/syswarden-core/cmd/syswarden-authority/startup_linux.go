package main

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
	"syswarden-core/journal"
)

type startupIdentity struct {
	uids, gids      [3]int
	groups          []int
	caps            [2]unix.CapUserData
	noNewPrivileges int
}

// This executable accepts an already confined launch. It never repairs or
// drops an unexpected identity. In particular, no_new_privs must precede exec:
// setting it on one Go thread would not constrain the other runtime threads.
func prepareAuthorityProcess(files [4]*os.File, digest string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	launch, err := journal.LoadAuthorityLaunch(files[0], digest)
	if err != nil {
		return err
	}
	var id startupIdentity
	id.uids[0], id.uids[1], id.uids[2] = unix.Getresuid()
	id.gids[0], id.gids[1], id.gids[2] = unix.Getresgid()
	id.groups, err = unix.Getgroups()
	if err != nil {
		return err
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &id.caps[0]); err != nil {
		return err
	}
	id.noNewPrivileges, err = unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if !validStartupIdentity(id, launch.ServiceUID, launch.ServiceGID, launch.EndpointGID) {
		return errors.New("unexpected authority process privileges")
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if dumpable != 0 {
		return errors.New("authority process remains dumpable")
	}
	for _, file := range files {
		if err := sealStartupDescriptor(file); err != nil {
			return err
		}
	}
	unix.Umask(0077)
	return nil
}

func validStartupIdentity(id startupIdentity, uid, gid, endpointGID uint32) bool {
	const maxID = 1<<31 - 1
	if uid == 0 || uid > maxID || gid == 0 || gid > maxID || endpointGID == 0 || endpointGID > maxID || id.noNewPrivileges != 1 {
		return false
	}
	for i := range id.uids {
		if id.uids[i] != int(uid) || id.gids[i] != int(gid) {
			return false
		}
	}
	if len(id.groups) == 0 {
		if gid != endpointGID {
			return false
		}
	} else if len(id.groups) != 1 || id.groups[0] != int(endpointGID) {
		return false
	}
	for _, caps := range id.caps {
		if caps.Effective != 0 || caps.Permitted != 0 || caps.Inheritable != 0 {
			return false
		}
	}
	// Linux requires every ambient capability to be both permitted and
	// inheritable. Empty sets above therefore also exclude ambient authority.
	return true
}

func sealStartupDescriptor(file *os.File) error {
	if file == nil {
		return errors.New("missing authority startup descriptor")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var operation error
	err = raw.Control(func(fd uintptr) {
		flags, e := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if e != nil {
			operation = e
			return
		}
		if _, e = unix.FcntlInt(fd, unix.F_SETFD, flags|unix.FD_CLOEXEC); e != nil {
			operation = e
			return
		}
		flags, e = unix.FcntlInt(fd, unix.F_GETFD, 0)
		operation = e
		if e == nil && flags&unix.FD_CLOEXEC == 0 {
			operation = errors.New("unsealed authority startup descriptor")
		}
	})
	return errors.Join(err, operation)
}
