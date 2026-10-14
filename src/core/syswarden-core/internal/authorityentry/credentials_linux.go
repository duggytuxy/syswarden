package authorityentry

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

var errAuthorityCredentials = errors.New("invalid authority credential transition")

func exactRootIdentity(uids, gids [3]int) bool {
	return uids == [3]int{} && gids == [3]int{}
}

func dropAuthorityCredentials(uid, gid, endpointGID uint32) error {
	// These stdlib credential wrappers synchronize Go threads, and use libc's
	// process-wide wrappers when cgo is linked. A raw thread-only setgroups call
	// would leave other runtime threads with the inherited supplementary groups.
	return changeAuthorityCredentials(uid, gid, endpointGID, credentialOperations{
		prepare: prepareCredentialDrop,
		groups:  syscall.Setgroups,
		gids:    syscall.Setresgid,
		uids:    syscall.Setresuid,
		clear: func() error {
			header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
			var empty [2]unix.CapUserData
			return unix.Capset(&header, &empty[0])
		},
	})
}

type credentialOperations struct {
	prepare    func() error
	groups     func([]int) error
	gids, uids func(int, int, int) error
	clear      func() error
}

func changeAuthorityCredentials(uid, gid, endpointGID uint32, ops credentialOperations) error {
	const maxID = 1<<31 - 1
	if uid == 0 || uid > maxID || gid == 0 || gid > maxID || endpointGID == 0 || endpointGID > maxID {
		return errAuthorityCredentials
	}
	if err := ops.prepare(); err != nil {
		return err
	}
	if err := ops.groups([]int{int(endpointGID)}); err != nil {
		return err
	}
	if err := ops.gids(int(gid), int(gid), int(gid)); err != nil {
		return err
	}
	if err := ops.uids(int(uid), int(uid), int(uid)); err != nil {
		return err
	}
	return ops.clear()
}

func prepareCredentialDrop() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}
	keep, err := unix.PrctlRetInt(unix.PR_GET_KEEPCAPS, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if keep != 0 {
		return errAuthorityCredentials
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	return clearAuthorityBoundingSet(func(cap uintptr) (int, error) { return unix.PrctlRetInt(unix.PR_CAPBSET_READ, cap, 0, 0, 0) }, func(cap uintptr) error { return unix.Prctl(unix.PR_CAPBSET_DROP, cap, 0, 0, 0) })
}

// Discover the kernel's end marker, with a hard bound matching the two-word
// capability ABI. Any unknown capability range or uncertain readback fails.
// The locked exec thread's empty set is inherited by all target runtime threads.
func clearAuthorityBoundingSet(read func(uintptr) (int, error), drop func(uintptr) error) error {
	for cap := uintptr(0); cap <= 64; cap++ {
		value, err := read(cap)
		if errors.Is(err, unix.EINVAL) && cap > 0 {
			return nil
		}
		if err != nil {
			return err
		}
		if cap == 64 || (value != 0 && value != 1) {
			return errAuthorityCredentials
		}
		if value == 1 {
			if err := drop(cap); err != nil {
				return err
			}
			value, err = read(cap)
			if err != nil {
				return err
			}
			if value != 0 {
				return errAuthorityCredentials
			}
		}
	}
	return errAuthorityCredentials
}
