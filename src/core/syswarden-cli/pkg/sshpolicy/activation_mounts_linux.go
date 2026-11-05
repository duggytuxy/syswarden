//go:build linux

package sshpolicy

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// Keep the original procfs descriptor: opening another mounts file would reset
// the kernel event baseline and could hide a mount/unmount ABA. This fence only
// observes namespace changes; it does not prevent mounts or prove policy use.
type sshMountEventFence struct {
	mu      sync.Mutex
	mounts  *os.File
	process *sshProcessBinding
	poll    func([]unix.PollFd, int) (int, error)
	failed  error
}

func pinSSHMountEvents(process *sshProcessBinding) (_ *sshMountEventFence, err error) {
	if err := checkSSHMountEventProcess(process); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(process.proc.Fd()), "mounts", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	fence := &sshMountEventFence{mounts: os.NewFile(uintptr(fd), "ssh-process-mount-events"), process: process, poll: unix.Poll}
	defer func() {
		if err != nil {
			err = errors.Join(err, fence.Close())
		}
	}()
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if err = errors.Join(unix.Fstat(fd, &stat), unix.Fstatfs(fd, &fs)); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFREG || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	// Opening procfs mounts establishes its event baseline. Do not discard a
	// first poll notification: an event since open already invalidates it.
	if err := fence.check(); err != nil {
		return nil, err
	}
	return fence, nil
}

func checkSSHMountEventProcess(process *sshProcessBinding) error {
	if process == nil || process.proc == nil || !process.requireSameMount ||
		process.verifier == nil || process.namespaces["mnt"] == nil {
		return ErrInventoryClosed
	}
	if err := errors.Join(process.alive(), process.checkMountView()); err != nil {
		return err
	}
	// The retained mounts descriptor follows its original namespace even if
	// the target moves elsewhere. Check the target's current namespace too.
	current, err := openSSHProcessLink(process.proc, "ns/mnt")
	if err != nil {
		return err
	}
	want, wantErr := sshKernelFileIdentity(process.namespaces["mnt"])
	got, gotErr := sshKernelFileIdentity(current)
	if err := errors.Join(wantErr, gotErr, current.Close()); err != nil || want != got {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

func (f *sshMountEventFence) check() error {
	if f == nil {
		return ErrInventoryClosed
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mounts == nil || f.process == nil || f.poll == nil {
		return ErrInventoryClosed
	}
	if f.failed != nil {
		return f.failed
	}
	// Once a notification or error is observed, never clear the failure or
	// open a replacement descriptor. Linux advances its poll baseline when
	// returning a notification, so a later clean poll cannot repair custody.
	if err := checkSSHMountEventProcess(f.process); err != nil {
		f.failed = errors.Join(ErrInventoryChanged, err)
		return f.failed
	}
	fd := f.mounts.Fd()
	if fd > 1<<31-1 {
		f.failed = ErrInventoryClosed
		return f.failed
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI | unix.POLLERR}}
	n, err := f.poll(fds, 0)
	if err != nil || n != 0 || fds[0].Revents != 0 {
		f.failed = errors.Join(ErrInventoryChanged, err)
		return f.failed
	}
	if err := checkSSHMountEventProcess(f.process); err != nil {
		f.failed = errors.Join(ErrInventoryChanged, err)
		return f.failed
	}
	return nil
}

func (f *sshMountEventFence) guard(check func() error) error {
	if check == nil {
		return ErrInventoryUnsafe
	}
	if err := f.check(); err != nil {
		return err
	}
	return errors.Join(check(), f.check())
}

func (f *sshMountEventFence) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mounts == nil {
		return nil
	}
	err := f.mounts.Close()
	f.mounts, f.process, f.poll = nil, nil, nil
	return err
}
