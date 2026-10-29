//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Linux binds an opened proc mem file to that address space, not to a future
// exec by the same PID. At fixed address zero an active, unmapped page returns
// EIO; an abandoned address space returns EOF. EIO alone does not establish
// which process still uses that space. No arbitrary address or memory contents
// are exposed. This is retirement evidence, not policy acceptance or an exec count.
type sshExecMemory struct{ file *os.File }

func classifySSHExecProbe(n int, err error) (bool, error) {
	if n == 0 && errors.Is(err, unix.EIO) {
		return false, nil
	}
	if n == 0 && errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, ErrInventoryUnsafe
}

func (memory *sshExecMemory) retired() (bool, error) {
	if memory == nil || memory.file == nil {
		return false, ErrInventoryClosed
	}
	var value [1]byte
	n, err := memory.file.ReadAt(value[:], 0)
	clear(value[:])
	return classifySSHExecProbe(n, err)
}

func (memory *sshExecMemory) Close() error {
	if memory == nil || memory.file == nil {
		return nil
	}
	err := memory.file.Close()
	memory.file = nil
	return err
}

func pinSSHExecMemory(proc *os.File, uid int) (_ *sshExecMemory, err error) {
	if proc == nil || uid < 0 || runtime.GOARCH != "amd64" {
		return nil, ErrInventoryUnsafe
	}
	fd, err := unix.Openat2(int(proc.Fd()), "mem", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	})
	if err != nil {
		return nil, err
	}
	memory := &sshExecMemory{os.NewFile(uintptr(fd), "ssh-exec-generation")}
	defer func() {
		if err != nil {
			err = errors.Join(err, memory.Close())
		}
	}()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := errors.Join(unix.Fstat(fd, &st), unix.Fstatfs(fd, &fs)); err != nil || fs.Type != unix.PROC_SUPER_MAGIC ||
		st.Mode != unix.S_IFREG|0600 || int64(st.Uid) != int64(uid) || st.Nlink != 1 || st.Size != 0 {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	retired, err := memory.retired()
	if err != nil || retired {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	return memory, nil
}

type sshExecReload struct {
	before, after *sshExecMemory
	open          func() (*sshExecMemory, error)
}

func (reload *sshExecReload) beforeRequest() error {
	if reload == nil || reload.before == nil || reload.after != nil || reload.open == nil {
		return ErrInventoryUnsafe
	}
	retired, err := reload.before.retired()
	if err != nil || retired {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

func (reload *sshExecReload) checkAfter() error {
	if reload == nil || reload.before == nil || reload.after == nil {
		return ErrInventoryUnsafe
	}
	old, oldErr := reload.before.retired()
	current, currentErr := reload.after.retired()
	if oldErr != nil || currentErr != nil || !old || current {
		return errors.Join(ErrInventoryChanged, oldErr, currentErr)
	}
	return nil
}

func (reload *sshExecReload) observe(ctx context.Context, guard func() error) error {
	if reload == nil || reload.before == nil || reload.after != nil || reload.open == nil || ctx == nil || guard == nil {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return err
	}
	retired, err := reload.before.retired()
	if err != nil || !retired {
		return errors.Join(errors.New("SSH address-space replacement was not observed; runtime recovery remains required"), err)
	}
	reload.after, err = reload.open()
	if err != nil {
		return err
	}
	return errors.Join(reload.checkAfter(), ctx.Err(), guard(), reload.checkAfter())
}

func (reload *sshExecReload) Close() error {
	if reload == nil {
		return nil
	}
	var check error
	if reload.after != nil {
		check = reload.checkAfter()
	}
	before, after := reload.before, reload.after
	reload.before, reload.after = nil, nil
	return errors.Join(check, before.Close(), after.Close())
}
