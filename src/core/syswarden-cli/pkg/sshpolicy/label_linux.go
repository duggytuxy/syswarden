//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The label is resolved for the final regular-file pathname, never copied
// from its directory. The callback repeats the lookup and enforcement-mode
// observation at transaction boundaries; it does not change either policy.
type sshTargetLabel struct {
	attributes map[string][]byte
	recheck    func(context.Context) error
	close      func() error
}

type sshSELinuxState struct {
	present bool
	mode    byte
	device  uint64
	inode   uint64
}

func readSSHSELinuxState(root *os.File, uid int) (sshSELinuxState, error) {
	if root == nil {
		return sshSELinuxState{}, ErrInventoryUnsafe
	}
	// selinuxfs and sysfs synthesize timestamps. Configuration-file inventory
	// equality is inappropriate for these virtual objects. Require the real
	// filesystem, protected ownership and descriptor-rooted no-symlink lookup.
	dirFD, err := unix.Openat2(int(root.Fd()), "sys/fs/selinux", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if errors.Is(err, unix.ENOENT) {
		return sshSELinuxState{}, nil
	}
	if err != nil {
		return sshSELinuxState{}, err
	}
	directory := os.NewFile(uintptr(dirFD), "ssh-selinux-mount")
	defer directory.Close()
	var directoryState unix.Stat_t
	if err := unix.Fstat(dirFD, &directoryState); err != nil ||
		int64(directoryState.Uid) != int64(uid) || directoryState.Mode&07022 != 0 {
		return sshSELinuxState{}, errors.Join(ErrInventoryUnsafe, err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(directory.Fd()), &fs); err != nil {
		return sshSELinuxState{}, err
	}
	if fs.Type != unix.SELINUX_MAGIC {
		return sshSELinuxState{}, fmt.Errorf("SELinux state directory is not selinuxfs")
	}
	fd, err := unix.Openat(int(directory.Fd()), "enforce", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return sshSELinuxState{}, err
	}
	file := os.NewFile(uintptr(fd), "ssh-selinux-enforcement")
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG ||
		int64(st.Uid) != int64(uid) || st.Mode&07022 != 0 {
		return sshSELinuxState{}, errors.Join(ErrInventoryUnsafe, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 3))
	if err != nil || len(data) != 1 || (data[0] != '0' && data[0] != '1') {
		return sshSELinuxState{}, errors.Join(ErrInventoryUnsafe, err)
	}
	return sshSELinuxState{true, data[0], st.Dev, st.Ino}, nil
}

type sshLabelExecutable struct {
	file   *os.File
	parent string
	state  inventoryStamp
	digest string
}

func openSSHLabelExecutable(root *os.File, uid int) (*sshLabelExecutable, error) {
	for _, parent := range []string{"/usr/bin", "/usr/sbin"} {
		reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
		directory, err := reader.openDirectory(parent)
		if err != nil {
			return nil, err
		}
		if directory == nil {
			continue
		}
		file, state, digest, err := readSSHExecutable(directory, "matchpathcon", uid)
		closeErr := directory.Close()
		if errors.Is(err, unix.ENOENT) && closeErr == nil {
			continue
		}
		if err != nil || closeErr != nil {
			if file != nil {
				_ = file.Close()
			}
			return nil, errors.Join(err, closeErr)
		}
		return &sshLabelExecutable{file, parent, state, digest}, nil
	}
	return nil, fmt.Errorf("trusted matchpathcon is required to resolve the SSH drop-in label")
}

func (tool *sshLabelExecutable) recheck(root *os.File, uid int) error {
	current, err := openSSHLabelExecutable(root, uid)
	if err != nil {
		return err
	}
	defer current.file.Close()
	if current.parent != tool.parent || current.state != tool.state || current.digest != tool.digest {
		return ErrInventoryChanged
	}
	return nil
}

func (tool *sshLabelExecutable) lookup(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The fixed command requests untranslated policy for a regular file.
	// It never relabels an existing object or changes enforcement mode.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "-N", "-n", "-m", "file", DropInPath)
	command.ExtraFiles = []*os.File{tool.file}
	command.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	var stdout, stderr parserOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("SELinux target-label lookup failed or exceeded execution bounds")
	}
	return parseSSHTargetLabel(stdout.Bytes())
}

func parseSSHTargetLabel(data []byte) ([]byte, error) {
	if len(data) < 6 || len(data) > 4096 || data[len(data)-1] != '\n' {
		return nil, ErrInventoryUnsafe
	}
	value := string(data[:len(data)-1])
	parts := strings.SplitN(value, ":", 4)
	if len(parts) < 3 {
		return nil, ErrInventoryUnsafe
	}
	for _, part := range parts {
		if part == "" {
			return nil, ErrInventoryUnsafe
		}
	}
	for _, ch := range value {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || strings.ContainsRune("_:.,-", ch)) {
			return nil, ErrInventoryUnsafe
		}
	}
	// security.selinux is a NUL-terminated raw context on Linux.
	return append([]byte(value), 0), nil
}

func resolveSSHTargetLabel(ctx context.Context, root *os.File, uid int, snapshot inventorySnapshot) (*sshTargetLabel, error) {
	state, err := readSSHSELinuxState(root, uid)
	if err != nil {
		return nil, err
	}
	checkState := func(context.Context) error {
		current, err := readSSHSELinuxState(root, uid)
		if err != nil || current != state {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	if !state.present {
		// A container can hide selinuxfs while the host still labels files.
		// Absence of a mount does not authorize stripping those labels.
		for _, attrs := range snapshot.attributes {
			if _, exists := attrs["security.selinux"]; exists {
				return nil, fmt.Errorf("SELinux labels exist but target policy is unavailable; no label is guessed")
			}
		}
		return &sshTargetLabel{map[string][]byte{}, checkState, func() error { return nil }}, nil
	}
	tool, err := openSSHLabelExecutable(root, uid)
	if err != nil {
		return nil, err
	}
	label, err := tool.lookup(ctx)
	if err != nil {
		return nil, errors.Join(err, tool.file.Close())
	}
	recheck := func(ctx context.Context) error {
		if err := errors.Join(ctx.Err(), checkState(ctx), tool.recheck(root, uid)); err != nil {
			return err
		}
		current, err := tool.lookup(ctx)
		if err != nil || !bytes.Equal(current, label) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return errors.Join(checkState(ctx), tool.recheck(root, uid))
	}
	if err := recheck(ctx); err != nil {
		return nil, errors.Join(err, tool.file.Close())
	}
	return &sshTargetLabel{map[string][]byte{"security.selinux": label}, recheck, tool.file.Close}, nil
}
