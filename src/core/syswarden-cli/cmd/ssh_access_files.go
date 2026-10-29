package cmd

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var errSSHExchangeFile = errors.New("SSH exchange requires a protected owner-only directory and bounded regular single-link files; preserve any partial output")

// All artifact names are fixed by the commands. Open every directory component
// without following links. A sticky root-owned ancestor permits /tmp sessions;
// the final directory must belong to this effective user and have mode 0700.
type sshExchangeDirectory struct {
	file     *os.File
	path     string
	identity unix.Stat_t
	inputs   map[string]unix.Stat_t
	poisoned bool
}

func openSSHExchangeDirectory(path string) (*sshExchangeDirectory, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errSSHExchangeFile
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSSHExchangeFile
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var stat unix.Stat_t
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if openErr != nil {
			return nil, errSSHExchangeFile
		}
		fd = next
		if closeErr != nil || unix.Fstat(fd, &stat) != nil ||
			(stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid())) ||
			(stat.Mode&0022 != 0 && !(stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0)) ||
			(index == len(parts)-1 && (int64(stat.Uid) != int64(os.Geteuid()) || stat.Mode&07777 != 0700)) {
			_ = unix.Close(fd)
			return nil, errSSHExchangeFile
		}
	}
	return &sshExchangeDirectory{file: os.NewFile(uintptr(fd), "ssh-private-exchange"), path: path, identity: stat, inputs: make(map[string]unix.Stat_t)}, nil
}

func (directory *sshExchangeDirectory) close() error { return directory.file.Close() }

func (directory *sshExchangeDirectory) check() error {
	if directory.poisoned {
		return errSSHExchangeFile
	}
	current, err := openSSHExchangeDirectory(directory.path)
	if err != nil {
		return err
	}
	defer current.close() // The descriptor carries no writes.
	if current.identity.Dev != directory.identity.Dev || current.identity.Ino != directory.identity.Ino ||
		current.identity.Mode != directory.identity.Mode || current.identity.Uid != directory.identity.Uid || current.identity.Gid != directory.identity.Gid {
		return errSSHExchangeFile
	}
	return nil
}

func (directory *sshExchangeDirectory) read(name string, limit int) ([]byte, error) {
	if name != filepath.Base(name) || name == "." || limit < 1 || limit > 1<<20 || directory.check() != nil {
		return nil, errSSHExchangeFile
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSSHExchangeFile
	}
	file := os.NewFile(uintptr(fd), "ssh-private-input")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 ||
		int64(before.Uid) != int64(os.Geteuid()) || before.Nlink != 1 || before.Size < 1 || before.Size > int64(limit) {
		return nil, errSSHExchangeFile
	}
	wire, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	statErr := unix.Fstat(fd, &after)
	before.Atim = after.Atim // Reading may update access time; content stamps must remain stable.
	if err != nil || len(wire) > limit || statErr != nil || before != after || directory.check() != nil {
		clear(wire)
		return nil, errSSHExchangeFile
	}
	after.Atim = unix.Timespec{}
	if original, seen := directory.inputs[name]; seen && original != after {
		clear(wire)
		directory.poisoned = true
		return nil, errSSHExchangeFile
	}
	directory.inputs[name] = after
	return wire, nil
}

func (directory *sshExchangeDirectory) unchanged(name string, original []byte, limit int) error {
	current, err := directory.read(name, limit)
	defer clear(current)
	if err != nil || !bytes.Equal(current, original) {
		directory.poisoned = true
		return errSSHExchangeFile
	}
	return nil
}

// Reserve before an irreversible journal issuance or network authentication.
// An interrupted/failed delivery leaves its new file in place, never overwrites
// an existing record and never deletes evidence to make a retry appear safe.
func (directory *sshExchangeDirectory) reserve(name string) (*os.File, error) {
	if name != filepath.Base(name) || name == "." || directory.check() != nil {
		return nil, errSSHExchangeFile
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errSSHExchangeFile
	}
	file := os.NewFile(uintptr(fd), "ssh-private-output")
	if err := errors.Join(file.Sync(), directory.file.Sync(), directory.check()); err != nil {
		_ = file.Close()
		return nil, errSSHExchangeFile
	}
	return file, nil
}

func (directory *sshExchangeDirectory) publish(file *os.File, name string, wire []byte) error {
	if len(wire) == 0 || len(wire) > 1<<20 || directory.check() != nil || directory.checkOutput(file, name, 0) != nil {
		return errSSHExchangeFile
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) {
		return errSSHExchangeFile
	}
	if err := errors.Join(file.Sync(), directory.file.Sync(), directory.check()); err != nil {
		return errSSHExchangeFile
	}
	if err := directory.checkOutput(file, name, int64(len(wire))); err != nil {
		return err
	}
	return directory.unchanged(name, wire, 1<<20)
}

func (directory *sshExchangeDirectory) checkOutput(file *os.File, name string, size int64) error {
	var held, named unix.Stat_t
	if unix.Fstat(int(file.Fd()), &held) != nil || unix.Fstatat(int(directory.file.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		held.Dev != named.Dev || held.Ino != named.Ino || held.Mode&unix.S_IFMT != unix.S_IFREG ||
		held.Nlink != 1 || held.Mode&07777 != 0600 || int64(held.Uid) != int64(os.Geteuid()) || held.Size != size {
		return errSSHExchangeFile
	}
	return nil
}
