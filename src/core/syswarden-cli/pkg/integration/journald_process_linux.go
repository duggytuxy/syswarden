//go:build linux

package integration

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumJournaldProcessFile = 64 << 10

// Pin the kernel process directory before reading its identity. A PID reuse
// cannot redirect these reads to a replacement process. The caller also
// rechecks the complete service-manager observation before admitting it.
func verifyJournaldRemovalProcess(state journaldRemovalService) error {
	const executable = "/usr/lib/systemd/systemd-journald"
	if err := validateTrustedExecutable(executable); err != nil {
		return err
	}
	trusted, err := unix.Open(executable, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(trusted) }()
	proc, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(proc) }()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(proc, &filesystem); err != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("journald process evidence is not on kernel procfs")
	}
	process, err := unix.Openat(proc, strconv.FormatUint(state.pid, 10), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(process) }()
	var owner unix.Stat_t
	if err := unix.Fstat(process, &owner); err != nil || owner.Uid != 0 || owner.Gid != 0 {
		return fmt.Errorf("journald process directory is not root owned")
	}
	// exe is the kernel's executable link in the pinned process directory.
	// Following this one link is required to compare the actual image inode.
	image, err := unix.Openat(process, "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(image) }()
	var expected, actual unix.Stat_t
	if err := unix.Fstat(trusted, &expected); err != nil {
		return err
	}
	if err := unix.Fstat(image, &actual); err != nil {
		return err
	}
	if expected.Mode&unix.S_IFMT != unix.S_IFREG || expected.Mode&0022 != 0 || expected.Uid != 0 || expected.Dev != actual.Dev || expected.Ino != actual.Ino {
		return fmt.Errorf("journald live executable differs from the trusted consumer")
	}
	fields := make(map[string][]byte)
	for _, name := range []string{"cmdline", "cgroup", "environ", "status"} {
		fields[name], err = readJournaldProcessFile(process, name)
		if err != nil {
			return err
		}
	}
	return verifyJournaldProcessFields(fields, state.invocation)
}

func readJournaldProcessFile(directory int, name string) ([]byte, error) {
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("journald process field is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumJournaldProcessFile+1))
	if err != nil || len(data) == 0 || len(data) > maximumJournaldProcessFile {
		return nil, fmt.Errorf("journald process field is unavailable or exceeds its bound")
	}
	return data, nil
}

func verifyJournaldProcessFields(fields map[string][]byte, invocation string) error {
	if !bytes.Equal(fields["cmdline"], []byte("/usr/lib/systemd/systemd-journald\x00")) && !bytes.Equal(fields["cmdline"], []byte("/lib/systemd/systemd-journald\x00")) {
		return fmt.Errorf("journald live command line is not the default consumer")
	}
	if !bytes.Equal(fields["cgroup"], []byte("0::/system.slice/systemd-journald.service\n")) {
		return fmt.Errorf("journald process is not in its expected service control group")
	}
	environment := fields["environ"]
	if !bytes.HasSuffix(environment, []byte{0}) {
		return fmt.Errorf("journald process environment is incomplete")
	}
	count := 0
	for _, variable := range bytes.Split(environment, []byte{0}) {
		if bytes.HasPrefix(variable, []byte("INVOCATION_ID=")) {
			count++
			if string(variable) != "INVOCATION_ID="+invocation {
				return fmt.Errorf("journald process invocation differs from the service manager")
			}
		}
	}
	if count != 1 {
		return fmt.Errorf("journald process invocation is missing or ambiguous")
	}
	identities := make(map[string]bool)
	for _, line := range strings.Split(string(fields["status"]), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Uid" && key != "Gid" {
			continue
		}
		if identities[key] || strings.Join(strings.Fields(value), " ") != "0 0 0 0" {
			return fmt.Errorf("journald process does not retain its root identity")
		}
		identities[key] = true
	}
	if len(identities) != 2 {
		return fmt.Errorf("journald process identity is incomplete")
	}
	return nil
}
