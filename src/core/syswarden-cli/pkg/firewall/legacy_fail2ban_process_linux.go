//go:build linux

package firewall

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Expectations must come from independently inspected service configuration
// and trusted files, never from the socket response or a process name. This
// layer binds a live process; it does not attest its loaded Python modules,
// authorize action hooks, establish quiescence, or prove service ownership.
type legacyFail2banProcessExpectation struct {
	executable os.FileInfo
	arguments  []string
	cgroup     []byte
	paths      map[string]os.FileInfo
}

type legacyFail2banProcessBinding struct {
	mu          sync.Mutex
	pidfd       int
	proc        *os.Root
	mount       *os.File
	peer        syscall.Ucred
	expected    legacyFail2banProcessExpectation
	start       uint64
	environment [sha256.Size]byte
	namespaces  map[string]os.FileInfo
	root        os.FileInfo
}

// A pidfd remains tied to the original process even after its numeric PID is
// reused. A pinned proc directory and independent executable, argument and
// namespace checks reject changed observations. Re-executing identical code
// with identical arguments is not a separately observable generation here.
func bindLegacyFail2banProcess(peer syscall.Ucred, expected legacyFail2banProcessExpectation) (*legacyFail2banProcessBinding, error) {
	if peer.Pid <= 0 || expected.executable == nil || !expected.executable.Mode().IsRegular() ||
		len(expected.arguments) < 2 || len(expected.arguments) > 128 || len(expected.cgroup) == 0 ||
		len(expected.cgroup) > 16384 || len(expected.paths) == 0 || len(expected.paths) > 4096 {
		return nil, fmt.Errorf("Fail2ban process expectation is incomplete or unbounded")
	}
	total := 0
	for _, argument := range expected.arguments {
		total += len(argument) + 1
		if argument == "" || strings.ContainsRune(argument, 0) || total > 65536 {
			return nil, fmt.Errorf("Fail2ban process arguments are invalid or unbounded")
		}
	}
	paths := make(map[string]os.FileInfo, len(expected.paths))
	for path, identity := range expected.paths {
		if !canonicalNFTPersistencePath(path, false) || identity == nil || identity.Mode()&os.ModeSymlink != 0 ||
			!identity.IsDir() && !identity.Mode().IsRegular() {
			return nil, fmt.Errorf("Fail2ban process path expectation is invalid")
		}
		paths[path] = identity
	}
	expected.arguments = slices.Clone(expected.arguments)
	expected.cgroup = bytes.Clone(expected.cgroup)
	expected.paths = paths
	pidfd, err := unix.PidfdOpen(int(peer.Pid), 0)
	if err != nil {
		return nil, fmt.Errorf("pin Fail2ban process identity: %w", err)
	}
	binding := &legacyFail2banProcessBinding{pidfd: pidfd, peer: peer, expected: expected, namespaces: make(map[string]os.FileInfo)}
	complete := false
	defer func() {
		if !complete {
			_ = binding.Close()
		}
	}()
	if err := binding.alive(); err != nil {
		return nil, err
	}
	// The only variable component is a positive kernel PID. This is an
	// intentional procfs entry point, not a path supplied by configuration.
	binding.proc, err = os.OpenRoot("/proc/" + strconv.FormatInt(int64(peer.Pid), 10))
	if err != nil {
		return nil, fmt.Errorf("pin Fail2ban process directory: %w", err)
	}
	directory, err := binding.proc.Open(".")
	if err != nil {
		return nil, err
	}
	var filesystem unix.Statfs_t
	err = unix.Fstatfs(int(directory.Fd()), &filesystem)
	if err != nil || filesystem.Type != unix.PROC_SUPER_MAGIC {
		_ = directory.Close()
		return nil, fmt.Errorf("Fail2ban process directory is not procfs")
	}
	// Hold the namespace descriptor so its inode cannot be recycled after a
	// mount namespace change. The magic link is a fixed path under pinned procfs.
	mountFD, err := unix.Openat(int(directory.Fd()), "ns/mnt", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	_ = directory.Close()
	if err != nil {
		return nil, fmt.Errorf("pin Fail2ban mount namespace: %w", err)
	}
	binding.mount = os.NewFile(uintptr(mountFD), "Fail2ban mount namespace")
	binding.namespaces["mnt"], err = binding.mount.Stat()
	if err != nil {
		return nil, err
	}
	binding.root, err = os.Stat("/")
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"net", "user", "pid"} {
		binding.namespaces[name], err = os.Stat("/proc/self/ns/" + name)
		if err != nil {
			return nil, fmt.Errorf("inspect local process namespace: %w", err)
		}
	}
	if err := binding.observe(true); err != nil {
		return nil, err
	}
	complete = true
	return binding, nil
}

func (binding *legacyFail2banProcessBinding) Close() error {
	if binding == nil {
		return nil
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	var closeErr error
	if binding.mount != nil {
		closeErr = binding.mount.Close()
		binding.mount = nil
	}
	if binding.proc != nil {
		err := binding.proc.Close()
		binding.proc = nil
		if closeErr == nil {
			closeErr = err
		}
	}
	if binding.pidfd >= 0 {
		err := unix.Close(binding.pidfd)
		binding.pidfd = -1
		if closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func (binding *legacyFail2banProcessBinding) alive() error {
	if binding.pidfd < 0 {
		return fmt.Errorf("Fail2ban process binding is closed")
	}
	// PidfdOpen returns an int descriptor, which Linux bounds to a signed
	// 32-bit value. Validate before converting to PollFd's ABI field.
	if uint64(binding.pidfd) > 1<<31-1 {
		return fmt.Errorf("Fail2ban process descriptor is outside the poll ABI")
	}
	fds := []unix.PollFd{{Fd: int32(binding.pidfd), Events: unix.POLLIN}}
	var n int
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		n, err = unix.Poll(fds, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil || n != 0 || fds[0].Revents != 0 {
		return fmt.Errorf("the bound Fail2ban process exited or cannot be verified (poll events=%d flags=%d error=%v)", n, fds[0].Revents, err)
	}
	return nil
}

func (binding *legacyFail2banProcessBinding) verify() error {
	if binding == nil {
		return fmt.Errorf("Fail2ban process binding is absent")
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	return binding.observe(false)
}

// Read-only runtime queries bind the same live peer without walking every
// configuration path for each individual property. The service reader reattests
// the complete file inventory immediately before and after the whole snapshot.
// Mutation authorization continues to require full evidence verification.
func (binding *legacyFail2banProcessBinding) verifyReadOnlyPeer() error {
	if binding == nil {
		return fmt.Errorf("Fail2ban process binding is absent")
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	return binding.observePaths(false, nil, nil)
}

func readLegacyFail2banProcessFile(root *os.Root, name string, maximum int64) ([]byte, error) {
	if root == nil || maximum <= 0 || maximum > 65536 {
		return nil, fmt.Errorf("invalid Fail2ban process read")
	}
	switch name {
	case "stat", "status", "cmdline", "cgroup", "environ":
	default:
		return nil, fmt.Errorf("unsupported Fail2ban process observation")
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open bounded Fail2ban process observation: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Fail2ban process observation is not a regular proc file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(content)) > maximum {
		return nil, fmt.Errorf("Fail2ban process observation exceeds its bound")
	}
	return content, nil
}

func legacyFail2banProcessStart(content []byte, pid int32) (uint64, error) {
	text := string(content)
	start := strconv.FormatInt(int64(pid), 10) + " ("
	end := strings.LastIndex(text, ") ")
	if !strings.HasPrefix(text, start) || end < len(start) || len(content) > 8192 {
		return 0, fmt.Errorf("malformed Fail2ban process stat record")
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 50 || len(fields[0]) != 1 || !strings.Contains("RSDTtWPIN", fields[0]) {
		return 0, fmt.Errorf("Fail2ban process is not in a supported live state")
	}
	// starttime is field 22; fields[0] is field 3 after the complete comm.
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, fmt.Errorf("Fail2ban process start time is unavailable")
	}
	return ticks, nil
}

func verifyLegacyFail2banProcessCredentials(content []byte, peer syscall.Ucred) error {
	required := map[string][]string{
		"Pid":       {strconv.FormatInt(int64(peer.Pid), 10)},
		"Tgid":      {strconv.FormatInt(int64(peer.Pid), 10)},
		"TracerPid": {"0"},
		"Uid":       {strconv.FormatUint(uint64(peer.Uid), 10), strconv.FormatUint(uint64(peer.Uid), 10), strconv.FormatUint(uint64(peer.Uid), 10), strconv.FormatUint(uint64(peer.Uid), 10)},
		"Gid":       {strconv.FormatUint(uint64(peer.Gid), 10), strconv.FormatUint(uint64(peer.Gid), 10), strconv.FormatUint(uint64(peer.Gid), 10), strconv.FormatUint(uint64(peer.Gid), 10)},
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(content), "\n") {
		key, value, found := strings.Cut(line, ":")
		if expected, needed := required[key]; needed && found {
			if seen[key] || !slices.Equal(expected, strings.Fields(value)) {
				return fmt.Errorf("Fail2ban process credentials or tracing state differ")
			}
			seen[key] = true
		}
	}
	if len(seen) != len(required) {
		return fmt.Errorf("Fail2ban process credentials are incomplete")
	}
	return nil
}

func (binding *legacyFail2banProcessBinding) observe(initial bool) error {
	return binding.observePaths(initial, binding.expected.paths, nil)
}

func (binding *legacyFail2banProcessBinding) observePaths(initial bool, paths map[string]os.FileInfo, absent []string) error {
	if binding.proc == nil {
		return fmt.Errorf("Fail2ban process binding is closed")
	}
	if err := binding.alive(); err != nil {
		return err
	}
	stat, err := readLegacyFail2banProcessFile(binding.proc, "stat", 8192)
	if err != nil {
		return err
	}
	start, err := legacyFail2banProcessStart(stat, binding.peer.Pid)
	if err != nil || !initial && start != binding.start {
		return fmt.Errorf("Fail2ban process start identity changed or is unavailable")
	}
	status, err := readLegacyFail2banProcessFile(binding.proc, "status", 16384)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banProcessCredentials(status, binding.peer); err != nil {
		return err
	}
	arguments, err := readLegacyFail2banProcessFile(binding.proc, "cmdline", 65536)
	wantArguments := []byte(strings.Join(binding.expected.arguments, "\x00") + "\x00")
	if err != nil || !bytes.Equal(arguments, wantArguments) {
		return fmt.Errorf("Fail2ban process arguments differ from the inspected service")
	}
	cgroup, err := readLegacyFail2banProcessFile(binding.proc, "cgroup", 16384)
	if err != nil || !bytes.Equal(cgroup, binding.expected.cgroup) {
		return fmt.Errorf("Fail2ban process control group differs from the inspected service")
	}
	environment, err := readLegacyFail2banProcessFile(binding.proc, "environ", 65536)
	if err != nil {
		return err
	}
	environmentDigest := sha256.Sum256(environment)
	if !initial && environmentDigest != binding.environment {
		return fmt.Errorf("Fail2ban process environment changed during inspection")
	}
	// Opening these fixed proc magic links is deliberate. os.Root's path
	// confinement must not be relaxed for configuration-controlled paths.
	procPath := "/proc/" + strconv.FormatInt(int64(binding.peer.Pid), 10)
	executable, err := os.Stat(procPath + "/exe")
	if err != nil || !sameNFTPersistenceIdentity(binding.expected.executable, executable) {
		return fmt.Errorf("Fail2ban live executable differs from the inspected interpreter")
	}
	for _, name := range []string{"net", "user", "pid", "mnt"} {
		identity, err := os.Stat(procPath + "/ns/" + name)
		if err != nil {
			return fmt.Errorf("Fail2ban process namespace is unavailable")
		}
		if !os.SameFile(binding.namespaces[name], identity) {
			return fmt.Errorf("Fail2ban process namespace differs or changed")
		}
	}
	root, err := os.OpenRoot(procPath + "/root")
	if err != nil {
		return fmt.Errorf("open Fail2ban process root: %w", err)
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := root.Stat(".")
	if err != nil || !os.SameFile(binding.root, rootInfo) {
		return fmt.Errorf("Fail2ban process root differs from the host root")
	}
	for path, expected := range paths {
		actual, err := root.Stat(strings.TrimPrefix(path, "/"))
		if err != nil || !sameNFTPersistenceIdentity(expected, actual) {
			return fmt.Errorf("Fail2ban process has a different trusted path view")
		}
	}
	for _, path := range absent {
		if _, err := root.Lstat(strings.TrimPrefix(path, "/")); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Fail2ban process still sees a retired configuration path")
		}
	}
	finalStat, err := readLegacyFail2banProcessFile(binding.proc, "stat", 8192)
	if err != nil {
		return err
	}
	finalStart, err := legacyFail2banProcessStart(finalStat, binding.peer.Pid)
	if err != nil || finalStart != start {
		return fmt.Errorf("Fail2ban process changed during observation")
	}
	if err := binding.alive(); err != nil {
		return err
	}
	if initial {
		binding.start, binding.environment = start, environmentDigest
	}
	return nil
}
