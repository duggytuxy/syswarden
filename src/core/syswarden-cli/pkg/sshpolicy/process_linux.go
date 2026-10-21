//go:build linux

package sshpolicy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func validSSHControlGroup(value string) bool {
	if len(value) < 2 || len(value) > 4096 || value[0] != '/' || path.Clean(value) != value {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 || c == ':' || c == '\\' {
			return false
		}
	}
	return true
}

func sshProcessStart(wire []byte, pid int) (uint64, error) {
	text := string(wire)
	prefix := strconv.Itoa(pid) + " ("
	end := strings.LastIndex(text, ") ")
	if pid <= 1 || len(wire) > 8192 || !strings.HasSuffix(text, "\n") ||
		!strings.HasPrefix(text, prefix) || end < len(prefix) || strings.ContainsAny(strings.TrimSuffix(text, "\n"), "\x00\r\n") {
		return 0, ErrInventoryUnsafe
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 50 || len(fields) > 64 || len(fields[0]) != 1 || !strings.Contains("RSDI", fields[0]) {
		return 0, fmt.Errorf("SSH process is not in a supported live state")
	}
	// Field 22, after the full parenthesized comm and field 3 (state).
	started, err := sshSystemdUint(fields[19], 64)
	if err != nil || started == 0 {
		return 0, ErrInventoryUnsafe
	}
	return started, nil
}

func verifySSHProcessCredentials(wire []byte, pid, uid int) error {
	if pid <= 1 || uid < 0 || len(wire) == 0 || len(wire) > 16384 || wire[len(wire)-1] != '\n' || bytes.ContainsRune(wire, 0) {
		return ErrInventoryUnsafe
	}
	u := strconv.Itoa(uid)
	want := map[string]string{"Pid": strconv.Itoa(pid), "Tgid": strconv.Itoa(pid), "TracerPid": "0", "Uid": strings.Join([]string{u, u, u, u}, " ")}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(wire), "\n") {
		key, value, found := strings.Cut(line, ":")
		if expected, needed := want[key]; needed {
			if !found || seen[key] || strings.Join(strings.Fields(value), " ") != expected {
				return fmt.Errorf("SSH process identity, credentials or tracing state differ")
			}
			seen[key] = true
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("SSH process credentials are incomplete")
	}
	return nil
}

func verifySSHProcessGroup(wire []byte, expected string) error {
	if !validSSHControlGroup(expected) || len(wire) == 0 || len(wire) > 16384 || wire[len(wire)-1] != '\n' {
		return ErrInventoryUnsafe
	}
	seen := make(map[string]bool)
	matches := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(wire), "\n"), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 || len(seen) >= 64 || seen[fields[0]] {
			return ErrInventoryUnsafe
		}
		id, err := sshSystemdUint(fields[0], 32)
		if err != nil || (id == 0) != (fields[1] == "") || (!validSSHControlGroup(fields[2]) && fields[2] != "/") {
			return ErrInventoryUnsafe
		}
		seen[fields[0]] = true
		controllers := strings.Split(fields[1], ",")
		controllerSeen := make(map[string]bool)
		for _, controller := range controllers {
			if controllerSeen[controller] || (id != 0 && controller == "") {
				return ErrInventoryUnsafe
			}
			controllerSeen[controller] = true
			for _, c := range controller {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '=') {
					return ErrInventoryUnsafe
				}
			}
		}
		if id == 0 || containsSSHUnit(controllers, "name=systemd") {
			matches++
			if fields[2] != expected {
				return fmt.Errorf("SSH process does not belong to the observed service cgroup")
			}
		}
	}
	if matches != 1 {
		return fmt.Errorf("SSH process system-manager cgroup is absent or ambiguous")
	}
	return nil
}

type sshKernelIdentity struct{ Device, Inode uint64 }

func sshKernelFileIdentity(file *os.File) (sshKernelIdentity, error) {
	if file == nil {
		return sshKernelIdentity{}, ErrInventoryUnsafe
	}
	var st unix.Stat_t
	err := unix.Fstat(int(file.Fd()), &st)
	return sshKernelIdentity{uint64(st.Dev), st.Ino}, err
}

type sshProcessIdentity struct {
	PID              int
	StartTicks       uint64
	ExecutableSHA256 string
	Namespaces       map[string]sshKernelIdentity
	Root             sshKernelIdentity
	ControlGroupHash string
}

// Private, short-lived read-only lease. A summary never replaces this live
// handle and never grants authority to reload, signal or authenticate.
type sshProcessBinding struct {
	pid, uid, pidfd int
	proc            *os.File
	executable      inventoryStamp
	digest, group   string
	namespaces      map[string]*os.File
	root            *os.File
}

func openSSHProcDirectory(parent *os.File, name string) (*os.File, error) {
	if parent == nil {
		return nil, ErrInventoryUnsafe
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ssh-process-directory")
	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		_ = f.Close()
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	return f, nil
}

func openSSHProcessLink(proc *os.File, name string) (*os.File, error) {
	if proc == nil {
		return nil, ErrInventoryUnsafe
	}
	switch name {
	case "exe", "root", "ns/pid", "ns/net", "ns/user", "ns/mnt":
	default:
		return nil, ErrInventoryUnsafe
	}
	// Only fixed kernel magic links beneath an independently pinned procfs
	// directory may be followed. No configuration path reaches this function.
	fd, err := unix.Openat(int(proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "ssh-process-kernel-object"), nil
}

func bindSSHProcess(pid, uid int, group string, executable inventoryStamp, digest string) (_ *sshProcessBinding, err error) {
	if pid <= 1 || pid > 1<<31-1 || uid < 0 || !validSSHControlGroup(group) || !lowerDigest.MatchString(digest) ||
		!executable.exists || int64(executable.uid) != int64(uid) || executable.mode&unix.S_IFMT != unix.S_IFREG {
		return nil, ErrInventoryUnsafe
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	proc, err := openSSHProcDirectory(root, "proc")
	if err != nil {
		return nil, err
	}
	defer proc.Close()
	// A procfs mounted for a different PID namespace cannot translate the
	// numeric manager PID safely for pidfd_open in this process's namespace.
	var link [32]byte
	n, err := unix.Readlinkat(int(proc.Fd()), "self", link[:])
	if err != nil || string(link[:n]) != strconv.Itoa(os.Getpid()) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	self, err := openSSHProcDirectory(proc, strconv.Itoa(os.Getpid()))
	if err != nil {
		return nil, err
	}
	defer self.Close()
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pin SSH process: %w", err)
	}
	b := &sshProcessBinding{pid: pid, uid: uid, pidfd: pidfd, executable: executable, digest: digest, group: group, namespaces: make(map[string]*os.File)}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, b.Close())
		}
	}()
	if err = b.alive(); err != nil {
		return nil, err
	}
	b.proc, err = openSSHProcDirectory(proc, strconv.Itoa(pid))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"pid", "net", "user", "mnt"} {
		b.namespaces[name], err = openSSHProcessLink(b.proc, "ns/"+name)
		if err != nil {
			return nil, err
		}
		local, openErr := openSSHProcessLink(self, "ns/"+name)
		if openErr != nil {
			return nil, openErr
		}
		localID, localErr := sshKernelFileIdentity(local)
		targetID, targetErr := sshKernelFileIdentity(b.namespaces[name])
		if err = errors.Join(localErr, targetErr, local.Close()); err != nil || (name != "mnt" && localID != targetID) {
			return nil, errors.Join(fmt.Errorf("SSH process uses a different identity or network namespace"), err)
		}
	}
	b.root, err = openSSHProcessLink(b.proc, "root")
	if err != nil {
		return nil, err
	}
	localRoot, localErr := sshKernelFileIdentity(root)
	targetRoot, targetErr := sshKernelFileIdentity(b.root)
	if err = errors.Join(localErr, targetErr); err != nil || localRoot != targetRoot {
		return nil, errors.Join(fmt.Errorf("SSH process uses a different filesystem root"), err)
	}
	if _, err = b.observe(); err != nil {
		return nil, err
	}
	complete = true
	return b, nil
}

func (b *sshProcessBinding) Close() error {
	if b == nil {
		return nil
	}
	var err error
	for name, file := range b.namespaces {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		delete(b.namespaces, name)
	}
	for _, file := range []*os.File{b.root, b.proc} {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	b.root, b.proc = nil, nil
	if b.pidfd >= 0 {
		err = errors.Join(err, unix.Close(b.pidfd))
		b.pidfd = -1
	}
	return err
}

func (b *sshProcessBinding) alive() error {
	if b == nil || b.pidfd < 0 || b.pidfd > 1<<31-1 {
		return ErrInventoryClosed
	}
	fds := []unix.PollFd{{Fd: int32(b.pidfd), Events: unix.POLLIN}}
	for attempt := 0; attempt < 8; attempt++ {
		n, err := unix.Poll(fds, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n != 0 || fds[0].Revents != 0 {
			return fmt.Errorf("SSH process exited or cannot be observed")
		}
		return nil
	}
	return ErrInventoryChanged
}

func readSSHProcText(proc *os.File, name string) ([]byte, error) {
	if proc == nil || (name != "stat" && name != "status" && name != "cgroup") {
		return nil, ErrInventoryUnsafe
	}
	fd, err := unix.Openat(int(proc.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "ssh-process-observation")
	defer f.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err = errors.Join(unix.Fstat(fd, &st), unix.Fstatfs(fd, &fs)); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	wire, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(wire) > 16384 {
		return nil, errors.Join(ErrInventoryBounds, err)
	}
	return wire, nil
}

func (b *sshProcessBinding) observe() (sshProcessIdentity, error) {
	if b == nil || b.proc == nil || b.root == nil || len(b.namespaces) != 4 {
		return sshProcessIdentity{}, ErrInventoryClosed
	}
	if err := b.alive(); err != nil {
		return sshProcessIdentity{}, err
	}
	stat, err := readSSHProcText(b.proc, "stat")
	if err != nil {
		return sshProcessIdentity{}, err
	}
	start, err := sshProcessStart(stat, b.pid)
	if err != nil {
		return sshProcessIdentity{}, err
	}
	status, err := readSSHProcText(b.proc, "status")
	if err != nil {
		return sshProcessIdentity{}, err
	}
	if err := verifySSHProcessCredentials(status, b.pid, b.uid); err != nil {
		return sshProcessIdentity{}, err
	}
	cgroup, err := readSSHProcText(b.proc, "cgroup")
	if err != nil {
		return sshProcessIdentity{}, err
	}
	if err := verifySSHProcessGroup(cgroup, b.group); err != nil {
		return sshProcessIdentity{}, err
	}
	result := sshProcessIdentity{PID: b.pid, StartTicks: start, ExecutableSHA256: b.digest, ControlGroupHash: digestBytes([]byte(b.group)), Namespaces: make(map[string]sshKernelIdentity)}
	for _, name := range []string{"pid", "net", "user", "mnt", "root"} {
		held, link := b.namespaces[name], "ns/"+name
		if name == "root" {
			held, link = b.root, "root"
		}
		current, openErr := openSSHProcessLink(b.proc, link)
		if openErr != nil {
			return sshProcessIdentity{}, openErr
		}
		want, wantErr := sshKernelFileIdentity(held)
		got, gotErr := sshKernelFileIdentity(current)
		if err = errors.Join(wantErr, gotErr, current.Close()); err != nil || want != got {
			return sshProcessIdentity{}, errors.Join(ErrInventoryChanged, err)
		}
		if name == "root" {
			result.Root = got
		} else {
			result.Namespaces[name] = got
		}
	}
	if err := b.checkExecutable(); err != nil {
		return sshProcessIdentity{}, err
	}
	stat, err = readSSHProcText(b.proc, "stat")
	if err != nil {
		return sshProcessIdentity{}, err
	}
	after, err := sshProcessStart(stat, b.pid)
	if err = errors.Join(err, b.alive()); err != nil || after != start {
		return sshProcessIdentity{}, errors.Join(ErrInventoryChanged, err)
	}
	return result, nil
}

func (b *sshProcessBinding) checkExecutable() error {
	f, err := openSSHProcessLink(b.proc, "exe")
	if err != nil {
		return err
	}
	defer f.Close()
	var before, after unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &before); err != nil || stamp(before) != b.executable || before.Size < 1 || before.Size > maxSSHDBytes {
		return errors.Join(fmt.Errorf("running SSH executable differs from the protected installed binary"), err)
	}
	h := sha256.New()
	n, readErr := io.Copy(h, io.LimitReader(f, maxSSHDBytes+1))
	if err = errors.Join(readErr, unix.Fstat(int(f.Fd()), &after)); err != nil || n != before.Size || stamp(after) != b.executable || fmt.Sprintf("%x", h.Sum(nil)) != b.digest {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}
