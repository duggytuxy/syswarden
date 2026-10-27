//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func sshMountEventTestProcess(t *testing.T) *sshProcessBinding {
	t.Helper()
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	proc, err := openSSHProcDirectory(root, "proc")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	b := &sshProcessBinding{pid: os.Getpid(), uid: os.Geteuid(), pidfd: -1,
		requireSameMount: true, namespaces: make(map[string]*os.File)}
	t.Cleanup(func() { _ = b.Close() })
	b.pidfd, err = unix.PidfdOpen(b.pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	b.proc, err = openSSHProcDirectory(proc, strconv.Itoa(b.pid))
	if err != nil {
		t.Fatal(err)
	}
	b.verifier, err = openSSHProcDirectory(proc, strconv.Itoa(b.pid))
	if err != nil {
		t.Fatal(err)
	}
	b.namespaces["mnt"], err = openSSHProcessLink(b.proc, "ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSSHMountEventsNativeProcfsAndClose(t *testing.T) {
	b := sshMountEventTestProcess(t)
	f, err := pinSSHMountEvents(b)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.mounts.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("mount event descriptor can escape into a child", err)
	}
	if err := f.check(); err != nil {
		t.Fatal("unchanged native mount namespace rejected", err)
	}
	if err := f.Close(); err != nil || f.check() == nil || f.Close() != nil {
		t.Fatal("mount event fence lifecycle failed", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("mount event descriptor leaked", err)
	}
	var absent *sshMountEventFence
	if absent.check() == nil || absent.Close() != nil || absent.guard(func() error { return nil }) == nil {
		t.Fatal("nil fence accepted")
	}
	if _, err := pinSSHMountEvents(nil); err == nil {
		t.Fatal("nil process accepted")
	}
}

func TestSSHMountEventsPollFailuresStayPoisoned(t *testing.T) {
	for _, scenario := range []string{"priority", "error-event", "hangup", "invalid", "unexpected-readable", "count-only", "event-without-count", "poll-error", "interrupted", "namespace-before", "namespace-during", "closed-file"} {
		t.Run(scenario, func(t *testing.T) {
			b := sshMountEventTestProcess(t)
			f, err := pinSSHMountEvents(b)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			calls := 0
			original := b.namespaces["mnt"]
			other, err := openSSHProcessLink(b.proc, "ns/net")
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			defer func() { b.namespaces["mnt"] = original }()
			fd := f.mounts.Fd()
			if fd > 1<<31-1 {
				t.Fatal("fixture descriptor exceeds the kernel poll range")
				return
			}
			expectedFD := int32(fd)
			f.poll = func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if len(fds) != 1 || timeout != 0 || fds[0].Fd != expectedFD || fds[0].Events != unix.POLLPRI|unix.POLLERR {
					t.Fatal("incorrect kernel event subscription")
				}
				switch scenario {
				case "priority":
					fds[0].Revents = unix.POLLPRI
				case "error-event":
					fds[0].Revents = unix.POLLERR
				case "hangup":
					fds[0].Revents = unix.POLLHUP
				case "invalid":
					fds[0].Revents = unix.POLLNVAL
				case "unexpected-readable":
					fds[0].Revents = unix.POLLIN
				case "event-without-count":
					fds[0].Revents = unix.POLLPRI
					return 0, nil
				case "poll-error":
					return 0, unix.EIO
				case "interrupted":
					return 0, unix.EINTR
				case "namespace-during":
					b.namespaces["mnt"] = other
					return 0, nil
				}
				return 1, nil
			}
			if scenario == "namespace-before" {
				b.namespaces["mnt"] = other
			}
			if scenario == "closed-file" {
				if err := f.mounts.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.check(); err == nil {
				t.Fatal("mount event or error accepted")
			}
			before := calls
			b.namespaces["mnt"] = original
			f.poll = func([]unix.PollFd, int) (int, error) { calls++; return 0, nil }
			if f.check() == nil || calls != before {
				t.Fatal("later clean poll erased mount event failure")
			}
		})
	}
}

func TestSSHMountEventsGuardAndActivationNoReplay(t *testing.T) {
	b := sshMountEventTestProcess(t)
	f, err := pinSSHMountEvents(b)
	if err != nil {
		t.Fatal(err)
	}
	event := false
	f.poll = func(fds []unix.PollFd, _ int) (int, error) {
		if event {
			fds[0].Revents = unix.POLLPRI | unix.POLLERR
			return 1, nil
		}
		return 0, nil
	}
	calls := 0
	lease := &sshActivationTarget{ctx: context.Background(), target: strings.Repeat("a", 64),
		verify:  func(context.Context) error { return f.check() },
		preSend: func() error { return f.guard(func() error { event = true; return nil }) },
		send:    func() error { calls++; return nil }, after: func(context.Context, func() error) error { return nil }, closeFn: f.Close}
	defer lease.Close()
	if lease.request(context.Background(), func() error { return nil }) == nil || calls != 0 || !lease.attempted {
		t.Fatal("mount change during final pre-send probe allowed dispatch")
	}
	event = false
	if lease.request(context.Background(), func() error { return nil }) == nil || calls != 0 {
		t.Fatal("mount failure allowed a second dispatch")
	}
	if err := lease.Close(); err != nil || f.mounts != nil {
		t.Fatal("activation did not release the mount fence", err)
	}
}

func TestSSHMountEventsRejectUnqualifiedProcessAndFakeProcfs(t *testing.T) {
	for _, scenario := range []string{"private-mount", "missing-verifier", "regular", "directory", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			b := sshMountEventTestProcess(t)
			switch scenario {
			case "private-mount":
				b.requireSameMount = false
			case "missing-verifier":
				original := b.verifier
				b.verifier = nil
				defer func() { b.verifier = original }()
			default:
				dir := t.TempDir()
				if err := os.Mkdir(filepath.Join(dir, "ns"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/proc/self/ns/mnt", filepath.Join(dir, "ns", "mnt")); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "mounts")
				var err error
				switch scenario {
				case "regular":
					err = os.WriteFile(path, nil, 0600)
				case "directory":
					err = os.Mkdir(path, 0700)
				case "symlink":
					err = os.Symlink("/proc/self/mounts", path)
				}
				if err != nil {
					t.Fatal(err)
				}
				fixtureRoot, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer fixtureRoot.Close()
				fake, err := fixtureRoot.Open(".")
				if err != nil {
					t.Fatal(err)
				}
				defer fake.Close()
				original := b.proc
				b.proc = fake
				defer func() { b.proc = original }()
			}
			if fence, err := pinSSHMountEvents(b); err == nil || fence != nil {
				_ = fence.Close()
				t.Fatal("unqualified mount event source accepted", err)
			}
		})
	}
}

// This optional rootless oracle changes only a new user/mount namespace. A
// host that disables unprivileged user namespaces reports the missing coverage.
func TestSSHMountEventsNativeMountUnmountABA(t *testing.T) {
	command := exec.Command("/proc/self/exe", "-test.run=^TestSSHMountEventsNativeABAChild$", "-test.v")
	command.Env = []string{"SYSWARDEN_MOUNT_EVENT_TEST_CHILD=yes", "GOMAXPROCS=2"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	output, err := command.CombinedOutput()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		t.Skip("native mount ABA oracle requires unprivileged user/mount namespaces")
	}
	if err != nil || !strings.Contains(string(output), "PASS: TestSSHMountEventsNativeABAChild") {
		t.Fatalf("native mount ABA oracle failed: %v\n%s", err, output)
	}
}

func TestSSHMountEventsNativeABAChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_MOUNT_EVENT_TEST_CHILD") != "yes" {
		t.Skip("isolated child only")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source"), filepath.Join(dir, "target")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	var before, after unix.Stat_t
	if err := unix.Stat(target, &before); err != nil {
		t.Fatal(err)
	}
	b := sshMountEventTestProcess(t)
	f, err := pinSSHMountEvents(b)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	mounted := true
	t.Cleanup(func() {
		if mounted {
			if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
				t.Errorf("isolated mount cleanup failed: %v", err)
			}
		}
	})
	if err := unix.Unmount(target, 0); err != nil {
		t.Fatal(err)
	}
	mounted = false
	if err := unix.Stat(target, &after); err != nil || stamp(before) != stamp(after) {
		t.Fatal("mount ABA did not preserve original path metadata", err)
	}
	if err := b.checkMountView(); err != nil {
		t.Fatal("mount ABA changed namespace identity", err)
	}
	if err := f.check(); err == nil {
		t.Fatal("mount ABA escaped the retained kernel event fence")
	}
	if err := f.check(); err == nil {
		t.Fatal("a consumed mount event cleared the retained failure")
	}
}
