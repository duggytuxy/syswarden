//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func sshResourcesFixture(t *testing.T) *inventoryFixture {
	t.Helper()
	f := newInventoryFixture(t, includeDropIns)
	for _, path := range []string{"/usr/bin/systemctl", "/usr/bin/sshd", "/usr/bin/busctl"} {
		f.write(path, "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00fixture")
		if err := f.chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	sshManagerSocketFixture(t, f)
	if err := os.MkdirAll(f.path("/run/dbus"), 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(f.path("/run/dbus"))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/system_bus_socket", directory.Fd())}); err != nil {
		t.Fatal(err)
	}
	return f
}

func sshResourcesRoot(t *testing.T, f *inventoryFixture) *os.File {
	t.Helper()
	fd, err := unix.FcntlInt(f.root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fd), "ssh-resource-fixture-root")
}

func TestSSHResourcesOwnAndCloseEveryDescriptor(t *testing.T) {
	for _, startup := range []bool{false, true} {
		t.Run(fmt.Sprint(startup), func(t *testing.T) {
			f := sshResourcesFixture(t)
			r, err := ownSSHProcessResources(context.Background(), sshResourcesRoot(t, f), os.Geteuid(), startup)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			files := []*os.File{r.root, r.tool.file, r.daemon.file}
			if startup {
				files = append(files, r.bus.file)
			}
			for _, file := range files {
				if _, err := file.Stat(); err != nil {
					t.Fatal("premature close", err)
				}
			}
			if err := r.recheck(); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("resource leaked", err)
				}
			}
			if r.recheck() == nil || r.Close() != nil {
				t.Fatal("closed owner remained usable or close was not idempotent")
			}
			if _, err := f.root.Stat(); err != nil {
				t.Fatal("closed the fixture's unrelated root", err)
			}
		})
	}
}

func TestSSHResourcesClosePartialAcquisitions(t *testing.T) {
	for _, path := range []string{"/usr/bin/systemctl", "/usr/bin/sshd", "/run/systemd/private", "/usr/bin/busctl", "/run/dbus/system_bus_socket"} {
		t.Run(path, func(t *testing.T) {
			f := sshResourcesFixture(t)
			if err := os.Remove(f.path(path)); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			root := sshResourcesRoot(t, f)
			r, err := ownSSHProcessResources(context.Background(), root, os.Geteuid(), true)
			if err == nil || r != nil {
				t.Fatal("accepted partial acquisition")
			}
			if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("transferred root leaked", err)
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) != len(before) {
				t.Fatal("partial acquisition leaked descriptors", len(before), len(after), err)
			}
		})
	}
}

func TestSSHResourcesRefuseChangedOrClosedHelpers(t *testing.T) {
	for _, scenario := range []string{"tool-close", "daemon-close", "bus-close", "root-close", "/usr/bin/systemctl", "/usr/bin/sshd", "/usr/bin/busctl", "/run/systemd/private", "/run/dbus/system_bus_socket"} {
		t.Run(scenario, func(t *testing.T) {
			f := sshResourcesFixture(t)
			r, err := ownSSHProcessResources(context.Background(), sshResourcesRoot(t, f), os.Geteuid(), true)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			switch scenario {
			case "tool-close":
				err = r.tool.file.Close()
			case "daemon-close":
				err = r.daemon.file.Close()
			case "bus-close":
				err = r.bus.file.Close()
			case "root-close":
				err = r.root.Close()
			default:
				err = os.Rename(f.path(scenario), f.path(scenario+"-retained"))
			}
			if err != nil || r.recheck() == nil {
				t.Fatal("accepted changed or closed resource", err)
			}
		})
	}
}

func TestSSHResourcesInvalidInputsStillReleaseRoot(t *testing.T) {
	for _, scenario := range []string{"nil-context", "cancelled", "negative-uid", "wrong-uid", "nil-root"} {
		t.Run(scenario, func(t *testing.T) {
			f := sshResourcesFixture(t)
			root := sshResourcesRoot(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var input context.Context = ctx
			uid := os.Geteuid()
			switch scenario {
			case "nil-context":
				input = nil
			case "cancelled":
				cancel()
			case "negative-uid":
				uid = -1
			case "wrong-uid":
				uid++
			case "nil-root":
				_ = root.Close()
				root = nil
			}
			r, err := ownSSHProcessResources(input, root, uid, true)
			if err == nil || r != nil {
				t.Fatal("accepted invalid owner")
			}
			if root != nil {
				if _, err := root.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("root leaked", err)
				}
			}
		})
	}
}
