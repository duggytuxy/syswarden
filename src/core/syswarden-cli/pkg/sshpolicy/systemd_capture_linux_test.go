//go:build linux

package sshpolicy

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHSystemctlRequiresProtectedIdentity(t *testing.T) {
	const header = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00"
	for _, scenario := range []string{"regular", "missing", "symlink", "hardlink", "writable", "script", "wrong-owner", "replacement", "writable-directory"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			const path = "/usr/bin/systemctl"
			if scenario != "missing" {
				f.write(path, header+"fixture")
				if err := f.chmod(path, 0755); err != nil {
					t.Fatal(err)
				}
			}
			uid := os.Geteuid()
			switch scenario {
			case "symlink":
				if err := os.Rename(f.path(path), f.path(path+"-original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("systemctl-original", f.path(path)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(path), f.path(path+"-alias")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := f.chmod(path, 0775); err != nil {
					t.Fatal(err)
				}
			case "writable-directory":
				if err := f.chmod("/usr/bin", 0775); err != nil {
					t.Fatal(err)
				}
			case "script":
				f.write(path, "#!/bin/sh\nexit 0\n")
			case "wrong-owner":
				uid++
			}
			tool, err := openSSHSystemctl(f.root, uid)
			if scenario != "regular" && scenario != "replacement" {
				if err == nil {
					_ = tool.file.Close()
					t.Fatal("accepted untrusted systemctl")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tool.file.Close()
			if err := tool.recheck(f.root, uid); err != nil {
				t.Fatal(err)
			}
			if scenario == "replacement" {
				f.write(path+"-new", header+"fixture")
				if err := f.chmod(path+"-new", 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.path(path+"-new"), f.path(path)); err != nil {
					t.Fatal(err)
				}
				if tool.recheck(f.root, uid) == nil {
					t.Fatal("accepted replaced manager binary")
				}
			}
		})
	}
	if _, err := openSSHSystemctl(nil, os.Geteuid()); err == nil {
		t.Fatal("accepted missing root")
	}
}

// Bind only a temporary Unix socket, without listening or accepting traffic.
// The descriptor path keeps the fixture independent of t.TempDir path length.
func sshManagerSocketFixture(t *testing.T, f *inventoryFixture) {
	t.Helper()
	if err := os.MkdirAll(f.path("/run/systemd"), 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := os.Open(f.path("/run/systemd"))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: fmt.Sprintf("/proc/self/fd/%d/private", directory.Fd())}); err != nil {
		t.Fatal(err)
	}
	if err := f.chmod("/run/systemd/private", 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSSHSystemdEndpointBoundary(t *testing.T) {
	for _, scenario := range []string{"socket", "missing", "regular", "symlink", "shared", "hardlink", "writable-parent", "wrong-owner", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			uid := os.Geteuid()
			if scenario != "missing" {
				sshManagerSocketFixture(t, f)
			}
			const path = "/run/systemd/private"
			switch scenario {
			case "regular":
				if err := os.Remove(f.path(path)); err != nil {
					t.Fatal(err)
				}
				f.write(path, "not a bus")
			case "symlink":
				if err := os.Rename(f.path(path), f.path(path+"-original")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("private-original", f.path(path)); err != nil {
					t.Fatal(err)
				}
			case "shared":
				if err := f.chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(path), f.path(path+"-alias")); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := f.chmod("/run/systemd", 0775); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			}
			before, err := readSSHSystemdEndpoint(f.root, uid)
			if scenario != "socket" && scenario != "replacement" {
				if err == nil {
					t.Fatal("accepted unsafe bus endpoint")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := readSSHSystemdEndpoint(f.root, uid)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("unstable fixture", err)
			}
			if scenario == "replacement" {
				if err := os.Remove(f.path(path)); err != nil {
					t.Fatal(err)
				}
				sshManagerSocketFixture(t, f)
				after, err = readSSHSystemdEndpoint(f.root, uid)
				if err != nil || reflect.DeepEqual(before, after) {
					t.Fatal("endpoint replacement was invisible", err)
				}
			}
		})
	}
	if _, err := readSSHSystemdEndpoint(nil, 0); err == nil {
		t.Fatal("accepted missing endpoint root")
	}
}

func TestSSHSystemdQueryIsFixedAndBounded(t *testing.T) {
	f := newInventoryFixture(t, includeDropIns)
	tool := &sshSystemctl{file: f.root}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/untrusted/bus")
	t.Setenv("SYSTEMD_BUS_TIMEOUT", "9999")
	t.Setenv("SYSTEMD_PAGER", "untrusted-command")
	for _, unit := range []string{"ssh.service", "sshd.service", "ssh.socket", "sshd.socket"} {
		command, err := tool.command(context.Background(), unit)
		if err != nil {
			t.Fatal(err)
		}
		properties, _ := sshSystemdProperties(unit)
		want := []string{"/proc/self/fd/3", "--system", "--no-pager", "--no-ask-password", "show", "--all", "--property=" + properties, unit}
		if !reflect.DeepEqual(command.Args, want) || command.Path != "/proc/self/fd/3" || command.Dir != "/" ||
			!reflect.DeepEqual(command.Env, []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}) ||
			len(command.ExtraFiles) != 1 || command.ExtraFiles[0] != tool.file || command.Stdin != nil || command.WaitDelay == 0 {
			t.Fatal("manager query inherited mutable command or environment")
		}
	}
	for _, unit := range []string{"", "restart", "ssh@administrator.service", "ssh.service;reboot", "--root=/untrusted"} {
		if _, err := tool.command(context.Background(), unit); err == nil {
			t.Fatal("accepted arbitrary unit or verb")
		}
	}
	for _, invalid := range []*sshSystemctl{nil, {}} {
		if _, err := invalid.command(context.Background(), "ssh.service"); err == nil {
			t.Fatal("accepted missing executable")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, err := tool.run(ctx, "ssh.service"); err == nil || output != nil {
		t.Fatal("accepted cancelled query")
	}
	var output sshSystemdOutput
	// Exercise io.Copy's ReaderFrom selection as well as its ordinary Write path.
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", maxSSHSystemdOutput+1))}
	if _, err := io.Copy(&output, reader); err == nil || output.buffer.Len() > maxSSHSystemdOutput {
		t.Fatal("manager pipe exceeded the output limit")
	}
}

func TestSSHSystemdInstalledOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST=1 for read-only installed manager verification")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tool, err := openSSHSystemctl(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tool.file.Close()
	before, err := readSSHSystemdEndpoint(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	guard := func() error {
		after, err := readSSHSystemdEndpoint(root, 0)
		if err != nil || !reflect.DeepEqual(before, after) {
			return ErrInventoryChanged
		}
		return tool.recheck(root, 0)
	}
	summary, err := observeSSHSystemd(context.Background(), tool.digest, tool.run, guard)
	if err != nil || !summary.ManagerObserved || summary.ProcessVerified || summary.ListenersVerified || summary.RuntimeActivated || summary.AccessVerified {
		t.Fatal("installed manager observation failed or invented runtime proof", err)
	}
	// Non-root systemctl uses the system bus. This oracle validates real property
	// formatting and fixed queries, not the root adapter's private-bus transport.
}
