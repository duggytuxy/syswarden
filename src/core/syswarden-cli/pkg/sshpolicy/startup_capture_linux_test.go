//go:build linux

package sshpolicy

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSSHBusctlPinnedIdentityAndFixedQuery(t *testing.T) {
	const header = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3e\x00"
	for _, scenario := range []string{"regular", "missing", "symlink", "hardlink", "writable", "wrong-owner", "script", "replacement", "writable-parent"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			const p = "/usr/bin/busctl"
			if scenario != "missing" {
				f.write(p, header+"fixture")
				if err := f.chmod(p, 0755); err != nil {
					t.Fatal(err)
				}
			}
			uid := os.Geteuid()
			switch scenario {
			case "symlink":
				if err := os.Rename(f.path(p), f.path(p+"-saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("busctl-saved", f.path(p)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(p), f.path(p+"-other")); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := f.chmod(p, 0775); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := f.chmod("/usr/bin", 0775); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				uid++
			case "script":
				f.write(p, "#!/bin/sh\nexit 0\n")
			}
			tool, err := openSSHBusctl(f.root, uid)
			if scenario != "regular" && scenario != "replacement" {
				if err == nil {
					_ = tool.file.Close()
					t.Fatal("accepted untrusted busctl")
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
				f.write(p+"-new", header+"fixture")
				if err := f.chmod(p+"-new", 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(f.path(p+"-new"), f.path(p)); err != nil {
					t.Fatal(err)
				}
				if tool.recheck(f.root, uid) == nil {
					t.Fatal("accepted byte-identical binary replacement")
				}
				return
			}
			for _, unit := range []string{"ssh.service", "sshd.service"} {
				c, err := tool.command(context.Background(), unit)
				if err != nil {
					t.Fatal(err)
				}
				want := []string{"/proc/self/fd/3", "--address=unix:path=/run/dbus/system_bus_socket", "--no-pager", "--json=short", "--timeout=5", "--auto-start=no", "--allow-interactive-authorization=no", "get-property", "org.freedesktop.systemd1", "/org/freedesktop/systemd1/unit/" + strings.ReplaceAll(unit, ".", "_2e"), "org.freedesktop.systemd1.Service", "ExecStartEx"}
				if !reflect.DeepEqual(c.Args, want) || len(c.ExtraFiles) != 1 || c.ExtraFiles[0] != tool.file || !reflect.DeepEqual(c.Env, []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}) || c.Dir != "/" {
					t.Fatal("query escaped fixed boundary")
				}
			}
			for _, unit := range []string{"", "other.service", "ssh.socket", "ssh.service;reboot", "ssh@other.service"} {
				if _, err := tool.command(context.Background(), unit); err == nil {
					t.Fatal("accepted caller-selected unit")
				}
			}
			var missingContext context.Context
			if _, err := tool.command(missingContext, "ssh.service"); err == nil {
				t.Fatal("accepted nil context")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := tool.run(ctx, "ssh.service"); err == nil {
				t.Fatal("cancelled query succeeded")
			}
		})
	}
	if _, err := openSSHBusctl(nil, 0); err == nil {
		t.Fatal("accepted missing root")
	}
	var tool *sshBusctl
	if _, err := tool.command(context.Background(), "ssh.service"); err == nil {
		t.Fatal("accepted missing tool")
	}
}

func TestSSHStartupInstalledTypedOracle(t *testing.T) {
	if os.Getenv("SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST") != "1" {
		t.Skip("set SYSWARDEN_SSH_SYSTEMD_ORACLE_TEST=1 for read-only installed manager verification")
	}
	root, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	tool, err := openSSHBusctl(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tool.file.Close()
	// Read the same fixed broker address and manager-identity queries as the
	// production helper. No privilege escalation or service mutation occurs.
	before, err := readSSHSystemBusEndpoint(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wire, err := tool.run(ctx, "sshd.service")
	if err != nil {
		t.Fatal("installed typed query failed", err)
	}
	command, err := decodeSSHStartup(wire)
	if err != nil || command.path == "" || len(command.args) == 0 {
		t.Fatal("installed typed schema changed", err)
	}
	after, err := readSSHSystemBusEndpoint(root, 0)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("system bus identity changed", err)
	}
	if err := tool.recheck(root, 0); err != nil {
		t.Fatal(err)
	}
}

func TestSSHStartupBusRequiresRootManagerOnBothSides(t *testing.T) {
	for _, scenario := range []string{"stable", "other-pid", "other-uid", "changed-pid", "changed-uid", "null-uid", "query-error", "identity-error", "wrong-type", "cancel", "empty-array", "overflow", "trailing"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls []string
			execute := func(_ context.Context, key string) ([]byte, error) {
				calls = append(calls, key)
				if scenario == "identity-error" && key == "manager-pid" {
					return nil, ErrInventoryChanged
				}
				if key == "ssh.service" {
					if scenario == "cancel" {
						cancel()
					}
					if scenario == "query-error" {
						return nil, ErrInventoryChanged
					}
					return sshStartupWire(sshStartupFixture()), nil
				}
				if scenario == "wrong-type" {
					return []byte(`{"type":"s","data":["0"]}`), nil
				}
				if scenario == "empty-array" {
					return []byte(`{"type":"u","data":[]}`), nil
				}
				if scenario == "overflow" {
					return []byte(`{"type":"u","data":[4294967296]}`), nil
				}
				if scenario == "trailing" {
					return []byte(`{"type":"u","data":[1]} {}`), nil
				}
				if key == "manager-pid" {
					if scenario == "other-pid" || scenario == "changed-pid" && len(calls) > 3 {
						return []byte(`{"type":"u","data":[2]}`), nil
					}
					return []byte(`{"type":"u","data":[1]}`), nil
				}
				if scenario == "null-uid" {
					return []byte(`{"type":"u","data":[null]}`), nil
				}
				if scenario == "other-uid" || scenario == "changed-uid" && len(calls) > 3 {
					return []byte(`{"type":"u","data":[1000]}`), nil
				}
				return []byte(`{"type":"u","data":[0]}`), nil
			}
			got, err := querySSHStartupBus(ctx, "ssh.service", execute)
			if scenario == "stable" {
				if err != nil || len(got) == 0 || !reflect.DeepEqual(calls, []string{"manager-pid", "manager-uid", "ssh.service", "manager-pid", "manager-uid"}) {
					t.Fatal("missing identity boundary", calls, err)
				}
			} else if err == nil || got != nil {
				t.Fatal("accepted spoofed, changed or failed manager identity", calls, err)
			}
		})
	}
	if _, err := querySSHStartupBus(context.Background(), "other.service", nil); err == nil {
		t.Fatal("accepted missing/invalid query")
	}
}

func TestSSHStartupSystemBusEndpointProtection(t *testing.T) {
	for _, scenario := range []string{"public-socket", "missing", "symlink", "hardlink", "regular", "wrong-owner", "writable-parent", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns)
			if err := os.MkdirAll(f.path("/run/dbus"), 0700); err != nil {
				t.Fatal(err)
			}
			const p = "/run/dbus/system_bus_socket"
			if scenario != "missing" {
				sshManagerSocketFixture(t, f)
				if err := os.Rename(f.path("/run/systemd/private"), f.path(p)); err != nil {
					t.Fatal(err)
				}
				if err := f.chmod(p, 0666); err != nil {
					t.Fatal(err)
				}
			}
			uid := os.Geteuid()
			switch scenario {
			case "symlink":
				if err := os.Rename(f.path(p), f.path(p+"-saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("system_bus_socket-saved", f.path(p)); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.path(p), f.path(p+"-other")); err != nil {
					t.Fatal(err)
				}
			case "regular":
				if err := os.Remove(f.path(p)); err != nil {
					t.Fatal(err)
				}
				f.write(p, "not a socket")
			case "wrong-owner":
				uid++
			case "writable-parent":
				if err := f.chmod("/run/dbus", 0777); err != nil {
					t.Fatal(err)
				}
			}
			before, err := readSSHSystemBusEndpoint(f.root, uid)
			if scenario != "public-socket" && scenario != "replacement" {
				if err == nil {
					t.Fatal("accepted untrusted bus endpoint")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := readSSHSystemBusEndpoint(f.root, uid)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("stable endpoint changed", err)
			}
			if scenario == "replacement" {
				sshManagerSocketFixture(t, f)
				if err := os.Rename(f.path("/run/systemd/private"), f.path(p)); err != nil {
					t.Fatal(err)
				}
				after, err = readSSHSystemBusEndpoint(f.root, uid)
				if err != nil || reflect.DeepEqual(before, after) {
					t.Fatal("lost endpoint replacement", err)
				}
			}
		})
	}
	if _, err := readSSHSystemBusEndpoint(nil, 0); err == nil {
		t.Fatal("accepted missing root")
	}
}
