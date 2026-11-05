//go:build linux

package sshpolicy

import (
	"os"
	"reflect"
	"testing"
)

func TestSSHBusAncestorsPreserveIdentityAcrossUnrelatedRuntimeChurn(t *testing.T) {
	for _, bus := range []bool{false, true} {
		for _, scenario := range []string{"sibling-file", "sibling-directory", "pid-replacement", "sibling-rename", "parent-mode", "parent-replacement", "socket-mode"} {
			t.Run(map[bool]string{false: "manager", true: "system-bus"}[bus]+"/"+scenario, func(t *testing.T) {
				f := newInventoryFixture(t, includeDropIns)
				sshManagerSocketFixture(t, f)
				parent, socket := "/run/systemd", "/run/systemd/private"
				read := readSSHSystemdEndpoint
				if bus {
					parent, socket = "/run/dbus", "/run/dbus/system_bus_socket"
					if err := os.MkdirAll(f.path(parent), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(f.path("/run/systemd/private"), f.path(socket)); err != nil {
						t.Fatal(err)
					}
					read = readSSHSystemBusEndpoint
				}
				f.write("/run/unrelated.pid", "123\n")
				before, err := read(f.root, os.Geteuid())
				if err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "sibling-file":
					f.write("/run/another.pid", "456\n")
				case "pid-replacement":
					if err := os.Remove(f.path("/run/unrelated.pid")); err != nil {
						t.Fatal(err)
					}
					f.write("/run/unrelated.pid", "456\n")
				case "sibling-rename":
					if err := os.Rename(f.path("/run/unrelated.pid"), f.path("/run/renamed.pid")); err != nil {
						t.Fatal(err)
					}
				case "sibling-directory":
					if err := os.Mkdir(f.path(parent+"/unrelated"), 0700); err != nil {
						t.Fatal(err)
					}
				case "parent-mode":
					if err := f.chmod(parent, 0750); err != nil {
						t.Fatal(err)
					}
				case "parent-replacement":
					if err := os.Rename(f.path(parent), f.path(parent+"-retained")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(f.path(parent), 0700); err != nil {
						t.Fatal(err)
					}
					old := parent + "-retained" + socket[len(parent):]
					if err := os.Rename(f.path(old), f.path(socket)); err != nil {
						t.Fatal(err)
					}
				case "socket-mode":
					if err := f.chmod(socket, 0400); err != nil {
						t.Fatal(err)
					}
				}
				after, err := read(f.root, os.Geteuid())
				same := err == nil && reflect.DeepEqual(before, after)
				if same != (scenario == "sibling-file" || scenario == "sibling-directory" || scenario == "pid-replacement" || scenario == "sibling-rename") {
					t.Fatal("incorrect runtime ancestor comparison", same, err)
				}
			})
		}
	}
}
