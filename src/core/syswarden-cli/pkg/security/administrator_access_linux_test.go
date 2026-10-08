//go:build linux

package security

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOSHardeningPreservesAdministratorAccess(t *testing.T) {
	for _, sudoUser := range []string{"", "root", "alice", "unknown-user"} {
		t.Run("invoker-"+sudoUser, func(t *testing.T) {
			t.Setenv("SUDO_USER", sudoUser)
			host := hardeningTestHost(t, hardeningExecutor{
				run: func(name string, args ...string) error {
					t.Fatalf("unexpected account or service mutation: %s %v", name, args)
					return nil
				},
			})
			files := map[string][]byte{
				"/etc/group":                   []byte("root:x:0:\nsudo:x:27:alice,bob\nwheel:x:10:alice,bob\nadm:x:4:auditor,syslog\n"),
				"/etc/gshadow":                 []byte("sudo:!:alice:alice,bob\nwheel:!::alice,bob\nadm:!::auditor,syslog\n"),
				"/etc/sudoers":                 []byte("root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL) ALL\n"),
				"/etc/sudoers.d/administrator": []byte("bob ALL=(ALL) ALL\n"),
			}
			for logical, content := range files {
				path, err := host.path(logical)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
					t.Fatal(err)
				}
				if err := writeHardeningFixtureFile(path, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Exercise every OS hardening stage on an intentionally minimal root.
			// Missing logging services may be reported; account policy must not change.
			_ = applyOSHardeningOn(host)
			for logical, want := range files {
				path, err := host.path(logical)
				if err != nil {
					t.Fatal(err)
				}
				got, err := readHardeningFixtureFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("administrator policy changed: %s: %v", logical, err)
				}
			}
		})
	}
}
