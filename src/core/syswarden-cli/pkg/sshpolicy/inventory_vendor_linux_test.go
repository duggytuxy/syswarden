//go:build linux

package sshpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const vendorFixtureTarget = "/usr/share/crypto-policies/DEFAULT/opensshserver.txt"

func vendorInventoryFixture(t *testing.T, content string) *inventoryFixture {
	t.Helper()
	fixture := newInventoryFixture(t, includeDropIns+"Include "+vendorSSHPath+"\n")
	fixture.write(vendorFixtureTarget, content)
	fixture.write(vendorSSHPath, "placeholder")
	if err := replaceVendorFixtureLink(fixture, vendorFixtureTarget); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func replaceVendorFixtureLink(fixture *inventoryFixture, target string) error {
	if err := os.Remove(fixture.path(vendorSSHPath)); err != nil {
		return err
	}
	return os.Symlink(target, fixture.path(vendorSSHPath))
}

func TestVendorInventoryPreservesPolicyAndTracksBothPaths(t *testing.T) {
	const policy = "Ciphers aes256-ctr\nMACs hmac-sha2-256\n"
	fixture := vendorInventoryFixture(t, policy)
	inventory := fixture.open()
	if inventory.snapshot.links[vendorSSHPath] != vendorFixtureTarget {
		t.Fatal("exact link text omitted")
	}
	for _, name := range []string{vendorSSHPath, vendorFixtureTarget} {
		if string(inventory.snapshot.files[name]) != policy || !inventory.snapshot.nodes[name].exists {
			t.Fatalf("missing target or alias observation: %s", name)
		}
	}
	for _, profile := range []Profile{Forwarding, CIS} {
		candidate, err := inventory.Prepare(profile)
		if err != nil || candidate == (Candidate{}) {
			t.Fatalf("valid vendor policy refused: %v", err)
		}
		if bytes.Contains(candidate.Bytes(), []byte("Ciphers")) || bytes.Contains(candidate.Bytes(), []byte("MACs")) {
			t.Fatal("vendor crypto policy was copied or overridden")
		}
	}
	if got, err := os.Readlink(fixture.path(vendorSSHPath)); err != nil || got != vendorFixtureTarget {
		t.Fatal("vendor alias changed")
	}
	if got, err := os.ReadFile(fixture.path(vendorFixtureTarget)); err != nil || string(got) != policy {
		t.Fatal("vendor target changed")
	}
	if _, err := os.Lstat(fixture.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inventory wrote the reserved drop-in")
	}
}

func TestVendorInventoryRegularGeneratedPolicyStillSupported(t *testing.T) {
	fixture := newInventoryFixture(t, includeDropIns+"Include "+vendorSSHPath+"\n")
	fixture.write(vendorSSHPath, "Ciphers aes256-ctr\n")
	inventory := fixture.open()
	if len(inventory.snapshot.links) != 0 {
		t.Fatal("regular generated policy misclassified as alias")
	}
	if _, err := inventory.Prepare(CIS); err != nil {
		t.Fatal(err)
	}
}

func TestVendorTargetLayout(t *testing.T) {
	for _, label := range []string{"DEFAULT", "FIPS", "CUSTOM_1", "DEFAULT:AD-SUPPORT:NO-SHA1", strings.Repeat("A", 128)} {
		if !vendorTarget("/usr/share/crypto-policies/" + label + "/opensshserver.txt") {
			t.Fatalf("bounded policy label refused: %s", label)
		}
	}
	for _, target := range []string{
		"", "/", "../../../usr/share/crypto-policies/DEFAULT/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT/../FIPS/opensshserver.txt",
		"/usr/share/crypto-policies//DEFAULT/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT/openssh.txt",
		"/usr/share/crypto-policies/DEFAULT/opensshserver.txt/extra",
		"/usr/share/crypto-policies/FIPS/nested/opensshserver.txt",
		"/usr/share/crypto-policies-foreign/DEFAULT/opensshserver.txt",
		"/etc/crypto-policies/DEFAULT/opensshserver.txt",
		"/proc/self/fd/1", "/dev/null", vendorSSHPath, MainPath, DropInPath,
		"/usr/share/crypto-policies/default/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT SPACE/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT\x00/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT\n/opensshserver.txt",
		"/usr/share/crypto-policies/\u00c9/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT::FIPS/opensshserver.txt",
		"/usr/share/crypto-policies/:DEFAULT/opensshserver.txt",
		"/usr/share/crypto-policies/DEFAULT:/opensshserver.txt",
		"/usr/share/crypto-policies/" + strings.Repeat("A", 129) + "/opensshserver.txt",
	} {
		if vendorTarget(target) {
			t.Fatalf("unbounded or redirected target accepted: %q", target)
		}
	}
}

func TestVendorInventoryRejectsUntrustedAliasAndTarget(t *testing.T) {
	cases := map[string]func(*inventoryFixture) error{
		"dangling-target": func(f *inventoryFixture) error { return os.Remove(f.path(vendorFixtureTarget)) },
		"missing-target-parent": func(f *inventoryFixture) error {
			return replaceVendorFixtureLink(f, "/usr/share/crypto-policies/ABSENT/opensshserver.txt")
		},
		"relative-target": func(f *inventoryFixture) error {
			return replaceVendorFixtureLink(f, "../../../usr/share/crypto-policies/DEFAULT/opensshserver.txt")
		},
		"redirected-target": func(f *inventoryFixture) error { return replaceVendorFixtureLink(f, MainPath) },
		"link-loop":         func(f *inventoryFixture) error { return replaceVendorFixtureLink(f, vendorSSHPath) },
		"overlong-link":     func(f *inventoryFixture) error { return replaceVendorFixtureLink(f, "/"+strings.Repeat("x", 1025)) },
		"writable-link-parent": func(f *inventoryFixture) error {
			return f.chmod("/etc/crypto-policies/back-ends", 0777)
		},
		"writable-target":   func(f *inventoryFixture) error { return f.chmod(vendorFixtureTarget, 0620) },
		"executable-target": func(f *inventoryFixture) error { return f.chmod(vendorFixtureTarget, 0700) },
		"writable-target-parent": func(f *inventoryFixture) error {
			return f.chmod("/usr/share/crypto-policies/DEFAULT", 0777)
		},
		"alias-hardlink": func(f *inventoryFixture) error {
			return os.Link(f.path(vendorSSHPath), f.path(vendorSSHPath+".linked"))
		},
		"target-hardlink": func(f *inventoryFixture) error {
			return os.Link(f.path(vendorFixtureTarget), f.path(vendorFixtureTarget+".linked"))
		},
		"target-symlink": func(f *inventoryFixture) error {
			if err := os.Remove(f.path(vendorFixtureTarget)); err != nil {
				return err
			}
			return os.Symlink(f.path(MainPath), f.path(vendorFixtureTarget))
		},
		"target-directory": func(f *inventoryFixture) error {
			if err := os.Remove(f.path(vendorFixtureTarget)); err != nil {
				return err
			}
			return os.Mkdir(f.path(vendorFixtureTarget), 0700)
		},
		"target-fifo": func(f *inventoryFixture) error {
			if err := os.Remove(f.path(vendorFixtureTarget)); err != nil {
				return err
			}
			return unix.Mkfifo(f.path(vendorFixtureTarget), 0600)
		},
		"target-ancestor-symlink": func(f *inventoryFixture) error {
			if err := os.Rename(f.path("/usr/share/crypto-policies/DEFAULT"), f.path("/usr/share/crypto-policies/saved")); err != nil {
				return err
			}
			return os.Symlink("saved", f.path("/usr/share/crypto-policies/DEFAULT"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := vendorInventoryFixture(t, "Ciphers aes256-ctr\n")
			if err := change(fixture); err != nil {
				t.Fatal(err)
			}
			if handle, err := openInventory(fixture.root, os.Geteuid()); err == nil || handle != nil {
				t.Fatal("unsafe vendor layout accepted")
			}
		})
	}
	t.Run("untrusted-link-metadata", func(t *testing.T) {
		fixture := vendorInventoryFixture(t, "# policy\n")
		var original unix.Stat_t
		if err := unix.Lstat(fixture.path(vendorSSHPath), &original); err != nil {
			t.Fatal(err)
		}
		reader := inventoryReader{uid: os.Geteuid()}
		if !reader.trustedVendorLink(vendorSSHPath, original) {
			t.Fatal("fixture link rejected")
		}
		if reader.trustedVendorLink(MainPath, original) || reader.trustedVendorLink(DropInPath, original) {
			t.Fatal("exception extended to administrator or reserved path")
		}
		reader.uid++
		if reader.trustedVendorLink(vendorSSHPath, original) {
			t.Fatal("wrong link owner accepted")
		}
	})
}

func TestVendorInventoryInvalidatesChanges(t *testing.T) {
	cases := map[string]func(*inventoryFixture) error{
		"identical-link-replacement": func(f *inventoryFixture) error { return replaceVendorFixtureLink(f, vendorFixtureTarget) },
		"policy-switch": func(f *inventoryFixture) error {
			target := "/usr/share/crypto-policies/FIPS/opensshserver.txt"
			f.write(target, "Ciphers aes256-ctr\n")
			return replaceVendorFixtureLink(f, target)
		},
		"target-content": func(f *inventoryFixture) error { f.write(vendorFixtureTarget, "Ciphers aes128-ctr\n"); return nil },
		"target-replacement": func(f *inventoryFixture) error {
			f.write(vendorFixtureTarget+".new", "Ciphers aes256-ctr\n")
			return os.Rename(f.path(vendorFixtureTarget+".new"), f.path(vendorFixtureTarget))
		},
		"target-mode":        func(f *inventoryFixture) error { return f.chmod(vendorFixtureTarget, 0644) },
		"target-removed":     func(f *inventoryFixture) error { return os.Remove(f.path(vendorFixtureTarget)) },
		"target-parent-mode": func(f *inventoryFixture) error { return f.chmod("/usr/share/crypto-policies", 0755) },
		"link-to-regular": func(f *inventoryFixture) error {
			if err := os.Remove(f.path(vendorSSHPath)); err != nil {
				return err
			}
			f.write(vendorSSHPath, "Ciphers aes256-ctr\n")
			return nil
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := vendorInventoryFixture(t, "Ciphers aes256-ctr\n")
			inventory := fixture.open()
			if err := change(fixture); err != nil {
				t.Fatal(err)
			}
			if candidate, err := inventory.Prepare(CIS); !errors.Is(err, ErrInventoryChanged) || candidate != (Candidate{}) {
				t.Fatalf("changed policy accepted: %v", err)
			}
			if !errors.Is(inventory.Recheck(), ErrInventoryChanged) {
				t.Fatal("changed vendor inventory remained reusable")
			}
		})
	}
}

func TestVendorLinkRejectsReplacementBetweenInspectionAndOpen(t *testing.T) {
	fixture := vendorInventoryFixture(t, "Ciphers aes256-ctr\n")
	parent, err := os.Open(fixture.path("/etc/crypto-policies/back-ends"))
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), "opensshserver.config", &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	// The replacement has identical text but a different observed identity.
	if err := replaceVendorFixtureLink(fixture, vendorFixtureTarget); err != nil {
		t.Fatal(err)
	}
	reader := inventoryReader{root: fixture.root, uid: os.Geteuid()}
	if data, exists, err := reader.readVendorLink(parent, vendorSSHPath, before); !errors.Is(err, ErrInventoryChanged) || exists || data != nil {
		t.Fatalf("stale link metadata accepted: %v", err)
	}
}

func TestVendorInventoryInspectsIncludedPolicyAndBounds(t *testing.T) {
	t.Run("included-conflict", func(t *testing.T) {
		fixture := vendorInventoryFixture(t, "Include /etc/ssh/site-policy\n")
		fixture.write("/etc/ssh/site-policy", "AllowTcpForwarding local\n")
		inventory := fixture.open()
		if candidate, err := inventory.Prepare(Forwarding); err == nil || candidate != (Candidate{}) {
			t.Fatal("conflict reached through vendor link ignored")
		}
	})
	t.Run("cycle", func(t *testing.T) {
		fixture := vendorInventoryFixture(t, "Include "+vendorSSHPath+"\n")
		if handle, err := openInventory(fixture.root, os.Geteuid()); err == nil || handle != nil {
			t.Fatal("alias include cycle accepted")
		}
	})
	t.Run("logical-byte-bound", func(t *testing.T) {
		fixture := vendorInventoryFixture(t, strings.Repeat("#\n", MaxBytes/4))
		if handle, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || handle != nil {
			t.Fatalf("alias bytes escaped inventory budget: %v", err)
		}
	})
	t.Run("logical-file-bound", func(t *testing.T) {
		fixture := vendorInventoryFixture(t, "# policy\n")
		for i := range MaxFiles - 2 {
			fixture.write(fmt.Sprintf("/etc/ssh/sshd_config.d/%03d.conf", i), "# file\n")
		}
		if handle, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || handle != nil {
			t.Fatalf("alias path escaped file budget: %v", err)
		}
	})
}
