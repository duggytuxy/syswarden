//go:build linux

package sshpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type inventoryFixture struct {
	t    *testing.T
	base string
	root *os.File
}

func newInventoryFixture(t *testing.T, main string) *inventoryFixture {
	t.Helper()
	fixture := &inventoryFixture{t: t, base: t.TempDir()}
	fixture.write(MainPath, main)
	if err := os.MkdirAll(fixture.path("/etc/ssh/sshd_config.d"), 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	fixture.root, err = os.Open(fixture.base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixture.root.Close() })
	return fixture
}

func (fixture *inventoryFixture) path(name string) string {
	return filepath.Join(fixture.base, name)
}

func (fixture *inventoryFixture) write(name, value string) {
	fixture.t.Helper()
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		fixture.t.Fatal("invalid fixture path")
	}
	root, err := os.OpenRoot(fixture.base)
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer root.Close()
	name = strings.TrimPrefix(name, "/")
	if err := root.MkdirAll(filepath.Dir(name), 0700); err != nil {
		fixture.t.Fatal(err)
	}
	if err := root.WriteFile(name, []byte(value), 0600); err != nil {
		fixture.t.Fatal(err)
	}
}

// Deliberately unsafe permissions stay inside the private temporary root.
func (fixture *inventoryFixture) chmod(name string, mode os.FileMode) error {
	root, err := os.OpenRoot(fixture.base)
	if err != nil {
		return err
	}
	defer root.Close()
	name = strings.TrimPrefix(name, "/")
	if name == "" {
		name = "."
	}
	return root.Chmod(name, mode)
}

func (fixture *inventoryFixture) open() *Inventory {
	fixture.t.Helper()
	result, err := openInventory(fixture.root, os.Geteuid())
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.t.Cleanup(func() { _ = result.Close() })
	return result
}

func TestInventoryCompleteGraphAndIndependentDescriptor(t *testing.T) {
	main := "Include /etc/crypto-policies/back-ends/opensshserver.config\n" + includeDropIns +
		"Include /etc/ssh/missing.conf /etc/ssh/absent/*.conf\n"
	fixture := newInventoryFixture(t, main)
	fixture.write("/etc/crypto-policies/back-ends/opensshserver.config", "Ciphers aes256-ctr\n")
	fixture.write("/etc/ssh/sshd_config.d/50-automation.conf", "# Ansible managed\nSubsystem sftp internal-sftp\nMaxSessions 12\n")
	fixture.write("/etc/ssh/sshd_config.d/unmatched.txt", "This is not SSH configuration.\n")
	inventory := fixture.open()
	if len(inventory.snapshot.files) != 3 {
		t.Fatal("incomplete graph or unmatched file read")
	}
	if len(inventory.snapshot.entries["/etc/ssh/sshd_config.d"]) != 2 {
		t.Fatal("unmatched directory membership omitted")
	}
	for _, absent := range []string{DropInPath, "/etc/ssh/missing.conf", "/etc/ssh/absent"} {
		if value, exists := inventory.snapshot.nodes[absent]; !exists || value.exists {
			t.Fatalf("negative lookup not retained: %s", absent)
		}
	}
	if err := fixture.root.Close(); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []Profile{Forwarding, CIS} {
		candidate, err := inventory.Prepare(profile)
		if err != nil {
			t.Fatal(err)
		}
		pure, err := Prepare(profile, inventory.snapshot.files)
		if err != nil || candidate != pure {
			t.Fatal("protected inventory differs from complete pure input")
		}
	}
	if data, err := os.ReadFile(fixture.path(MainPath)); err != nil || string(data) != main {
		t.Fatal("main configuration was modified")
	}
	if _, err := os.Lstat(fixture.path(DropInPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inventory published a policy")
	}
}

func TestInventoryRefusesUnsafeStorage(t *testing.T) {
	cases := map[string]func(*inventoryFixture) error{
		"writable-main":       func(f *inventoryFixture) error { return f.chmod(MainPath, 0666) },
		"group-writable-main": func(f *inventoryFixture) error { return f.chmod(MainPath, 0620) },
		"executable-main":     func(f *inventoryFixture) error { return f.chmod(MainPath, 0700) },
		"writable-ancestor":   func(f *inventoryFixture) error { return f.chmod("/etc", 0777) },
		"writable-root":       func(f *inventoryFixture) error { return f.chmod("/", 0777) },
		"symlink-main": func(f *inventoryFixture) error {
			if err := os.Rename(f.path(MainPath), f.path(MainPath+".saved")); err != nil {
				return err
			}
			return os.Symlink("sshd_config.saved", f.path(MainPath))
		},
		"symlink-ancestor": func(f *inventoryFixture) error {
			if err := os.Rename(f.path("/etc/ssh"), f.path("/etc/saved")); err != nil {
				return err
			}
			return os.Symlink("saved", f.path("/etc/ssh"))
		},
		"symlink-match": func(f *inventoryFixture) error {
			return os.Symlink("../sshd_config", f.path("/etc/ssh/sshd_config.d/50-external.conf"))
		},
		"dangling-match": func(f *inventoryFixture) error {
			return os.Symlink("absent", f.path("/etc/ssh/sshd_config.d/50-external.conf"))
		},
		"hardlink-main": func(f *inventoryFixture) error { return os.Link(f.path(MainPath), f.path("/etc/ssh/linked")) },
		"directory-match": func(f *inventoryFixture) error {
			return os.Mkdir(f.path("/etc/ssh/sshd_config.d/50-external.conf"), 0700)
		},
		"fifo-match": func(f *inventoryFixture) error {
			return unix.Mkfifo(f.path("/etc/ssh/sshd_config.d/50-external.conf"), 0600)
		},
		"missing-main": func(f *inventoryFixture) error { return os.Remove(f.path(MainPath)) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, includeDropIns)
			if err := change(fixture); err != nil {
				t.Fatal(err)
			}
			if result, err := openInventory(fixture.root, os.Geteuid()); err == nil || result != nil {
				t.Fatal("unsafe storage accepted or partial handle returned")
			}
		})
	}
	t.Run("wrong-owner", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		if result, err := openInventory(fixture.root, os.Geteuid()+1); err == nil || result != nil {
			t.Fatal("unexpected owner accepted")
		}
	})
}

func TestInventoryRecheckPoisonsChangedHandles(t *testing.T) {
	cases := map[string]func(*inventoryFixture) error{
		"content": func(f *inventoryFixture) error {
			f.write(MainPath, includeDropIns+"AllowTcpForwarding yes\n")
			return nil
		},
		"removed-main": func(f *inventoryFixture) error { return os.Remove(f.path(MainPath)) },
		"mode":         func(f *inventoryFixture) error { return f.chmod(MainPath, 0644) },
		"new-conflict": func(f *inventoryFixture) error {
			f.write("/etc/ssh/sshd_config.d/50-admin.conf", "AllowTcpForwarding local\n")
			return nil
		},
		"new-unmatched-member": func(f *inventoryFixture) error { f.write("/etc/ssh/sshd_config.d/note.txt", "note"); return nil },
		"new-literal":          func(f *inventoryFixture) error { f.write("/etc/ssh/missing.conf", "# new\n"); return nil },
		"new-directory":        func(f *inventoryFixture) error { return os.Mkdir(f.path("/etc/ssh/absent"), 0700) },
		"reserved-created":     func(f *inventoryFixture) error { f.write(DropInPath, "AllowTcpForwarding no\n"); return nil },
		"identical-replacement": func(f *inventoryFixture) error {
			data, err := os.ReadFile(f.path(MainPath))
			if err != nil {
				return err
			}
			f.write(MainPath+".new", string(data))
			return os.Rename(f.path(MainPath+".new"), f.path(MainPath))
		},
		"parent-renamed": func(f *inventoryFixture) error {
			if err := os.Rename(f.path("/etc/ssh/sshd_config.d"), f.path("/etc/ssh/old")); err != nil {
				return err
			}
			return os.Mkdir(f.path("/etc/ssh/sshd_config.d"), 0700)
		},
		"parent-symlink": func(f *inventoryFixture) error {
			if err := os.Rename(f.path("/etc/ssh/sshd_config.d"), f.path("/etc/ssh/old")); err != nil {
				return err
			}
			return os.Symlink("old", f.path("/etc/ssh/sshd_config.d"))
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			main := includeDropIns + "Include /etc/ssh/missing.conf /etc/ssh/absent/*.conf\n"
			fixture := newInventoryFixture(t, main)
			inventory := fixture.open()
			if err := inventory.Recheck(); err != nil {
				t.Fatal(err)
			}
			if err := change(fixture); err != nil {
				t.Fatal(err)
			}
			if candidate, err := inventory.Prepare(CIS); !errors.Is(err, ErrInventoryChanged) || candidate != (Candidate{}) {
				t.Fatalf("changed inventory returned candidate: %v", err)
			}
			if !errors.Is(inventory.Recheck(), ErrInventoryChanged) {
				t.Fatal("changed handle was reusable")
			}
		})
	}
	t.Run("restoring-bytes-does-not-unpoison", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		inventory := fixture.open()
		fixture.write(MainPath, includeDropIns+"# edit\n")
		if !errors.Is(inventory.Recheck(), ErrInventoryChanged) {
			t.Fatal("edit missed")
		}
		fixture.write(MainPath, includeDropIns)
		if !errors.Is(inventory.Recheck(), ErrInventoryChanged) {
			t.Fatal("restored bytes revived handle")
		}
	})
}

func TestInventoryExistingOrLegacyPolicyRemainsUnadopted(t *testing.T) {
	for _, name := range []string{"reserved", "legacy", "bastion", "conditional"} {
		t.Run(name, func(t *testing.T) {
			main := includeDropIns
			switch name {
			case "legacy":
				main += "# SYSWARDEN OVERRIDE: AllowTcpForwarding yes\n"
			case "bastion":
				main += "Match User jump\n AllowTcpForwarding local\n"
			case "conditional":
				main = "Match User jump\n" + includeDropIns
			}
			fixture := newInventoryFixture(t, main)
			if name == "reserved" {
				fixture.write(DropInPath, "AllowTcpForwarding no\n")
			}
			inventory := fixture.open()
			if candidate, err := inventory.Prepare(CIS); err == nil || candidate != (Candidate{}) {
				t.Fatal("unproven existing policy adopted")
			}
			if err := inventory.Recheck(); err != nil {
				t.Fatalf("semantic refusal corrupted inventory: %v", err)
			}
			if data, err := os.ReadFile(fixture.path(MainPath)); err != nil || !bytes.Equal(data, []byte(main)) {
				t.Fatal("source changed")
			}
		})
	}
}

func TestInventorySyntaxAndBounds(t *testing.T) {
	for name, main := range map[string]string{
		"directory-glob": "Include /etc/ssh/*/*.conf\n",
		"bracket-glob":   "Include /etc/ssh/sshd_config.d/[0-9]*.conf\n",
		"traversal":      "Include /etc/ssh/../config\n",
		"quote":          "Include \"unterminated\n",
		"empty-include":  "Include\n",
		"nul":            includeDropIns + "#\x00\n",
		"line":           strings.Repeat("#", MaxLineBytes+1),
		"bytes":          strings.Repeat("#", MaxBytes+1),
		"cycle":          "Include /etc/ssh/sshd_config\n",
		"patterns":       includeDropIns + strings.Repeat("Include /etc/ssh/missing\n", MaxExpansions),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newInventoryFixture(t, main)
			if result, err := openInventory(fixture.root, os.Geteuid()); err == nil || result != nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	t.Run("depth", func(t *testing.T) {
		fixture := newInventoryFixture(t, "Include /etc/ssh/step-0\n")
		for i := 0; i <= MaxIncludeDepth; i++ {
			fixture.write(fmt.Sprintf("/etc/ssh/step-%d", i), fmt.Sprintf("Include /etc/ssh/step-%d\n", i+1))
		}
		if result, err := openInventory(fixture.root, os.Geteuid()); err == nil || result != nil {
			t.Fatal("unbounded depth")
		}
	})
	t.Run("files", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		for i := 0; i < MaxFiles; i++ {
			fixture.write(fmt.Sprintf("/etc/ssh/sshd_config.d/%03d.conf", i), "# file\n")
		}
		if result, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || result != nil {
			t.Fatalf("unbounded files: %v", err)
		}
	})
	t.Run("directory-entries", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		for i := 0; i <= MaxDirectoryEntries; i++ {
			fixture.write(fmt.Sprintf("/etc/ssh/sshd_config.d/%04d.txt", i), "")
		}
		if result, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || result != nil {
			t.Fatalf("unbounded directory: %v", err)
		}
	})
	t.Run("combined-bytes", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		for i := range 9 {
			fixture.write(fmt.Sprintf("/etc/ssh/sshd_config.d/%03d.conf", i), strings.Repeat("# fixture\n", MaxBytes/64))
		}
		if result, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || result != nil {
			t.Fatalf("unbounded combined bytes: %v", err)
		}
	})
	t.Run("observed-nodes", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns)
		var main strings.Builder
		main.WriteString(includeDropIns)
		for i := range 100 {
			directory := fmt.Sprintf("/etc/ssh/branches/%03d/a/b/c/d/e", i)
			if err := os.MkdirAll(fixture.path(directory), 0700); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&main, "Include %s/absent.conf\n", directory)
		}
		fixture.write(MainPath, main.String())
		if result, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryBounds) || result != nil {
			t.Fatalf("unbounded observed nodes: %v", err)
		}
	})
	t.Run("locale-sensitive-membership", func(t *testing.T) {
		fixture := newInventoryFixture(t, includeDropIns+"Include /etc/ssh/locale/??.conf\n")
		fixture.write("/etc/ssh/locale/\u00e9.conf", "AllowTcpForwarding yes\n")
		if result, err := openInventory(fixture.root, os.Geteuid()); !errors.Is(err, ErrInventoryUnsafe) || result != nil {
			t.Fatalf("locale-dependent filename accepted: %v", err)
		}
	})
}

func TestInventoryClosedAndConcurrentUse(t *testing.T) {
	var empty *Inventory
	if !errors.Is(empty.Recheck(), ErrInventoryClosed) {
		t.Fatal("nil handle accepted")
	}
	if candidate, err := empty.Prepare(CIS); !errors.Is(err, ErrInventoryClosed) || candidate != (Candidate{}) {
		t.Fatal("nil preparation accepted")
	}
	if err := empty.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := openInventory(nil, 0); err == nil || result != nil {
		t.Fatal("nil root accepted")
	}
	fixture := newInventoryFixture(t, includeDropIns)
	inventory := fixture.open()
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 4 {
				_, err := inventory.Prepare(Forwarding)
				if err != nil && !errors.Is(err, ErrInventoryClosed) {
					t.Errorf("unexpected concurrent result: %v", err)
				}
			}
		})
	}
	if err := inventory.Close(); err != nil {
		t.Fatal(err)
	}
	group.Wait()
	if err := inventory.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(inventory.Recheck(), ErrInventoryClosed) {
		t.Fatal("closed inventory accepted")
	}
	if _, err := fixture.root.Stat(); err != nil {
		t.Fatal("caller descriptor was closed")
	}
}
