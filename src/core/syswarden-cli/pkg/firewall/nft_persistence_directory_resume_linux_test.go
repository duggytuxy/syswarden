//go:build linux

package firewall

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestNFTPersistenceRecoveryAfterSiblingDirectoryChange(t *testing.T) {
	for _, change := range []string{"retired", "created"} {
		t.Run(change, func(t *testing.T) {
			host, files, retiring := fixtureNFTPersistenceGraphRecord(t)
			if err := host.root.MkdirAll("var/backups", 0700); err != nil {
				t.Fatal(err)
			}
			if change == "retired" {
				if err := host.root.MkdirAll("etc/syswarden/lists", 0700); err != nil {
					t.Fatal(err)
				}
				if err := host.root.WriteFile("etc/syswarden/lists/original", []byte("private retained data\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ownership, producers := strings.Repeat("a", 64), strings.Repeat("b", 64)
			record, digest, err := prepareNFTPersistenceGraphRecord(host, []string{nftSharedFixturePath}, retiring, ownership, producers)
			if err != nil {
				t.Fatal(err)
			}
			guard := func(string, string) error { return nil }
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			before, err := host.root.Stat("etc/syswarden")
			if err != nil {
				t.Fatal(err)
			}
			if change == "retired" {
				if err := host.root.Rename("etc/syswarden/lists", "var/backups/retained-lists"); err != nil {
					t.Fatal(err)
				}
			} else if err := host.root.MkdirAll("etc/syswarden/unrelated", 0700); err != nil {
				t.Fatal(err)
			}
			after, err := host.root.Stat("etc/syswarden")
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("fixture changed the parent identity", err)
			}
			if before.Sys().(*syscall.Stat_t).Nlink == after.Sys().(*syscall.Stat_t).Nlink {
				t.Log("filesystem has constant directory link counts; identity and recovery are still checked")
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("completed source retirement cannot resume after a sibling directory change", err)
			}
			assertNFTPersistenceRecoveryComplete(t, host, record, digest)
			for _, path := range []string{"/root/operator-policy.nft", "/etc/nftables.d/10-administrator.nft"} {
				content, err := host.root.ReadFile(path[1:])
				if err != nil || string(content) != files[path] {
					t.Fatal("administrator source changed", err)
				}
			}
			if change == "retired" {
				content, err := host.root.ReadFile("var/backups/retained-lists/original")
				if err != nil || string(content) != "private retained data\n" {
					t.Fatal("private recovery original changed", err)
				}
			}
		})
	}
}

func TestNFTPersistenceRecoveryStillRejectsChangedParent(t *testing.T) {
	for _, change := range []string{"replacement", "mode", "symlink"} {
		t.Run(change, func(t *testing.T) {
			host, record, digest, guard := fixtureNFTPersistenceRecovery(t)
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			original, err := host.root.ReadFile("root/operator-policy.nft")
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "mode":
				if err := host.root.Chmod("etc/syswarden", 0750); err != nil {
					t.Fatal(err)
				}
			case "replacement", "symlink":
				if err := host.root.Rename("etc/syswarden", "etc/original-product-directory"); err != nil {
					t.Fatal(err)
				}
				if change == "replacement" {
					if err := host.root.MkdirAll("etc/syswarden", 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := host.root.Symlink("original-product-directory", "etc/syswarden"); err != nil {
					t.Fatal(err)
				}
			}
			if err := applyNFTPersistenceGraphRecord(host, record, digest, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed parent was accepted")
			}
			current, err := host.root.ReadFile("root/operator-policy.nft")
			if err != nil || string(current) != string(original) {
				t.Fatal("rejected recovery changed administrator policy", err)
			}
		})
	}
}
