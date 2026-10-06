//go:build linux

package firewall

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNFTPersistenceRemovalPreservesReferencedAndUnrelatedSources(t *testing.T) {
	for _, fixture := range []struct {
		name, input, nested string
		allowed             bool
	}{
		{"no references", "table inet administrator {\n}\n", "", true},
		{"comment only", "# SysWarden was removed\ntable inet administrator {\n}\n", "", true},
		{"literal product table", "table inet syswarden {\n}\n", "", false},
		{"quoted product table", "table inet \"syswarden\" {\n}\n", "", false},
		{"unrelated include", "include \"/etc/nftables.d/*.nft\"\n", "table inet administrator {\n}\n", true},
		{"nested product table", "include \"/etc/nftables.d/*.nft\"\n", "table inet syswarden_f2b {\n}\n", false},
		{"ambiguous custom dependency", "include \"/etc/nftables.d/*.nft\"\n", "table inet administrator {\n chain input {\n  log prefix \"private-syswarden-sentinel\"\n }\n}\n", false},
		{"missing literal include", "include \"/etc/nftables.d/missing.nft\"\n", "", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			_, host := fixtureNFTPersistenceFilesystem(t)
			if err := host.root.MkdirAll("etc/nftables.d", 0700); err != nil {
				t.Fatal(err)
			}
			if err := host.root.WriteFile("etc/nftables.conf", []byte(fixture.input), 0600); err != nil {
				t.Fatal(err)
			}
			if fixture.nested != "" {
				if err := host.root.WriteFile("etc/nftables.d/administrator.nft", []byte(fixture.nested), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := preflightKnownNFTPersistenceRemoval(host)
			if (err == nil) != fixture.allowed {
				t.Fatal("unexpected persistence decision", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-syswarden-sentinel") {
				t.Fatal("rule content leaked into the diagnostic")
			}
			if content, err := host.root.ReadFile("etc/nftables.conf"); err != nil || string(content) != fixture.input {
				t.Fatal("entry point was modified by inspection", err)
			}
			if fixture.nested != "" {
				if content, err := host.root.ReadFile("etc/nftables.d/administrator.nft"); err != nil || string(content) != fixture.nested {
					t.Fatal("administrator source was modified by inspection", err)
				}
			}
		})
	}
}

func TestNFTPersistenceRemovalRejectsAmbiguousEntryMetadataAndRaces(t *testing.T) {
	for _, change := range []string{"absent", "dangling symlink", "writable file", "new entry", "changed source"} {
		t.Run(change, func(t *testing.T) {
			_, host := fixtureNFTPersistenceFilesystem(t)
			if err := host.root.MkdirAll("etc/sysconfig", 0700); err != nil {
				t.Fatal(err)
			}
			if change == "absent" {
				if err := preflightKnownNFTPersistenceRemoval(host); err != nil {
					t.Fatal("proven absence rejected", err)
				}
				return
			}
			input := []byte("table inet administrator {\n}\n")
			if err := host.root.WriteFile("etc/nftables.conf", input, 0600); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "dangling symlink":
				if err := host.root.Remove("etc/nftables.conf"); err != nil {
					t.Fatal(err)
				}
				if err := host.root.Symlink("missing", "etc/nftables.conf"); err != nil {
					t.Fatal(err)
				}
			case "writable file":
				if err := host.root.Chmod("etc/nftables.conf", 0660); err != nil {
					t.Fatal(err)
				}
			default:
				reads := 0
				host.afterRead = func() {
					reads++
					if reads != 2 {
						return
					}
					path := "etc/nftables.conf"
					if change == "new entry" {
						path = "etc/nftables.nft"
					}
					if err := host.root.WriteFile(path, []byte("table inet syswarden {\n}\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := preflightKnownNFTPersistenceRemoval(host); err == nil {
				t.Fatal("unsafe or changed persistence source accepted")
			}
		})
	}
}

func TestNFTPersistenceRemovalKeepsEmptyWildcardsAndSharedAdminGraph(t *testing.T) {
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.MkdirAll("etc/nftables.d", 0700); err != nil {
		t.Fatal(err)
	}
	input := []byte("include \"/etc/nftables.d/*.nft\"\n")
	if err := host.root.WriteFile("etc/nftables.conf", input, 0600); err != nil {
		t.Fatal(err)
	}
	if err := preflightKnownNFTPersistenceRemoval(host); err != nil {
		t.Fatal("empty wildcard rejected", err)
	}
	if err := host.root.WriteFile("etc/nftables.d/administrator.nft", []byte("table inet administrator {\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := preflightKnownNFTPersistenceRemoval(host); err != nil {
		t.Fatal("unrelated protection rejected", err)
	}
	if content, err := host.root.ReadFile("etc/nftables.conf"); err != nil || !bytes.Equal(content, input) {
		t.Fatal("shared entry point was changed", err)
	}
	if _, err := host.root.Lstat("etc/nftables.d/administrator.nft"); os.IsNotExist(err) {
		t.Fatal("administrator source disappeared")
	}
}

func TestNFTPersistenceRemovalNativeReadOnly(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_PERSISTENCE_REMOVAL_NATIVE") != "1" {
		t.Skip("explicit read-only native inspection not requested")
	}
	if os.Geteuid() != 0 {
		t.Fatal("native read-only persistence inspection requires root metadata access")
	}
	if err := PreflightKnownNFTPersistenceRemoval(); err != nil {
		t.Fatal(err)
	}
}
