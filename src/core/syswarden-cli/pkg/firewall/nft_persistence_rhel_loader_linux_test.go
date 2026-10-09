//go:build linux

package firewall

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixtureNFTRHELLoaderStatus() []byte {
	wire := string(fixtureNFTPersistenceLoaderStatus())
	wire = strings.ReplaceAll(wire, "/usr/sbin/nft", "/sbin/nft")
	wire = strings.ReplaceAll(wire, "/etc/nftables.conf", "/etc/sysconfig/nftables.conf")
	wire = strings.Replace(wire, "ExecReload={ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf ;", `ExecReload={ path=/sbin/nft ; argv[]=/sbin/nft flush ruleset; include "/etc/sysconfig/nftables.conf"; ;`, 1)
	return []byte(wire)
}

func TestNFTPersistenceLoaderObservesBoundedRHELReload(t *testing.T) {
	valid := fixtureNFTRHELLoaderStatus()
	status, err := decodeNFTPersistenceLoaderStatus(valid)
	if err != nil || status.binary != "/sbin/nft" || !reflect.DeepEqual(status.entries, []string{"/etc/sysconfig/nftables.conf"}) {
		t.Fatal("standard distribution loader observation rejected", err)
	}
	for _, change := range [][2]string{
		{"flush ruleset; include", "flush ruleset; delete table inet administrator; include"},
		{`include "/etc/sysconfig/nftables.conf";`, `include "/etc/sysconfig/*.conf";`},
		{`include "/etc/sysconfig/nftables.conf";`, `include "relative.conf";`},
		{`include "/etc/sysconfig/nftables.conf";`, `include "/etc/a"; include "/etc/b";`},
		{`include "/etc/sysconfig/nftables.conf";`, `include "/etc/sysconfig/nftables.conf"; flush ruleset;`},
		{`include "/etc/sysconfig/nftables.conf";`, `include "/etc/path with spaces";`},
		{"path=/sbin/nft", "path=/sbin/custom-nft"},
		{"ExecStart={ path=/sbin/nft ; argv[]=/sbin/nft -f /etc/sysconfig/nftables.conf ;", `ExecStart={ path=/sbin/nft ; argv[]=/sbin/nft flush ruleset; include "/etc/sysconfig/nftables.conf"; ;`},
		{"ExecStop=\n", `ExecStop={ path=/sbin/nft ; argv[]=/sbin/nft flush ruleset; include "/etc/sysconfig/nftables.conf"; ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }` + "\n"},
	} {
		input := bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)
		if bytes.Equal(input, valid) {
			t.Fatal("fixture change did not apply")
		}
		if _, err := decodeNFTPersistenceLoaderStatus(input); err == nil {
			t.Fatalf("unsupported loader accepted: %s", change[1])
		}
	}
}

func TestNFTRHELLoaderAliasIsBoundAndNeverExecuted(t *testing.T) {
	for _, change := range []string{"none", "replacement", "different-target", "binary", "untrusted-parent"} {
		t.Run(change, func(t *testing.T) {
			host, _ := fixtureNFTPersistenceLoaderInspection(t)
			if err := host.root.Symlink("usr/sbin", "sbin"); err != nil {
				t.Fatal(err)
			}
			arguments := "--system --no-pager --all show --property=" + nftPersistenceLoaderProperties + " -- nftables.service"
			script := "#!/bin/sh\nset -eu\ntest \"$*\" = '" + arguments + "'\nprintf '%s' '" + string(fixtureNFTRHELLoaderStatus()) + "'\n"
			if err := host.root.WriteFile("usr/bin/systemctl", []byte(script), 0700); err != nil { // #nosec G306 -- Private fixed-argument read-only service observation fixture.
				t.Fatal(err)
			}
			inspection, err := inspectNFTPersistenceLoader(context.Background(), host)
			if err != nil {
				t.Fatal("distribution loader inspection failed", err)
			}
			before, err := nftRemovalLoaderDigest(inspection, inspection.status.entries, nil)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "replacement", "different-target":
				if err := host.root.Rename("sbin", "sbin-original"); err != nil {
					t.Fatal(err)
				}
				target := "usr/sbin"
				if change == "different-target" {
					target = "usr/bin"
				}
				if err := host.root.Symlink(target, "sbin"); err != nil {
					t.Fatal(err)
				}
			case "binary":
				if err := host.root.WriteFile("usr/sbin/nft", []byte("changed\n"), 0700); err != nil { // #nosec G306 -- Private nonexecuted sentinel mutation.
					t.Fatal(err)
				}
			case "untrusted-parent":
				if err := host.root.Chmod("usr/sbin", 0777); err != nil { // #nosec G302 -- Deliberately unsafe private directory must be rejected.
					t.Fatal(err)
				}
			}
			if err := inspection.verify(context.Background()); (err == nil) != (change == "none") {
				t.Fatal("incorrect executable alias reattestation", err)
			}
			if change == "replacement" {
				fresh, err := inspectNFTPersistenceLoader(context.Background(), host)
				if err != nil {
					t.Fatal(err)
				}
				after, err := nftRemovalLoaderDigest(fresh, fresh.status.entries, nil)
				if err != nil || after == before {
					t.Fatal("replacement alias retained its original durable identity", err)
				}
			}
		})
	}
	// The shared persistence reader remains strict about symlinks.
	host, _ := fixtureNFTPersistenceLoaderInspection(t)
	if err := host.root.Symlink("usr/sbin", "sbin"); err != nil {
		t.Fatal(err)
	}
	if _, err := host.snapshot("/sbin/nft"); err == nil {
		t.Fatal("loader support weakened the general persistence reader")
	}
}

func TestNFTRHELLoaderRejectsUnsupportedAliasTargets(t *testing.T) {
	for _, target := range []string{"usr/sbin", "/usr/sbin", "usr/bin", "../usr/sbin", "/tmp/sbin", "usr/sbin/.."} {
		t.Run(target, func(t *testing.T) {
			host, _ := fixtureNFTPersistenceLoaderInspection(t)
			if err := host.root.Symlink(target, "sbin"); err != nil {
				t.Fatal(err)
			}
			path, alias, err := resolveNFTPersistenceLoaderBinary(host, "/sbin/nft")
			allowed := target == "usr/sbin" || target == "/usr/sbin"
			if (err == nil) != allowed {
				t.Fatal("incorrect executable alias boundary", err)
			}
			if allowed && (path != "/usr/sbin/nft" || alias == nil || alias.Target != target || alias.UID != uint32(os.Geteuid())) {
				t.Fatal("incomplete alias identity")
			}
		})
	}
}
