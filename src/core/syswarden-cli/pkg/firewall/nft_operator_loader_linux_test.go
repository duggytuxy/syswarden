//go:build linux

package firewall

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func fixtureNFTOperatorBootProperties() []byte {
	return []byte("Id=nftables.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nUnitFileState=enabled\nNeedDaemonReload=no\n")
}

func TestNFTOperatorLoaderRequiresPersistentEnablement(t *testing.T) {
	valid := fixtureNFTOperatorBootProperties()
	if err := verifyNFTOperatorBootProperties(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{"enabled", "disabled"}, {"enabled", "enabled-runtime"}, {"enabled", "static"}, {"loaded", "masked"}, {"active", "inactive"}, {"exited", "dead"}, {"Reload=no", "Reload=yes"}, {"nftables.service", "other.service"}} {
		if err := verifyNFTOperatorBootProperties(bytes.Replace(valid, []byte(change[0]), []byte(change[1]), 1)); err == nil {
			t.Fatal("unsupported boot state accepted", change)
		}
	}
	for _, wire := range [][]byte{nil, valid[:len(valid)-1], append(bytes.Clone(valid), []byte("UnitFileState=enabled\n")...), bytes.Replace(valid, []byte("UnitFileState=enabled\n"), nil, 1)} {
		if err := verifyNFTOperatorBootProperties(wire); err == nil {
			t.Fatal("ambiguous boot state accepted")
		}
	}
}

func TestNFTOperatorLoaderUsesOnlyPinnedReadOnlyQueries(t *testing.T) {
	host, _ := fixtureNFTPersistenceLoaderInspection(t)
	oldArgs := "--system --no-pager --all show --property=" + nftPersistenceLoaderProperties + " -- nftables.service"
	newArgs := "--system --no-pager --all show --property=" + nftOperatorBootProperties + " -- nftables.service"
	script := "#!/bin/sh\nset -eu\ncase \"$*\" in\n'" + oldArgs + "') printf '%s' '" + string(fixtureNFTPersistenceLoaderStatus()) + "';;\n'" + newArgs + "') printf '%s' '" + string(fixtureNFTOperatorBootProperties()) + "';;\n*) exit 92;;\nesac\n"
	if err := host.root.WriteFile("usr/bin/systemctl", []byte(script), 0700); err != nil {
		t.Fatal(err)
	} // #nosec G306 -- Private fixture executable accepts only two read-only argument sets.
	inspection, err := inspectNFTOperatorBootLoader(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if !validLegacyRetirementDigest(inspection.digest) {
		t.Fatal("loader identity is unbound")
	}
	if _, err := queryNFTPersistenceLoaderProperties(context.Background(), host, inspection.loader.manager, "Id"); err == nil {
		t.Fatal("arbitrary service-manager query accepted")
	}
	if err := host.root.WriteFile("usr/bin/systemctl", []byte(strings.Replace(script, "UnitFileState=enabled", "UnitFileState=disabled", 1)), 0700); err != nil {
		t.Fatal(err)
	} // #nosec G306 -- Exact private fixture mutation tests loader identity drift.
	if err := inspection.verify(context.Background()); err == nil {
		t.Fatal("changed boot enablement accepted")
	}
}
