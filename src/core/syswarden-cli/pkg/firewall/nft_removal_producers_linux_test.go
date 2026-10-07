//go:build linux

package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestNFTRemovalProducersBindActualLoaderAndIndependentGuard(t *testing.T) {
	for _, change := range []string{"none", "producer", "new-entry", "loader-unit", "loader-binary", "missing-guard", "missing-loader"} {
		t.Run(change, func(t *testing.T) {
			host, loader := fixtureNFTPersistenceLoaderInspection(t)
			if err := host.root.WriteFile("etc/nftables.conf", []byte(nftOwnedPolicyAdministratorSource), 0600); err != nil {
				t.Fatal(err)
			}
			fail := false
			calls := 0
			guard := func() error {
				calls++
				if fail {
					return errors.New("producer is no longer quiescent")
				}
				return nil
			}
			inspect := func(context.Context, nftPersistenceFilesystem) (*nftPersistenceLoaderInspection, error) {
				return loader, nil
			}
			if change == "missing-guard" {
				guard = nil
			}
			if change == "missing-loader" {
				inspect = nil
			}
			producers, err := inspectNFTRemovalProducersUsing(context.Background(), host, inspect, guard)
			if change == "missing-guard" || change == "missing-loader" {
				if err == nil {
					t.Fatal("incomplete authority accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if calls < 2 || !reflect.DeepEqual(producers.entries, []string{"/etc/nftables.conf"}) || !validLegacyRetirementDigest(producers.digest) {
				t.Fatal("producer evidence is incomplete")
			}
			switch change {
			case "producer":
				fail = true
			case "new-entry":
				if err := host.root.WriteFile("etc/nftables.nft", []byte("table inet unexpected {}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "loader-unit":
				if err := host.root.WriteFile("usr/lib/systemd/system/nftables.service", []byte("# administrator changed loader\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "loader-binary":
				if err := host.root.Chmod("usr/sbin/nft", 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = producers.verify(context.Background())
			if (err == nil) != (change == "none") {
				t.Fatal("unexpected producer reattestation", err)
			}
		})
	}
}

func TestNFTRemovalProducersPersistStableIdentityAcrossRuntimeTimestamps(t *testing.T) {
	_, loader := fixtureNFTPersistenceLoaderInspection(t)
	entries := []string{"/etc/nftables.conf"}
	before, err := nftRemovalLoaderDigest(loader, entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	loader.status.values["ActiveState"] = "inactive"
	loader.status.values["SubState"] = "dead"
	loader.status.values["ExecStart"] = "changed runtime observation"
	after, err := nftRemovalLoaderDigest(loader, entries, nil)
	if err != nil || after != before {
		t.Fatal("volatile runtime state changed persistent loader identity", err)
	}
	// This does not bypass live validation within an operation.
	if err := loader.verify(context.Background()); err == nil {
		t.Fatal("changed live observations passed reattestation")
	}
	after, err = nftRemovalLoaderDigest(loader, []string{"/etc/other.nft"}, nil)
	if err != nil || after == before {
		t.Fatal("different entry point retained the same identity", err)
	}
}

func TestNFTRemovalSessionRejectsUnknownRuntimeBeforeAnySourceMutation(t *testing.T) {
	for _, change := range []string{"extra-table", "missing-table", "extra-rule", "different-static-set"} {
		t.Run(change, func(t *testing.T) {
			session := fixtureNFTRemovalSession(t, "include")
			fixture := fixtureNFTCurrentFiles(t)[7]
			runner := fixtureNFTCurrentRuntimeRunner(fixture)
			switch change {
			case "extra-table":
				runner.tables[nftTableTarget{family: "inet", name: "syswarden_table"}] = []byte(`{}`)
			case "missing-table":
				delete(runner.tables, nftTableTarget{family: "inet", name: "syswarden"})
			case "extra-rule":
				runner.tables[nftTableTarget{family: "inet", name: "syswarden"}] = []byte(`{"nftables":[{"rule":{"family":"inet","table":"syswarden","chain":"administrator","expr":[{"drop":null}]}}]}`)
			case "different-static-set":
				runner.tables[nftTableTarget{family: "inet", name: "syswarden"}] = mutateNFTCurrentSet(t, fixture.InetJSON, "syswarden_whitelist", func(s map[string]any) { s["elem"] = append(s["elem"].([]any), "203.0.113.99") })
			}
			if err := session.retire(context.Background(), runner, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("unproven runtime was retired")
			}
			if _, err := session.host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
				t.Fatal("source was changed before runtime ownership validation", err)
			}
		})
	}
}
