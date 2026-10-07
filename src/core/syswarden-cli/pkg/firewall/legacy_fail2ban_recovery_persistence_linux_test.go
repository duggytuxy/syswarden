//go:build linux

package firewall

import (
	"context"
	"strings"
	"testing"
)

func TestLegacyFail2banActivePersistenceRequiresIndependentlyBoundAbsentTargets(t *testing.T) {
	for _, change := range []string{"none", "owned-entry", "unbound-claim", "source", "loader", "new-entry"} {
		t.Run(change, func(t *testing.T) {
			host, _, kernel := fixtureLegacyFail2banNFTJournal(t, true)
			installNFTPersistenceLoaderFixture(t, host)
			const shared = "table inet f2b-table { set administrator { type ipv4_addr; elements = { 127.0.0.3 } } chain f2b-chain { type filter hook input priority -1; policy accept; ip saddr @administrator drop; } }\n"
			content := shared
			if change == "owned-entry" {
				content = strings.Replace(legacyFail2banPersistenceFixture, "include \"/etc/administrator.nft\"\n", "", 1)
			}
			if change == "unbound-claim" {
				kernel.Quiescence.FilePlan = strings.Repeat("f", 64)
			}
			if err := host.root.WriteFile("etc/nftables.conf", []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			check, err := bindLegacyFail2banRecoveryPersistenceUsing(context.Background(), host, nil, &kernel)
			if change == "owned-entry" || change == "unbound-claim" {
				if err == nil || check != nil {
					t.Fatal("runtime retirement accepted persistent targets or an unbound claim", change)
				}
				return
			}
			if err != nil {
				t.Fatal("independently unrelated shared protection was rejected", err)
			}
			switch change {
			case "source":
				err = host.root.WriteFile("etc/nftables.conf", []byte(shared+"# administrator update\n"), 0600)
			case "loader":
				err = host.root.WriteFile("usr/lib/systemd/system/nftables.service", []byte("changed\n"), 0600)
			case "new-entry":
				err = host.root.WriteFile("etc/nftables.nft", []byte("table inet administrator_extra {}\n"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := check(context.Background()); (err == nil) != (change == "none") {
				t.Fatal("runtime retirement did not retain its complete persistence boundary", change, err)
			}
		})
	}
}

func TestLegacyFail2banUnusedPersistencePreservesSharedAdministratorSources(t *testing.T) {
	for _, mutation := range []string{"none", "persistent-source", "loader", "new-entry", "definition", "changed-views"} {
		t.Run(mutation, func(t *testing.T) {
			fixture := fixtureLegacyFail2banUnused(t)
			installNFTPersistenceLoaderFixture(t, fixture.host)
			shared := []byte("table inet f2b-table { }\n")
			if err := fixture.host.root.WriteFile("etc/nftables.conf", shared, 0600); err != nil {
				t.Fatal(err)
			}
			record := fixtureLegacyUnusedPersistencePlan(t, fixture)
			check, err := bindLegacyFail2banRecoveryPersistence(context.Background(), fixture.host, &record)
			if err != nil {
				t.Fatal("unrelated persistent protection blocked proven unused definitions", err)
			}
			if _, err := bindLegacyFail2banRecoveryPersistence(context.Background(), fixture.host, nil); err == nil {
				t.Fatal("active-jail recovery accepted independently persisted Fail2ban rules")
			}
			switch mutation {
			case "persistent-source":
				err = fixture.host.root.WriteFile("etc/nftables.conf", append(shared, '#', ' ', 'x', '\n'), 0600)
			case "loader":
				err = fixture.host.root.WriteFile("usr/lib/systemd/system/nftables.service", []byte("changed\n"), 0600)
			case "new-entry":
				err = fixture.host.root.WriteFile("etc/nftables.nft", []byte("table inet operator_added {}\n"), 0600)
			case "definition":
				err = fixture.host.root.WriteFile("etc/fail2ban/filter.d/syswarden-portscan.conf", []byte("administrator replacement\n"), 0600)
			case "changed-views":
				record.Views[2][0] ^= 1
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := check(context.Background()); (err == nil) != (mutation == "none") {
				t.Fatal("shared-loader or unused-definition evidence was not independently guarded", err)
			}
		})
	}
}

func TestLegacyFail2banUnusedPersistenceRequiresCompleteUnchangedViews(t *testing.T) {
	fixture := fixtureLegacyFail2banUnused(t)
	installNFTPersistenceLoaderFixture(t, fixture.host)
	if err := fixture.host.root.WriteFile("etc/nftables.conf", []byte("table inet f2b-table {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	record := fixtureLegacyUnusedPersistencePlan(t, fixture)
	record.Views[2][0] ^= 1
	if _, err := bindLegacyFail2banRecoveryPersistence(context.Background(), fixture.host, &record); err == nil {
		t.Fatal("file-only persistence handling accepted changed enabled configuration")
	}
}

// Bind the plan after the complete loader fixture has been installed. The
// normal directory-identity guard must remain enabled during every test.
func fixtureLegacyUnusedPersistencePlan(t *testing.T, fixture *legacyFail2banUnusedFixture) legacyFail2banPlanRecord {
	t.Helper()
	probe, err := newLegacyFail2banConfigurationProbe(fixture.host)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := prepareLegacyFail2banRetirement(fixture.host, append([]string(nil), fixture.plan.binding.Targets...), probe)
	if err != nil {
		t.Fatal(err)
	}
	return plan.binding
}
