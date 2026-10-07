//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixtureLegacyFail2banScopedPersistence(t *testing.T) (nftPersistenceFilesystem, *nftPersistenceLoaderInspection, legacyFail2banNFTJournalRecord) {
	t.Helper()
	host, _, _, _ := fixtureNFTPersistenceShared(t)
	_, _, kernel := fixtureLegacyFail2banNFTJournal(t, true)
	entry := strings.Replace(legacyFail2banPersistenceFixture, "flush ruleset\ninclude \"/etc/administrator.nft\"\n", "destroy table inet administrator\ntable inet administrator { chain input { type filter hook input priority -2; policy accept; include \"/etc/site-input.nft\"\n}; }\nadd table inet independent\nflush table inet independent\ninclude \"/etc/independent.nft\"\n", 1)
	for path, content := range map[string]string{
		"etc/nftables.conf":   entry,
		"etc/site-input.nft":  "ip saddr 192.0.2.9 drop\ninclude \"/etc/site-more.nft\"\n",
		"etc/site-more.nft":   "ip6 saddr 2001:db8::9 drop\n",
		"etc/independent.nft": "table inet independent { chain input { type filter hook input priority 0; policy accept; ip saddr 198.51.100.9 accept; }; }\n",
	} {
		if err := host.root.WriteFile(path, []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}
	loader := &nftPersistenceLoaderInspection{digest: strings.Repeat("a", 64), status: nftPersistenceLoaderStatus{entries: []string{"/etc/nftables.conf"}}}
	return host, loader, kernel
}

func TestLegacyFail2banPersistencePreservesScopedLoaderAfterInterruption(t *testing.T) {
	for _, phase := range []string{"none", "shared-edit-intent-durable", "shared-edit-exchanged", "shared-edit-original-retained", "shared-edit-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, loader, kernel := fixtureLegacyFail2banScopedPersistence(t)
			record, review, err := prepareLegacyFail2banPersistence(host, loader, kernel.Quiescence.FilePlan, kernel)
			if err != nil {
				t.Fatal("independent scoped loader refused", err)
			}
			original, attrs, err := snapshotNFTPersistenceMetadata(host, nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			planner := func(content []byte) (nftPersistenceEdit, error) {
				return planLegacyFail2banPersistence(content, record.Kernel)
			}
			expected, err := planner(original.content)
			if err != nil || len(expected.removed) != 2 {
				t.Fatal("unexpected native claim edit", err)
			}
			guard := func() error { _, err := inspectLegacyFail2banPersistenceState(host, record, review); return err }
			interrupted := errors.New("injected scoped loader exchange interruption")
			ops := defaultLegacyRetirementFileOps()
			ops.checkpoint = func(current string) error {
				if current == phase {
					return interrupted
				}
				return nil
			}
			shared, err := prepareNFTPersistenceSharedEditUsing(host, nftSharedFixturePath, review, guard, ops, planner)
			if phase == "shared-edit-intent-durable" {
				if !errors.Is(err, interrupted) {
					t.Fatal("preparation interruption absent", err)
				}
				shared, err = prepareNFTPersistenceSharedEditUsing(host, nftSharedFixturePath, review, guard, defaultLegacyRetirementFileOps(), planner)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = applyNFTPersistenceSharedEditUsing(host, shared, func(bool) error { return guard() }, ops, planner)
			if phase == "none" || phase == "shared-edit-intent-durable" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, interrupted) {
				t.Fatal("exchange interruption absent", err)
			}
			if err := applyNFTPersistenceSharedEditUsing(host, shared, func(bool) error { return guard() }, defaultLegacyRetirementFileOps(), planner); err != nil {
				t.Fatal("scoped loader resumption failed", err)
			}
			if err := guard(); err != nil {
				t.Fatal("settled graph context failed", err)
			}
			active, err := host.read(nftSharedFixturePath)
			if err != nil || !bytes.Equal(active, expected.content) {
				t.Fatal("administrator loader bytes changed", err)
			}
			backup, backupAttrs, err := snapshotNFTPersistenceMetadata(host, nftPersistenceSharedDirectory(shared)+"/original")
			if err != nil || !os.SameFile(backup.identity, original.identity) || !bytes.Equal(backup.content, original.content) || nftPersistenceXattrDigest(attrs) != nftPersistenceXattrDigest(backupAttrs) {
				t.Fatal("original loader evidence changed", err)
			}
		})
	}
}

func TestLegacyFail2banPersistenceRefusesUnprovenIncludeContexts(t *testing.T) {
	for _, change := range []string{"fragment-at-root", "fragment-table", "fragment-escape", "fragment-command", "fragment-variable", "fragment-target-reference", "nested-target", "nested-reserved", "wrong-reset-table", "multiple-reset-tables", "reset-reserved-target", "reset-target-table", "reset-include-indirection", "reset-body-include", "receiver-used-as-fragment"} {
		t.Run(change, func(t *testing.T) {
			host, loader, kernel := fixtureLegacyFail2banScopedPersistence(t)
			entry, err := host.read(nftSharedFixturePath)
			if err != nil {
				t.Fatal(err)
			}
			path, content := "etc/nftables.conf", string(entry)
			switch change {
			case "fragment-at-root":
				content += "include \"/etc/site-input.nft\"\n"
			case "fragment-table":
				path, content = "etc/site-more.nft", "table inet independent {}\n"
			case "fragment-escape":
				path, content = "etc/site-more.nft", "}\nflush ruleset\n{\n"
			case "fragment-command":
				path, content = "etc/site-more.nft", "flush ruleset\n"
			case "fragment-variable":
				path, content = "etc/site-more.nft", "ip saddr $address drop\n"
			case "fragment-target-reference":
				path, content = "etc/site-more.nft", "ip saddr @addr-set-syswarden-portscan accept\n"
			case "nested-target":
				content = strings.Replace(content, "table inet f2b-table {", "table inet f2b-table { include \"/etc/site-more.nft\"\n", 1)
			case "nested-reserved":
				content = strings.ReplaceAll(content, "administrator", "syswarden")
			case "wrong-reset-table":
				path, content = "etc/independent.nft", "table inet different {}\n"
			case "multiple-reset-tables":
				path, content = "etc/independent.nft", "table inet independent {}\ntable inet different {}\n"
			case "reset-reserved-target":
				content = strings.ReplaceAll(content, "table inet independent", "table inet syswarden")
			case "reset-target-table":
				content = strings.ReplaceAll(content, "table inet independent", "table inet f2b-table")
			case "reset-include-indirection":
				path, content = "etc/independent.nft", "include \"/etc/site-more.nft\"\n"
			case "reset-body-include":
				path, content = "etc/independent.nft", "table inet independent { chain input { include \"/etc/site-more.nft\"\n}; }\n"
			case "receiver-used-as-fragment":
				path, content = "etc/site-more.nft", "include \"/etc/independent.nft\"\n"
			}
			if err := host.root.WriteFile(path, []byte(content), 0640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := prepareLegacyFail2banPersistence(host, loader, kernel.Quiescence.FilePlan, kernel); err == nil {
				t.Fatal("unproven include context accepted")
			}
			after, err := host.read("/" + path)
			if err != nil || !bytes.Equal(after, []byte(content)) {
				t.Fatal("refusal changed a source", err)
			}
		})
	}
}

func TestLegacyFail2banPersistenceRechecksAdministratorFragment(t *testing.T) {
	host, loader, kernel := fixtureLegacyFail2banScopedPersistence(t)
	record, review, err := prepareLegacyFail2banPersistence(host, loader, kernel.Quiescence.FilePlan, kernel)
	if err != nil {
		t.Fatal(err)
	}
	original, err := host.read(nftSharedFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("etc/site-more.nft", []byte("ip6 saddr 2001:db8::10 drop\n"), 0640); err != nil {
		t.Fatal(err)
	}
	guard := func() error { _, err := inspectLegacyFail2banPersistenceState(host, record, review); return err }
	planner := func(content []byte) (nftPersistenceEdit, error) {
		return planLegacyFail2banPersistence(content, record.Kernel)
	}
	if _, err := prepareNFTPersistenceSharedEditUsing(host, nftSharedFixturePath, review, guard, defaultLegacyRetirementFileOps(), planner); err == nil {
		t.Fatal("changed administrator fragment did not block mutation")
	}
	after, err := host.read(nftSharedFixturePath)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("changed dependency caused a partial edit", err)
	}
}
