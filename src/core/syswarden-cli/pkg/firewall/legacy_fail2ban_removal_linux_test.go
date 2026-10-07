//go:build linux

package firewall

import (
	"strings"
	"testing"
)

func TestLegacyFail2banRemovalPreflightPreservesExactAndAmbiguousEvidence(t *testing.T) {
	for _, kind := range []string{"exact", "modified", "shared-admin-action", "absent", "admin-only"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			switch kind {
			case "modified":
				writeNFTPersistenceFixture(t, root, legacyPlanTarget, "[custom]\nenabled=true\n# private fixture content\n")
			case "shared-admin-action":
				if err := host.root.Remove(strings.TrimPrefix(legacyPlanTarget, "/")); err != nil {
					t.Fatal(err)
				}
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/administrator.local", "[administrator-web]\naction=syswarden-nft\n# private fixture content\n")
			case "admin-only":
				if err := host.root.Remove(strings.TrimPrefix(legacyPlanTarget, "/")); err != nil {
					t.Fatal(err)
				}
			case "absent":
				_, host = fixtureNFTPersistenceFilesystem(t)
			}
			before := readLegacyFail2banInventoryFixture(t, host)
			err := preflightHistoricalFail2banRemoval(host)
			if (err == nil) != (kind == "absent" || kind == "admin-only") {
				t.Fatal("unexpected preflight result", kind, err)
			}
			if err != nil {
				if !strings.Contains(err.Error(), "recovery is incomplete") || strings.Contains(err.Error(), "private fixture content") {
					t.Fatal("unsafe or misleading diagnostic", err)
				}
				if kind == "exact" && !strings.Contains(err.Error(), "exact generated sources: [\""+legacyPlanTarget+"\"]") {
					t.Fatal("exact source not identified", err)
				}
			}
			after := readLegacyFail2banInventoryFixture(t, host)
			if err := verifyLegacyFail2banInventoryRetirement(before, after, nil); err != nil {
				t.Fatal("preflight changed configuration", err)
			}
		})
	}
}

func TestLegacyFail2banRemovalPreflightRejectsUnsafeSource(t *testing.T) {
	_, host := fixtureLegacyFail2banInventory(t)
	if err := host.root.Remove(strings.TrimPrefix(legacyPlanTarget, "/")); err != nil {
		t.Fatal(err)
	}
	if err := host.root.Symlink("administrator.local", strings.TrimPrefix(legacyPlanTarget, "/")); err != nil {
		t.Fatal(err)
	}
	if err := preflightHistoricalFail2banRemoval(host); err == nil {
		t.Fatal("unsafe evidence accepted")
	}
}
