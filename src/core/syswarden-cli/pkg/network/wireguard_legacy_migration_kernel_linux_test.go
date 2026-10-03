//go:build linux

package network

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

// These real kernel transactions use synthetic service states. Native package
// lifecycle, encrypted client traffic and reboot acceptance remain separate.
func TestLegacyWireGuardMigrationKernel(t *testing.T) {
	if os.Getenv("SYSWARDEN_WG_REMOVAL_KERNEL_TEST") != "isolated-netns-v1" {
		t.Skip("requires an explicitly isolated network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	parent := os.Getenv("SYSWARDEN_WG_REMOVAL_HOST_NETNS")
	if err != nil || parent == "" || current == parent || os.Geteuid() != 0 {
		t.Fatal("refusing kernel test outside attested isolated namespace")
	}
	runner := execWireGuardNFTCommandRunner{}
	batch := productionLegacyWireGuardRecoveryHost().nftBatch
	ctx := context.Background()
	initial, err := runner.Run(ctx, "-j", "list", "tables")
	if err != nil || bytes.Contains(initial, []byte(`"table"`)) {
		t.Fatal("isolated namespace is not empty")
	}
	for _, kind := range []string{"normal", "private-table-absent", "policy-accept", "foreign-change"} {
		t.Run(kind, func(t *testing.T) {
			host, _, originals := migrationTestHost(t)
			host.nftRunner, host.nftBatch = runner, batch
			script := `add table inet filter
add chain inet filter forward { type filter hook forward priority 0; policy drop; }
add rule inet filter forward ip saddr 192.0.2.123 counter drop comment "operator-preservation-probe"
add rule inet filter forward iifname "wg-syswarden" accept
add rule inet filter forward oifname "wg-syswarden" accept
add table inet syswarden_wg
add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }
add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }
add rule inet syswarden_wg postrouting oifname "ens3" masquerade
`
			if kind == "policy-accept" {
				script = strings.Replace(script, "policy drop", "policy accept", 1)
			}
			if wire, err := batch(ctx, script); err != nil {
				t.Fatalf("fixture failed: %s %v", wire, err)
			}
			t.Cleanup(func() {
				for _, name := range []string{"syswarden_wg", "filter"} {
					_, _ = runner.Run(ctx, "delete", "table", "inet", name)
				}
			})
			plan, err := host.inspectMigration()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := LegacyWireGuardMigrationPlanSHA256(plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := host.applyMigration(digest); err != nil {
				t.Fatal(err)
			}
			manifest, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			server, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ServerConfigurationPath, host.expectedUID, host.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := wireguardstate.ParseServerConfiguration(server)
			if err != nil || !identity.SharedForward {
				t.Fatal("migration did not retain shared forwarding", err)
			}
			client, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ClientConfigurationPath, host.expectedUID, host.expectedGID)
			if err != nil || !bytes.Equal(client, originals[wireguardstate.ClientConfigurationPath]) {
				t.Fatal("client bytes changed", err)
			}
			postUp := strings.Split(string(server), "\n")[4]
			postUp = strings.TrimPrefix(postUp, "PostUp = "+identity.NFTPath+" '")
			postUp = strings.TrimSuffix(postUp, "'")
			t.Logf("generated-post-up: %s", postUp)
			if wire, err := runner.Run(ctx, postUp); err != nil {
				t.Fatalf("generated atomic activation: %s %v", wire, err)
			}
			if err := attestWireGuardSharedForward(ctx, runner, identity, true); err != nil {
				t.Fatal(err)
			}
			completed, err := host.inspectMigration()
			if err != nil || completed.State != "complete" {
				t.Fatal("completed runtime inspection failed", err)
			}
			if kind == "private-table-absent" {
				if _, err := runner.Run(ctx, "delete", "table", "inet", "syswarden_wg"); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "foreign-change" {
				if _, err := runner.Run(ctx, `add rule inet syswarden_wg forward counter accept`); err != nil {
					t.Fatal(err)
				}
				before, err := runner.Run(ctx, "-a", "-j", "list", "ruleset")
				if err != nil {
					t.Fatal(err)
				}
				if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, func() error { return nil }, func() error { return nil }); err == nil {
					t.Fatal("deleted changed table")
				}
				after, err := runner.Run(ctx, "-a", "-j", "list", "ruleset")
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("refused cleanup changed runtime", err)
				}
				return
			}
			for range 2 {
				if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity, func() error { return nil }, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			after, err := runner.Run(ctx, "-a", "-j", "list", "ruleset")
			if err != nil || !bytes.Contains(after, []byte("operator-preservation-probe")) || bytes.Contains(after, []byte("syswarden-wg-")) || bytes.Contains(after, []byte("syswarden_wg")) {
				t.Fatal("exact cleanup lost foreign policy or retained owned state", err)
			}
			policy := `"policy":"drop"`
			if kind == "policy-accept" {
				policy = `"policy":"accept"`
			}
			if !bytes.Contains(bytes.ReplaceAll(after, []byte(" "), nil), []byte(policy)) {
				t.Fatal("operator forwarding policy changed")
			}
		})
	}
}
