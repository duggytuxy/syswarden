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

// Real nft transactions in a disposable network namespace supplement unit
// tests. Service-manager states are fixtures, not native lifecycle evidence.
func TestLegacyWireGuardRetirementKernel(t *testing.T) {
	if os.Getenv("SYSWARDEN_WG_REMOVAL_KERNEL_TEST") != "isolated-netns-v1" {
		t.Skip("requires an explicitly isolated network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv("SYSWARDEN_WG_REMOVAL_HOST_NETNS")
	if parent == "" || current == parent || os.Geteuid() != 0 {
		t.Fatal("refusing kernel test outside attested isolated namespace")
	}
	runner := execWireGuardNFTCommandRunner{}
	batch := productionLegacyWireGuardRecoveryHost().nftBatch
	ctx := context.Background()
	initial, err := runner.Run(ctx, "-j", "list", "tables")
	if err != nil || bytes.Contains(initial, []byte(`"table"`)) {
		t.Fatal("isolated namespace is not empty")
	}
	for _, kind := range []string{"dual-generation", "table-already-absent", "chain-already-absent", "current-table-preserved", "foreign-table", "duplicate-rule", "active-old-vpn"} {
		t.Run(kind, func(t *testing.T) {
			host, _ := retirementTestHost(t)
			host.nftRunner, host.nftBatch = runner, batch
			script := ""
			if kind != "table-already-absent" && kind != "chain-already-absent" {
				script = `add table inet syswarden_wg
add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }
add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }
add rule inet syswarden_wg postrouting oifname "ens3" masquerade
`
			}
			if kind == "current-table-preserved" {
				script = `add table inet syswarden_wg { comment "syswarden-wg-v1:` + strings.Repeat("a", 64) + `"; }
add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }
add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }
add chain inet syswarden_wg forward { type filter hook forward priority 0; }
add rule inet syswarden_wg postrouting oifname "ens3" masquerade
add rule inet syswarden_wg forward iifname "wg-syswarden" accept
add rule inet syswarden_wg forward oifname "wg-syswarden" accept
`
			}
			if kind != "chain-already-absent" {
				script += `add table inet filter
add chain inet filter forward { type filter hook forward priority 0; policy drop; }
add rule inet filter forward ip saddr 192.0.2.123 counter drop comment "administrator-preservation-probe"
add rule inet filter forward iifname "wg0" accept
add rule inet filter forward oifname "wg0" accept
add rule inet filter forward oifname "wg-syswarden" accept
`
			}
			if kind == "foreign-table" {
				script += "add rule inet syswarden_wg postrouting counter accept\n"
			}
			if kind == "duplicate-rule" {
				script += "add rule inet filter forward iifname \"wg0\" accept\n"
			}
			if kind == "active-old-vpn" {
				host.commandOutput = fakeLegacyWireGuardServiceOutput(true, true, true)
			}
			if script != "" {
				if wire, err := batch(ctx, script); err != nil {
					t.Fatalf("fixture failed: %s %v", wire, err)
				}
			}
			t.Cleanup(func() {
				for _, name := range []string{"syswarden_wg", "filter"} {
					_, _ = runner.Run(ctx, "delete", "table", "inet", name)
				}
			})
			before, err := runner.Run(ctx, "-a", "-j", "list", "ruleset")
			if err != nil {
				t.Fatal(err)
			}
			reject := kind == "foreign-table" || kind == "duplicate-rule" || kind == "active-old-vpn"
			plan, inspectErr := host.inspectRetirement()
			var applyErr error
			if inspectErr == nil {
				digest, digestErr := LegacyWireGuardRetirementPlanSHA256(plan)
				if digestErr != nil {
					t.Fatal(digestErr)
				}
				_, applyErr = host.applyRetirement(digest)
			}
			if (inspectErr != nil || applyErr != nil) != reject {
				t.Fatalf("inspect=%v apply=%v reject=%v", inspectErr, applyErr, reject)
			}
			after, err := runner.Run(ctx, "-a", "-j", "list", "ruleset")
			if err != nil {
				t.Fatal(err)
			}
			if reject {
				if !bytes.Equal(before, after) {
					t.Fatal("rejected retirement mutated kernel state")
				}
				requireHistoricalConfigRetained(t, host)
				return
			}
			if kind != "chain-already-absent" && !bytes.Contains(after, []byte("administrator-preservation-probe")) {
				t.Fatal("administrator rule was lost")
			}
			if bytes.Contains(after, []byte(`"wg0"`)) {
				t.Fatal("old shared forward rules remain")
			}
			if kind == "current-table-preserved" {
				currentWire, err := runner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
				if err != nil || retirementDigest(currentWire) != plan.TableSHA256 {
					t.Fatal("current table changed")
				}
			} else if bytes.Contains(after, []byte("syswarden_wg")) {
				t.Fatal("historical table remains")
			}
			if _, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
				t.Fatal(err)
			}
			repeat, err := host.inspectRetirement()
			if err != nil || repeat.State != "retired" || !repeat.SafeToApply {
				t.Fatalf("repeat inspection: %v %#v", err, repeat)
			}
		})
	}
}
