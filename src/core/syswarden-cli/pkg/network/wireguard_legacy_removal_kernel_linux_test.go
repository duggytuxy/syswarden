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

// This supplemental kernel test exercises the production nft reader and atomic
// batch against a disposable namespace. Service-manager and removal-barrier
// evidence remain fixtures; it is not a native package lifecycle qualification.
func TestLegacyWireGuardRemovalKernel(t *testing.T) {
	if os.Getenv("SYSWARDEN_WG_REMOVAL_KERNEL_TEST") != "isolated-netns-v1" {
		t.Skip("requires an explicitly isolated network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	initial := os.Getenv("SYSWARDEN_WG_REMOVAL_HOST_NETNS")
	if initial == "" || current == initial || os.Geteuid() != 0 {
		t.Fatal("refusing kernel test without a distinct, harness-attested parent network namespace")
	}
	runner := execWireGuardNFTCommandRunner{}
	batch := productionLegacyWireGuardRecoveryHost().nftBatch
	ctx := context.Background()
	initialRules, err := runner.Run(ctx, "-j", "list", "tables")
	if err != nil || bytes.Contains(initialRules, []byte(`"table"`)) {
		t.Fatalf("kernel test requires an empty namespace: %s %v", initialRules, err)
	}
	for _, kind := range []string{"zero", "one", "two", "duplicate", "conflicting", "foreign-table"} {
		t.Run(kind, func(t *testing.T) {
			host, _ := newManifestLegacyWireGuardTestHost(t)
			host.nftRunner, host.nftBatch = runner, batch
			script := `add table inet syswarden_wg
add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }
add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }
add rule inet syswarden_wg postrouting oifname "ens3" masquerade
add table inet filter
add chain inet filter forward { type filter hook forward priority 0; policy drop; }
add rule inet filter forward ip saddr 192.0.2.123 counter drop comment "administrator-preservation-probe"
`
			if kind != "zero" {
				script += "add rule inet filter forward iifname \"wg-syswarden\" accept\n"
			}
			if kind == "two" {
				script += "add rule inet filter forward oifname \"wg-syswarden\" accept\n"
			}
			if kind == "duplicate" {
				script += "add rule inet filter forward iifname \"wg-syswarden\" accept\n"
			}
			if kind == "conflicting" {
				script += "add rule inet filter forward oifname \"wg0\" accept\n"
			}
			if kind == "foreign-table" {
				script += "add rule inet syswarden_wg postrouting counter accept\n"
			}
			if output, err := batch(ctx, script); err != nil {
				t.Fatalf("create isolated fixture: %s %v", output, err)
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
			checks := 0
			err = host.remove(func() error { checks++; return nil })
			reject := kind == "duplicate" || kind == "conflicting" || kind == "foreign-table"
			if (err != nil) != reject {
				t.Fatalf("removal error = %v; expected rejection = %v", err, reject)
			}
			after, readErr := runner.Run(ctx, "-a", "-j", "list", "ruleset")
			if readErr != nil {
				t.Fatal(readErr)
			}
			if reject {
				if !bytes.Equal(before, after) {
					t.Fatal("refused cleanup changed kernel rules")
				}
			} else if checks != 3 || strings.Contains(string(after), "syswarden_wg") ||
				strings.Contains(string(after), "wg-syswarden") ||
				!strings.Contains(string(after), "administrator-preservation-probe") {
				t.Fatalf("cleanup did not preserve the exact expected rules: checks=%d %s", checks, after)
			}
			if _, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
				t.Fatalf("manifest was changed: %v", err)
			}
			t.Logf("kernel scenario %s: rejection=%t, removal checks=%d, manifest retained", kind, reject, checks)
		})
	}
}
