//go:build linux

package firewall

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNFTRuntimePreservationAcceptsExactIPv6Chains(t *testing.T) {
	for _, family := range []string{"inet", "netdev"} {
		t.Run(family, func(t *testing.T) {
			wire, snapshot := runtimePreservationFixture(t)
			var document map[string][]json.RawMessage
			if err := json.Unmarshal(wire, &document); err != nil {
				t.Fatal(err)
			}
			table, _, err := ipv6ControlPlaneTarget(family)
			if err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				kind, name string
				accepted   bool
			}{
				{"chain", ipv6ControlPlaneChain, true},
				{"set", ipv6ControlPlaneChain, false},
				{"map", ipv6ControlPlaneChain, false},
				{"counter", ipv6ControlPlaneChain, false},
				{"chain", ipv6ControlPlaneChain + "-other", false},
				{"chain", ipv6ControlPlaneChain + "; flush ruleset", false},
				{"chain", ipv6ControlPlaneChain + "\nflush ruleset", false},
			} {
				entry, err := json.Marshal(map[string]any{test.kind: map[string]string{
					"family": family, "table": table, "name": test.name,
				}})
				if err != nil {
					t.Fatal(err)
				}
				candidate := append(append([]json.RawMessage(nil), document["nftables"]...), entry)
				changed, err := json.Marshal(map[string]any{"nftables": candidate})
				if err != nil {
					t.Fatal(err)
				}
				rules, err := nftRuntimePreservationRules(changed, snapshot)
				if !test.accepted {
					if err == nil || rules != "" {
						t.Fatalf("unsafe %s %q accepted: %q, %v", test.kind, test.name, rules, err)
					}
					continue
				}
				if err != nil {
					t.Fatalf("generated IPv6 chain prevents reload: %v", err)
				}
				want := "delete chain " + family + " " + table + " " + ipv6ControlPlaneChain + "\n"
				if strings.Count(rules, want) != 1 || strings.Contains(rules, "banned_ips") {
					t.Fatalf("IPv6 chain replacement changed runtime set ownership: %s", rules)
				}
			}
		})
	}
}
