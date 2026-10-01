//go:build linux

package network

import (
	"errors"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func TestLegacyWireGuardRemovalPreservesManifestAndUsesExactAtomicBatch(t *testing.T) {
	for _, rules := range [][]LegacyWireGuardForwardRuleEvidence{{}, {{Direction: "iifname", Handle: 17}}, {{Direction: "iifname", Handle: 17}, {Direction: "oifname", Handle: 18}}} {
		host, state := newManifestLegacyWireGuardTestHost(t)
		state.forwardRules["wg-syswarden"] = rules
		checks := 0
		if err := host.remove(func() error { checks++; return nil }); err != nil {
			t.Fatal(err)
		}
		if checks != 3 || len(state.batches) != 1 || state.tablePresent || len(state.forwardRules["wg-syswarden"]) != 0 {
			t.Fatalf("checks=%d state=%#v", checks, state)
		}
		if strings.Contains(state.batches[0], "handle 90") || strings.Contains(state.batches[0], "delete table inet filter") {
			t.Fatal("administrator rule included in removal")
		}
		if _, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
			t.Fatalf("ownership evidence changed: %v", err)
		}
		if err := host.remove(func() error { return nil }); err == nil {
			t.Fatal("absent legacy table accepted as fresh legacy authorization")
		}
		if len(state.batches) != 1 {
			t.Fatal("repeated legacy recovery mutated nftables")
		}
	}
}

func TestLegacyWireGuardRemovalRejectsUnmanifestedState(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg-syswarden", nil)
	if err := host.remove(func() error { return nil }); err == nil {
		t.Fatal("unmanifested legacy state was automatically removed")
	}
	if len(state.batches) != 0 {
		t.Fatal("rejection mutated nftables")
	}
}

func TestLegacyWireGuardRemovalReattestsBarrierAndServices(t *testing.T) {
	for failureAt := 1; failureAt <= 3; failureAt++ {
		host, state := newManifestLegacyWireGuardTestHost(t)
		sentinel := errors.New("removal evidence changed")
		checks := 0
		err := host.remove(func() error {
			checks++
			if checks == failureAt {
				return sentinel
			}
			return nil
		})
		if !errors.Is(err, sentinel) || len(state.batches) != 0 {
			t.Fatalf("failureAt=%d err=%v batches=%v", failureAt, err, state.batches)
		}
	}
}

func TestLegacyWireGuardRemovalRejectsActiveRuntimeAndAmbiguousRules(t *testing.T) {
	for _, kind := range []string{"active", "enabled", "duplicate", "conflicting"} {
		host, state := newManifestLegacyWireGuardTestHost(t)
		switch kind {
		case "active":
			host.commandOutput = fakeLegacyWireGuardServiceOutput(true, false, false)
		case "enabled":
			host.commandOutput = fakeLegacyWireGuardServiceOutput(false, true, false)
		case "duplicate":
			state.forwardRules["wg-syswarden"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}, {Direction: "iifname", Handle: 18}}
		case "conflicting":
			state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}}
		}
		if err := host.remove(func() error { return nil }); err == nil || len(state.batches) != 0 {
			t.Fatalf("kind=%s err=%v batches=%v", kind, err, state.batches)
		}
	}
}

func TestWireGuardRemovalPreflightRejectsUnmanifestedArtifacts(t *testing.T) {
	for _, test := range []struct {
		inventory wireguardstate.Inventory
		rejected  bool
	}{
		{wireguardstate.Inventory{}, false},
		{wireguardstate.Inventory{Manifest: true}, false},
		{wireguardstate.Inventory{Transaction: true}, false},
		{wireguardstate.Inventory{Artifacts: []string{wireguardstate.ServerConfigurationPath}}, true},
	} {
		err := preflightWireGuardRemovalInventory(func() (wireguardstate.Inventory, error) { return test.inventory, nil })
		if (err != nil) != test.rejected {
			t.Fatalf("inventory=%#v err=%v", test.inventory, err)
		}
	}
	sentinel := errors.New("unsafe file")
	if err := preflightWireGuardRemovalInventory(func() (wireguardstate.Inventory, error) { return wireguardstate.Inventory{}, sentinel }); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
