//go:build linux

package network

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"syswarden-core/engine"
)

func newWAAPPolicyTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signatures.json")
	configuration := `{
  "rules": [
    {"id":"waap-ban","type":"regex","pattern":"blocked from <HOST>","service":"test","action":"ban"}
  ]
}`
	if err := os.WriteFile(path, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	detector, err := engine.NewEngine(path, 1, 60)
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func newWAAPPolicyTestEngineBoundary(t *testing.T, manager *recordingWAAPFirewall) *WAAPEngine {
	t.Helper()
	return &WAAPEngine{
		config:                  WAAPConfig{Mode: "enforcing"},
		fw:                      manager,
		engine:                  newWAAPPolicyTestEngine(t),
		localInterfaceAddresses: func() ([]netip.Addr, error) { return nil, nil },
		protectedHAPeers:        func() ([]netip.Prefix, error) { return nil, nil },
		isWhitelisted:           func(string) (bool, error) { return false, nil },
	}
}

func TestWAAPProtectedTargetsNeverMutateFirewall_SW_SEC_M1(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		local        []netip.Addr
		peers        []netip.Prefix
		whitelisted  bool
		mode         string
		localErr     error
		whitelistErr error
	}{
		{name: "private address", target: "10.0.0.8"},
		{name: "documentation address", target: "192.0.2.8"},
		{name: "local interface", target: "9.9.9.9", local: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
		{name: "HA peer", target: "8.8.4.44", peers: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")}},
		{name: "whitelisted address", target: "1.1.1.1", whitelisted: true},
		{name: "local inventory unavailable", target: "8.8.8.8", localErr: errors.New("interface inventory unavailable")},
		{name: "required whitelist unavailable", target: "8.8.8.8", whitelistErr: errors.New("required whitelist unavailable")},
		{name: "audit mode", target: "8.8.8.8", mode: "audit"},
		{name: "invalid mode", target: "8.8.8.8", mode: "unexpected"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manager := &recordingWAAPFirewall{}
			waap := newWAAPPolicyTestEngineBoundary(t, manager)
			waap.localInterfaceAddresses = func() ([]netip.Addr, error) { return test.local, test.localErr }
			waap.protectedHAPeers = func() ([]netip.Prefix, error) { return test.peers, nil }
			waap.isWhitelisted = func(address string) (bool, error) {
				return test.whitelisted && address == test.target, test.whitelistErr
			}
			if test.mode != "" {
				waap.config.Mode = test.mode
			}

			waap.processLogLine("blocked from " + test.target)

			manager.mu.Lock()
			defer manager.mu.Unlock()
			if len(manager.banned) != 0 {
				t.Fatalf("protected WAAP event mutated firewall: %v", manager.banned)
			}
		})
	}
}

func TestWAAPUnavailableDependenciesFailClosed_SW_SEC_M1(t *testing.T) {
	manager := &recordingWAAPFirewall{}
	waap := newWAAPPolicyTestEngineBoundary(t, manager)
	waap.fw = nil
	waap.processLogLine("blocked from 8.8.8.8")
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 0 {
		t.Fatalf("unavailable WAAP firewall recorded mutations: %v", manager.banned)
	}

	waap.engine = nil
	waap.processLogLine("blocked from 8.8.8.8")
}

func TestWAAPCanonicalPolicyPreservesPublicMutation_SW_SEC_M1(t *testing.T) {
	manager := &recordingWAAPFirewall{}
	waap := newWAAPPolicyTestEngineBoundary(t, manager)

	waap.processLogLine(`8.8.4.4 blocked from 8.8.8.8 {"client_ip":"1.1.1.1"}`)

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.banned) != 1 || manager.banned[0] != "8.8.4.4" {
		t.Fatalf("WAAP firewall mutations = %v, want structural access-log host 8.8.4.4", manager.banned)
	}
}
