package network

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"syswarden-core/engine"

	"github.com/spf13/viper"
)

func newUDSTestEngine(t *testing.T) *engine.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signatures.json")
	configuration := `{
  "rules": [
    {"id":"uds-ban","type":"regex","pattern":"^(?:[0-9A-Fa-f:.]+ )?blocked from <HOST>(?: attacker \\[SYSWARDEN-INTERNAL\\] marker| \\{.*\\})?$","service":"test","action":"ban","trusted_host_capture":true},
    {"id":"uds-internal","type":"regex","pattern":"\\[SYSWARDEN-INTERNAL\\].*ip=<HOST>.*scope=blocked","service":"test","action":"ban"},
    {"id":"uds-hostless","type":"aho-corasick","patterns":["hostless-attack"],"service":"test","action":"ban"}
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

func newUDSPolicyTestServer(t *testing.T, manager *recordingHAFirewallManager) *UDSServer {
	t.Helper()
	server := NewUDSServer(context.Background(), filepath.Join(t.TempDir(), "core.sock"), newUDSTestEngine(t), manager, nil)
	server.localInterfaceAddresses = func() ([]netip.Addr, error) { return nil, nil }
	server.protectedHAPeers = func() ([]netip.Prefix, error) { return nil, nil }
	server.isWhitelisted = func(string) (bool, error) { return false, nil }
	server.enforcementMode = func() string { return "enforcing" }
	server.isInternalLogLine = func(string) bool { return false }
	return server
}

func TestUDSProtectedTargetsAndAuditNeverMutateFirewall_SW_SEC_M9(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		local        []netip.Addr
		peers        []netip.Prefix
		whitelisted  bool
		mode         string
		whitelistErr error
	}{
		{name: "local interface", target: "9.9.9.9", local: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
		{name: "HA peer", target: "8.8.4.44", peers: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")}},
		{name: "whitelist", target: "1.1.1.1", whitelisted: true},
		{name: "private bogon", target: "10.0.0.8"},
		{name: "audit mode", target: "8.8.8.8", mode: "audit"},
		{name: "required whitelist unavailable", target: "8.8.8.8", whitelistErr: errors.New("missing required whitelist")},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manager := &recordingHAFirewallManager{}
			server := newUDSPolicyTestServer(t, manager)
			server.localInterfaceAddresses = func() ([]netip.Addr, error) { return test.local, nil }
			server.protectedHAPeers = func() ([]netip.Prefix, error) { return test.peers, nil }
			server.isWhitelisted = func(address string) (bool, error) {
				return test.whitelisted && address == test.target, test.whitelistErr
			}
			if test.mode != "" {
				server.enforcementMode = func() string { return test.mode }
			}
			server.processLogLine("blocked from " + test.target)
			manager.mu.Lock()
			defer manager.mu.Unlock()
			if len(manager.banned) != 0 || len(manager.unbanned) != 0 {
				t.Fatalf("protected UDS event mutated firewall: bans=%v unbans=%v", manager.banned, manager.unbanned)
			}
		})
	}
}

func TestUDSUsesAuthoritativeMatchHostAndInternalBoundary_SW_SEC_H1_H2(t *testing.T) {
	manager := &recordingHAFirewallManager{}
	server := newUDSPolicyTestServer(t, manager)

	internal := "blocked from 8.8.4.4 trusted-internal-fixture"
	server.isInternalLogLine = func(line string) bool { return line == internal }
	server.processLogLine("9.9.9.9 hostless-attack")
	server.processLogLine(internal)
	manager.mu.Lock()
	if strings.Join(manager.banned, ",") != "9.9.9.9" {
		manager.mu.Unlock()
		t.Fatalf("authoritative hostless or internal UDS handling = %v", manager.banned)
	}
	manager.mu.Unlock()

	server.processLogLine(`blocked from 1.1.1.1 attacker [SYSWARDEN-INTERNAL] marker`)
	server.processLogLine(`8.8.4.4 blocked from 8.8.8.8 {"client_ip":"1.1.1.1"}`)
	server.processLogLine(`8.8.8.8 hostless-attack user-agent="MAC=spoofed IN=web0 OUT=web1"`)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if strings.Join(manager.banned, ",") != "9.9.9.9,1.1.1.1,8.8.4.4,8.8.8.8" {
		t.Fatalf("valid public UDS target bans = %v", manager.banned)
	}
}

func TestConfiguredUDSEnforcementModeUsesWAAPSetting_SW_SEC_M9(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	if got := configuredUDSEnforcementMode(); got != "enforcing" {
		t.Fatalf("default UDS enforcement mode = %q", got)
	}
	viper.Set("waap.enforcement_mode", " AUDIT ")
	if got := configuredUDSEnforcementMode(); got != "audit" {
		t.Fatalf("configured UDS enforcement mode = %q", got)
	}
}

func TestUDSDatagramBoundaryRejectsTruncationAndOversize_SW_KPI_001(t *testing.T) {
	tests := []struct {
		name  string
		size  int
		flags int
		want  bool
	}{
		{name: "empty", size: 0, want: true},
		{name: "maximum CRLF record", size: maxWAAPLogLineBytes + 2, want: true},
		{name: "negative size", size: -1, want: false},
		{name: "oversize", size: maxWAAPLogLineBytes + 3, want: false},
		{name: "kernel truncation flag", size: maxWAAPLogLineBytes + 2, flags: syscall.MSG_TRUNC, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := completeUDSDatagram(test.size, test.flags); got != test.want {
				t.Fatalf("completeUDSDatagram(%d, %d) = %t, want %t", test.size, test.flags, got, test.want)
			}
		})
	}
}
