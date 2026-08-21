//go:build linux

package network

import (
	"bytes"
	"encoding/base64"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestSetupWireguardOfflineRefusesBeforeMutation(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousClassifier := wireGuardManagerRuntimeState
	config.GlobalConfig = &config.Config{EnableWG: true}
	classifierCalls := 0
	wireGuardManagerRuntimeState = func() (string, error) {
		classifierCalls++
		return "OFFLINE", nil
	}
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardManagerRuntimeState = previousClassifier
	})
	if err := SetupWireguard(); err == nil || !strings.Contains(err.Error(), "attestable active service manager") {
		t.Fatalf("offline WireGuard result = %v", err)
	}
	if classifierCalls != 1 {
		t.Fatalf("service-manager classifier calls = %d, want 1", classifierCalls)
	}
}

func testWireGuardKey(fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func validWireGuardRenderInput() wireGuardRenderInput {
	return wireGuardRenderInput{
		Subnet:       "10.66.0.0/16",
		Port:         "51820",
		Backend:      "nftables",
		ActiveIf:     "ens3.100",
		EndpointIP:   "2001:db8::10",
		ServerPriv:   testWireGuardKey(1),
		ServerPub:    testWireGuardKey(2),
		ClientPriv:   testWireGuardKey(3),
		ClientPub:    testWireGuardKey(4),
		PresharedKey: testWireGuardKey(5),
	}
}

func TestWireGuardRendererUsesValidatedContextValues_SW_CFG_002(t *testing.T) {
	server, client, err := renderWireGuardConfigurations(validWireGuardRenderInput())
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{
		"Address = 10.66.0.1/16",
		"AllowedIPs = 10.66.0.2/32",
		`oifname "ens3.100" masquerade`,
	} {
		if !strings.Contains(server, fragment) {
			t.Fatalf("server configuration missing %q:\n%s", fragment, server)
		}
	}
	for _, fragment := range []string{
		"Address = 10.66.0.2/16",
		"Endpoint = [2001:db8::10]:51820",
	} {
		if !strings.Contains(client, fragment) {
			t.Fatalf("client configuration missing %q:\n%s", fragment, client)
		}
	}
}

func TestWireGuardRendererRejectsContextInjection_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*wireGuardRenderInput)
	}{
		{name: "interface breakout", mutate: func(value *wireGuardRenderInput) { value.ActiveIf = "eth0\"; touch /tmp/x" }},
		{name: "subnet command", mutate: func(value *wireGuardRenderInput) { value.Subnet = "10.66.0.0/16;touch" }},
		{name: "IPv6 subnet", mutate: func(value *wireGuardRenderInput) { value.Subnet = "2001:db8::/64" }},
		{name: "subnet too small", mutate: func(value *wireGuardRenderInput) { value.Subnet = "10.66.0.0/31" }},
		{name: "port breakout", mutate: func(value *wireGuardRenderInput) { value.Port = "51820\nPostUp = evil" }},
		{name: "endpoint breakout", mutate: func(value *wireGuardRenderInput) { value.EndpointIP = "192.0.2.1\nPostUp = evil" }},
		{name: "key breakout", mutate: func(value *wireGuardRenderInput) { value.ClientPub += "\nPostUp = evil" }},
		{name: "unknown backend", mutate: func(value *wireGuardRenderInput) { value.Backend = "firewalld;touch" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validWireGuardRenderInput()
			test.mutate(&input)
			if _, _, err := renderWireGuardConfigurations(input); err == nil {
				t.Fatal("WireGuard renderer accepted an injection or unsupported value")
			}
		})
	}
}
