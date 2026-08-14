package config

import "testing"

func TestCustomValidators(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   any
		tag     string
		wantErr bool
	}{
		{name: "empty optional port", value: "", tag: "port"},
		{name: "lowest port", value: "1", tag: "port"},
		{name: "highest port", value: "65535", tag: "port"},
		{name: "zero port", value: "0", tag: "port", wantErr: true},
		{name: "oversized port", value: "65536", tag: "port", wantErr: true},
		{name: "IPv4 CIDR", value: "192.0.2.0/24", tag: "cidr"},
		{name: "IPv6 CIDR", value: "2001:db8::/32", tag: "cidr"},
		{name: "host is not CIDR", value: "192.0.2.1", tag: "cidr", wantErr: true},
		{name: "IPv4", value: "192.0.2.1", tag: "ip"},
		{name: "IPv6", value: "2001:db8::1", tag: "ip"},
		{name: "invalid IP", value: "999.0.2.1", tag: "ip", wantErr: true},
		{name: "ASN prefixed", value: "AS64500", tag: "asn"},
		{name: "ASN numeric", value: "64500", tag: "asn"},
		{name: "invalid ASN", value: "AS-example", tag: "asn", wantErr: true},
		{name: "duration", value: "24h", tag: "duration"},
		{name: "invalid duration", value: "daily", tag: "duration", wantErr: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validate.Var(test.value, test.tag)
			if (err != nil) != test.wantErr {
				t.Fatalf("validate.Var(%v, %q) error = %v, wantErr %t", test.value, test.tag, err, test.wantErr)
			}
		})
	}
}

func TestValidateConfigContract_SW_CFG_002(t *testing.T) {
	valid := &ModularConfig{}
	valid.Core.ConfigDir = "/etc/syswarden/config/modules"
	valid.Core.LogLevel = "INFO"
	valid.Core.FirewallBackend = "keep"
	valid.Core.SSHPort = "2222"
	valid.Network.Wireguard.Port = "51820"
	valid.Network.Wireguard.Subnet = "10.10.0.0/24"
	valid.Security.Compliance.CheckInterval = "24h"
	valid.WAAP.EnforcementMode = "enforcing"
	valid.WAAP.BruteforceThreshold = 5
	valid.WAAP.BruteforceWindowSeconds = 60
	valid.Integrations.HA.PeerPort = 62026

	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid modular configuration was rejected: %v", err)
	}

	invalid := *valid
	invalid.Core.SSHPort = "65536"
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted an invalid SSH port")
	}
}

func TestMapToGlobalConfigCompatibility(t *testing.T) {
	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })

	modular := &ModularConfig{}
	modular.Core.EnterpriseMode = true
	modular.Core.SSHPort = "2222"
	modular.Network.WhitelistIPs = []string{"192.0.2.10", "2001:db8::10"}
	modular.Network.LanSubnets = []string{"10.0.0.0/8"}
	modular.Network.Wireguard.Port = "51820"
	modular.WAAP.BruteforceThreshold = 7
	modular.WAAP.BruteforceWindowSeconds = 90
	modular.Integrations.HA.PeerIPs = []string{"192.0.2.20", "192.0.2.21"}
	modular.Integrations.HA.PeerPort = 62026

	mapToGlobalConfig(modular)
	if GlobalConfig == nil {
		t.Fatal("mapToGlobalConfig() left GlobalConfig nil")
	}
	if GlobalConfig.SSHPort != "2222" || GlobalConfig.WGPort != "51820" {
		t.Fatalf("port mapping changed: SSH=%q WG=%q", GlobalConfig.SSHPort, GlobalConfig.WGPort)
	}
	if GlobalConfig.WhitelistIPs != "192.0.2.10 2001:db8::10" {
		t.Fatalf("whitelist mapping = %q", GlobalConfig.WhitelistIPs)
	}
	if GlobalConfig.BruteforceThreshold != "7" || GlobalConfig.BruteforceWindow != "90s" {
		t.Fatalf("WAAP mapping changed: threshold=%q window=%q", GlobalConfig.BruteforceThreshold, GlobalConfig.BruteforceWindow)
	}
	if GlobalConfig.HAPeerIP != "192.0.2.20 192.0.2.21" || GlobalConfig.HAPeerPort != "62026" {
		t.Fatalf("HA mapping changed: peers=%q port=%q", GlobalConfig.HAPeerIP, GlobalConfig.HAPeerPort)
	}
}
