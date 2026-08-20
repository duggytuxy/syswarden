package config

import (
	"strings"
	"testing"
)

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
		{name: "canonical LAN", value: []string{"10.0.0.0/8", "2001:db8::/32"}, tag: "canonical_cidr_slice"},
		{name: "LAN host bits", value: []string{"10.0.0.1/8"}, tag: "canonical_cidr_slice", wantErr: true},
		{name: "whitelist shell payload", value: []string{"192.0.2.1;flush"}, tag: "ip_or_cidr_slice", wantErr: true},
		{name: "country list", value: []string{"be", "FR"}, tag: "country_code_slice"},
		{name: "long country", value: []string{"BEL"}, tag: "country_code_slice", wantErr: true},
		{name: "maximum ASN", value: []string{"AS4294967295"}, tag: "asn_slice"},
		{name: "negative ASN", value: []string{"AS-1"}, tag: "asn_slice", wantErr: true},
		{name: "oversized ASN", value: []string{"4294967296"}, tag: "asn_slice", wantErr: true},
		{name: "interfaces", value: "eth0,ens3.10", tag: "interface_list"},
		{name: "interface command injection", value: "eth0;flush ruleset", tag: "interface_list", wantErr: true},
		{name: "HTTPS URL", value: "https://feeds.example.invalid/list.txt", tag: "https_url_optional"},
		{name: "HTTP URL", value: "http://feeds.example.invalid/list.txt", tag: "https_url_optional", wantErr: true},
		{name: "URL userinfo", value: "https://user:secret@example.invalid/hook", tag: "https_url_optional", wantErr: true}, // #nosec G101 -- deliberate invalid userinfo fixture contains no real credential
		{name: "SHA-256", value: strings.Repeat("a", 64), tag: "sha256_optional"},
		{name: "short digest", value: "sha256:abcd", tag: "sha256_optional", wantErr: true},
		{name: "absolute CA", value: "/etc/syswarden/ca.pem", tag: "absolute_path"},
		{name: "relative CA", value: "../../ca.pem", tag: "absolute_path", wantErr: true},
		{name: "absolute log glob", value: "/var/log/nginx/*.log", tag: "log_path_optional"},
		{name: "log newline", value: "/var/log/access.log\nmodule(load=\"evil\")", tag: "log_path_optional", wantErr: true},
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

	invalid = *valid
	invalid.Integrations.Wazuh.Enabled = true
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted enabled Wazuh without a manager endpoint")
	}

	invalid = *valid
	invalid.Integrations.SIEM.Port = "70000"
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted an invalid SIEM port")
	}

	invalid = *valid
	invalid.Security.Honeyports = []string{"23", "not-a-port"}
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted an invalid honeyport")
	}

	invalid = *valid
	invalid.SchemaVersion = CurrentSchemaVersion + 1
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted an unsupported schema version")
	}

	invalid = *valid
	invalid.Integrations.SIEM.Enabled = true
	invalid.Integrations.SIEM.IP = "192.0.2.20"
	invalid.Integrations.SIEM.Port = "6514"
	invalid.Integrations.SIEM.Protocol = "tls"
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted TLS SIEM without a CA path")
	}

	invalid = *valid
	invalid.Integrations.Webhooks.Enabled = true
	if err := validateConfig(&invalid); err == nil {
		t.Fatal("modular configuration accepted enabled webhooks without an HTTPS endpoint")
	}
}

func TestValidateHARequiresTokenAndAcceptsPeerCIDRs(t *testing.T) {
	base := &ModularConfig{}
	base.Core.ConfigDir = "/etc/syswarden/config/modules"
	base.Core.LogLevel = "INFO"
	base.Core.FirewallBackend = "keep"
	base.Core.SSHPort = "2222"
	base.Network.Wireguard.Port = "51820"
	base.Network.Wireguard.Subnet = "10.10.0.0/24"
	base.Security.Compliance.CheckInterval = "24h"
	base.WAAP.EnforcementMode = "enforcing"
	base.WAAP.BruteforceThreshold = 5
	base.WAAP.BruteforceWindowSeconds = 60
	base.Integrations.HA.Enabled = true
	base.Integrations.HA.PeerPort = 62026
	base.Integrations.HA.PeerIPs = []string{"10.20.30.0/29", "2001:db8::20"}
	base.Integrations.HA.Token = "shared-cluster-token"

	if err := validateConfig(base); err != nil {
		t.Fatalf("valid HA IP/CIDR configuration was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ModularConfig)
	}{
		{
			name: "empty token",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.Token = ""
			},
		},
		{
			name: "surrounding token whitespace",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.Token = " shared-cluster-token "
			},
		},
		{
			name: "embedded token newline",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.Token = "shared\ncluster-token"
			},
		},
		{
			name: "missing peers",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.PeerIPs = nil
			},
		},
		{
			name: "invalid peer",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.PeerIPs = []string{"docker-network"}
			},
		},
		{
			name: "IPv4-mapped IPv6 peer",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.PeerIPs = []string{"::ffff:192.0.2.10"}
			},
		},
		{
			name: "CIDR with host bits",
			mutate: func(config *ModularConfig) {
				config.Integrations.HA.PeerIPs = []string{"10.20.30.3/29"}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			candidate := *base
			candidate.Integrations.HA.PeerIPs = append([]string(nil), base.Integrations.HA.PeerIPs...)
			test.mutate(&candidate)
			if err := validateConfig(&candidate); err == nil {
				t.Fatal("invalid HA configuration was accepted")
			}
		})
	}
}

func TestBunkerWebFeatureGateRequiresAuthenticatedHA_SW_CFG_002(t *testing.T) {
	base := &ModularConfig{}
	base.Core.ConfigDir = "/etc/syswarden/config/modules"
	base.Core.LogLevel = "INFO"
	base.Core.FirewallBackend = "keep"
	base.Core.SSHPort = "2222"
	base.Network.Wireguard.Port = "51820"
	base.Network.Wireguard.Subnet = "10.10.0.0/24"
	base.Security.Compliance.CheckInterval = "24h"
	base.WAAP.EnforcementMode = "enforcing"
	base.WAAP.BruteforceThreshold = 5
	base.WAAP.BruteforceWindowSeconds = 60
	base.Integrations.HA.PeerPort = 62026

	if err := validateConfig(base); err != nil {
		t.Fatalf("disabled BunkerWeb gate changed the default contract: %v", err)
	}

	base.Integrations.BunkerWeb.Enabled = true
	if err := validateConfig(base); err == nil {
		t.Fatal("BunkerWeb gate accepted disabled HA")
	}

	base.Integrations.HA.Enabled = true
	base.Integrations.HA.Token = " shared-token "
	base.Integrations.HA.PeerIPs = []string{"192.0.2.20"}
	if err := validateConfig(base); err == nil {
		t.Fatal("BunkerWeb gate accepted an HA token with surrounding whitespace")
	}

	base.Integrations.HA.Token = "shared-token"
	base.Integrations.HA.PeerIPs = nil
	if err := validateConfig(base); err == nil {
		t.Fatal("BunkerWeb gate accepted an empty HA peer allowlist")
	}

	base.Integrations.HA.PeerIPs = []string{"192.0.2.20", "10.20.30.0/29"}
	if err := validateConfig(base); err != nil {
		t.Fatalf("BunkerWeb gate rejected authenticated HA with canonical peers: %v", err)
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
	modular.Integrations.BunkerWeb.Enabled = true

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
	if !GlobalConfig.BunkerWebEnabled {
		t.Fatal("BunkerWeb feature gate was not mapped to the runtime configuration")
	}
}
