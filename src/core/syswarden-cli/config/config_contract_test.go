package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const minimalModularConfig = `# Operator comment must remain byte-for-byte identical.
[core]
config_dir = "/etc/syswarden/config/modules"
log_level = "INFO"
firewall_backend = "keep"
ssh_port = "2222"

[waap]
enforcement_mode = "enforcing"
bruteforce_threshold = 5
bruteforce_window_seconds = 60

[integrations.ha]
peer_port = 62026
`

func TestLoadModularConfigMinimalAndUnknownKeysAreReadOnly_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	master := filepath.Join(root, "config.toml")
	module := filepath.Join(modules, "99-user.toml")
	masterContent := minimalModularConfig + `
[operator_extension]
unknown_key = "must remain on disk" # unknown inline comment
`
	moduleContent := `# Operator-owned extension and comment.
[user]
webtui_password = "existing-token"
profile_name = "production"

[future_module]
future_key = 42
`
	if err := os.WriteFile(master, []byte(masterContent), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte(moduleContent), 0600); err != nil {
		t.Fatal(err)
	}

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadModularConfig(root); err != nil {
		t.Fatalf("loadModularConfig() error = %v", err)
	}
	if GlobalConfig == nil {
		t.Fatal("loadModularConfig() left GlobalConfig nil")
	}
	if GlobalConfig.SSHPort != "2222" || GlobalConfig.WebTUIPassword != "existing-token" {
		t.Fatalf("mapped configuration changed: SSH=%q token=%q", GlobalConfig.SSHPort, GlobalConfig.WebTUIPassword)
	}
	assertFileContent(t, master, masterContent)
	assertFileContent(t, module, moduleContent)
}

func TestLoadModularConfigCompleteAndPriorityContract_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	master := filepath.Join(root, "config.toml")
	if err := os.WriteFile(master, []byte(minimalModularConfig), 0600); err != nil {
		t.Fatal(err)
	}

	lowPriority := `[core]
ssh_port = "2200"
hardening_enabled = true

[network]
whitelist_infra = false
lan_subnets = ["10.0.0.0/8", "2001:db8::/32"]
whitelist_ips = ["192.0.2.10", "2001:db8::10"]
interfaces = "eth0,eth1"

[network.geo]
enabled = true
blocked_countries = ["be"]
allowed_countries = ["fr"]

[network.asn]
enabled = true
blocked_asns = ["AS64500"]
allowed_asns = ["AS64501"]

[network.wireguard]
enabled = true
port = "51820"
subnet = "10.66.66.0/24"

[security]
honeyports = ["23", "6379"]

[security.l2]
enable_l2 = true
arp_protect = true
lan_mode = true

[security.compliance]
enable_watchdog = true
check_interval = "24h"

[integrations.ha]
enabled = true
peer_ips = ["192.0.2.20", "2001:db8::20"]
peer_port = 62026
token = "cluster-token"

[integrations.siem]
enabled = true
ip = "192.0.2.30"
port = "6514"
protocol = "tls"
tls_ca = "/etc/ssl/example-ca.pem"

[integrations.abuseipdb]
enabled = true
api_key = "fixture-api-key"

[integrations.webhooks]
enabled = true
discord_url = "https://example.invalid/discord"
teams_url = "https://example.invalid/teams"
slack_url = "https://example.invalid/slack"
`
	highPriority := `# The final module wins.
[core]
ssh_port = "2222"

[user]
webtui_password = "operator-token"
`
	if err := os.WriteFile(filepath.Join(modules, "10-network.toml"), []byte(lowPriority), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modules, "99-user.toml"), []byte(highPriority), 0600); err != nil {
		t.Fatal(err)
	}

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadModularConfig(root); err != nil {
		t.Fatalf("loadModularConfig() error = %v", err)
	}
	if GlobalConfig.SSHPort != "2222" || !GlobalConfig.EnableWG || GlobalConfig.WGPort != "51820" {
		t.Fatalf("core/network priority changed: SSH=%q WG=%t/%q", GlobalConfig.SSHPort, GlobalConfig.EnableWG, GlobalConfig.WGPort)
	}
	if GlobalConfig.HAPeerIP != "192.0.2.20 2001:db8::20" || GlobalConfig.HAToken != "cluster-token" {
		t.Fatalf("HA mapping changed: peers=%q token=%q", GlobalConfig.HAPeerIP, GlobalConfig.HAToken)
	}
	if GlobalConfig.WebTUIPassword != "operator-token" {
		t.Fatalf("user override changed: %q", GlobalConfig.WebTUIPassword)
	}
	if GlobalConfig.LANSubnets != "10.0.0.0/8 2001:db8::/32" || GlobalConfig.HoneyPorts != "23 6379" {
		t.Fatalf("slice mapping changed: LAN=%q honeyports=%q", GlobalConfig.LANSubnets, GlobalConfig.HoneyPorts)
	}
}

func TestLoadModularConfigRejectsInvalidTOMLAndValues(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "invalid TOML", content: "[core\n"},
		{name: "invalid SSH port", content: minimalModularConfig + "\n[core]\nssh_port = \"70000\"\n"},
		{name: "invalid WAAP mode", content: minimalModularConfig + "\n[waap]\nenforcement_mode = \"disabled\"\n"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := loadModularConfig(root); err == nil {
				t.Fatal("invalid modular configuration was accepted")
			}
		})
	}
}

func TestInitializeDefaultsIsByteIdempotentAndUsesRestrictiveModes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatalf("InitializeDefaults() first run: %v", err)
	}
	before := directoryDigest(t, root)
	if err := InitializeDefaults(root); err != nil {
		t.Fatalf("InitializeDefaults() second run: %v", err)
	}
	after := directoryDigest(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("repeated default initialization changed files:\nbefore=%v\nafter=%v", before, after)
	}

	entries := []string{
		"config.toml",
		"modules/00-core.toml",
		"modules/10-network.toml",
		"modules/20-security.toml",
		"modules/30-waap.toml",
		"modules/40-integrations.toml",
		"modules/99-user.toml",
	}
	for _, relative := range entries {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0640 {
			t.Errorf("%s mode = %#o, want 0640", relative, got)
		}
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path) // #nosec G304 -- path is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("%s changed during a read-only load:\ngot=%q\nwant=%q", path, got, want)
	}
}
