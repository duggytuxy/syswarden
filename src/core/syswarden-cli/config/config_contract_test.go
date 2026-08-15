package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

[integrations.bunkerweb]
enabled = true
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
	if !GlobalConfig.BunkerWebEnabled {
		t.Fatal("operator BunkerWeb feature-gate override was lost")
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

func TestLoadModularConfigRejectsUnsafeModesAndSymlinks_SW_CFG_002(t *testing.T) {
	t.Run("world-writable master", func(t *testing.T) {
		root := t.TempDir()
		master := filepath.Join(root, "config.toml")
		if err := os.WriteFile(master, []byte(minimalModularConfig), 0600); err != nil {
			t.Fatal(err)
		}
		secureRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = secureRoot.Close() }()
		masterFile, err := secureRoot.Open("config.toml")
		if err != nil {
			t.Fatal(err)
		}
		if err := masterFile.Chmod(0666); err != nil {
			_ = masterFile.Close()
			t.Fatal(err)
		}
		if err := masterFile.Close(); err != nil {
			t.Fatal(err)
		}
		if err := loadModularConfig(root); err == nil {
			t.Fatal("world-writable master configuration was accepted")
		}
	})

	t.Run("symlinked master", func(t *testing.T) {
		root := t.TempDir()
		outside := filepath.Join(t.TempDir(), "outside.toml")
		if err := os.WriteFile(outside, []byte(minimalModularConfig), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(root, "config.toml")); err != nil {
			t.Fatal(err)
		}
		if err := loadModularConfig(root); err == nil {
			t.Fatal("symlinked master configuration was accepted")
		}
	})

	t.Run("world-writable modules directory", func(t *testing.T) {
		root := t.TempDir()
		modules := filepath.Join(root, "modules")
		if err := os.Mkdir(modules, 0700); err != nil {
			t.Fatal(err)
		}
		secureRoot, err := os.OpenRoot(root)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = secureRoot.Close() }()
		modulesFile, err := secureRoot.Open("modules")
		if err != nil {
			t.Fatal(err)
		}
		if err := modulesFile.Chmod(0777); err != nil {
			_ = modulesFile.Close()
			t.Fatal(err)
		}
		if err := modulesFile.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(minimalModularConfig), 0600); err != nil {
			t.Fatal(err)
		}
		if err := loadModularConfig(root); err == nil {
			t.Fatal("world-writable modules directory was accepted")
		}
	})
}

func TestInvalidModularCandidateRetainsLastValidatedConfiguration_SW_CFG_001(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte("[core\n"), 0600); err != nil {
		t.Fatal(err)
	}

	previous := &Config{SSHPort: "2222", FirewallBackend: "keep"}
	previousState := CurrentLoadState()
	GlobalConfig = previous
	t.Cleanup(func() {
		GlobalConfig = NewFailSafeConfig()
		loadStateMu.Lock()
		loadState = previousState
		loadStateMu.Unlock()
	})

	if err := loadModularConfig(root); err == nil {
		t.Fatal("invalid modular candidate was accepted")
	}
	if GlobalConfig != previous || GlobalConfig.SSHPort != "2222" {
		t.Fatal("invalid modular candidate replaced the last validated configuration")
	}
	state := CurrentLoadState()
	if !state.Degraded || state.Source != root || state.Error == "" {
		t.Fatalf("load state = %#v, want a degraded state bound to the rejected candidate", state)
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
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("%s mode = %#o, want 0600", relative, got)
		}
	}
	integrationModule, err := os.ReadFile(filepath.Join(root, "modules", "40-integrations.toml")) // #nosec G304 -- root is a t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(integrationModule), "[integrations.bunkerweb]\n") ||
		!strings.Contains(string(integrationModule), "enabled = false\n") {
		t.Fatal("default integration module omitted the disabled BunkerWeb feature gate")
	}
}

func TestEnsureDefaultsCompletesPartialConfigWithoutOverwritingOperatorState_SW_CFG_001(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(modules, "99-user.toml")
	const userContent = "# operator-owned\n[user]\nwebtui_password = \"preserve-exactly\"\n"
	modulesRoot, err := os.OpenRoot(modules)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = modulesRoot.Close() }()
	userFile, err := modulesRoot.OpenFile("99-user.toml", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userFile.Write([]byte(userContent)); err != nil {
		_ = userFile.Close()
		t.Fatal(err)
	}
	if err := userFile.Chmod(0640); err != nil {
		_ = userFile.Close()
		t.Fatal(err)
	}
	if err := userFile.Close(); err != nil {
		t.Fatal(err)
	}

	if err := EnsureDefaults(root); err != nil {
		t.Fatalf("EnsureDefaults() error = %v", err)
	}
	assertFileContent(t, userPath, userContent)
	info, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0640 {
		t.Fatalf("operator module mode = %#o, want preserved 0640", got)
	}

	for _, relative := range []string{
		"config.toml",
		"modules/00-core.toml",
		"modules/10-network.toml",
		"modules/20-security.toml",
		"modules/30-waap.toml",
		"modules/40-integrations.toml",
		"modules/99-user.toml",
	} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("missing completed configuration file %s: %v", relative, err)
		}
	}

	previous := GlobalConfig
	previousState := CurrentLoadState()
	t.Cleanup(func() {
		GlobalConfig = previous
		loadStateMu.Lock()
		loadState = previousState
		loadStateMu.Unlock()
	})
	if err := ParseConfig(root); err != nil {
		t.Fatalf("ParseConfig() after partial bootstrap = %v", err)
	}
	if GlobalConfig == nil || GlobalConfig.WebTUIPassword != "preserve-exactly" {
		t.Fatalf("completed config did not preserve the operator token: %#v", GlobalConfig)
	}
	if state := CurrentLoadState(); state.Degraded || state.Source != root {
		t.Fatalf("load state = %#v, want validated modular source", state)
	}
	if GlobalConfig.HAEnabled {
		t.Fatal("default bootstrap enabled HA without an explicit peer and bearer token")
	}
	if GlobalConfig.BunkerWebEnabled {
		t.Fatal("default bootstrap enabled the BunkerWeb feature gate")
	}
}

func TestEnsureDefaultsRejectsSymlinkedOperatorModule_SW_CFG_001(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	modules := filepath.Join(root, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.toml")
	if err := os.WriteFile(outside, []byte("[core]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(modules, "00-core.toml")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefaults(root); err == nil {
		t.Fatal("EnsureDefaults() accepted a symlinked operator module")
	}
	assertFileContent(t, outside, "[core]\n")
}

func TestEnsureDefaultsRejectsSymlinkedAncestor_SW_CFG_001(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0700); err != nil {
		t.Fatal(err)
	}
	redirect := filepath.Join(root, "redirect")
	if err := os.Symlink(victim, redirect); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefaults(filepath.Join(redirect, "config")); err == nil {
		t.Fatal("EnsureDefaults() accepted a symlinked ancestor")
	}
	entries, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked ancestor modified its victim: %v", entries)
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
