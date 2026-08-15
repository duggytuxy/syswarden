package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBoolCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  bool
	}{
		{value: "y", want: true},
		{value: "YES", want: true},
		{value: "True", want: true},
		{value: "1", want: true},
		{value: "n", want: false},
		{value: "false", want: false},
		{value: "0", want: false},
		{value: "", want: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()
			if got := parseBool(test.value); got != test.want {
				t.Fatalf("parseBool(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestLoadOldConfigCompatibility(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "syswarden-auto.conf")
	content := `# Existing flat configuration
SYSWARDEN_ENTERPRISE_MODE="yes"
SYSWARDEN_SSH_PORT='2222'
SYSWARDEN_WHITELIST_IPS="192.0.2.10 2001:db8::10"
SYSWARDEN_HA_PEER_PORT="62026"
SYSWARDEN_LAN_SUBNETS="10.0.0.0/8 192.168.0.0/16"
UNKNOWN_USER_KEY="preserved-on-disk"
MALFORMED_LINE
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath) // #nosec G304 -- configPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })

	if err := loadOldConfig(configPath); err != nil {
		t.Fatalf("loadOldConfig() error = %v", err)
	}
	if GlobalConfig == nil {
		t.Fatal("loadOldConfig() left GlobalConfig nil")
	}
	if !GlobalConfig.EnterpriseMode {
		t.Error("enterprise mode was not parsed")
	}
	if GlobalConfig.SSHPort != "2222" {
		t.Errorf("SSH port = %q, want 2222", GlobalConfig.SSHPort)
	}
	if GlobalConfig.WhitelistIPs != "192.0.2.10 2001:db8::10" {
		t.Errorf("whitelist = %q", GlobalConfig.WhitelistIPs)
	}
	if GlobalConfig.HAPeerPort != "62026" {
		t.Errorf("HA peer port = %q, want 62026", GlobalConfig.HAPeerPort)
	}
	if GlobalConfig.LANSubnets != "10.0.0.0/8 192.168.0.0/16" {
		t.Errorf("LAN subnets = %q", GlobalConfig.LANSubnets)
	}
	after, err := os.ReadFile(configPath) // #nosec G304 -- configPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("legacy parser rewrote operator input:\ngot=%q\nwant=%q", after, before)
	}
}

func TestLoadOldConfigMissingFileFails(t *testing.T) {
	previous := &Config{SSHPort: "2222", FirewallBackend: "keep"}
	previousState := CurrentLoadState()
	GlobalConfig = previous
	t.Cleanup(func() {
		GlobalConfig = NewFailSafeConfig()
		loadStateMu.Lock()
		loadState = previousState
		loadStateMu.Unlock()
	})

	missing := filepath.Join(t.TempDir(), "missing.conf")
	if err := loadOldConfig(missing); err == nil {
		t.Fatal("loadOldConfig() succeeded for a missing file")
	}
	if GlobalConfig != previous || GlobalConfig.SSHPort != "2222" {
		t.Fatal("failed legacy load replaced the last validated configuration")
	}
	state := CurrentLoadState()
	if !state.Degraded || state.Source != missing || state.Error == "" {
		t.Fatalf("load state = %#v, want a degraded state bound to the failed source", state)
	}
}

func TestLoadOldConfigRejectsInvalidCandidateWithoutReplacingActive_SW_CFG_001(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "syswarden-auto.conf")
	if err := os.WriteFile(configPath, []byte("SYSWARDEN_HA_PEER_PORT=70000\n"), 0600); err != nil {
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

	if err := loadOldConfig(configPath); err == nil {
		t.Fatal("loadOldConfig() accepted an invalid port")
	}
	if GlobalConfig != previous || GlobalConfig.SSHPort != "2222" {
		t.Fatal("invalid legacy candidate replaced the active configuration")
	}
	if state := CurrentLoadState(); !state.Degraded || state.Source != configPath || state.Error == "" {
		t.Fatalf("load state = %#v, want degraded legacy rejection", state)
	}
}

func TestLegacyHAAndTypedValidationMatchesModularFailClosedContract_SW_CFG_001(t *testing.T) {
	original := GlobalConfig
	t.Cleanup(func() { GlobalConfig = original })
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "HA token without peer",
			content: "SYSWARDEN_HA_ENABLED=y\n" +
				"SYSWARDEN_HA_TOKEN=shared-token\nSYSWARDEN_HA_PEER_IP=\n",
		},
		{
			name: "HA peer without token",
			content: "SYSWARDEN_HA_ENABLED=y\n" +
				"SYSWARDEN_HA_TOKEN=\nSYSWARDEN_HA_PEER_IP=192.0.2.20\n",
		},
		{
			name: "non-canonical HA peer",
			content: "SYSWARDEN_HA_ENABLED=y\n" +
				"SYSWARDEN_HA_TOKEN=shared-token\nSYSWARDEN_HA_PEER_IP=10.20.30.3/29\n",
		},
		{
			name: "BunkerWeb without HA",
			content: "SYSWARDEN_HA_ENABLED=n\n" +
				"SYSWARDEN_BUNKERWEB_ENABLED=y\n",
		},
		{
			name:    "invalid SIEM port",
			content: "SYSWARDEN_HA_ENABLED=n\nSYSWARDEN_SIEM_PORT=70000\n",
		},
		{
			name:    "invalid honeyport",
			content: "SYSWARDEN_HA_ENABLED=n\nSYSWARDEN_HONEYPORTS=23,invalid\n",
		},
		{
			name:    "invalid HA boolean",
			content: "SYSWARDEN_HA_ENABLED=automatic\n",
		},
		{
			name:    "invalid BunkerWeb boolean",
			content: "SYSWARDEN_HA_ENABLED=n\nSYSWARDEN_BUNKERWEB_ENABLED=automatic\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy.conf")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			previous := &Config{SSHPort: "2222", FirewallBackend: "keep"}
			GlobalConfig = previous
			if err := loadOldConfig(path); err == nil {
				t.Fatal("invalid legacy configuration was accepted")
			}
			if GlobalConfig != previous {
				t.Fatal("invalid legacy configuration replaced the previous GlobalConfig")
			}
		})
	}
}

func TestLegacyValidAuthenticatedHARemainsEnabled_SW_CFG_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.conf")
	content := "SYSWARDEN_HA_ENABLED=y\n" +
		"SYSWARDEN_HA_TOKEN=shared-token\n" +
		"SYSWARDEN_HA_PEER_IP=192.0.2.20,10.20.30.0/29\n" +
		"SYSWARDEN_BUNKERWEB_ENABLED=y\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadOldConfig(path); err != nil {
		t.Fatalf("valid legacy HA configuration rejected: %v", err)
	}
	if !GlobalConfig.HAEnabled || !GlobalConfig.BunkerWebEnabled {
		t.Fatalf("valid legacy gates = HA %t, BunkerWeb %t", GlobalConfig.HAEnabled, GlobalConfig.BunkerWebEnabled)
	}
}
