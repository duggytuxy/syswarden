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
	if err := loadOldConfig(filepath.Join(t.TempDir(), "missing.conf")); err == nil {
		t.Fatal("loadOldConfig() succeeded for a missing file")
	}
}
