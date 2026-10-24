package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFreshNativeProfileIsStandardOnly(t *testing.T) {
	old, state := GlobalConfig, CurrentLoadState()
	t.Cleanup(func() { GlobalConfig = old; loadStateMu.Lock(); loadState = state; loadStateMu.Unlock() })
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	if err := loadModularConfig(root); err != nil {
		t.Fatal(err)
	}
	c := GlobalConfig
	if c.InstallProfile != StandardInstallProfile || c.ListChoice != "1" || c.FirewallBackend != "keep" {
		t.Fatalf("wrong standard profile: %s/%s/%s", c.InstallProfile, c.ListChoice, c.FirewallBackend)
	}
	for name, enabled := range map[string]bool{"OS": c.Hardening, "CIS": c.CISL2Hardening, "OSINT": c.OSINTEnabled, "WAAP": c.WAAPEnabled, "bridge": c.LogBridgeEnabled, "detection": c.DetectionEnabled, "Geo": c.EnableGeo, "ASN": c.EnableASN, "L2": c.EnableL2, "ARP": c.ArpProtect, "WG": c.EnableWG, "HA": c.HAEnabled, "BunkerWeb": c.BunkerWebEnabled, "SaaS": c.AllowSaaSMonitors, "SIEM": c.SiemEnabled, "Wazuh": c.EnableWazuh, "Abuse": c.EnableAbuse, "webhook": c.EnableWebhook} {
		if enabled {
			t.Errorf("fresh installation enabled %s", name)
		}
	}
	if c.SSHPort != "" || c.HoneyPorts != "" || c.ModsecLogs != "" || c.BruteforceLogs != "" {
		t.Fatal("fresh profile selected a host port or log discovery")
	}
	report, err := ValidateModularConfig(root)
	if err != nil || len(report.UnknownKeys) != 0 {
		t.Fatalf("profile validation: %+v %v", report, err)
	}
	if value, _, err := GetValidatedModularValue(root, "security.compliance.enable_watchdog"); err != nil || value != "false" {
		t.Fatalf("watchdog = %q, %v", value, err)
	}
}

func TestHistoricalConfigurationIsPreservedAndRetirable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	var models map[string]string
	if err := json.Unmarshal(historicalDefaultModelsV4104, &models); err != nil {
		t.Fatal(err)
	}
	for name, content := range models {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	fixtureRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fixtureRoot.Close()
	for name, content := range models {
		actual, err := fixtureRoot.ReadFile(name)
		if err != nil || string(actual) != content {
			t.Fatalf("upgrade changed %s: %v", name, err)
		}
	}
	variants, err := DefaultModularFileVariants("/etc/syswarden/config")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range models {
		found := false
		for _, candidate := range variants[name] {
			found = found || candidate == content
		}
		if !found {
			t.Fatalf("lost ownership reference for %s", name)
		}
	}
	if err := os.Remove(filepath.Join(root, "modules/10-network.toml")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefaults(root); err == nil {
		t.Fatal("partial historical policy silently replaced by fresh defaults")
	}
	if _, err := os.Stat(filepath.Join(root, "modules/10-network.toml")); !os.IsNotExist(err) {
		t.Fatal("refused repair wrote a network module")
	}
}

func TestModuleSelectionContractsMatchCore(t *testing.T) {
	cli, err := os.ReadFile("module_selection.go")
	if err != nil {
		t.Fatal(err)
	}
	core, err := os.ReadFile("../../syswarden-core/config/module_selection.go")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cli, core) {
		t.Fatal("CLI and runtime selection policy differ")
	}
}

func TestLogBridgeRefusalPreservesInstalledConfigurationAndLastValidSnapshot(t *testing.T) {
	old, state := GlobalConfig, CurrentLoadState()
	t.Cleanup(func() { GlobalConfig = old; loadStateMu.Lock(); loadState = state; loadStateMu.Unlock() })
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	if err := loadModularConfig(root); err != nil {
		t.Fatal(err)
	}
	before := GlobalConfig
	fixtureRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fixtureRoot.Close()
	override := filepath.Join(root, "modules", "99-user.toml")
	content := []byte("[waap]\nenabled=false\nlog_bridge_enabled=true\n")
	if err := os.WriteFile(override, content, 0600); err != nil {
		t.Fatal(err)
	}
	for _, validate := range []func() error{
		func() error { _, err := ValidateModularConfig(root); return err },
		func() error { _, _, err := GetValidatedModularValue(root, "waap.log_bridge_enabled"); return err },
		func() error { return loadModularConfig(root) },
	} {
		err := validate()
		if err == nil || !strings.Contains(err.Error(), "waap.log_bridge_enabled requires explicit waap.enabled=true") {
			t.Fatal("inconsistent configuration accepted", err)
		}
		if GlobalConfig != before {
			t.Fatal("invalid candidate replaced last valid snapshot")
		}
		got, err := fixtureRoot.ReadFile("modules/99-user.toml")
		if err != nil || string(got) != string(content) {
			t.Fatal("validation rewrote administrator choices", err)
		}
	}
	if err := os.WriteFile(override, []byte("[waap]\nenabled=true\nlog_bridge_enabled=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadModularConfig(root); err != nil {
		t.Fatal(err)
	}
	if !GlobalConfig.WAAPEnabled || !GlobalConfig.LogBridgeEnabled || GlobalConfig.EnableWG || GlobalConfig.EnableWazuh {
		t.Fatal("explicit pair did not remain scoped")
	}
}
