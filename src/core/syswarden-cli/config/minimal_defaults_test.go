package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFreshNativeProfileIsUnconfigured(t *testing.T) {
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
	if c.InstallProfile != UnconfiguredInstallProfile || c.ListChoice != "4" || c.FirewallBackend != "keep" {
		t.Fatalf("wrong unconfigured profile: %s/%s/%s", c.InstallProfile, c.ListChoice, c.FirewallBackend)
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

func TestExistingStandardProfileAndExplicitChoicesSurviveFreshDefaultChange(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := os.MkdirAll(filepath.Join(root, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	models, err := defaultModularFileModels(root, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range models {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := directoryDigest(t, root)
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
		t.Fatal("fresh default change rewrote existing standard profile")
	}
	if err := loadModularConfig(root); err != nil {
		t.Fatal(err)
	}
	if GlobalConfig.InstallProfile != StandardInstallProfile || GlobalConfig.ListChoice != "1" {
		t.Fatal("existing standard choice changed")
	}
	variants, err := DefaultModularFileVariants(root)
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range models {
		found := false
		for _, candidate := range variants[name] {
			found = found || candidate == content
		}
		if !found {
			t.Fatal("lost prior standard template ownership", name)
		}
	}
	override := []byte("[network.blocklists]\nlist_choice='2'\n[waap]\nenabled=true\n")
	if err := os.WriteFile(filepath.Join(root, "modules/99-user.toml"), override, 0600); err != nil {
		t.Fatal(err)
	}
	before = directoryDigest(t, root)
	if err := PrepareInstallationConfiguration(root); err != nil {
		t.Fatal(err)
	}
	if GlobalConfig.ListChoice != "2" || !GlobalConfig.WAAPEnabled || GlobalConfig.EnableWG {
		t.Fatal("existing explicit choices changed")
	}
	if got := directoryDigest(t, root); !reflect.DeepEqual(got, before) {
		t.Fatal("upgrade changed administrator bytes")
	}
}

func TestUnconfiguredProfileAcceptsOnlyExplicitScopedTOMLSelections(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := EnsureDefaults(root); err != nil {
		t.Fatal(err)
	}
	override := []byte("[network.blocklists]\nlist_choice='1'\n[waap]\nenabled=true\n")
	if err := os.WriteFile(filepath.Join(root, "modules/99-user.toml"), override, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadModularConfig(root); err != nil {
		t.Fatal(err)
	}
	if GlobalConfig.InstallProfile != UnconfiguredInstallProfile || GlobalConfig.ListChoice != "1" || !GlobalConfig.WAAPEnabled || GlobalConfig.EnableWG || GlobalConfig.EnableWazuh || GlobalConfig.Hardening {
		t.Fatal("explicit selection enabled unrelated modules")
	}
	t.Setenv("SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE", "2")
	if err := loadModularConfig(root); err == nil {
		t.Fatal("environment selected a list for an unconfigured profile")
	}
}
