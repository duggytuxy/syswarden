package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateAndGetPreserveSaaSAliasSourceAndEnvironmentPrecedence(t *testing.T) {
	for _, scenario := range []struct {
		name, master, early, late string
		officialEnv, legacyEnv    *bool
		wantValidation, wantGet   bool
	}{
		{name: "absent"},
		{name: "legacy-file", early: "[integrations.saas]\nenabled=true\n", wantValidation: true, wantGet: true},
		{name: "official-false-over-legacy-true", early: "[network.saas]\nallow_monitors=false\n", late: "[integrations.saas]\nenabled=true\n"},
		{name: "official-lexical-last-false", master: "[network.saas]\nallow_monitors=true\n", early: "[integrations.saas]\nenabled=true\n", late: "[network.saas]\nallow_monitors=false\n"},
		{name: "official-lexical-last-true", early: "[network.saas]\nallow_monitors=false\n", late: "[network.saas]\nallow_monitors=true\n[integrations.saas]\nenabled=false\n", wantValidation: true, wantGet: true},
		{name: "legacy-lexical-last-false", master: "[integrations.saas]\nenabled=true\n", late: "[integrations.saas]\nenabled=false\n"},
		{name: "legacy-lexical-last-true", early: "[integrations.saas]\nenabled=false\n", late: "[integrations.saas]\nenabled=true\n", wantValidation: true, wantGet: true},
		{name: "legacy-environment-overrides-alias", early: "[integrations.saas]\nenabled=true\n", legacyEnv: boolValue(false), wantValidation: true},
		{name: "official-environment-overrides-alias", early: "[integrations.saas]\nenabled=true\n", officialEnv: boolValue(false), wantValidation: true},
		{name: "official-environment-overrides-official-false", early: "[network.saas]\nallow_monitors=false\n[integrations.saas]\nenabled=true\n", officialEnv: boolValue(true), wantGet: true},
		{name: "official-environment-only", officialEnv: boolValue(true), wantGet: true},
		{name: "legacy-environment-only", legacyEnv: boolValue(true), wantGet: true},
		{name: "official-file-over-legacy-environment", early: "[network.saas]\nallow_monitors=false\n", legacyEnv: boolValue(true)},
		{name: "official-environment-over-legacy-environment", officialEnv: boolValue(false), legacyEnv: boolValue(true)},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			preserveOperatorPolicyGlobals(t)
			setOptionalBooleanEnvironment(t, "SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS", scenario.officialEnv)
			setOptionalBooleanEnvironment(t, "SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", scenario.legacyEnv)
			root := t.TempDir()
			if err := writeModuleFixture(filepath.Join(root, "config.toml"), []byte(minimalModularConfig+"\n"+scenario.master), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "modules"), 0750); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{"10-alias.toml": scenario.early, "99-alias.toml": scenario.late} {
				if content == "" {
					continue
				}
				if err := writeModuleFixture(filepath.Join(root, "modules", name), []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _, err := captureModuleInputs(root, userTOMLTarget(), nil)
			if err != nil {
				t.Fatal(err)
			}
			files := intentFixtureFiles(t, root)
			global, load := GlobalConfig, CurrentLoadState()
			report, err := ValidateModularConfig(root)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(report.ModulePlan, "\n"), fmt.Sprintf("SaaS allowlists selected: %t", scenario.wantValidation)) {
				t.Fatalf("validation did not use TOML-only alias precedence: %v", report.ModulePlan)
			}
			value, present, err := GetValidatedModularValue(root, "network.saas.allow_monitors")
			if err != nil || !present || value != fmt.Sprint(scenario.wantGet) {
				t.Fatalf("config-get effective SaaS selection = %q, %t, %v", value, present, err)
			}
			if err := before.revalidate(root, false, nil); err != nil {
				t.Fatal("configuration readers changed source metadata", err)
			}
			if !reflect.DeepEqual(files, intentFixtureFiles(t, root)) || global != GlobalConfig || !reflect.DeepEqual(load, CurrentLoadState()) {
				t.Fatal("configuration readers changed bytes or global state")
			}
			if err := ParseConfigForInspection(root); err != nil {
				t.Fatal(err)
			}
			if GlobalConfig.AllowSaaSMonitors != scenario.wantGet {
				t.Fatal("config-get differs from runtime alias semantics")
			}
		})
	}
}

func TestValidateModularConfigIsNonMutatingAndReportsSchema_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	master := filepath.Join(root, "config.toml")
	before, err := os.ReadFile(master) // #nosec G304 -- master is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	beforeTree := directoryDigest(t, root)
	report, err := ValidateModularConfig(root)
	if err != nil {
		t.Fatalf("ValidateModularConfig() error = %v", err)
	}
	if report.SchemaVersion != CurrentSchemaVersion || report.Historical {
		t.Fatalf("report = %#v, want current schema", report)
	}
	if len(report.UnknownKeys) != 0 || len(report.DeprecatedKeys) != 0 {
		t.Fatalf("default configuration diagnostics = %#v", report)
	}
	after, err := os.ReadFile(master) // #nosec G304 -- master is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("validation modified the master configuration")
	}
	if afterTree := directoryDigest(t, root); !reflect.DeepEqual(afterTree, beforeTree) {
		t.Fatalf("validation modified the configuration inventory: before=%v after=%v", beforeTree, afterTree)
	}
}

func TestValidateModularConfigTreatsMissingSchemaAsHistoricalWithoutRewrite_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	master := filepath.Join(root, "config.toml")
	content, err := os.ReadFile(master) // #nosec G304 -- master is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	historical := []byte(strings.Replace(string(content), "schema_version = 1\n", "", 1))
	if err := os.WriteFile(master, historical, 0600); err != nil { // #nosec G703 -- path is rooted in t.TempDir with a fixed configuration filename
		t.Fatal(err)
	}
	report, err := ValidateModularConfig(root)
	if err != nil {
		t.Fatalf("ValidateModularConfig() error = %v", err)
	}
	if !report.Historical || report.SchemaVersion != 0 {
		t.Fatalf("report = %#v, want historical schema", report)
	}
	after, err := os.ReadFile(master) // #nosec G304 -- master is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, historical) {
		t.Fatal("historical validation rewrote the master configuration")
	}
}

func TestValidateModularConfigReportsUnknownAndDeprecatedKeys_SW_CFG_002(t *testing.T) {
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(root, "modules", userModuleName)
	content := []byte("[user]\nprofile_name = \"production\"\nwebtui_password = \"retired\"\n\n[future]\nenabled = true\n")
	if err := os.WriteFile(user, content, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := ValidateModularConfig(root)
	if err != nil {
		t.Fatalf("ValidateModularConfig() error = %v", err)
	}
	if !reflect.DeepEqual(report.UnknownKeys, []string{"future.enabled"}) {
		t.Fatalf("unknown keys = %#v", report.UnknownKeys)
	}
	if len(report.DeprecatedKeys) != 1 || !strings.HasPrefix(report.DeprecatedKeys[0], "user.webtui_password ") {
		t.Fatalf("deprecated keys = %#v", report.DeprecatedKeys)
	}
}

func TestSchemaVersionRequiresAnIntegerAndRejectsFutureVersions_SW_CFG_002(t *testing.T) {
	for _, value := range []string{`"1"`, "2", "-1"} {
		t.Run(value, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			master := filepath.Join(root, "config.toml")
			content, err := os.ReadFile(master) // #nosec G304 -- master is rooted in t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			content = []byte(strings.Replace(string(content), "schema_version = 1", "schema_version = "+value, 1))
			if err := os.WriteFile(master, content, 0600); err != nil { // #nosec G703 -- path is rooted in t.TempDir with a fixed configuration filename
				t.Fatal(err)
			}
			if _, err := ValidateModularConfig(root); err == nil {
				t.Fatal("invalid schema version was accepted by config validation")
			}
			if err := loadModularConfig(root); err == nil {
				t.Fatal("invalid schema version was accepted by the runtime loader")
			}
		})
	}
}

func TestCLIValidationAndRuntimeLoaderParityMatrix_SW_CFG_002(t *testing.T) {
	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	tests := []struct {
		name    string
		mutate  func(*testing.T, string)
		wantErr bool
	}{
		{name: "current defaults"},
		{name: "highest priority override", mutate: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "modules", userModuleName), []byte("[core]\nlog_level = \"DEBUG\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "historical schema", mutate: func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, "config.toml")
			content, err := os.ReadFile(path) // #nosec G304 -- path is rooted in t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(content), "schema_version = 1\n", "", 1)), 0600); err != nil { // #nosec G703 -- path is rooted in t.TempDir with a fixed configuration filename
				t.Fatal(err)
			}
		}},
		{name: "interface injection", wantErr: true, mutate: func(t *testing.T, root string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(root, "modules", userModuleName), []byte("[network]\ninterfaces = \"eth0; flush ruleset\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "future schema", wantErr: true, mutate: func(t *testing.T, root string) {
			t.Helper()
			path := filepath.Join(root, "config.toml")
			content, err := os.ReadFile(path) // #nosec G304 -- path is rooted in t.TempDir
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(content), "schema_version = 1", "schema_version = 2", 1)), 0600); err != nil { // #nosec G703 -- path is rooted in t.TempDir with a fixed configuration filename
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			if test.mutate != nil {
				test.mutate(t, root)
			}
			_, validateErr := ValidateModularConfig(root)
			loadErr := loadModularConfig(root)
			_, _, getErr := GetValidatedModularValue(root, "core.firewall_backend")
			if (validateErr != nil) != test.wantErr || (loadErr != nil) != test.wantErr || (getErr != nil) != test.wantErr {
				t.Fatalf("parity errors: validate=%v load=%v get=%v wantErr=%t", validateErr, loadErr, getErr, test.wantErr)
			}
		})
	}
}

func TestCLIValidatorMatchesCoreParityContract_SW_CFG_002(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		module  string
		wantErr bool
	}{
		{name: "baseline"},
		{name: "custom choice with pinned URL", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\n"},
		{name: "custom choice with unpinned URL", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"https://example.invalid/list\"\n", wantErr: true},
		{name: "custom choice with partially pinned URLs", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\ncustom_url_ipv6 = \"https://example.invalid/list6\"\n", wantErr: true},
		{name: "non-custom choice with unpinned URL", module: "[network.blocklists]\nlist_choice = \"4\"\ncustom_url = \"https://example.invalid/list\"\n", wantErr: true},
		{name: "custom choice without URL", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"\"\ncustom_url_ipv6 = \"\"\n", wantErr: true},
		{name: "hash with matching URL", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\n"},
		{name: "IPv6 hash with matching URL", module: "[network.blocklists]\ncustom_url_ipv6 = \"https://example.invalid/list6\"\ncustom_hash_ipv6 = \"sha256:" + digest + "\"\n"},
		{name: "IPv6 URL without hash", module: "[network.blocklists]\ncustom_url_ipv6 = \"https://example.invalid/list6\"\n", wantErr: true},
		{name: "hash without matching URL", module: "[network.blocklists]\ncustom_url = \"\"\ncustom_hash = \"sha256:" + digest + "\"\n", wantErr: true},
		{name: "IPv6 hash without matching URL", module: "[network.blocklists]\ncustom_url_ipv6 = \"\"\ncustom_hash_ipv6 = \"sha256:" + digest + "\"\n", wantErr: true},
		{name: "complete Wazuh", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"1514\"\nenroll_port = \"1515\"\n"},
		{name: "Wazuh missing communication port", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"\"\nenroll_port = \"1515\"\n", wantErr: true},
		{name: "Wazuh missing enrollment port", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"1514\"\nenroll_port = \"\"\n", wantErr: true},
		{name: "valid compliance duration", module: "[security.compliance]\ncheck_interval = \"5m\"\n"},
		{name: "invalid compliance duration", module: "[security.compliance]\ncheck_interval = \"forever\"\n", wantErr: true},
		{name: "lowercase SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\n"},
		{name: "empty SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:\"\n", wantErr: true},
		{name: "uppercase SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"SHA256:" + digest + "\"\n", wantErr: true},
		{name: "canonical HA peer", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n"},
		{name: "bounded private HA networks", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"10.20.30.0/24\", \"fd00:20:30::/64\"]\npeer_port = 62026\ntoken = \"shared-token\"\n"},
		{name: "broad IPv4 HA network", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"10.20.30.0/23\"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
		{name: "broad IPv6 HA network", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"fd00:20:30::/63\"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
		{name: "HA IPv4 default route", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"0.0.0.0/0\"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
		{name: "whitespace padded HA peer", module: "[integrations.ha]\nenabled = true\npeer_ips = [\" 192.0.2.10 \"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
		{name: "explicit producer", module: "[waap]\ntrusted_log_producers = \"/var/log/waf/audit.log=999\"\n"},
		{name: "unmapped producer", module: "[waap]\ntrusted_log_producers = \"/var/log/waf/audit.log=65534\"\n", wantErr: true},
		{name: "producer glob", module: "[waap]\ntrusted_log_producers = \"/var/log/waf/*.log=999\"\n", wantErr: true},
		{name: "canonical log pattern list", module: "[waap]\nbruteforce_logs = \"/var/log/nginx/*.log /var/log/auth.log\"\nmodsec_logs = \"/var/log/modsec/*.log\"\n"},
		{name: "noncanonical log pattern spacing", module: "[waap]\nbruteforce_logs = \"/var/log/nginx/*.log  /var/log/auth.log\"\n", wantErr: true},
		{name: "duplicate log pattern", module: "[waap]\nbruteforce_logs = \"/var/log/auth.log /var/log/auth.log\"\n", wantErr: true},
		{name: "invalid log glob", module: "[waap]\nmodsec_logs = \"/var/log/modsec/[.log\"\n", wantErr: true},
		{name: "canonical IPv4 WireGuard subnet", module: "[core]\nfirewall_backend = \"nftables\"\n[network]\npolicy_mode = \"host\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n"},
		{name: "WireGuard with keep backend", module: "[network]\npolicy_mode = \"host\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n", wantErr: true},
		{name: "IPv6 WireGuard subnet", module: "[core]\nfirewall_backend = \"nftables\"\n[network]\npolicy_mode = \"host\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"2001:db8::/64\"\n", wantErr: true},
		{name: "distinct SSH and HA ports with WireGuard", module: "[core]\nfirewall_backend = \"nftables\"\nssh_port = \"2222\"\n[network]\npolicy_mode = \"host\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n"},
		{name: "HA port collides with SSH while WireGuard enabled", module: "[core]\nfirewall_backend = \"nftables\"\nssh_port = \"62026\"\n[network]\npolicy_mode = \"host\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
	}
	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			if test.module != "" {
				if err := os.WriteFile(filepath.Join(root, "modules", userModuleName), []byte(test.module), 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, validateErr := ValidateModularConfig(root)
			loadErr := loadModularConfig(root)
			_, _, getErr := GetValidatedModularValue(root, "core.firewall_backend")
			if (validateErr != nil) != test.wantErr || (loadErr != nil) != test.wantErr || (getErr != nil) != test.wantErr {
				t.Fatalf("contract mismatch: validate=%v load=%v get=%v wantErr=%t", validateErr, loadErr, getErr, test.wantErr)
			}
		})
	}
}
