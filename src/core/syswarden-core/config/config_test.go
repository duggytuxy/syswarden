package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

func writeConfigFixture(t *testing.T, master string, modules map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil { // #nosec G302 -- private test directory requires owner execute permission
		t.Fatal(err)
	}
	if master != "" {
		if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(master), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if len(modules) != 0 {
		moduleRoot := filepath.Join(root, "modules")
		if err := os.Mkdir(moduleRoot, 0700); err != nil {
			t.Fatal(err)
		}
		for name, content := range modules {
			if err := os.WriteFile(filepath.Join(moduleRoot, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func validMaster(schema string) string {
	return schema + `
[core]
log_level = "INFO"
firewall_backend = "keep"

[network.blocklists]
list_choice = "4"

[waap]
enforcement_mode = "enforcing"
bruteforce_logs = "auto"
bruteforce_threshold = 5
bruteforce_window_seconds = 60
modsec_logs = ""

[integrations.ha]
enabled = false
peer_port = 62026
`
}

func TestLoadConfigDirectoryCurrentAndHistorical(t *testing.T) {
	t.Cleanup(viper.Reset)
	current := writeConfigFixture(t, validMaster("schema_version = 1"), nil)
	diagnostics, err := LoadConfigDirectory(current)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.SchemaVersion != 1 || diagnostics.Historical {
		t.Fatalf("unexpected current diagnostics: %+v", diagnostics)
	}
	if got := viper.GetString("core.config_dir"); got != filepath.Join(current, "modules") {
		t.Fatalf("runtime mapping mismatch: %q", got)
	}

	historical := writeConfigFixture(t, validMaster(""), nil)
	diagnostics, err = LoadConfigDirectory(historical)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.SchemaVersion != 0 || !diagnostics.Historical {
		t.Fatalf("unexpected historical diagnostics: %+v", diagnostics)
	}
}

func TestLoadConfigDirectoryDiagnosticsAndPriority(t *testing.T) {
	t.Cleanup(viper.Reset)
	root := writeConfigFixture(t, validMaster("schema_version = 1")+`
[integrations.saas]
enabled = true

[future]
feature = true
`, map[string]string{
		"10-core.toml": "[core]\nlog_level = \"DEBUG\"\n",
		"20-core.toml": "[core]\nlog_level = \"WARN\"\n",
	})
	diagnostics, err := LoadConfigDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := viper.GetString("core.log_level"); got != "WARN" {
		t.Fatalf("module priority mismatch: %q", got)
	}
	if got := viper.GetBool("network.saas.allow_monitors"); !got {
		t.Fatal("legacy SaaS setting was not mapped to the canonical runtime key")
	}
	if len(diagnostics.DeprecatedKeys) != 1 || !strings.Contains(diagnostics.DeprecatedKeys[0], "integrations.saas.enabled") {
		t.Fatalf("missing deprecated-key diagnostic: %+v", diagnostics)
	}
	if len(diagnostics.UnknownKeys) != 1 || diagnostics.UnknownKeys[0] != "future.feature" {
		t.Fatalf("missing unknown-key diagnostic: %+v", diagnostics)
	}
}

func boolValue(value bool) *bool {
	return &value
}

func setOptionalBooleanEnvironment(t *testing.T, key string, value *bool) {
	t.Helper()
	previous, existed := os.LookupEnv(key)
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(key, previous)
		} else {
			_ = os.Unsetenv(key)
		}
	})
	if value == nil {
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.Setenv(key, strconv.FormatBool(*value)); err != nil {
		t.Fatal(err)
	}
}

func TestCoreSaaSAliasPrecedenceMatchesCLI_SW_SAAS_001(t *testing.T) {
	tests := []struct {
		name         string
		officialFile *bool
		legacyFile   *bool
		officialEnv  *bool
		legacyEnv    *bool
		want         bool
	}{
		{name: "absent defaults false"},
		{name: "legacy file true", legacyFile: boolValue(true), want: true},
		{name: "legacy environment true", legacyEnv: boolValue(true), want: true},
		{name: "legacy environment overrides legacy file", legacyFile: boolValue(true), legacyEnv: boolValue(false)},
		{name: "official file false overrides legacy file", officialFile: boolValue(false), legacyFile: boolValue(true)},
		{name: "official environment false overrides legacy file", officialEnv: boolValue(false), legacyFile: boolValue(true)},
		{name: "official environment overrides official file", officialFile: boolValue(true), officialEnv: boolValue(false)},
		{name: "official true overrides legacy false", officialFile: boolValue(true), legacyEnv: boolValue(false), want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			setOptionalBooleanEnvironment(t, "SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS", test.officialEnv)
			setOptionalBooleanEnvironment(t, "SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", test.legacyEnv)
			var module strings.Builder
			if test.officialFile != nil {
				fmt.Fprintf(&module, "[network.saas]\nallow_monitors = %t\n", *test.officialFile)
			}
			if test.legacyFile != nil {
				fmt.Fprintf(&module, "[integrations.saas]\nenabled = %t\n", *test.legacyFile)
			}
			modules := map[string]string(nil)
			if module.Len() > 0 {
				modules = map[string]string{"99-saas.toml": module.String()}
			}
			root := writeConfigFixture(t, validMaster("schema_version = 1"), modules)
			if _, err := LoadConfigDirectory(root); err != nil {
				t.Fatalf("LoadConfigDirectory() error = %v", err)
			}
			if got := viper.GetBool("network.saas.allow_monitors"); got != test.want {
				t.Fatalf("network.saas.allow_monitors = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLoadConfigDirectoryRejectsInvalidCandidateWithoutPublishing(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Set("core.log_level", "SENTINEL")
	cases := map[string]string{
		"future schema":     strings.Replace(validMaster("schema_version = 1"), "schema_version = 1", "schema_version = 2", 1),
		"noninteger schema": strings.Replace(validMaster("schema_version = 1"), "schema_version = 1", "schema_version = \"1\"", 1),
		"invalid sink":      validMaster("schema_version = 1") + "\n[network]\ninterfaces = \"eth0;touch /tmp/x\"\n",
		"invalid choice":    strings.Replace(validMaster("schema_version = 1"), "list_choice = \"4\"", "list_choice = \"12\"", 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeConfigFixture(t, content, nil)
			if _, err := LoadConfigDirectory(root); err == nil {
				t.Fatal("expected validation failure")
			}
			if got := viper.GetString("core.log_level"); got != "SENTINEL" {
				t.Fatalf("invalid candidate was published: %q", got)
			}
		})
	}
}

func TestLoadConfigDirectoryRejectsSymlinkedConfiguration(t *testing.T) {
	t.Cleanup(viper.Reset)
	targetRoot := writeConfigFixture(t, validMaster("schema_version = 1"), nil)
	root := t.TempDir()
	if err := os.Symlink(filepath.Join(targetRoot, "config.toml"), filepath.Join(root, "config.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigDirectory(root); err == nil {
		t.Fatal("expected symlinked configuration to be rejected")
	}

	parent := t.TempDir()
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(targetRoot, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigDirectory(linked); err == nil {
		t.Fatal("expected symlinked configuration root to be rejected")
	}
}

func TestLoadConfigDirectoryRecognizesCompleteCLISchema(t *testing.T) {
	t.Cleanup(viper.Reset)
	root := writeConfigFixture(t, validMaster("schema_version = 1"), map[string]string{"10-complete.toml": `
[core]
enterprise_mode = false
hardening_enabled = true
cis_l2_hardening = false
secure_wipe_conf = true

[network]
whitelist_infra = true

[network.geo]
enabled = true
blocked_countries = ["RU"]

[network.asn]
enabled = false

[network.blocklists]
use_spamhaus = true

[security.l2]
enable_l2 = true
arp_protect = true
lan_mode = false

[security.compliance]
enable_watchdog = false
check_interval = "5m"

[integrations.abuseipdb]
enabled = false
api_key = ""

[integrations.wazuh]
enabled = false
name = "agent"
group = "default"
`})
	diagnostics, err := LoadConfigDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnostics.UnknownKeys) != 0 {
		t.Fatalf("CLI schema keys reported as unknown: %v", diagnostics.UnknownKeys)
	}
}

func TestCoreValidatorMatchesCLIParityContract_SW_CFG_002(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		module  string
		wantErr bool
	}{
		{name: "baseline"},
		{name: "custom choice with URL", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"https://example.invalid/list\"\n"},
		{name: "custom choice without URL", module: "[network.blocklists]\nlist_choice = \"3\"\ncustom_url = \"\"\ncustom_url_ipv6 = \"\"\n", wantErr: true},
		{name: "hash with matching URL", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\n"},
		{name: "hash without matching URL", module: "[network.blocklists]\ncustom_url = \"\"\ncustom_hash = \"sha256:" + digest + "\"\n", wantErr: true},
		{name: "complete Wazuh", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"1514\"\nenroll_port = \"1515\"\n"},
		{name: "Wazuh missing communication port", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"\"\nenroll_port = \"1515\"\n", wantErr: true},
		{name: "Wazuh missing enrollment port", module: "[integrations.wazuh]\nenabled = true\nip = \"192.0.2.20\"\ncomm_port = \"1514\"\nenroll_port = \"\"\n", wantErr: true},
		{name: "valid compliance duration", module: "[security.compliance]\ncheck_interval = \"5m\"\n"},
		{name: "invalid compliance duration", module: "[security.compliance]\ncheck_interval = \"forever\"\n", wantErr: true},
		{name: "lowercase SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:" + digest + "\"\n"},
		{name: "empty SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"sha256:\"\n", wantErr: true},
		{name: "uppercase SHA prefix", module: "[network.blocklists]\ncustom_url = \"https://example.invalid/list\"\ncustom_hash = \"SHA256:" + digest + "\"\n", wantErr: true},
		{name: "canonical HA peer", module: "[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n"},
		{name: "whitespace padded HA peer", module: "[integrations.ha]\nenabled = true\npeer_ips = [\" 192.0.2.10 \"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
		{name: "canonical log pattern list", module: "[waap]\nbruteforce_logs = \"/var/log/nginx/*.log /var/log/auth.log\"\nmodsec_logs = \"/var/log/modsec/*.log\"\n"},
		{name: "noncanonical log pattern spacing", module: "[waap]\nbruteforce_logs = \"/var/log/nginx/*.log  /var/log/auth.log\"\n", wantErr: true},
		{name: "duplicate log pattern", module: "[waap]\nbruteforce_logs = \"/var/log/auth.log /var/log/auth.log\"\n", wantErr: true},
		{name: "invalid log glob", module: "[waap]\nmodsec_logs = \"/var/log/modsec/[.log\"\n", wantErr: true},
		{name: "canonical IPv4 WireGuard subnet", module: "[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n"},
		{name: "IPv6 WireGuard subnet", module: "[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"2001:db8::/64\"\n", wantErr: true},
		{name: "distinct SSH and HA ports with WireGuard", module: "[core]\nssh_port = \"2222\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n"},
		{name: "HA port collides with SSH while WireGuard enabled", module: "[core]\nssh_port = \"62026\"\n[network.wireguard]\nenabled = true\nport = \"51820\"\nsubnet = \"10.66.66.0/24\"\n[integrations.ha]\nenabled = true\npeer_ips = [\"192.0.2.10\"]\npeer_port = 62026\ntoken = \"shared-token\"\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := writeConfigFixture(t, validMaster("schema_version = 1"), map[string]string{"99-user.toml": test.module})
			_, err := LoadConfigDirectory(root)
			if (err != nil) != test.wantErr {
				t.Fatalf("LoadConfigDirectory() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
