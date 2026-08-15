package config

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

const (
	v4028Commit                  = "371d353e871fedb410b08f0618a1ae6aa2f7fedc"
	v4028DefaultSourceSHA256     = "fc41d5c0ee637dab10616a02b319d7818876e9af509565580477164e864e23c6"
	v4028MigratorSourceSHA256    = "062c24cabfda9f022adbad17adf10b6805283a258e901314ee72f015d529e653"
	v4028LegacyFixtureSHA256     = "8c6d16efe22ef75e616507a6c10d4e6adf7b090c8891acd62f4928adac01acc0"
	v4028ModularFixtureSHA256    = "42222efc3af457255ee63e37e7c53600a57ad26b2b820492a0ee754f5831eeee"
	v4028DefaultSourceObject     = v4028Commit + ":src/core/syswarden-cli/config/default.go"
	v4028MigratorSourceObject    = v4028Commit + ":src/core/syswarden-cli/config/migrator.go"
	v4028IntegrationsSourceStart = "func (m *Migrator) generateIntegrations"
)

func readImmutableFixture(t *testing.T, name, expectedDigest string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("testdata", "v4.02.8", name)) // #nosec G304 -- fixed repository fixture path
	if err != nil {
		t.Fatal(err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(content)); digest != expectedDigest {
		t.Fatalf("immutable v4.02.8 fixture %s digest = %s, want %s", name, digest, expectedDigest)
	}
	return content
}

func TestV4028CompatibilityFixturesHavePinnedRepositoryProvenance_SW_CFG_001(t *testing.T) {
	resolved, err := exec.Command("git", "rev-parse", "v4.02.8^{}").Output()
	if err != nil {
		t.Fatalf("resolve immutable v4.02.8 tag: %v", err)
	}
	if got := strings.TrimSpace(string(resolved)); got != v4028Commit {
		t.Fatalf("v4.02.8 resolves to %s, want pinned commit %s", got, v4028Commit)
	}

	defaultSource, err := exec.Command("git", "show", v4028DefaultSourceObject).Output()
	if err != nil {
		t.Fatalf("read pinned v4.02.8 default source: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(defaultSource)); got != v4028DefaultSourceSHA256 {
		t.Fatalf("v4.02.8 default source digest = %s, want %s", got, v4028DefaultSourceSHA256)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), "v4.02.8/default.go", defaultSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	var publishedDefault string
	ast.Inspect(parsed, func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "DefaultConfig" || len(declaration.Values) != 1 {
			return true
		}
		literal, ok := declaration.Values[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return false
		}
		publishedDefault, err = strconv.Unquote(literal.Value)
		return false
	})
	if err != nil || publishedDefault == "" {
		t.Fatalf("extract pinned DefaultConfig: %v", err)
	}
	legacyFixture := readImmutableFixture(t, "legacy-ha-default.conf", v4028LegacyFixtureSHA256)
	if !bytes.Equal(legacyFixture, []byte(publishedDefault)) {
		t.Fatal("legacy compatibility fixture is not byte-for-byte DefaultConfig from the pinned v4.02.8 commit")
	}

	migratorSource, err := exec.Command("git", "show", v4028MigratorSourceObject).Output()
	if err != nil {
		t.Fatalf("read pinned v4.02.8 migrator source: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(migratorSource)); got != v4028MigratorSourceSHA256 {
		t.Fatalf("v4.02.8 migrator source digest = %s, want %s", got, v4028MigratorSourceSHA256)
	}
	if !bytes.Contains(migratorSource, []byte(v4028IntegrationsSourceStart)) {
		t.Fatal("pinned migrator source does not contain the historical integration generator")
	}
	legacyValues, err := (&Migrator{}).ParseFromMemory(publishedDefault)
	if err != nil {
		t.Fatal(err)
	}
	modularFixture := readImmutableFixture(t, "40-integrations.toml", v4028ModularFixtureSHA256)
	if got := renderV4028IntegrationsFixture(legacyValues); !bytes.Equal(modularFixture, got) {
		t.Fatalf("modular compatibility fixture is not the byte-for-byte output of the pinned v4.02.8 integration generator:\ngot=%q\nwant=%q", modularFixture, got)
	}
}

// renderV4028IntegrationsFixture mirrors generateIntegrations in the pinned,
// digest-checked v4.02.8 migrator source above. It deliberately remains local
// to the provenance test so current generator changes cannot rewrite history.
func renderV4028IntegrationsFixture(oldConfig map[string]string) []byte {
	getBool := func(key, defaultValue string) string {
		value, ok := oldConfig[key]
		if !ok || value == "" {
			return defaultValue
		}
		if value == "y" || value == "yes" || value == "true" || value == "1" {
			return "true"
		}
		return "false"
	}
	get := func(key, defaultValue string) string {
		if value, ok := oldConfig[key]; ok && value != "" {
			return value
		}
		return defaultValue
	}
	parseSlice := func(value string) string {
		if value == "" || value == "false" || value == "none" || value == "0" {
			return ""
		}
		value = strings.ReplaceAll(value, ",", " ")
		var valid []string
		for _, item := range strings.Fields(value) {
			item = strings.TrimSpace(item)
			if item != "" && item != "false" && item != "none" {
				valid = append(valid, `"`+item+`"`)
			}
		}
		return strings.Join(valid, ", ")
	}
	peerIPs := parseSlice(get("SYSWARDEN_HA_PEER_IP", ""))
	return []byte(`# [40] INTEGRATIONS & NOTIFICATIONS
# Priority: 40

[integrations.ha]
enabled = ` + getBool("SYSWARDEN_HA_ENABLED", "false") + `
# Format requires quotes: ["10.0.0.1", "10.0.0.2"]
peer_ips = [` + peerIPs + `]
peer_port = ` + get("SYSWARDEN_HA_PEER_PORT", "62026") + `

# HA Shared Secret Token for API Authentication (Must be identical on all nodes)
# Generate a secure token using: openssl rand -hex 32
token = "` + get("SYSWARDEN_HA_TOKEN", "") + `"

[integrations.siem]
enabled = ` + getBool("SYSWARDEN_SIEM_ENABLED", "false") + `
ip = "` + get("SYSWARDEN_SIEM_IP", "") + `"
port = "` + get("SYSWARDEN_SIEM_PORT", "6514") + `"
protocol = "` + get("SYSWARDEN_SIEM_PROTO", "tls") + `"
tls_ca = "` + get("SYSWARDEN_SIEM_TLS_CA", "/etc/ssl/certs/ca-certificates.crt") + `"

[integrations.abuseipdb]
enabled = ` + getBool("SYSWARDEN_ENABLE_ABUSE", "false") + `
api_key = "` + get("SYSWARDEN_ABUSE_API_KEY", "") + `"

[integrations.webhooks]
enabled = ` + getBool("SYSWARDEN_ENABLE_WEBHOOK", "false") + `
discord_url = "` + get("SYSWARDEN_WEBHOOK_URL_DISCORD", "") + `"
teams_url = "` + get("SYSWARDEN_WEBHOOK_URL_TEAMS", "") + `"
slack_url = "` + get("SYSWARDEN_WEBHOOK_URL_SLACK", "") + `"
`)
}

func TestV4028LegacyHADefaultNormalizesWithoutWeakeningPartialStates_SW_CFG_001(t *testing.T) {
	fixture := readImmutableFixture(t, "legacy-ha-default.conf", v4028LegacyFixtureSHA256)
	root := t.TempDir()
	legacy := filepath.Join(root, "syswarden-auto.conf")
	if err := os.WriteFile(legacy, fixture, 0600); err != nil {
		t.Fatal(err)
	}

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadOldConfig(legacy); err != nil {
		t.Fatalf("loadOldConfig(v4.02.8 default) error = %v", err)
	}
	if GlobalConfig.HAEnabled || GlobalConfig.BunkerWebEnabled {
		t.Fatalf("historical default normalized to HA=%t BunkerWeb=%t", GlobalConfig.HAEnabled, GlobalConfig.BunkerWebEnabled)
	}
	wantLegacy := strings.Replace(string(fixture), `SYSWARDEN_HA_ENABLED="y"`, `SYSWARDEN_HA_ENABLED="n"`, 1) +
		`SYSWARDEN_BUNKERWEB_ENABLED="n"` + "\n"
	assertFileContent(t, legacy, wantLegacy)
	if err := loadOldConfig(legacy); err != nil {
		t.Fatalf("loadOldConfig(normalized v4.02.8 default) error = %v", err)
	}
	assertFileContent(t, legacy, wantLegacy)

	migrationSource := filepath.Join(root, "migration.conf")
	if err := os.WriteFile(migrationSource, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "config")
	if err := (&Migrator{SourcePath: migrationSource, OutputDir: output}).Run(); err != nil {
		t.Fatalf("Migrator.Run(v4.02.8 default) error = %v", err)
	}
	if err := loadModularConfig(output); err != nil {
		t.Fatalf("loadModularConfig(migrated default) error = %v", err)
	}
	if GlobalConfig.HAEnabled || GlobalConfig.BunkerWebEnabled {
		t.Fatal("persistent migration re-enabled the historical insecure HA default")
	}
	integrations, err := os.ReadFile(filepath.Join(output, "modules", "40-integrations.toml")) // #nosec G304 -- output is a t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(integrations), "[integrations.ha]\nenabled = false") ||
		!strings.Contains(string(integrations), "[integrations.bunkerweb]\n") {
		t.Fatalf("normalized migration output omitted explicit safe gates:\n%s", integrations)
	}
}

func TestHistoricalModularHANormalizationRefusesEnvironmentOverrides_SW_CFG_001(t *testing.T) {
	fixture := readImmutableFixture(t, "40-integrations.toml", v4028ModularFixtureSHA256)
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	integrationPath := filepath.Join(root, "modules", "40-integrations.toml")
	if err := os.WriteFile(integrationPath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYSWARDEN_INTEGRATIONS_HA_ENABLED", "true")
	previous := GlobalConfig
	GlobalConfig = &Config{SSHPort: "2222", FirewallBackend: "keep"}
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadModularConfig(root); err == nil {
		t.Fatal("historical normalization persisted over an explicit environment override")
	}
	assertFileContent(t, integrationPath, string(fixture))
}

func TestV4028ModularHADefaultNormalizesAtomicallyAndPreservesOtherBytes_SW_CFG_001(t *testing.T) {
	fixture := readImmutableFixture(t, "40-integrations.toml", v4028ModularFixtureSHA256)
	root := filepath.Join(t.TempDir(), "config")
	if err := InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	integrationPath := filepath.Join(root, "modules", "40-integrations.toml")
	if err := os.WriteFile(integrationPath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(root, "modules", "99-user.toml")
	const userContent = "# operator bytes must survive\n[user]\nwebtui_password = \"operator-token\"\n"
	if err := os.WriteFile(userPath, []byte(userContent), 0600); err != nil {
		t.Fatal(err)
	}
	before := directoryDigest(t, root)

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadModularConfig(root); err != nil {
		t.Fatalf("loadModularConfig(v4.02.8 default) error = %v", err)
	}
	if GlobalConfig.HAEnabled || GlobalConfig.BunkerWebEnabled {
		t.Fatalf("normalized modular state = HA %t, BunkerWeb %t", GlobalConfig.HAEnabled, GlobalConfig.BunkerWebEnabled)
	}
	after := directoryDigest(t, root)
	for path, digest := range before {
		if path == "modules/40-integrations.toml" {
			continue
		}
		if after[path] != digest {
			t.Errorf("historical normalization changed unrelated file %s", path)
		}
	}
	assertFileContent(t, userPath, userContent)
	normalized, err := os.ReadFile(integrationPath) // #nosec G304 -- integrationPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(fixture), "enabled = true", "enabled = false", 1) +
		"\n[integrations.bunkerweb]\nenabled = false\n"
	if string(normalized) != want {
		t.Fatalf("normalized integration bytes differ:\ngot=%q\nwant=%q", normalized, want)
	}
	firstDigest := directoryDigest(t, root)
	if err := loadModularConfig(root); err != nil {
		t.Fatalf("second normalized load error = %v", err)
	}
	if secondDigest := directoryDigest(t, root); !reflect.DeepEqual(firstDigest, secondDigest) {
		t.Fatal("historical normalization was not byte-idempotent")
	}
}

func TestValidAndPartialModularHAStatesAreNotNormalized_SW_CFG_001(t *testing.T) {
	original := GlobalConfig
	t.Cleanup(func() { GlobalConfig = original })
	fixture := string(readImmutableFixture(t, "40-integrations.toml", v4028ModularFixtureSHA256))
	tests := []struct {
		name      string
		content   string
		wantError bool
	}{
		{
			name: "valid authenticated HA",
			content: strings.Replace(
				strings.Replace(fixture, "peer_ips = []", `peer_ips = ["10.20.30.0/29"]`, 1),
				`token = ""`, `token = "shared-token"`, 1,
			),
		},
		{
			name:      "token without peer",
			content:   strings.Replace(fixture, `token = ""`, `token = "shared-token"`, 1),
			wantError: true,
		},
		{
			name:      "peer without token",
			content:   strings.Replace(fixture, "peer_ips = []", `peer_ips = ["192.0.2.20"]`, 1),
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := InitializeDefaults(root); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "modules", "40-integrations.toml")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			previous := &Config{SSHPort: "2222", FirewallBackend: "keep"}
			GlobalConfig = previous
			err := loadModularConfig(root)
			if test.wantError {
				if err == nil {
					t.Fatal("partial HA state was accepted")
				}
				if GlobalConfig != previous {
					t.Fatal("partial HA state replaced the previous GlobalConfig")
				}
				assertFileContent(t, path, test.content)
				return
			}
			if err != nil {
				t.Fatalf("valid HA state rejected: %v", err)
			}
			if !GlobalConfig.HAEnabled {
				t.Fatal("valid authenticated HA was normalized to disabled")
			}
			assertFileContent(t, path, test.content)
		})
	}
}
