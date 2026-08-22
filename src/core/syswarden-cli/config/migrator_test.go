package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

const migrationFixture = `
SYSWARDEN_ENTERPRISE_MODE="n"
SYSWARDEN_ENFORCEMENT_MODE="audit"
SYSWARDEN_FIREWALL_BACKEND="nftables"
SYSWARDEN_SSH_PORT="2222"
SYSWARDEN_INTERFACES="eth0,eth1"
SYSWARDEN_WHITELIST_INFRA="y"
SYSWARDEN_WHITELIST_IPS="192.0.2.10 2001:db8::10"
SYSWARDEN_LAN_SUBNETS="10.0.0.0/8 192.168.0.0/16"
SYSWARDEN_ALLOW_SAAS_MONITORS="y"
SYSWARDEN_ENABLE_GEO="y"
SYSWARDEN_GEO_CODES="ru cn"
SYSWARDEN_GEO_ALLOWED="be fr"
SYSWARDEN_ENABLE_ASN="y"
SYSWARDEN_ASN_LIST="AS64500 AS64501"
SYSWARDEN_ASN_ALLOWED="AS64496"
SYSWARDEN_LIST_CHOICE="3"
SYSWARDEN_USE_SPAMHAUS="y"
SYSWARDEN_CUSTOM_URL="https://example.invalid/ipv4.txt"
SYSWARDEN_CUSTOM_HASH="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SYSWARDEN_CUSTOM_URL_IPV6="https://example.invalid/ipv6.txt"
SYSWARDEN_CUSTOM_HASH_IPV6="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
SYSWARDEN_ENABLE_WG="y"
SYSWARDEN_WG_PORT="51820"
SYSWARDEN_WG_SUBNET="10.66.66.0/24"
SYSWARDEN_MODSEC_LOGS="/var/log/modsec/*.log"
SYSWARDEN_BRUTEFORCE_LOGS="/var/log/nginx/access.log"
SYSWARDEN_BRUTEFORCE_THRESHOLD="7"
SYSWARDEN_BRUTEFORCE_WINDOW="1m"
SYSWARDEN_HONEYPORTS="23 6379"
SYSWARDEN_HARDENING="y"
APPLY_CIS_L2_HARDENING="y"
SYSWARDEN_SECURE_WIPE_CONF="n"
SYSWARDEN_ENABLE_L2="y"
SYSWARDEN_ARP_PROTECT="y"
SYSWARDEN_LAN_MODE="y"
SYSWARDEN_HA_ENABLED="y"
SYSWARDEN_HA_PEER_IP="192.0.2.20"
SYSWARDEN_HA_PEER_PORT="62026"
SYSWARDEN_HA_TOKEN="example-shared-token"
SYSWARDEN_SIEM_ENABLED="y"
SYSWARDEN_SIEM_IP="192.0.2.30"
SYSWARDEN_SIEM_PORT="6514"
SYSWARDEN_SIEM_PROTO="tls"
SYSWARDEN_SIEM_TLS_CA="/etc/syswarden/siem-ca.pem"
SYSWARDEN_ENABLE_ABUSE="y"
SYSWARDEN_ABUSE_API_KEY="abuse-key"
SYSWARDEN_ENABLE_WEBHOOK="y"
SYSWARDEN_WEBHOOK_URL_DISCORD="https://example.invalid/discord"
SYSWARDEN_WEBHOOK_URL_TEAMS="https://example.invalid/teams"
SYSWARDEN_WEBHOOK_URL_SLACK="https://example.invalid/slack"
SYSWARDEN_BUNKERWEB_ENABLED="y"
SYSWARDEN_ENABLE_WAZUH="y"
SYSWARDEN_WAZUH_IP="192.0.2.40"
SYSWARDEN_WAZUH_NAME="syswarden-node"
SYSWARDEN_WAZUH_GROUP="production"
SYSWARDEN_WAZUH_COMM_PORT="1514"
SYSWARDEN_WAZUH_ENROLL_PORT="1515"
SYSWARDEN_WEB_TOKEN="existing-user-token"
UNKNOWN_USER_KEY="must-not-change-the-input-file"
`

func TestMigratedCoreDoesNotPublishObsoleteFirewallBackendClaim_SW2_FWBACKEND_001(t *testing.T) {
	content, err := (&Migrator{}).generateCore(map[string]string{
		"SYSWARDEN_FIREWALL_BACKEND": "keep",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(content, "RHEL/Alma/Fedora ONLY") {
		t.Fatalf("migrated core configuration retains the obsolete backend claim:\n%s", content)
	}
	if !strings.Contains(content, "firewall_backend = 'keep'") {
		t.Fatalf("migrated core configuration lost the backend value:\n%s", content)
	}
}

func TestMigratedFirewallBackendMapsHistoricalFirewalldAndRejectsWireGuardMismatch_SW2_FWBACKEND_001(t *testing.T) {
	for _, test := range []struct {
		legacy string
		want   string
	}{
		{legacy: "firewalld", want: "keep"},
		{legacy: "keep", want: "keep"},
		{legacy: "nftables", want: "nftables"},
		{legacy: "iptables", want: "iptables"},
	} {
		t.Run(test.legacy, func(t *testing.T) {
			got, err := migratedFirewallBackend(map[string]string{
				"SYSWARDEN_FIREWALL_BACKEND": test.legacy,
				"SYSWARDEN_ENABLE_WG":        "n",
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("migrated backend = %q, want %q", got, test.want)
			}
		})
	}

	for _, backend := range []string{"firewalld", "keep", "iptables"} {
		t.Run("wireguard-"+backend, func(t *testing.T) {
			_, err := migratedFirewallBackend(map[string]string{
				"SYSWARDEN_FIREWALL_BACKEND": backend,
				"SYSWARDEN_ENABLE_WG":        "y",
			})
			if err == nil || !strings.Contains(err.Error(), "enabled WireGuard requires nftables") {
				t.Fatalf("migration error = %v", err)
			}
		})
	}
}

var runtimeLegacyMigrationKeys = []string{
	"SYSWARDEN_ENTERPRISE_MODE",
	"SYSWARDEN_ENFORCEMENT_MODE",
	"SYSWARDEN_FIREWALL_BACKEND",
	"SYSWARDEN_SSH_PORT",
	"SYSWARDEN_INTERFACES",
	"SYSWARDEN_WHITELIST_INFRA",
	"SYSWARDEN_WHITELIST_IPS",
	"SYSWARDEN_LAN_SUBNETS",
	"SYSWARDEN_ALLOW_SAAS_MONITORS",
	"SYSWARDEN_ENABLE_GEO",
	"SYSWARDEN_GEO_CODES",
	"SYSWARDEN_GEO_ALLOWED",
	"SYSWARDEN_ENABLE_ASN",
	"SYSWARDEN_ASN_LIST",
	"SYSWARDEN_ASN_ALLOWED",
	"SYSWARDEN_LIST_CHOICE",
	"SYSWARDEN_USE_SPAMHAUS",
	"SYSWARDEN_CUSTOM_URL",
	"SYSWARDEN_CUSTOM_HASH",
	"SYSWARDEN_CUSTOM_URL_IPV6",
	"SYSWARDEN_CUSTOM_HASH_IPV6",
	"SYSWARDEN_ENABLE_WG",
	"SYSWARDEN_WG_PORT",
	"SYSWARDEN_WG_SUBNET",
	"SYSWARDEN_MODSEC_LOGS",
	"SYSWARDEN_BRUTEFORCE_LOGS",
	"SYSWARDEN_BRUTEFORCE_THRESHOLD",
	"SYSWARDEN_BRUTEFORCE_WINDOW",
	"SYSWARDEN_HONEYPORTS",
	"SYSWARDEN_HARDENING",
	"APPLY_CIS_L2_HARDENING",
	"SYSWARDEN_SECURE_WIPE_CONF",
	"SYSWARDEN_ENABLE_L2",
	"SYSWARDEN_ARP_PROTECT",
	"SYSWARDEN_LAN_MODE",
	"SYSWARDEN_HA_ENABLED",
	"SYSWARDEN_HA_PEER_IP",
	"SYSWARDEN_HA_PEER_PORT",
	"SYSWARDEN_HA_TOKEN",
	"SYSWARDEN_SIEM_ENABLED",
	"SYSWARDEN_SIEM_IP",
	"SYSWARDEN_SIEM_PORT",
	"SYSWARDEN_SIEM_PROTO",
	"SYSWARDEN_SIEM_TLS_CA",
	"SYSWARDEN_ENABLE_ABUSE",
	"SYSWARDEN_ABUSE_API_KEY",
	"SYSWARDEN_ENABLE_WEBHOOK",
	"SYSWARDEN_WEBHOOK_URL_DISCORD",
	"SYSWARDEN_WEBHOOK_URL_TEAMS",
	"SYSWARDEN_WEBHOOK_URL_SLACK",
	"SYSWARDEN_BUNKERWEB_ENABLED",
	"SYSWARDEN_ENABLE_WAZUH",
	"SYSWARDEN_WAZUH_IP",
	"SYSWARDEN_WAZUH_NAME",
	"SYSWARDEN_WAZUH_GROUP",
	"SYSWARDEN_WAZUH_COMM_PORT",
	"SYSWARDEN_WAZUH_ENROLL_PORT",
	"SYSWARDEN_CIS_L2",
	"SYSWARDEN_ALLOW_MONITORS",
}

var runtimeLegacyAliases = map[string]string{
	"SYSWARDEN_CIS_L2":         "APPLY_CIS_L2_HARDENING",
	"SYSWARDEN_ALLOW_MONITORS": "SYSWARDEN_ALLOW_SAAS_MONITORS",
}

func TestRuntimeLegacyMigrationMatrixIsExhaustive_SW_CFG_002(t *testing.T) {
	parsed, err := (&Migrator{}).ParseFromMemory(migrationFixture)
	if err != nil {
		t.Fatal(err)
	}
	matrix := make(map[string]struct{}, len(runtimeLegacyMigrationKeys))
	for _, key := range runtimeLegacyMigrationKeys {
		matrix[key] = struct{}{}
		if _, alias := runtimeLegacyAliases[key]; alias {
			continue
		}
		if _, exists := parsed[key]; !exists {
			t.Errorf("runtime legacy key %s is absent from the exact migration fixture", key)
		}
	}
	defaults, err := (&Migrator{}).ParseFromMemory(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	for key := range defaults {
		if _, mapped := matrix[key]; !mapped {
			t.Errorf("published legacy key %s has no explicit migration-matrix entry", key)
		}
	}

	parserKeys := runtimeLegacyParserKeys(t)
	matrixKeys := append([]string(nil), runtimeLegacyMigrationKeys...)
	sort.Strings(matrixKeys)
	if !reflect.DeepEqual(parserKeys, matrixKeys) {
		t.Fatalf("migration matrix keys = %v, runtime parser keys = %v", matrixKeys, parserKeys)
	}
}

func runtimeLegacyParserKeys(t *testing.T) []string {
	t.Helper()
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, "parser.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		switchNode, ok := node.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		identifier, ok := switchNode.Tag.(*ast.Ident)
		if !ok || identifier.Name != "key" {
			return true
		}
		for _, statement := range switchNode.Body.List {
			caseNode, ok := statement.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, expression := range caseNode.List {
				literal, ok := expression.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				key, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				keys = append(keys, key)
			}
		}
		return false
	})
	sort.Strings(keys)
	return keys
}

func readModularSaaSAllowance(t *testing.T, root string) bool {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "modules", "10-network.toml")) // #nosec G304 -- root is a test temporary directory
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := toml.Unmarshal(content, &document); err != nil {
		t.Fatalf("parse generated network module: %v", err)
	}
	network, ok := document["network"].(map[string]any)
	if !ok {
		t.Fatalf("generated network table = %#v", document["network"])
	}
	saas, ok := network["saas"].(map[string]any)
	if !ok {
		t.Fatalf("generated network.saas table = %#v", network["saas"])
	}
	allowed, ok := saas["allow_monitors"].(bool)
	if !ok {
		t.Fatalf("generated network.saas.allow_monitors = %#v", saas["allow_monitors"])
	}
	return allowed
}

func TestFreshDefaultPathsDisableSaaSWithoutChangingPinnedLegacyInput_SW_SAAS_001(t *testing.T) {
	parsed, err := (&Migrator{}).ParseFromMemory(DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}
	if parsed["SYSWARDEN_ALLOW_SAAS_MONITORS"] != "y" {
		t.Fatalf("pinned historical default changed to %q", parsed["SYSWARDEN_ALLOW_SAAS_MONITORS"])
	}

	tests := []struct {
		name       string
		initialize func(string) error
	}{
		{name: "InitializeDefaults", initialize: InitializeDefaults},
		{name: "EnsureDefaults", initialize: EnsureDefaults},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "config")
			if err := test.initialize(root); err != nil {
				t.Fatalf("%s() error = %v", test.name, err)
			}
			if readModularSaaSAllowance(t, root) {
				t.Fatalf("%s() enabled SaaS monitors on a fresh modular installation", test.name)
			}
		})
	}
}

func TestMigrationPreservesLegacySaaSIntent_SW_SAAS_001(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		want    bool
	}{
		{
			name:    "absent remains disabled",
			fixture: strings.Replace(migrationFixture, "SYSWARDEN_ALLOW_SAAS_MONITORS=\"y\"\n", "", 1),
		},
		{
			name:    "explicit true remains enabled",
			fixture: migrationFixture,
			want:    true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			if err := os.WriteFile(source, []byte(test.fixture), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "config")
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatalf("Migrator.Run() error = %v", err)
			}
			if got := readModularSaaSAllowance(t, output); got != test.want {
				t.Fatalf("migrated allow_monitors = %t, want %t", got, test.want)
			}
		})
	}
}

func TestLegacyMigrationMapsHistoricalAliases_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name      string
		canonical string
		alias     string
		mapped    func(*Config) bool
	}{
		{
			name:      "CIS L2",
			canonical: "APPLY_CIS_L2_HARDENING",
			alias:     "SYSWARDEN_CIS_L2",
			mapped:    func(config *Config) bool { return config.CISL2Hardening },
		},
		{
			name:      "SaaS monitors",
			canonical: "SYSWARDEN_ALLOW_SAAS_MONITORS",
			alias:     "SYSWARDEN_ALLOW_MONITORS",
			mapped:    func(config *Config) bool { return config.AllowSaaSMonitors },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			fixture := strings.Replace(migrationFixture, test.canonical+`="y"`, test.alias+`="y"`, 1)
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "config")
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatalf("Migrator.Run() alias error = %v", err)
			}
			previous := GlobalConfig
			t.Cleanup(func() { GlobalConfig = previous })
			if err := loadModularConfig(output); err != nil {
				t.Fatalf("loadModularConfig() alias error = %v", err)
			}
			if !test.mapped(GlobalConfig) {
				t.Fatalf("legacy alias %s was not mapped", test.alias)
			}
		})
	}
}

func TestParseFromMemoryLegacyInlineCommentBehavior_SW_CFG_002(t *testing.T) {
	t.Parallel()
	migrator := &Migrator{}
	parsed, err := migrator.ParseFromMemory(`
# comment
KEY_ONE="value"
		KEY_TWO="second" # inline comment
KEY_THREE=#
KEY_FOUR=value#fragment
KEY_FIVE="#quoted"
KEY_SIX='single#quoted'
KEY_SEVEN=value # inline comment
KEY_EIGHT="  quoted spaces  " # inline comment
KEY_NINE=   unquoted-spaces   # inline comment
INVALID
=ignored
`)
	if err != nil {
		t.Fatalf("ParseFromMemory() error = %v", err)
	}
	if parsed["KEY_ONE"] != "value" {
		t.Errorf("KEY_ONE = %q", parsed["KEY_ONE"])
	}
	if parsed["KEY_TWO"] != "second" {
		t.Errorf("KEY_TWO = %q, want second without quote residue", parsed["KEY_TWO"])
	}
	expectedValues := map[string]string{
		"KEY_THREE": "#",
		"KEY_FOUR":  "value#fragment",
		"KEY_FIVE":  "#quoted",
		"KEY_SIX":   "single#quoted",
		"KEY_SEVEN": "value",
		"KEY_EIGHT": "  quoted spaces  ",
		"KEY_NINE":  "unquoted-spaces",
	}
	for key, want := range expectedValues {
		if got := parsed[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if _, exists := parsed["INVALID"]; exists {
		t.Error("malformed line was accepted")
	}
}

func TestMigrationTOMLSerializerContainsOperatorValuesWithoutStructureInjection_SW_CFG_002(t *testing.T) {
	t.Parallel()
	payload := "eth0\"\n[future]\nenabled = true\n#"
	content, err := (&Migrator{}).generateNetwork(map[string]string{
		"SYSWARDEN_INTERFACES": payload,
	})
	if err != nil {
		t.Fatalf("generateNetwork() error = %v", err)
	}
	var document map[string]any
	if err := toml.Unmarshal([]byte(content), &document); err != nil {
		t.Fatalf("generated document is invalid TOML: %v", err)
	}
	if _, injected := document["future"]; injected {
		t.Fatal("operator string created an injected TOML table")
	}
	network, ok := document["network"].(map[string]any)
	if !ok || network["interfaces"] != payload {
		t.Fatalf("network.interfaces = %#v, want exact operator value", network["interfaces"])
	}
}

func TestMigrationAtomicPublicationPreservesOwnerGroupAndMode_SW_CFG_002(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.toml")
	if err := os.WriteFile(path, []byte("before\n"), 0640); err != nil { // #nosec G306 -- deliberate fixture mode verifies exact owner/group preservation
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID, ok := fileOwnerUIDGID(before)
	if !ok {
		t.Fatal("file ownership is unavailable")
	}
	if err := writeSecureFileAtomically(directory, "config.toml", []byte("after\n")); err != nil {
		t.Fatalf("writeSecureFileAtomically() error = %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, gotGID, ok := fileOwnerUIDGID(after)
	if !ok {
		t.Fatal("replacement ownership is unavailable")
	}
	if gotUID != wantUID || gotGID != wantGID || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("replacement identity = uid %d gid %d mode %#o, want uid %d gid %d mode %#o", gotUID, gotGID, after.Mode().Perm(), wantUID, wantGID, before.Mode().Perm())
	}
	assertFileContent(t, path, "after\n")
}

func TestMigratorIsRepeatableAndPreservesUserModule(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "config")
	sourceDir := t.TempDir()

	runMigration := func(name string) {
		t.Helper()
		source := filepath.Join(sourceDir, name)
		if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
			t.Fatal(err)
		}
		migrator := &Migrator{SourcePath: source, OutputDir: outputDir}
		if err := migrator.Run(); err != nil {
			t.Fatalf("Migrator.Run() error = %v", err)
		}
		if _, err := os.Stat(source + ".migrated"); err != nil {
			t.Fatalf("migrated source was not retained: %v", err)
		}
	}

	runMigration("first.conf")
	wantModules := []string{
		"00-core.toml",
		"10-network.toml",
		"20-security.toml",
		"30-waap.toml",
		"40-integrations.toml",
		"99-user.toml",
	}
	entries, err := os.ReadDir(filepath.Join(outputDir, "modules"))
	if err != nil {
		t.Fatal(err)
	}
	var gotModules []string
	for _, entry := range entries {
		if !entry.IsDir() {
			gotModules = append(gotModules, entry.Name())
		}
	}
	if fmt.Sprint(gotModules) != fmt.Sprint(wantModules) {
		t.Fatalf("generated modules = %v, want ordered contract %v", gotModules, wantModules)
	}
	before := directoryDigest(t, outputDir)

	userPath := filepath.Join(outputDir, "modules", "99-user.toml")
	const userOverride = "\n# operator-owned override\n[core]\nlog_level = \"DEBUG\"\n"
	file, err := os.OpenFile(userPath, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(userOverride); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	runMigration("second.conf")
	afterUser, err := os.ReadFile(userPath) // #nosec G304 -- userPath is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterUser), userOverride) {
		t.Fatal("repeat migration overwrote the operator-owned 99-user.toml module")
	}

	withoutUserOverride := directoryDigestExcluding(t, outputDir, "modules/99-user.toml")
	beforeWithoutUser := before
	delete(beforeWithoutUser, "modules/99-user.toml")
	if fmt.Sprint(beforeWithoutUser) != fmt.Sprint(withoutUserOverride) {
		t.Fatalf("repeat migration changed generated modules:\nbefore=%v\nafter=%v", beforeWithoutUser, withoutUserOverride)
	}
}

func TestMigratorRejectsInvalidPreservedUserModuleWithoutReplacingItsInode_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	modules := filepath.Join(output, "modules")
	if err := os.MkdirAll(modules, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	userPath := filepath.Join(modules, userModuleName)
	const invalid = "# preserve even when rejected\n[core]\nssh_port = \"70000\"\n"
	if err := os.WriteFile(userPath, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}

	err = (&Migrator{SourcePath: source, OutputDir: output}).Run()
	if err == nil || !strings.Contains(err.Error(), "validate effective migration artifacts") {
		t.Fatalf("invalid preserved operator module error = %v", err)
	}
	after, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected migration replaced the invalid operator inode")
	}
	assertFileContent(t, userPath, invalid)
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("invalid effective candidate created a migration marker: %v", err)
	}
	assertFileContent(t, source, migrationFixture)
}

func TestMigratorDryRunLegacyDirectorySideEffect_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	beforeSource, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}

	migrator := &Migrator{SourcePath: source, OutputDir: output, DryRun: true}
	if err := migrator.Run(); err != nil {
		t.Fatalf("Migrator.Run() dry-run error = %v", err)
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("dry-run created destination state: %v", err)
	}
	afterSource, err := os.Lstat(source)
	if err != nil {
		t.Fatalf("dry-run changed source file: %v", err)
	}
	if !os.SameFile(beforeSource, afterSource) || beforeSource.Mode() != afterSource.Mode() {
		t.Fatal("dry-run changed source identity or mode")
	}
	assertFileContent(t, source, migrationFixture)

	if err := os.MkdirAll(filepath.Join(output, "modules"), 0750); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "modules", "operator.keep")
	if err := os.WriteFile(sentinel, []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	beforeOutput := directoryDigest(t, output)
	if err := migrator.Run(); err != nil {
		t.Fatalf("Migrator.Run() dry-run against existing destination error = %v", err)
	}
	if afterOutput := directoryDigest(t, output); !reflect.DeepEqual(afterOutput, beforeOutput) {
		t.Fatalf("dry-run changed existing destination: got %s want %s", afterOutput, beforeOutput)
	}
}

func TestMigratorDryRunNeverRecoversOrMutatesInterruptedTransactions_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name      string
		wantState string
		prepare   func(*testing.T, string, string) error
	}{
		{
			name:      "publishing",
			wantState: migrationPublishing,
			prepare: func(t *testing.T, source, output string) error {
				previous := publishMigrationFile
				publishMigrationFile = func(string, string, []byte, bool) error {
					return errors.New("stop in publishing")
				}
				defer func() { publishMigrationFile = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
		{
			name:      "published before retention",
			wantState: migrationPublished,
			prepare: func(t *testing.T, source, output string) error {
				previous := renameLegacyFile
				renameLegacyFile = func(*legacySourceSnapshot) error {
					return errors.New("stop before retention")
				}
				defer func() { renameLegacyFile = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
		{
			name:      "published after retention response loss",
			wantState: migrationPublished,
			prepare: func(t *testing.T, source, output string) error {
				previous := renameLegacyFile
				renameLegacyFile = func(snapshot *legacySourceSnapshot) error {
					if err := secureRenameLegacySource(snapshot); err != nil {
						return err
					}
					return errors.New("stop after retention")
				}
				defer func() { renameLegacyFile = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
		{
			name:      "published before secure wipe",
			wantState: migrationPublished,
			prepare: func(t *testing.T, source, output string) error {
				previous := shredLegacyFile
				shredLegacyFile = func(*legacySourceSnapshot, func(string) error) error {
					return errors.New("stop before secure wipe")
				}
				defer func() { shredLegacyFile = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
		{
			name:      "published with durable wipe staging",
			wantState: migrationPublished,
			prepare: func(t *testing.T, source, output string) error {
				previous := secureWipeCheckpoint
				secureWipeCheckpoint = func(phase int) error {
					if phase == 6 {
						return errors.New("stop after durable wipe staging")
					}
					return nil
				}
				defer func() { secureWipeCheckpoint = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
		{
			name:      "wipe staged after removal",
			wantState: migrationWipeStaged,
			prepare: func(t *testing.T, source, output string) error {
				previous := secureWipeCheckpoint
				secureWipeCheckpoint = func(phase int) error {
					if phase == 7 {
						return errors.New("stop after wipe removal")
					}
					return nil
				}
				defer func() { secureWipeCheckpoint = previous }()
				return (&Migrator{SourcePath: source, OutputDir: output}).Run()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			fixture := migrationFixture
			if strings.Contains(test.name, "wipe") || strings.Contains(test.name, "secure") {
				fixture = strings.Replace(fixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
			}
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			if err := test.prepare(t, source, output); err == nil {
				t.Fatal("test setup did not interrupt the migration")
			}
			marker, err := readMigrationMarker(output)
			if err != nil {
				t.Fatal(err)
			}
			if marker == nil || marker.State != test.wantState {
				t.Fatalf("interrupted marker = %#v, want state %s", marker, test.wantState)
			}
			before := directoryDigest(t, root)
			err = (&Migrator{SourcePath: source, OutputDir: output, DryRun: true}).Run()
			if err == nil || !strings.Contains(err.Error(), "dry-run cannot resume") {
				t.Fatalf("dry-run recovery error = %v", err)
			}
			if after := directoryDigest(t, root); !reflect.DeepEqual(after, before) {
				t.Fatalf("dry-run mutated interrupted transaction: before=%v after=%v", before, after)
			}
		})
	}
}

func TestLegacyMigrationToGlobalConfigContract_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	legacyPath := filepath.Join(root, "legacy.conf")
	migrationPath := filepath.Join(root, "migration.conf")
	outputDir := filepath.Join(root, "config")
	for _, path := range []string{legacyPath, migrationPath} {
		if err := os.WriteFile(path, []byte(migrationFixture), 0600); err != nil {
			t.Fatal(err)
		}
	}

	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadOldConfig(legacyPath); err != nil {
		t.Fatalf("loadOldConfig() error = %v", err)
	}
	legacy := *GlobalConfig

	migrator := &Migrator{SourcePath: migrationPath, OutputDir: outputDir}
	if err := migrator.Run(); err != nil {
		t.Fatalf("Migrator.Run() error = %v", err)
	}
	if err := loadModularConfig(outputDir); err != nil {
		t.Fatalf("loadModularConfig() error = %v", err)
	}
	migrated := GlobalConfig

	if migrated.SSHPort != legacy.SSHPort || migrated.FirewallBackend != legacy.FirewallBackend {
		t.Fatalf("core contract changed: legacy=%q/%q migrated=%q/%q", legacy.SSHPort, legacy.FirewallBackend, migrated.SSHPort, migrated.FirewallBackend)
	}
	canonicalList := func(value string) string {
		return strings.Join(strings.Fields(strings.ReplaceAll(value, ",", " ")), " ")
	}
	if migrated.WhitelistIPs != canonicalList(legacy.WhitelistIPs) || migrated.LANSubnets != canonicalList(legacy.LANSubnets) {
		t.Fatalf("network contract changed: whitelist=%q LAN=%q", migrated.WhitelistIPs, migrated.LANSubnets)
	}
	if migrated.GeoCodes != canonicalList(legacy.GeoCodes) || migrated.ASNList != canonicalList(legacy.ASNList) {
		t.Fatalf("threat intelligence contract changed: GEO=%q ASN=%q", migrated.GeoCodes, migrated.ASNList)
	}
	if migrated.HoneyPorts != canonicalList(legacy.HoneyPorts) {
		t.Fatalf("security contract changed: honeyports=%q", migrated.HoneyPorts)
	}
	if !migrated.HAEnabled || migrated.HAPeerIP != legacy.HAPeerIP || migrated.HAPeerPort != legacy.HAPeerPort || migrated.HAToken != "example-shared-token" {
		t.Fatalf("HA contract changed: enabled=%t peer=%q port=%q token=%q", migrated.HAEnabled, migrated.HAPeerIP, migrated.HAPeerPort, migrated.HAToken)
	}
	if !migrated.SiemEnabled || migrated.SiemIP != "192.0.2.30" || migrated.SiemPort != "6514" || migrated.SiemProto != "tls" {
		t.Fatalf("SIEM contract changed: enabled=%t endpoint=%s:%s protocol=%q", migrated.SiemEnabled, migrated.SiemIP, migrated.SiemPort, migrated.SiemProto)
	}
	if !legacy.CISL2Hardening || !migrated.CISL2Hardening {
		t.Fatalf("CIS L2 setting was not preserved: legacy=%t migrated=%t", legacy.CISL2Hardening, migrated.CISL2Hardening)
	}
	expected := legacy
	expected.BruteforceWindow = "60s"
	if !reflect.DeepEqual(expected, *migrated) {
		t.Fatalf("complete legacy-to-modular contract changed:\nlegacy=%#v\nmigrated=%#v", expected, *migrated)
	}
}

func TestMigratorPropagatesRenameFailure_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	previous := renameLegacyFile
	renameLegacyFile = func(*legacySourceSnapshot) error { return errors.New("injected rename failure") }
	t.Cleanup(func() { renameLegacyFile = previous })

	err := (&Migrator{SourcePath: source, OutputDir: filepath.Join(root, "config")}).Run()
	if err == nil || !strings.Contains(err.Error(), "injected rename failure") {
		t.Fatalf("Migrator.Run() rename error = %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("rename failure lost the migration source: %v", err)
	}
}

func TestMigratorPropagatesSecureWipeFailure_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	fixture := strings.Replace(migrationFixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	previous := shredLegacyFile
	shredLegacyFile = func(*legacySourceSnapshot, func(string) error) error { return errors.New("injected shred failure") }
	t.Cleanup(func() { shredLegacyFile = previous })

	err := (&Migrator{SourcePath: source, OutputDir: filepath.Join(root, "config")}).Run()
	if err == nil || !strings.Contains(err.Error(), "injected shred failure") {
		t.Fatalf("Migrator.Run() shred error = %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("shred failure lost the migration source: %v", err)
	}
}

func TestMigratorRejectsSymlinkedOutputPath_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "config")
	if err := os.Symlink(victim, output); err != nil {
		t.Fatal(err)
	}

	if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err == nil {
		t.Fatal("Migrator.Run() accepted a symlinked output root")
	}
	entries, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked output modified its victim: %v", entries)
	}
}

func TestMigratorRejectsSymlinkedOrUnsafeSource_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	realSource := filepath.Join(root, "real.conf")
	if err := os.WriteFile(realSource, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkSource := filepath.Join(root, "symlink.conf")
	if err := os.Symlink(realSource, symlinkSource); err != nil {
		t.Fatal(err)
	}
	if err := (&Migrator{SourcePath: symlinkSource, OutputDir: filepath.Join(root, "symlink-output")}).Run(); err == nil {
		t.Fatal("Migrator.Run() accepted a symlinked source")
	}

	secureRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secureRoot.Close() }()
	realSourceFile, err := secureRoot.Open("real.conf")
	if err != nil {
		t.Fatal(err)
	}
	if err := realSourceFile.Chmod(0666); err != nil {
		_ = realSourceFile.Close()
		t.Fatal(err)
	}
	if err := realSourceFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&Migrator{SourcePath: realSource, OutputDir: filepath.Join(root, "unsafe-output")}).Run(); err == nil {
		t.Fatal("Migrator.Run() accepted a world-writable source")
	}
}

func TestMigratorRejectsInvalidTypedCandidateBeforeWriting_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "fractional duration",
			fixture: strings.Replace(migrationFixture, `SYSWARDEN_BRUTEFORCE_WINDOW="1m"`, `SYSWARDEN_BRUTEFORCE_WINDOW="1500ms"`, 1),
		},
		{
			name:    "HA without token",
			fixture: strings.Replace(migrationFixture, `SYSWARDEN_HA_TOKEN="example-shared-token"`, `SYSWARDEN_HA_TOKEN=""`, 1),
		},
		{
			name:    "conflicting historical alias",
			fixture: migrationFixture + "\nSYSWARDEN_CIS_L2=\"n\"\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			if err := os.WriteFile(source, []byte(test.fixture), 0600); err != nil {
				t.Fatal(err)
			}
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err == nil {
				t.Fatal("Migrator.Run() accepted an invalid typed candidate")
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatalf("invalid candidate created output state: %v", err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("invalid candidate changed its source: %v", err)
			}
		})
	}
}

func TestMigrationTransactionRetriesEveryArtifactPublishWithoutDefaultFill_SW_CFG_002(t *testing.T) {
	const artifactCount = 7
	for failAt := 1; failAt <= artifactCount; failAt++ {
		t.Run(fmt.Sprintf("publish-%d", failAt), func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
				t.Fatal(err)
			}
			previousPublisher := publishMigrationFile
			calls := 0
			publishMigrationFile = func(directory, name string, content []byte, noReplace bool) error {
				calls++
				if calls == failAt {
					return fmt.Errorf("injected publish failure %d", failAt)
				}
				return previousPublisher(directory, name, content, noReplace)
			}
			err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
			publishMigrationFile = previousPublisher
			if err == nil || !strings.Contains(err.Error(), "injected publish failure") {
				t.Fatalf("publish failure %d error = %v", failAt, err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("publish failure changed source: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); err != nil {
				t.Fatalf("publish failure omitted retry marker: %v", err)
			}
			beforeDefaults := directoryDigest(t, output)
			if err := EnsureDefaults(output); err == nil {
				t.Fatal("EnsureDefaults filled a partially migrated transaction")
			}
			if afterDefaults := directoryDigest(t, output); !reflect.DeepEqual(beforeDefaults, afterDefaults) {
				t.Fatal("failed package-style retry filled defaults over legacy migration state")
			}

			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatalf("transaction retry after publish %d error = %v", failAt, err)
			}
			if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
				t.Fatalf("successful retry left marker: %v", err)
			}
			if _, err := os.Stat(source + ".migrated"); err != nil {
				t.Fatalf("successful retry did not retain source: %v", err)
			}
			if err := loadModularConfig(output); err != nil {
				t.Fatalf("retried migration is not loadable: %v", err)
			}
			if GlobalConfig.SSHPort != "2222" || !GlobalConfig.BunkerWebEnabled {
				t.Fatalf("retried migration lost legacy values: %#v", GlobalConfig)
			}
		})
	}
}

func TestMigrationUserModuleNoReplaceInterleavingPreservesConcurrentInodeAndRetryConverges_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}

	const concurrent = "# concurrent validated operator state\n[user]\nprofile_name = \"must-survive-migration\"\n"
	previousPublisher := publishMigrationFile
	injected := false
	var concurrentInfo os.FileInfo
	publishMigrationFile = func(directory, name string, content []byte, noReplace bool) error {
		if name == userModuleName && noReplace && !injected {
			injected = true
			if err := writeMissingSecureFile(directory, name, []byte(concurrent)); err != nil {
				return err
			}
			var err error
			concurrentInfo, err = os.Lstat(filepath.Join(directory, name))
			if err != nil {
				return err
			}
		}
		return previousPublisher(directory, name, content, noReplace)
	}
	t.Cleanup(func() { publishMigrationFile = previousPublisher })

	err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
	publishMigrationFile = previousPublisher
	if err == nil || !strings.Contains(err.Error(), "publish migration artifact modules/99-user.toml") {
		t.Fatalf("no-replace user-module interleaving error = %v", err)
	}
	if !injected || concurrentInfo == nil {
		t.Fatal("test did not publish the concurrent operator inode")
	}
	userPath := filepath.Join(output, "modules", userModuleName)
	afterFailure, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(concurrentInfo, afterFailure) {
		t.Fatal("failed no-replace migration changed the concurrent operator inode")
	}
	assertFileContent(t, userPath, concurrent)
	marker, markerErr := readMigrationMarker(output)
	if markerErr != nil {
		t.Fatal(markerErr)
	}
	if marker == nil || marker.State != migrationPublishing || marker.PreserveUser {
		t.Fatalf("interrupted migration marker = %#v", marker)
	}

	if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
		t.Fatalf("bounded retry did not adopt the concurrent operator module: %v", err)
	}
	afterRetry, statErr := os.Lstat(userPath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !os.SameFile(concurrentInfo, afterRetry) {
		t.Fatal("migration retry replaced the adopted operator inode")
	}
	assertFileContent(t, userPath, concurrent)
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("successful retry left migration marker: %v", err)
	}
	if _, err := os.Lstat(source + ".migrated"); err != nil {
		t.Fatalf("successful retry did not retain the legacy source: %v", err)
	}
	previous := GlobalConfig
	t.Cleanup(func() { GlobalConfig = previous })
	if err := loadModularConfig(output); err != nil {
		t.Fatalf("retried migration is not loadable: %v", err)
	}
	if !GlobalConfig.BunkerWebEnabled {
		t.Fatalf("retried configuration lost operator/BunkerWeb state: %#v", GlobalConfig)
	}
}

func TestMigrationRejectsUnexpectedTOMLInventoryBeforeSourceFinalizationAndRetries_SW_CFG_002(t *testing.T) {
	tests := []struct {
		name  string
		phase string
	}{
		{name: "preexisting invalid module", phase: "preexisting"},
		{name: "invalid module appears during artifact publication", phase: "publication"},
		{name: "invalid module appears after marker commit", phase: "commit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			modules := filepath.Join(output, "modules")
			if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(modules, 0750); err != nil {
				t.Fatal(err)
			}
			extraPath := filepath.Join(modules, "41-concurrent.toml")
			const invalidModule = "[core\nssh_port = \"70000\"\n"
			if test.phase == "preexisting" {
				if err := os.WriteFile(extraPath, []byte(invalidModule), 0600); err != nil {
					t.Fatal(err)
				}
			}

			previousPublisher := publishMigrationFile
			previousCommitHook := migrationCommitHook
			injected := test.phase == "preexisting"
			publishMigrationFile = func(directory, name string, content []byte, noReplace bool) error {
				if err := previousPublisher(directory, name, content, noReplace); err != nil {
					return err
				}
				if !injected && test.phase == "publication" && name == "config.toml" {
					injected = true
					return writeMissingSecureFile(modules, filepath.Base(extraPath), []byte(invalidModule))
				}
				return nil
			}
			migrationCommitHook = func() error {
				if !injected && test.phase == "commit" {
					injected = true
					return writeMissingSecureFile(modules, filepath.Base(extraPath), []byte(invalidModule))
				}
				return nil
			}
			err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
			publishMigrationFile = previousPublisher
			migrationCommitHook = previousCommitHook
			t.Cleanup(func() {
				publishMigrationFile = previousPublisher
				migrationCommitHook = previousCommitHook
			})
			if err == nil || !strings.Contains(err.Error(), "migration TOML module inventory") {
				t.Fatalf("unexpected module migration error = %v", err)
			}
			if !injected {
				t.Fatal("test did not publish the unexpected module")
			}
			assertFileContent(t, source, migrationFixture)
			assertFileContent(t, extraPath, invalidModule)
			if _, err := os.Lstat(source + ".migrated"); !os.IsNotExist(err) {
				t.Fatalf("invalid final inventory retained the source prematurely: %v", err)
			}
			marker, markerErr := readMigrationMarker(output)
			if markerErr != nil {
				t.Fatal(markerErr)
			}
			if marker == nil || marker.State != migrationPublishing {
				t.Fatalf("invalid final inventory marker = %#v, want publishing", marker)
			}

			if err := os.Remove(extraPath); err != nil {
				t.Fatal(err)
			}
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatalf("bounded retry after removing unexpected module: %v", err)
			}
			if _, err := os.Lstat(source); !os.IsNotExist(err) {
				t.Fatalf("successful retry left the source: %v", err)
			}
			if _, err := os.Lstat(source + ".migrated"); err != nil {
				t.Fatalf("successful retry did not retain the source: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
				t.Fatalf("successful retry left its marker: %v", err)
			}
			if err := loadModularConfig(output); err != nil {
				t.Fatalf("retried migration is not loadable: %v", err)
			}
		})
	}
}

func TestPublishedMigrationRecoversAfterCleanupSuccessResponseLoss_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	previous := renameLegacyFile
	renameLegacyFile = func(snapshot *legacySourceSnapshot) error {
		if err := secureRenameLegacySource(snapshot); err != nil {
			return err
		}
		return errors.New("injected response loss after rooted rename")
	}
	err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
	renameLegacyFile = previous
	if err == nil || !strings.Contains(err.Error(), "response loss") {
		t.Fatalf("cleanup response-loss error = %v", err)
	}
	if _, err := os.Stat(source + ".migrated"); err != nil {
		t.Fatalf("rooted rename did not complete: %v", err)
	}
	if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
		t.Fatalf("published transaction recovery error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
		t.Fatalf("recovered transaction left marker: %v", err)
	}
}

func TestMigrationCleanupRejectsSourceSubstitutionBeforeRenameOrWipe_SW_CFG_002(t *testing.T) {
	for _, wipe := range []bool{false, true} {
		name := "rename"
		if wipe {
			name = "wipe"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			fixture := migrationFixture
			if wipe {
				fixture = strings.Replace(fixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
			}
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			const replacement = "replacement must survive\n"
			previousHook := sourceFinalizeHook
			sourceFinalizeHook = func() error {
				if err := os.Rename(source, source+".original"); err != nil {
					return err
				}
				return os.WriteFile(source, []byte(replacement), 0600)
			}
			t.Cleanup(func() { sourceFinalizeHook = previousHook })
			err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
			if err == nil || (!strings.Contains(err.Error(), "substituted") && !strings.Contains(err.Error(), "changed before secure wipe")) {
				t.Fatalf("source substitution error = %v", err)
			}
			assertFileContent(t, source, replacement)
			if _, err := os.Stat(source + ".original"); err != nil {
				t.Fatalf("validated original snapshot was lost: %v", err)
			}
			if _, err := os.Lstat(source + ".migrated"); !os.IsNotExist(err) {
				t.Fatalf("substituted inode reached the retention target: %v", err)
			}
		})
	}
}

func TestMigrationCleanupRejectsSameInodeContentMutation_SW_CFG_002(t *testing.T) {
	for _, wipe := range []bool{false, true} {
		name := "rename"
		if wipe {
			name = "wipe"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			fixture := migrationFixture
			if wipe {
				fixture = strings.Replace(fixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
			}
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			originalInfo, err := os.Lstat(source)
			if err != nil {
				t.Fatal(err)
			}
			const replacement = "same inode content mutation must survive\n"
			previousHook := sourceFinalizeHook
			sourceFinalizeHook = func() error {
				parent, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer func() { _ = parent.Close() }()
				file, err := parent.OpenFile("legacy.conf", os.O_WRONLY|os.O_TRUNC, 0)
				if err != nil {
					return err
				}
				if _, err := file.WriteString(replacement); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			}
			t.Cleanup(func() { sourceFinalizeHook = previousHook })

			err = (&Migrator{SourcePath: source, OutputDir: filepath.Join(root, "config")}).Run()
			if err == nil || !strings.Contains(err.Error(), "content changed") {
				t.Fatalf("same-inode content mutation error = %v", err)
			}
			currentInfo, statErr := os.Lstat(source)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if !os.SameFile(originalInfo, currentInfo) {
				t.Fatal("same-inode mutation unexpectedly replaced the source inode")
			}
			assertFileContent(t, source, replacement)
			if _, err := os.Lstat(source + ".migrated"); !os.IsNotExist(err) {
				t.Fatalf("mutated source was finalized: %v", err)
			}
		})
	}
}

func TestMigrationCleanupRejectsSourceParentMutationAtFinalization_SW_CFG_002(t *testing.T) {
	for _, wipe := range []bool{false, true} {
		name := "rename"
		if wipe {
			name = "wipe"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			fixture := migrationFixture
			if wipe {
				fixture = strings.Replace(fixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
			}
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			previousHook := sourceFinalizeHook
			sourceFinalizeHook = func() error {
				parentRoot, err := os.OpenRoot(root)
				if err != nil {
					return err
				}
				defer func() { _ = parentRoot.Close() }()
				parent, err := parentRoot.Open(".")
				if err != nil {
					return err
				}
				defer func() { _ = parent.Close() }()
				return parent.Chmod(0770)
			}
			t.Cleanup(func() { sourceFinalizeHook = previousHook })

			err := (&Migrator{SourcePath: source, OutputDir: filepath.Join(root, "config")}).Run()
			parentRoot, openErr := os.OpenRoot(root)
			if openErr != nil {
				t.Fatal(openErr)
			}
			parent, openErr := parentRoot.Open(".")
			if openErr == nil {
				openErr = parent.Chmod(0700)
				_ = parent.Close()
			}
			_ = parentRoot.Close()
			if openErr != nil {
				t.Fatal(openErr)
			}
			if err == nil || !strings.Contains(err.Error(), "parent changed") {
				t.Fatalf("source-parent mutation error = %v", err)
			}
			assertFileContent(t, source, fixture)
			if _, err := os.Lstat(source + ".migrated"); !os.IsNotExist(err) {
				t.Fatalf("parent mutation finalized the source: %v", err)
			}
		})
	}
}

func TestSecureWipeTransactionResumesAfterEveryDurablePhase_SW_CFG_002(t *testing.T) {
	for phase := 1; phase <= 7; phase++ {
		t.Run(fmt.Sprintf("phase-%d", phase), func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "legacy.conf")
			output := filepath.Join(root, "config")
			fixture := strings.Replace(migrationFixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
			if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			previousCheckpoint := secureWipeCheckpoint
			secureWipeCheckpoint = func(current int) error {
				if current == phase {
					return fmt.Errorf("injected interruption at phase %d", phase)
				}
				return nil
			}
			err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
			secureWipeCheckpoint = previousCheckpoint
			if err == nil || !strings.Contains(err.Error(), "injected interruption") {
				t.Fatalf("phase %d interruption error = %v", phase, err)
			}
			if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); err != nil {
				t.Fatalf("phase %d interruption lost retry marker: %v", phase, err)
			}
			if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err != nil {
				t.Fatalf("phase %d bounded retry error = %v", phase, err)
			}
			if _, err := os.Lstat(source); !os.IsNotExist(err) {
				t.Fatalf("phase %d retry left source: %v", phase, err)
			}
			if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); !os.IsNotExist(err) {
				t.Fatalf("phase %d retry left marker: %v", phase, err)
			}
			previous := GlobalConfig
			t.Cleanup(func() { GlobalConfig = previous })
			if err := loadModularConfig(output); err != nil {
				t.Fatalf("phase %d retry output is invalid: %v", phase, err)
			}
			if !GlobalConfig.HAEnabled || !GlobalConfig.BunkerWebEnabled || GlobalConfig.HAToken != "example-shared-token" {
				t.Fatalf("phase %d retry lost validated HA/BunkerWeb state: %#v", phase, GlobalConfig)
			}
		})
	}
}

func TestSecureWipeRetryRejectsSubstitutedInodeAfterInterruption_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	fixture := strings.Replace(migrationFixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	previousCheckpoint := secureWipeCheckpoint
	secureWipeCheckpoint = func(phase int) error {
		if phase == 1 {
			return errors.New("injected wipe interruption")
		}
		return nil
	}
	err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
	secureWipeCheckpoint = previousCheckpoint
	if err == nil || !strings.Contains(err.Error(), "injected wipe interruption") {
		t.Fatalf("initial wipe interruption error = %v", err)
	}
	if err := os.Rename(source, source+".interrupted"); err != nil {
		t.Fatal(err)
	}
	const replacement = "replacement inode must never be wiped\n"
	if err := os.WriteFile(source, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	err = (&Migrator{SourcePath: source, OutputDir: output}).Run()
	if err == nil || !strings.Contains(err.Error(), "does not match the in-progress transaction") {
		t.Fatalf("substituted wipe retry error = %v", err)
	}
	assertFileContent(t, source, replacement)
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); err != nil {
		t.Fatalf("unsafe retry removed its marker: %v", err)
	}
}

func TestSecureWipeRetryRejectsMissingSourceWithoutDurableStagingProof_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	fixture := strings.Replace(migrationFixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	previous := shredLegacyFile
	shredLegacyFile = func(*legacySourceSnapshot, func(string) error) error {
		if err := os.Rename(source, source+".unexpected-removal"); err != nil {
			return err
		}
		return errors.New("injected source disappearance before wipe")
	}
	err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
	shredLegacyFile = previous
	if err == nil || !strings.Contains(err.Error(), "injected source disappearance") {
		t.Fatalf("initial disappearance error = %v", err)
	}
	err = (&Migrator{SourcePath: source, OutputDir: output}).Run()
	if err == nil || !strings.Contains(err.Error(), "disappeared before a durable secure-wipe staging state") {
		t.Fatalf("missing-source recovery error = %v", err)
	}
	assertFileContent(t, source+".unexpected-removal", fixture)
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); err != nil {
		t.Fatalf("unsafe missing-source retry removed its marker: %v", err)
	}
}

func TestSecureWipeRetryRejectsSubstitutedParentWithSameSourceInode_SW_CFG_002(t *testing.T) {
	base := t.TempDir()
	sourceParent := filepath.Join(base, "source")
	if err := os.Mkdir(sourceParent, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(sourceParent, "legacy.conf")
	output := filepath.Join(base, "config")
	fixture := strings.Replace(migrationFixture, `SYSWARDEN_SECURE_WIPE_CONF="n"`, `SYSWARDEN_SECURE_WIPE_CONF="y"`, 1)
	if err := os.WriteFile(source, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	previousCheckpoint := secureWipeCheckpoint
	secureWipeCheckpoint = func(phase int) error {
		if phase == 1 {
			return errors.New("injected parent-substitution checkpoint")
		}
		return nil
	}
	err := (&Migrator{SourcePath: source, OutputDir: output}).Run()
	secureWipeCheckpoint = previousCheckpoint
	if err == nil || !strings.Contains(err.Error(), "parent-substitution checkpoint") {
		t.Fatalf("initial interruption error = %v", err)
	}
	before, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	originalParent := filepath.Join(base, "source-original")
	if err := os.Rename(sourceParent, originalParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sourceParent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(originalParent, "legacy.conf"), source); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("test setup did not preserve the interrupted source inode")
	}
	err = (&Migrator{SourcePath: source, OutputDir: output}).Run()
	if err == nil || !strings.Contains(err.Error(), "does not match the in-progress transaction") {
		t.Fatalf("substituted parent retry error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(output, migrationMarkerName)); err != nil {
		t.Fatalf("parent-substitution retry removed its marker: %v", err)
	}
}

func TestMigratorRejectsUnsafeSourceParentBeforeCreatingOutput_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "unsafe-parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	secureRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secureRoot.Close() }()
	parentFile, err := secureRoot.Open("unsafe-parent")
	if err != nil {
		t.Fatal(err)
	}
	if err := parentFile.Chmod(0777); err != nil {
		_ = parentFile.Close()
		t.Fatal(err)
	}
	if err := parentFile.Close(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(parent, "legacy.conf")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "config")
	if err := (&Migrator{SourcePath: source, OutputDir: output}).Run(); err == nil {
		t.Fatal("migrator accepted a group/world-writable source parent")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("unsafe source parent created output state: %v", err)
	}
	assertFileContent(t, source, migrationFixture)
}

func TestWriteSecureFileAtomicallyReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	directory := t.TempDir()
	victimPath := filepath.Join(directory, "operator-owned.toml")
	if err := os.WriteFile(victimPath, []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(directory, "config.toml")
	if err := os.Symlink(filepath.Base(victimPath), targetPath); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	if err := writeSecureFileAtomically(directory, filepath.Base(targetPath), []byte("replacement\n")); err != nil {
		t.Fatalf("writeSecureFileAtomically() error = %v", err)
	}
	victim, err := root.ReadFile("operator-owned.toml")
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "preserve\n" {
		t.Fatalf("atomic replacement followed destination symlink: %q", victim)
	}
	target, err := root.ReadFile("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if string(target) != "replacement\n" {
		t.Fatalf("replacement content = %q", target)
	}
	info, err := root.Lstat("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("replacement mode = %v, want regular 0600", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".config.toml.tmp-") {
			t.Fatalf("temporary file was not removed: %s", entry.Name())
		}
	}
}

func TestWriteSecureFileAtomicallyCleansTemporaryFileAfterRenameFailure(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "config.toml"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeSecureFileAtomically(directory, "config.toml", []byte("replacement\n")); err == nil {
		t.Fatal("writeSecureFileAtomically() accepted a directory destination")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.toml" || !entries[0].IsDir() {
		t.Fatalf("failed atomic replacement left artifacts: %#v", entries)
	}
}

func directoryDigest(t *testing.T, root string) map[string]string {
	t.Helper()
	return directoryDigestExcluding(t, root, "")
}

func directoryDigestExcluding(t *testing.T, root, excluded string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if filepath.ToSlash(relative) != excluded {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		content, err := os.ReadFile(path) // #nosec G304 -- every path is discovered under a t.TempDir root
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		result[filepath.ToSlash(relative)] = fmt.Sprintf("%x", sha256.Sum256(content))
	}
	return result
}
