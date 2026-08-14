package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const migrationFixture = `
SYSWARDEN_ENTERPRISE_MODE="n"
SYSWARDEN_FIREWALL_BACKEND="keep"
SYSWARDEN_SSH_PORT="2222"
SYSWARDEN_WHITELIST_INFRA="y"
SYSWARDEN_WHITELIST_IPS="192.0.2.10, 2001:db8::10"
SYSWARDEN_LAN_SUBNETS="10.0.0.0/8 192.168.0.0/16"
SYSWARDEN_ENABLE_GEO="y"
SYSWARDEN_GEO_CODES="ru cn"
SYSWARDEN_ENABLE_ASN="y"
SYSWARDEN_ASN_LIST="AS64500 AS64501"
SYSWARDEN_HONEYPORTS="23,6379"
APPLY_CIS_L2_HARDENING="y"
SYSWARDEN_HA_ENABLED="y"
SYSWARDEN_HA_PEER_IP="192.0.2.20"
SYSWARDEN_HA_PEER_PORT="62026"
SYSWARDEN_HA_TOKEN="example-shared-token"
SYSWARDEN_SIEM_ENABLED="y"
SYSWARDEN_SIEM_IP="192.0.2.30"
SYSWARDEN_SIEM_PORT="6514"
SYSWARDEN_SIEM_PROTO="tls"
SYSWARDEN_WEB_TOKEN="existing-user-token"
UNKNOWN_USER_KEY="must-not-change-the-input-file"
`

func TestParseFromMemoryLegacyInlineCommentBehavior_SW_CFG_002(t *testing.T) {
	t.Parallel()
	migrator := &Migrator{}
	parsed, err := migrator.ParseFromMemory(`
# comment
KEY_ONE="value"
		KEY_TWO="second" # inline comment
INVALID
=ignored
`)
	if err != nil {
		t.Fatalf("ParseFromMemory() error = %v", err)
	}
	if parsed["KEY_ONE"] != "value" {
		t.Errorf("KEY_ONE = %q", parsed["KEY_ONE"])
	}
	// This assertion intentionally records the legacy quote residue. It must be
	// inverted when the parser is corrected under SW-CFG-002.
	if parsed["KEY_TWO"] != `second"` {
		t.Errorf("KEY_TWO = %q; expected the tracked legacy inline-comment behavior", parsed["KEY_TWO"])
	}
	if _, exists := parsed["INVALID"]; exists {
		t.Error("malformed line was accepted")
	}
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

func TestMigratorDryRunLegacyDirectorySideEffect_SW_CFG_002(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	if err := os.WriteFile(source, []byte(migrationFixture), 0600); err != nil {
		t.Fatal(err)
	}

	migrator := &Migrator{SourcePath: source, OutputDir: output, DryRun: true}
	if err := migrator.Run(); err != nil {
		t.Fatalf("Migrator.Run() dry-run error = %v", err)
	}
	// The current dry-run creates the directory hierarchy but no files. This
	// side effect is tracked and must be removed when SW-CFG-002 is corrected.
	entries, err := os.ReadDir(filepath.Join(output, "modules"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dry-run created %d module files", len(entries))
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("dry-run changed source file: %v", err)
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
	if migrated.WebTUIPassword != "existing-user-token" {
		t.Fatalf("user override token changed: %q", migrated.WebTUIPassword)
	}
	// The legacy parser consumes APPLY_CIS_L2_HARDENING while the migrator
	// currently reads SYSWARDEN_CIS_L2. Preserve visibility of this known gap
	// until its compatible migration is implemented under SW-CFG-002.
	if !legacy.CISL2Hardening || migrated.CISL2Hardening {
		t.Fatalf("unexpected CIS L2 compatibility baseline: legacy=%t migrated=%t", legacy.CISL2Hardening, migrated.CISL2Hardening)
	}
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
