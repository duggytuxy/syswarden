package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModularWhitelistNeutralizesRetiredZeroEntriesAcrossSources_SW_SEC_M1(t *testing.T) {
	whitelistBlock := `[network]
	whitelist_ips = ["0.0.0.0", "0.0.0.0", "10.20.30.40", "0.0.0.0/32", "0.0.0.0/32", "192.0.2.0/24", "fd00:1234::/64"]
`
	for _, source := range []string{"master", "module"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			masterContent := minimalModularConfig
			if source == "master" {
				masterContent += whitelistBlock
			}
			if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(masterContent), 0600); err != nil {
				t.Fatal(err)
			}
			if source == "module" {
				modules := filepath.Join(root, "modules")
				if err := os.Mkdir(modules, 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(modules, "10-network.toml"), []byte(whitelistBlock), 0600); err != nil {
					t.Fatal(err)
				}
			}

			previousConfig := GlobalConfig
			previousLogOutput := log.Writer()
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() {
				GlobalConfig = previousConfig
				log.SetOutput(previousLogOutput)
			})

			if err := loadModularConfig(root); err != nil {
				t.Fatalf("loadModularConfig() error = %v", err)
			}
			if got, want := GlobalConfig.WhitelistIPs, "10.20.30.40 192.0.2.0/24 fd00:1234::/64"; got != want {
				t.Fatalf("effective modular whitelist = %q, want %q", got, want)
			}
			for _, retired := range []string{"0.0.0.0", "0.0.0.0/32"} {
				message := "Ignoring deprecated network.whitelist_ips entry \"" + retired + "\";"
				if count := strings.Count(logs.String(), message); count != 1 {
					t.Fatalf("modular compatibility log = %q, want observable neutralization for %s", logs.String(), retired)
				}
			}
		})
	}
}

func TestModularWhitelistEnvironmentIsBoundWithoutTOMLKey_SW_SEC_M1(t *testing.T) {
	t.Setenv(
		"SYSWARDEN_NETWORK_WHITELIST_IPS",
		"0.0.0.0,10.20.30.40,0.0.0.0/32,192.0.2.0/24,fd00:1234::/64",
	)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(minimalModularConfig), 0600); err != nil {
		t.Fatal(err)
	}

	previousConfig := GlobalConfig
	previousLogOutput := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() {
		GlobalConfig = previousConfig
		log.SetOutput(previousLogOutput)
	})

	if err := loadModularConfig(root); err != nil {
		t.Fatalf("loadModularConfig() environment compatibility error = %v", err)
	}
	if got, want := GlobalConfig.WhitelistIPs, "10.20.30.40 192.0.2.0/24 fd00:1234::/64"; got != want {
		t.Fatalf("effective environment whitelist = %q, want %q", got, want)
	}
	for _, retired := range []string{"0.0.0.0", "0.0.0.0/32"} {
		if count := strings.Count(logs.String(), "Ignoring deprecated network.whitelist_ips entry \""+retired+"\";"); count != 1 {
			t.Fatalf("environment compatibility log = %q, want one warning for %s", logs.String(), retired)
		}
	}

	got, found, err := GetValidatedModularValue(root, "network.whitelist_ips")
	if err != nil || !found {
		t.Fatalf("GetValidatedModularValue() = %q, %t, %v", got, found, err)
	}
	if want := `["10.20.30.40","192.0.2.0/24","fd00:1234::/64"]`; got != want {
		t.Fatalf("effective environment config-get whitelist = %q, want %q", got, want)
	}

	candidate, err := mergeHistoricalDefaultFirewallCandidate(
		root,
		[]byte(minimalModularConfig),
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("historical environment merge error = %v", err)
	}
	if got, want := strings.Join(candidate.Network.WhitelistIPs, " "), "10.20.30.40 192.0.2.0/24 fd00:1234::/64"; got != want {
		t.Fatalf("historical environment whitelist = %q, want %q", got, want)
	}
}

func TestModularWhitelistEnvironmentRejectsUnsafeNeighborWithoutTOMLKey_SW_SEC_M1(t *testing.T) {
	t.Setenv("SYSWARDEN_NETWORK_WHITELIST_IPS", "0.0.0.0/31")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(minimalModularConfig), 0600); err != nil {
		t.Fatal(err)
	}

	if err := loadModularConfig(root); err == nil {
		t.Fatal("runtime loader ignored an unsafe environment whitelist without a TOML key")
	}
	if _, _, err := GetValidatedModularValue(root, "network.whitelist_ips"); err == nil {
		t.Fatal("config-get ignored an unsafe environment whitelist without a TOML key")
	}
	if _, err := mergeHistoricalDefaultFirewallCandidate(root, []byte(minimalModularConfig), nil, nil); err == nil {
		t.Fatal("historical compatibility merge ignored an unsafe environment whitelist without a TOML key")
	}
}

func TestConfigGetPreservesAbsentWhitelistWithoutEnvironment_SW_SEC_M1(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(minimalModularConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if got, found, err := GetValidatedModularValue(root, "network.whitelist_ips"); err != nil || found || got != "" {
		t.Fatalf("GetValidatedModularValue(absent whitelist) = %q, %t, %v; want absent", got, found, err)
	}
}

func TestLegacyWhitelistNeutralizesRetiredZeroEntries_SW_SEC_M1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syswarden-auto.conf")
	content := `SYSWARDEN_HA_ENABLED=n
SYSWARDEN_WHITELIST_IPS="0.0.0.0 10.20.30.40 0.0.0.0/32 192.0.2.0/24"
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	previousConfig := GlobalConfig
	previousLogOutput := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer func() {
		GlobalConfig = previousConfig
		log.SetOutput(previousLogOutput)
	}()

	if err := loadOldConfig(path); err != nil {
		t.Fatalf("loadOldConfig() error = %v", err)
	}
	if got, want := GlobalConfig.WhitelistIPs, "10.20.30.40 192.0.2.0/24"; got != want {
		t.Fatalf("effective legacy whitelist = %q, want %q", got, want)
	}
	for _, retired := range []string{"0.0.0.0", "0.0.0.0/32"} {
		if !strings.Contains(logs.String(), "Ignoring deprecated network.whitelist_ips entry \""+retired+"\";") {
			t.Fatalf("legacy compatibility log = %q, want observable neutralization for %s", logs.String(), retired)
		}
	}
}

func TestReadOnlyConfigPathsNeutralizeRetiredZeroWhitelistEntries_SW_SEC_M1(t *testing.T) {
	root := t.TempDir()
	master := filepath.Join(root, "config.toml")
	content := minimalModularConfig + `[network]
whitelist_ips = ["0.0.0.0", "10.20.30.40", "0.0.0.0/32", "192.0.2.0/24", "fd00:1234::/64"]
`
	if err := os.WriteFile(master, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	report, err := ValidateModularConfig(root)
	if err != nil {
		t.Fatalf("ValidateModularConfig() error = %v", err)
	}
	joinedDiagnostics := strings.Join(report.DeprecatedKeys, "\n")
	for _, retired := range []string{"0.0.0.0", "0.0.0.0/32"} {
		if count := strings.Count(joinedDiagnostics, retiredUnspecifiedWhitelistDiagnostic(retired)); count != 1 {
			t.Fatalf("deprecated diagnostics = %q, want ignored %s entry", joinedDiagnostics, retired)
		}
	}
	if after, err := os.ReadFile(master); err != nil { // #nosec G304 -- master is a fixed configuration file beneath t.TempDir
		t.Fatal(err)
	} else if string(after) != content {
		t.Fatal("read-only configuration validation rewrote the retired whitelist entries")
	}

	got, found, err := GetValidatedModularValue(root, "network.whitelist_ips")
	if err != nil || !found {
		t.Fatalf("GetValidatedModularValue() = %q, %t, %v", got, found, err)
	}
	if want := `["10.20.30.40","192.0.2.0/24","fd00:1234::/64"]`; got != want {
		t.Fatalf("effective config-get whitelist = %q, want %q", got, want)
	}
	network, found, err := GetValidatedModularValue(root, "network")
	if err != nil || !found {
		t.Fatalf("GetValidatedModularValue(network) = %q, %t, %v", network, found, err)
	}
	if strings.Contains(network, `"0.0.0.0"`) || strings.Contains(network, `"0.0.0.0/32"`) ||
		!strings.Contains(network, `"10.20.30.40"`) {
		t.Fatalf("effective config-get network section retained retired whitelist policy: %s", network)
	}
}

func TestRetiredZeroWhitelistCompatibilityDoesNotMaskOtherErrors_SW_SEC_M1(t *testing.T) {
	root := t.TempDir()
	content := minimalModularConfig + `[network]
whitelist_ips = ["0.0.0.0", "127.0.0.1", "0.0.0.0/32"]
`
	if err := os.WriteFile(filepath.Join(root, "config.toml"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateModularConfig(root); err == nil {
		t.Fatal("read-only validation masked a non-retired unsafe whitelist entry")
	}
	if _, _, err := GetValidatedModularValue(root, "network.whitelist_ips"); err == nil {
		t.Fatal("config-get validation masked a non-retired unsafe whitelist entry")
	}
}

func TestLegacyMigrationDryRunNeutralizesRetiredZeroWhitelistEntries_SW_SEC_M1(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.conf")
	output := filepath.Join(root, "config")
	content := strings.Replace(
		migrationFixture,
		`SYSWARDEN_WHITELIST_IPS="192.0.2.10 2001:db8::10"`,
		`SYSWARDEN_WHITELIST_IPS="0.0.0.0 10.20.30.40 0.0.0.0/32 192.0.2.0/24"`,
		1,
	)
	if err := os.WriteFile(source, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	previousLogOutput := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)
	if err := (&Migrator{SourcePath: source, OutputDir: output, DryRun: true}).Run(); err != nil {
		t.Fatalf("Migrator.Run() compatibility dry-run error = %v", err)
	}
	for _, retired := range []string{"0.0.0.0", "0.0.0.0/32"} {
		message := "Ignoring deprecated network.whitelist_ips entry \"" + retired + "\";"
		if count := strings.Count(logs.String(), message); count != 1 {
			t.Fatalf("migration compatibility log = %q, want one warning for %s", logs.String(), retired)
		}
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("compatibility dry-run created destination state: %v", err)
	}
	if after, err := os.ReadFile(source); err != nil { // #nosec G304 -- source is a fixed legacy configuration file beneath t.TempDir
		t.Fatal(err)
	} else if string(after) != content {
		t.Fatal("compatibility dry-run changed its legacy source")
	}

	renderedNetwork, err := (&Migrator{}).generateNetwork(map[string]string{
		"SYSWARDEN_WHITELIST_IPS": "0.0.0.0 10.20.30.40 0.0.0.0/32 192.0.2.0/24",
	})
	if err != nil {
		t.Fatalf("generateNetwork() compatibility error = %v", err)
	}
	if strings.Contains(renderedNetwork, "0.0.0.0") {
		t.Fatalf("generated migration retained retired whitelist authority:\n%s", renderedNetwork)
	}
	if !strings.Contains(renderedNetwork, "10.20.30.40") || !strings.Contains(renderedNetwork, "192.0.2.0/24") {
		t.Fatalf("generated migration lost legitimate whitelist entries:\n%s", renderedNetwork)
	}

	invalidSource := filepath.Join(root, "invalid-legacy.conf")
	invalid := strings.Replace(content, `SYSWARDEN_SSH_PORT="2222"`, `SYSWARDEN_SSH_PORT="70000"`, 1)
	if err := os.WriteFile(invalidSource, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&Migrator{SourcePath: invalidSource, OutputDir: output, DryRun: true}).Run(); err == nil {
		t.Fatal("retired whitelist compatibility masked an invalid legacy SSH port")
	}
}

func TestValidatedUserEditToleratesExistingRetiredZeroWhitelistEntries_SW_SEC_M1(t *testing.T) {
	root, userPath := initializedUserModule(t)
	networkPath := filepath.Join(root, "modules", "10-network.toml")
	network, err := os.ReadFile(networkPath) // #nosec G304 -- networkPath is a fixed module filename beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	updatedNetwork := strings.Replace(
		string(network),
		"whitelist_ips = []",
		`whitelist_ips = ["0.0.0.0", "10.20.30.40", "0.0.0.0/32"]`,
		1,
	)
	if updatedNetwork == string(network) {
		t.Fatal("default network fixture has no empty whitelist assignment")
	}
	if err := os.WriteFile(networkPath, []byte(updatedNetwork), 0600); err != nil { // #nosec G703 -- networkPath is a fixed module filename beneath t.TempDir
		t.Fatal(err)
	}

	const user = "[user]\nprofile_name = \"compatibility-edit\"\n"
	if err := WriteValidatedUserModule(root, []byte(user)); err != nil {
		t.Fatalf("WriteValidatedUserModule() error = %v", err)
	}
	if after, err := os.ReadFile(networkPath); err != nil { // #nosec G304 -- networkPath is a fixed module filename beneath t.TempDir
		t.Fatal(err)
	} else if string(after) != updatedNetwork {
		t.Fatal("validated user edit rewrote an unrelated network module")
	}
	if after, err := os.ReadFile(userPath); err != nil { // #nosec G304 -- userPath is a fixed module filename beneath t.TempDir
		t.Fatal(err)
	} else if string(after) != user {
		t.Fatalf("published user module = %q, want %q", after, user)
	}
}

func TestValidatedUserEditPreservesHistoricalRetiredEntriesButRejectsNewOnes_SW_SEC_M1(t *testing.T) {
	root, userPath := initializedUserModule(t)
	historical := `[network]
whitelist_ips = ["0.0.0.0", "10.20.30.40", "0.0.0.0/32"]

[user]
profile_name = "historical"
`
	if err := os.WriteFile(userPath, []byte(historical), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SetValidatedProfileName(root, "upgraded"); err != nil {
		t.Fatalf("SetValidatedProfileName() with historical entries error = %v", err)
	}
	upgraded, err := os.ReadFile(userPath) // #nosec G304 -- userPath is a fixed module filename beneath t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(upgraded), `profile_name = "upgraded"`) ||
		!strings.Contains(string(upgraded), `"0.0.0.0"`) ||
		!strings.Contains(string(upgraded), `"0.0.0.0/32"`) {
		t.Fatalf("historical operator module was not preserved during upgrade edit:\n%s", upgraded)
	}
	got, found, err := GetValidatedModularValue(root, "network.whitelist_ips")
	if err != nil || !found {
		t.Fatalf("GetValidatedModularValue() = %q, %t, %v", got, found, err)
	}
	if want := `["10.20.30.40"]`; got != want {
		t.Fatalf("effective historical operator whitelist = %q, want %q", got, want)
	}

	before, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	added := strings.Replace(string(upgraded), `"0.0.0.0",`, `"0.0.0.0", "0.0.0.0",`, 1)
	if err := WriteValidatedUserModule(root, []byte(added)); err == nil || !strings.Contains(err.Error(), "cannot add retired network.whitelist_ips value") {
		t.Fatalf("WriteValidatedUserModule(new retired entry) error = %v", err)
	}
	after, err := os.Lstat(userPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("rejected retired whitelist addition replaced the operator module")
	}
	if unchanged, err := os.ReadFile(userPath); err != nil { // #nosec G304 -- userPath is a fixed module filename beneath t.TempDir
		t.Fatal(err)
	} else if string(unchanged) != string(upgraded) {
		t.Fatal("rejected retired whitelist addition changed the operator module bytes")
	}
}

func TestHistoricalFirewallCandidateNeutralizesRetiredZeroWhitelistEntries_SW_SEC_M1(t *testing.T) {
	whitelistModule := historicalDefaultFirewallModule{
		name: "10-network.toml",
		content: []byte(`[network]
whitelist_ips = ["0.0.0.0", "10.20.30.40", "0.0.0.0/32", "fd00:1234::/64"]
`),
	}
	candidate, err := mergeHistoricalDefaultFirewallCandidate(
		t.TempDir(),
		[]byte(minimalModularConfig),
		[]historicalDefaultFirewallModule{whitelistModule},
		nil,
	)
	if err != nil {
		t.Fatalf("mergeHistoricalDefaultFirewallCandidate() error = %v", err)
	}
	if got, want := strings.Join(candidate.Network.WhitelistIPs, " "), "10.20.30.40 fd00:1234::/64"; got != want {
		t.Fatalf("historical compatibility whitelist = %q, want %q", got, want)
	}
}
