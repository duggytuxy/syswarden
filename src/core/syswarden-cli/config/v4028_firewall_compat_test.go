package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func installHistoricalDefaultFirewallCompatibilityTestGlobals(t *testing.T) {
	t.Helper()
	previousOwner := historicalDefaultFirewallCompatibilityOwner
	previousPublisher := publishHistoricalDefaultFirewallCompatibility
	historicalDefaultFirewallCompatibilityOwner = func() (uint32, uint32) {
		return uint32(os.Getuid()), uint32(os.Getgid()) // #nosec G115 -- host UID/GID are nonnegative kernel identifiers represented by the production uint32 contract
	}
	publishHistoricalDefaultFirewallCompatibility = replaceSecureFileAtomicallyIfUnchangedValidated
	t.Cleanup(func() {
		historicalDefaultFirewallCompatibilityOwner = previousOwner
		publishHistoricalDefaultFirewallCompatibility = previousPublisher
	})
	for _, key := range []string{
		"SYSWARDEN_CORE_FIREWALL_BACKEND",
		"SYSWARDEN_NETWORK_WIREGUARD_ENABLED",
	} {
		value, present := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
		key, value, present := key, value, present
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(key, value)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
}

func writeHistoricalDefaultFirewallCompatibilityFixture(t *testing.T) string {
	t.Helper()
	configDir := filepath.Join(t.TempDir(), "config")
	modulesDir := filepath.Join(configDir, "modules")
	if err := os.MkdirAll(modulesDir, 0750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(configDir, "config.toml"):   "schema_version = 1\n",
		filepath.Join(modulesDir, "00-core.toml"): historicalDefaultCoreModule,
		filepath.Join(modulesDir, "10-network.toml"): `[network.wireguard]
enabled = false
`,
		filepath.Join(modulesDir, "20-security.toml"): "# compatibility fixture security module\n",
		filepath.Join(modulesDir, "30-waap.toml"):     "# compatibility fixture WAAP module\n",
		filepath.Join(modulesDir, "40-integrations.toml"): `[integrations.ha]
enabled = false
peer_ips = []
peer_port = 62026
token = ""
`,
		filepath.Join(modulesDir, "99-user.toml"): `[user]
profile_name = "compatibility-test"
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0640); err != nil { // #nosec G306 -- private fixture must reproduce the deployed root-group-readable 0640 contract
			t.Fatal(err)
		}
	}
	return configDir
}

func readHistoricalDefaultCore(t *testing.T, configDir string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)) // #nosec G304 -- test temporary directory
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertNoHistoricalDefaultTransactionFiles(t *testing.T, configDir string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(configDir, "modules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "."+historicalDefaultCoreModuleName+".") {
			t.Fatalf("compatibility transaction residue: %s", entry.Name())
		}
	}
}

func TestHistoricalDefaultFirewallCompatibilityPinnedBytesAndDigests(t *testing.T) {
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(historicalDefaultCoreModule))); got != historicalDefaultCoreModuleSHA256 {
		t.Fatalf("v4.02.8 provenance fixture core digest = %s, want %s", got, historicalDefaultCoreModuleSHA256)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(historicalDefaultCompatibleCoreModule))); got != historicalDefaultCompatibleCoreModuleSHA256 {
		t.Fatalf("compatible core digest = %s, want %s", got, historicalDefaultCompatibleCoreModuleSHA256)
	}
	if got := bytes.Count([]byte(historicalDefaultCoreModule), []byte(`firewall_backend = "nftables"`)); got != 1 {
		t.Fatalf("historical backend assignment count = %d, want 1", got)
	}
	if got := bytes.Count([]byte(historicalDefaultCompatibleCoreModule), []byte(`firewall_backend = "keep"`)); got != 1 {
		t.Fatalf("compatible backend assignment count = %d, want 1", got)
	}
	if !bytes.Equal(
		bytes.Replace([]byte(historicalDefaultCoreModule), []byte(`firewall_backend = "nftables"`), []byte(`firewall_backend = "keep"`), 1),
		[]byte(historicalDefaultCompatibleCoreModule),
	) {
		t.Fatal("compatible core is not the unique backend-only byte replacement")
	}
}

func TestHistoricalDefaultFirewallCompatibilityCoreHasPinnedV4028Provenance(t *testing.T) {
	publishedDefault := readImmutableFixture(t, "legacy-ha-default.conf", v4028LegacyFixtureSHA256)
	legacyValues, err := (&Migrator{}).ParseFromMemory(string(publishedDefault))
	if err != nil {
		t.Fatalf("parse pinned v4.02.8 DefaultConfig fixture: %v", err)
	}
	rendered := renderPinnedV4028CoreFixture(legacyValues)
	if !bytes.Equal(rendered, []byte(historicalDefaultCoreModule)) {
		t.Fatalf(
			"historical core is not the byte-for-byte output of pinned v4.02.8 DefaultConfig and generateCore:\ngot=%q\nwant=%q",
			rendered,
			historicalDefaultCoreModule,
		)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(rendered)); got != historicalDefaultCoreModuleSHA256 {
		t.Fatalf("rendered pinned v4.02.8 core digest = %s, want %s", got, historicalDefaultCoreModuleSHA256)
	}
}

// renderPinnedV4028CoreFixture mirrors generateCore in the immutable,
// digest-checked v4.02.8 migrator source validated by
// TestV4028CompatibilityFixturesHavePinnedRepositoryProvenance_SW_CFG_001. It
// remains local so changes to the current generator cannot rewrite history.
func renderPinnedV4028CoreFixture(oldConfig map[string]string) []byte {
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
	return []byte(`# [00] CORE SYSTEM CONFIGURATION
# Priority: 00 (loaded first, lowest precedence)

[core]
# Supported backends (RHEL/Alma/Fedora ONLY): "nftables", "iptables", "keep"
firewall_backend = "` + get("SYSWARDEN_FIREWALL_BACKEND", "keep") + `"

# Boolean values: true or false (no quotes)
hardening_enabled = ` + getBool("SYSWARDEN_HARDENING", "false") + `
cis_l2_hardening = ` + getBool("SYSWARDEN_CIS_L2", "false") + `
secure_wipe_conf = ` + getBool("SYSWARDEN_SECURE_WIPE_CONF", "false") + `

# SSH Port string (e.g. "2222")
ssh_port = "` + get("SYSWARDEN_SSH_PORT", "") + `"
`)
}

func TestHistoricalDefaultFirewallCompatibilityCurrentInitializeDefaultsIsNotApplicable(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	configDir := filepath.Join(t.TempDir(), "current-defaults")
	if err := InitializeDefaults(configDir); err != nil {
		t.Fatalf("InitializeDefaults() error = %v", err)
	}
	before := readHistoricalDefaultCore(t, configDir)
	if bytes.Equal(before, []byte(historicalDefaultCoreModule)) ||
		bytes.Equal(before, []byte(historicalDefaultCompatibleCoreModule)) {
		t.Fatal("current InitializeDefaults unexpectedly reproduced the historical byte family")
	}
	plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
	if err != nil || plan != nil {
		t.Fatalf("current InitializeDefaults inspection = (%#v, %v), want no plan", plan, err)
	}
	if after := readHistoricalDefaultCore(t, configDir); !bytes.Equal(after, before) {
		t.Fatal("non-applicable current default inspection changed 00-core.toml")
	}
}

func TestHistoricalDefaultFirewallCompatibilityPublishesAtomicallyAndIsIdempotent(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
	unrelatedPath := filepath.Join(configDir, "modules", "10-network.toml")
	unrelatedBefore, err := os.ReadFile(unrelatedPath) // #nosec G304 -- test temporary directory
	if err != nil {
		t.Fatal(err)
	}
	coreBefore, err := os.Stat(filepath.Join(configDir, "modules", historicalDefaultCoreModuleName))
	if err != nil {
		t.Fatal(err)
	}

	plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
	if err != nil {
		t.Fatalf("InspectHistoricalDefaultFirewallCompatibility() error = %v", err)
	}
	if plan == nil {
		t.Fatal("fixture containing the pinned v4.02.8 00-core bytes did not produce a historical-family compatibility plan")
	}
	if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCoreModule)) {
		t.Fatal("inspection mutated the historical core module")
	}
	hostRevalidations := 0
	if err := ApplyHistoricalDefaultFirewallCompatibility(plan, func() error {
		hostRevalidations++
		return nil
	}); err != nil {
		t.Fatalf("ApplyHistoricalDefaultFirewallCompatibility() error = %v", err)
	}
	if hostRevalidations != 3 {
		t.Fatalf("successful host revalidations = %d, want 3 transaction barriers", hostRevalidations)
	}
	if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCompatibleCoreModule)) {
		t.Fatalf("published core = %q", got)
	}
	coreAfter, err := os.Stat(filepath.Join(configDir, "modules", historicalDefaultCoreModuleName))
	if err != nil {
		t.Fatal(err)
	}
	if coreAfter.Mode().Perm() != 0640 {
		t.Fatalf("published mode = %#o, want 0640", coreAfter.Mode().Perm())
	}
	beforeUID, beforeGID, beforeOK := fileOwnerUIDGID(coreBefore)
	afterUID, afterGID, afterOK := fileOwnerUIDGID(coreAfter)
	if !beforeOK || !afterOK || beforeUID != afterUID || beforeGID != afterGID {
		t.Fatalf("published owner changed from %d:%d to %d:%d", beforeUID, beforeGID, afterUID, afterGID)
	}
	stat, ok := coreAfter.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		t.Fatalf("published link count = %v, want 1", stat.Nlink)
	}
	unrelatedAfter, err := os.ReadFile(unrelatedPath) // #nosec G304 -- test temporary directory
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unrelatedBefore, unrelatedAfter) {
		t.Fatal("compatibility publication changed an unrelated module")
	}
	second, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
	if err != nil || second != nil {
		t.Fatalf("idempotent inspection = (%#v, %v), want no plan", second, err)
	}
	assertNoHistoricalDefaultTransactionFiles(t, configDir)
}

func TestHistoricalDefaultFirewallCompatibilityRejectsNonExactOrAmbiguousInputs(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T, configDir string)
	}{
		{
			name: "one byte core drift",
			mutate: func(t *testing.T, configDir string) {
				path := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
				content := append([]byte(nil), []byte(historicalDefaultCoreModule)...)
				content[0] = '!'
				if err := os.WriteFile(path, content, 0640); err != nil { // #nosec G306 -- private adversarial fixture must preserve the attested 0640 mode
					t.Fatal(err)
				}
			},
		},
		{
			name: "fresh nftables content",
			mutate: func(t *testing.T, configDir string) {
				path := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
				content := strings.Replace(historicalDefaultCoreModule, "# [00] CORE SYSTEM CONFIGURATION", "# fresh configuration", 1)
				if err := os.WriteFile(path, []byte(content), 0640); err != nil { // #nosec G306 -- private adversarial fixture must preserve the attested 0640 mode
					t.Fatal(err)
				}
			},
		},
		{
			name: "already compatible",
			mutate: func(t *testing.T, configDir string) {
				path := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
				if err := os.WriteFile(path, []byte(historicalDefaultCompatibleCoreModule), 0640); err != nil { // #nosec G306 -- private compatibility fixture must reproduce the deployed 0640 mode
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			test.mutate(t, configDir)
			before := readHistoricalDefaultCore(t, configDir)
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err != nil || plan != nil {
				t.Fatalf("non-exact inspection = (%#v, %v), want no plan", plan, err)
			}
			if after := readHistoricalDefaultCore(t, configDir); !bytes.Equal(after, before) {
				t.Fatal("non-applicable inspection changed the core module")
			}
		})
	}
}

func TestHistoricalDefaultFirewallCompatibilityRejectsUnsafeSemantics(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T, configDir string)
		want   string
	}{
		{
			name: "wireguard enabled",
			mutate: func(t *testing.T, configDir string) {
				content := `[network.wireguard]
enabled = true
port = "51820"
subnet = "10.20.0.0/24"
`
				if err := os.WriteFile(filepath.Join(configDir, "modules", "10-network.toml"), []byte(content), 0640); err != nil { // #nosec G306 -- private semantic fixture must reproduce the deployed 0640 mode
					t.Fatal(err)
				}
			},
			want: "refuses enabled WireGuard",
		},
		{
			name: "backend module override",
			mutate: func(t *testing.T, configDir string) {
				content := "[core]\nfirewall_backend = \"nftables\"\n"
				if err := os.WriteFile(filepath.Join(configDir, "modules", "99-user.toml"), []byte(content), 0640); err != nil { // #nosec G306 -- private semantic fixture must reproduce the deployed 0640 mode
					t.Fatal(err)
				}
			},
			want: "refuses firewall backend override",
		},
		{
			name: "backend master override",
			mutate: func(t *testing.T, configDir string) {
				content := "schema_version = 1\n[core]\nfirewall_backend = \"nftables\"\n"
				if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(content), 0640); err != nil { // #nosec G306 -- private semantic fixture must reproduce the deployed 0640 mode
					t.Fatal(err)
				}
			},
			want: "refuses a master firewall backend override",
		},
		{
			name: "missing required module",
			mutate: func(t *testing.T, configDir string) {
				if err := os.Remove(filepath.Join(configDir, "modules", "30-waap.toml")); err != nil {
					t.Fatal(err)
				}
			},
			want: "configuration is incomplete",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			test.mutate(t, configDir)
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err == nil || plan != nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unsafe semantic inspection = (%#v, %v), want %q", plan, err, test.want)
			}
			if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCoreModule)) {
				t.Fatal("semantic refusal changed the core module")
			}
		})
	}
}

func TestHistoricalDefaultFirewallCompatibilityRejectsEnvironmentOverrides(t *testing.T) {
	for _, key := range []string{
		"SYSWARDEN_CORE_FIREWALL_BACKEND",
		"SYSWARDEN_NETWORK_WIREGUARD_ENABLED",
	} {
		t.Run(key, func(t *testing.T) {
			installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			if err := os.Setenv(key, "false"); err != nil {
				t.Fatal(err)
			}
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err == nil || plan != nil || !strings.Contains(err.Error(), "refuses environment override "+key) {
				t.Fatalf("environment override inspection = (%#v, %v)", plan, err)
			}
		})
	}
}

func TestHistoricalDefaultFirewallCompatibilityRejectsUnsafeMetadata(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T, configDir string)
	}{
		{
			name: "wrong exact mode",
			mutate: func(t *testing.T, configDir string) {
				if err := os.Chmod(filepath.Join(configDir, "modules", historicalDefaultCoreModuleName), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			mutate: func(t *testing.T, configDir string) {
				target := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
				if err := os.Link(target, filepath.Join(configDir, "modules", "core-hardlink")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, configDir string) {
				target := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
				outside := filepath.Join(t.TempDir(), "outside.toml")
				if err := os.WriteFile(outside, []byte(historicalDefaultCoreModule), 0640); err != nil { // #nosec G306 -- private symlink target must reproduce the attested 0640 mode
					t.Fatal(err)
				}
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			test.mutate(t, configDir)
			if plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir); err == nil || plan != nil {
				t.Fatalf("unsafe metadata inspection = (%#v, %v), want refusal", plan, err)
			}
		})
	}

	t.Run("wrong owner", func(t *testing.T) {
		configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
		previous := historicalDefaultFirewallCompatibilityOwner
		historicalDefaultFirewallCompatibilityOwner = func() (uint32, uint32) {
			return uint32(os.Getuid()) + 1, uint32(os.Getgid()) // #nosec G115 -- host UID/GID are nonnegative kernel identifiers and +1 deliberately models a wrong owner
		}
		t.Cleanup(func() { historicalDefaultFirewallCompatibilityOwner = previous })
		if plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir); err == nil || plan != nil {
			t.Fatalf("wrong owner inspection = (%#v, %v), want refusal", plan, err)
		}
	})
}

func TestHistoricalDefaultFirewallCompatibilityRejectsPreCommitRaces(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	tests := []struct {
		name   string
		mutate func(t *testing.T, configDir string)
	}{
		{
			name: "content",
			mutate: func(t *testing.T, configDir string) {
				path := filepath.Join(configDir, "modules", "10-network.toml")
				if err := os.WriteFile(path, []byte("# concurrent content change\n"), 0640); err != nil { // #nosec G306 -- private race fixture must preserve the attested 0640 mode
					t.Fatal(err)
				}
			},
		},
		{
			name: "metadata",
			mutate: func(t *testing.T, configDir string) {
				if err := os.Chmod(filepath.Join(configDir, "modules", "10-network.toml"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "inventory",
			mutate: func(t *testing.T, configDir string) {
				if err := os.WriteFile(filepath.Join(configDir, "modules", "15-race.toml"), []byte("# race\n"), 0640); err != nil { // #nosec G306 -- private inventory-race fixture must reproduce the deployed 0640 mode
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err != nil || plan == nil {
				t.Fatalf("inspection = (%#v, %v)", plan, err)
			}
			test.mutate(t, configDir)
			if err := ApplyHistoricalDefaultFirewallCompatibility(plan, func() error { return nil }); err == nil {
				t.Fatal("compatibility apply accepted a pre-commit race")
			}
			if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCoreModule)) {
				t.Fatal("pre-commit race changed the core module")
			}
			assertNoHistoricalDefaultTransactionFiles(t, configDir)
		})
	}
}

func TestHistoricalDefaultFirewallCompatibilityRollsBackPublicationRaces(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	tests := []struct {
		name string
		hook func(
			t *testing.T,
			configDir string,
			prePublish func() error,
			postCommit func() error,
		) (func() error, func() error)
	}{
		{
			name: "pre-publication unrelated module",
			hook: func(t *testing.T, configDir string, prePublish, postCommit func() error) (func() error, func() error) {
				return func() error {
					path := filepath.Join(configDir, "modules", "10-network.toml")
					if err := os.WriteFile(path, []byte("# pre-publication race\n"), 0640); err != nil { // #nosec G306 -- private publication-race fixture must preserve the attested 0640 mode
						t.Fatal(err)
					}
					return prePublish()
				}, postCommit
			},
		},
		{
			name: "post-publication target content",
			hook: func(t *testing.T, configDir string, prePublish, postCommit func() error) (func() error, func() error) {
				return prePublish, func() error {
					path := filepath.Join(configDir, "modules", historicalDefaultCoreModuleName)
					if err := os.WriteFile(path, []byte("# post-publication race\n"), 0640); err != nil { // #nosec G306 -- private publication-race fixture must preserve the attested 0640 mode
						t.Fatal(err)
					}
					return postCommit()
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err != nil || plan == nil {
				t.Fatalf("inspection = (%#v, %v)", plan, err)
			}
			publishHistoricalDefaultFirewallCompatibility = func(
				directory, name string,
				content []byte,
				expected *secureFileIdentity,
				preCommit, prePublish, postCommit func() error,
			) error {
				wrappedPrePublish, wrappedPostCommit := test.hook(t, configDir, prePublish, postCommit)
				return replaceSecureFileAtomicallyIfUnchangedValidated(
					directory, name, content, expected, preCommit, wrappedPrePublish, wrappedPostCommit,
				)
			}
			if err := ApplyHistoricalDefaultFirewallCompatibility(plan, func() error { return nil }); err == nil {
				t.Fatal("compatibility apply accepted a publication race")
			}
			if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCoreModule)) {
				t.Fatalf("publication race did not restore historical core: %q", got)
			}
			assertNoHistoricalDefaultTransactionFiles(t, configDir)
			publishHistoricalDefaultFirewallCompatibility = replaceSecureFileAtomicallyIfUnchangedValidated
		})
	}
}

func TestHistoricalDefaultFirewallCompatibilityRollsBackHostStateRaces(t *testing.T) {
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	for _, test := range []struct {
		name   string
		failAt int
	}{
		{name: "before quarantine", failAt: 1},
		{name: "while target quarantined", failAt: 2},
		{name: "after publication", failAt: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
			plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
			if err != nil || plan == nil {
				t.Fatalf("inspection = (%#v, %v)", plan, err)
			}
			hostDrift := errors.New("historical default host state drift")
			hostRevalidations := 0
			err = ApplyHistoricalDefaultFirewallCompatibility(plan, func() error {
				hostRevalidations++
				if hostRevalidations == test.failAt {
					return hostDrift
				}
				return nil
			})
			if err == nil || !errors.Is(err, hostDrift) {
				t.Fatalf("host drift publication error = %v", err)
			}
			if hostRevalidations != test.failAt {
				t.Fatalf("host revalidations = %d, want failure at %d", hostRevalidations, test.failAt)
			}
			if got := readHistoricalDefaultCore(t, configDir); !bytes.Equal(got, []byte(historicalDefaultCoreModule)) {
				t.Fatalf("host drift did not restore historical core: %q", got)
			}
			assertNoHistoricalDefaultTransactionFiles(t, configDir)
		})
	}
}

func TestApplyHistoricalDefaultFirewallCompatibilityRejectsInvalidPlan(t *testing.T) {
	if err := ApplyHistoricalDefaultFirewallCompatibility(nil, func() error { return nil }); err == nil {
		t.Fatal("nil compatibility plan was accepted")
	}
	if err := ApplyHistoricalDefaultFirewallCompatibility(&HistoricalDefaultFirewallCompatibilityPlan{}, func() error { return nil }); err == nil {
		t.Fatal("forged empty compatibility plan was accepted")
	}
	configDir := writeHistoricalDefaultFirewallCompatibilityFixture(t)
	installHistoricalDefaultFirewallCompatibilityTestGlobals(t)
	plan, err := InspectHistoricalDefaultFirewallCompatibility(configDir)
	if err != nil || plan == nil {
		t.Fatalf("inspection = (%#v, %v)", plan, err)
	}
	if err := ApplyHistoricalDefaultFirewallCompatibility(plan, nil); err == nil {
		t.Fatal("compatibility apply accepted a nil host revalidation")
	}
}
