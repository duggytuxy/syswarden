package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func effectText(effects []ConfigurationEffect) string {
	var text strings.Builder
	for _, effect := range effects {
		fmt.Fprintf(&text, "%s: %s\n", effect.Area, effect.Detail)
	}
	return text.String()
}

func TestConfigurationPreviewPreservesFilesMetadataAndRuntime(t *testing.T) {
	root, _ := initializedUserModule(t)
	before, _, err := captureModuleEdit(root, userTOMLTarget())
	if err != nil {
		t.Fatal(err)
	}
	files := intentFixtureFiles(t, root)
	global, load := GlobalConfig, CurrentLoadState()
	preview, err := PreviewConfiguration(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if preview.InputCount != 7 || !strings.Contains(effectText(preview.Effects), "No managed threat list") || !strings.Contains(effectText(preview.Effects), "VPN setup is not selected") {
		t.Fatalf("wrong fresh preview: %+v", preview)
	}
	if err := before.revalidate(root, false, nil); err != nil {
		t.Fatal("preview changed metadata:", err)
	}
	if !reflect.DeepEqual(files, intentFixtureFiles(t, root)) || GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) {
		t.Fatal("preview changed files/runtime")
	}
}

func TestConfigurationPreviewUsesMergedOverridesWithoutDisclosingValues(t *testing.T) {
	root, _ := initializedUserModule(t)
	raw := []byte("[user]\nprofile_name=\"SECRET-NAME\"\n[network.blocklists]\nlist_choice=\"2\"\n[private_extension]\ncredential=\"SECRET-CREDENTIAL\"\n")
	if err := writeSecureFileAtomically(filepath.Join(root, "modules"), userModuleName, raw); err != nil {
		t.Fatal(err)
	}
	if err := writeSecureFileAtomically(filepath.Join(root, "modules"), "05-ssh.toml", []byte("[ssh]\nhardening=\"forwarding\"\n")); err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewConfiguration(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	text := effectText(preview.Effects)
	if !strings.Contains(text, "Critical Data-Shield") || !strings.Contains(text, "forwarding profile is selected") || preview.UnknownKeyCount != 1 || preview.InputCount != 8 {
		t.Fatalf("wrong merged preview: %+v", preview)
	}
	wire, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"SECRET-", "private_extension", root} {
		if strings.Contains(string(wire), private) {
			t.Fatal("preview disclosed private input", private)
		}
	}
	if err := writeSecureFileAtomically(filepath.Join(root, "modules"), "zz-admin.toml", []byte("[network.blocklists]\nlist_choice=\"4\"\n")); err != nil {
		t.Fatal(err)
	}
	later, err := PreviewConfiguration(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(effectText(later.Effects), "No managed threat list") {
		t.Fatal("late lexical administrator override lost")
	}
}

func TestConfigurationPreviewRefusesInvalidIncompleteAndPendingInputs(t *testing.T) {
	for _, scenario := range []string{"invalid", "missing-fresh", "pending-edit", "pending-migration", "symlink", "oversize", "environment"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			switch scenario {
			case "invalid":
				if err := writeSecureFileAtomically(filepath.Join(root, "modules"), userModuleName, []byte("[broken\n")); err != nil {
					t.Fatal(err)
				}
			case "missing-fresh":
				if err := os.Remove(filepath.Join(root, "modules", "10-network.toml")); err != nil {
					t.Fatal(err)
				}
			case "pending-edit":
				if err := writeModuleFixture(filepath.Join(root, moduleEditIntentName), []byte("invalid intent must remain"), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-migration":
				if err := writeModuleFixture(filepath.Join(root, migrationMarkerName), []byte("pending"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("99-user.toml", filepath.Join(root, "modules", "zz-link.toml")); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := writeModuleFixture(filepath.Join(root, "modules", userModuleName), []byte(strings.Repeat("#", int(maximumUserModuleSize)+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "environment":
				t.Setenv("SYSWARDEN_NETWORK_POLICY_MODE", "host")
			}
			before := intentFixtureFiles(t, root)
			if _, err := PreviewConfiguration(context.Background(), root); err == nil {
				t.Fatal("unsafe preview succeeded")
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) {
				t.Fatal("refused preview changed inputs")
			}
		})
	}
}

func TestConfigurationPreviewContextAndDirectoryBounds(t *testing.T) {
	root, _ := initializedUserModule(t)
	for _, ctx := range []context.Context{nil, cancelledPreviewContext()} {
		if _, err := PreviewConfiguration(ctx, root); err == nil {
			t.Fatal("invalid context accepted")
		}
	}
	for _, path := range []string{"relative", root + "/../config", root + "/missing"} {
		if _, err := PreviewConfiguration(context.Background(), path); err == nil {
			t.Fatal("invalid root accepted")
		}
	}
	for _, toml := range []bool{false, true} {
		t.Run(fmt.Sprint(toml), func(t *testing.T) {
			root, _ := initializedUserModule(t)
			modules, err := os.OpenRoot(filepath.Join(root, "modules"))
			if err != nil {
				t.Fatal(err)
			}
			defer modules.Close()
			for i := 0; i < maximumModuleEditInputs+16; i++ {
				name := fmt.Sprintf("extra-%03d", i)
				if toml {
					name += ".toml"
				}
				if err := modules.WriteFile(name, []byte("# extra\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := PreviewConfiguration(context.Background(), root); err == nil || !strings.Contains(err.Error(), "inventory limit") {
				t.Fatalf("unbounded preview inventory: %v", err)
			}
		})
	}
}
func cancelledPreviewContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestConfigurationEffectsDescribeSelectedAndDisabledHostEffects(t *testing.T) {
	c := &ModularConfig{}
	c.Network.PolicyMode = "host"
	c.Core.FirewallBackend = "nftables"
	c.Network.Blocklists.ListChoice = "3"
	c.Network.Wireguard.Enabled = true
	c.Network.Geo.Enabled = true
	c.Network.ASN.Enabled = true
	c.Network.Blocklists.UseSpamhaus = true
	c.Network.WhitelistIPs = []string{"192.0.2.10"}
	c.Security.DetectionEnabled = true
	c.WAAP.Enabled = true
	c.WAAP.EnforcementMode = "audit"
	c.WAAP.LogBridgeEnabled = true
	c.Integrations.SIEM.Enabled = true
	c.Integrations.Wazuh.Enabled = true
	c.Integrations.Webhooks.Enabled = true
	c.Integrations.AbuseIPDB.Enabled = true
	c.Integrations.HA.Enabled = true
	c.Integrations.BunkerWeb.Enabled = true
	c.Core.Hardening = true
	c.Core.CISL2Hardening = true
	c.SSH.Hardening = "cis"
	c.Network.Blocklists.CustomURL = "https://private.invalid/secret"
	c.Integrations.AbuseIPDB.APIKey = "PRIVATE-KEY"
	c.Integrations.SIEM.IP = "192.0.2.11"
	text := effectText(configurationEffects(c))
	for _, part := range []string{"restrict inbound", "nftables", "Custom feeds", "Spamhaus", "IPv4 and IPv6", "1 configured whitelist", "forwarding", "WAAP audit", "rsyslog", "receiver authentication", "independently installed Wazuh", "connectivity notification", "core reads its API key from TOML", "transfer policy data", "independent from native HA", "CIS profile", "OS hardening selected: true"} {
		if !strings.Contains(text, part) {
			t.Errorf("missing effect %q", part)
		}
	}
	for _, private := range []string{"private.invalid", "PRIVATE-KEY", "192.0.2."} {
		if strings.Contains(text, private) {
			t.Fatal("private value in effects", private)
		}
	}
	c.Core.EnterpriseMode = true
	if text := effectText(configurationEffects(c)); !strings.Contains(text, "Reporting is disabled by selection or enterprise mode") || strings.Contains(text, "core reads its API key from TOML") {
		t.Fatal("enterprise reporting override omitted")
	}
}

func TestModuleProposalEffectReviewIsBoundToCandidateAndCopied(t *testing.T) {
	root, edit, _, _ := proposalFixture(t)
	p, err := edit.Prepare(context.Background(), []byte("[network.blocklists]\nlist_choice=\"2\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	review := p.Review()
	if !strings.Contains(effectText(review.Effects), "Critical Data-Shield") {
		t.Fatal("candidate effects missing")
	}
	review.Effects[0].Detail = "tampered"
	if strings.Contains(effectText(p.Review().Effects), "tampered") {
		t.Fatal("review aliases retained approval")
	}
	current, err := PreviewConfiguration(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(effectText(current.Effects), "No managed threat list") {
		t.Fatal("preview published unapproved candidate")
	}
}

func TestConfigurationPreviewAndEditorUseTOMLSaaSAliasPrecedence(t *testing.T) {
	for _, scenario := range []struct {
		name, content, environment, value string
		want                              bool
	}{
		{name: "legacy-true", content: "[integrations.saas]\nenabled=true\n", want: true},
		{name: "legacy-false", content: "[integrations.saas]\nenabled=false\n"},
		{name: "official-false-wins", content: "[network.saas]\nallow_monitors=false\n[integrations.saas]\nenabled=true\n"},
		{name: "official-true-wins", content: "[network.saas]\nallow_monitors=true\n[integrations.saas]\nenabled=false\n", want: true},
		{name: "no-selection", content: "# no SaaS selection\n"},
		{name: "official-env-does-not-hide-alias", content: "[integrations.saas]\nenabled=true\n", environment: "SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS", value: "false", want: true},
		{name: "legacy-env-does-not-change-alias", content: "[integrations.saas]\nenabled=true\n", environment: "SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", value: "false", want: true},
		{name: "official-env-does-not-enable", content: "# no SaaS selection\n", environment: "SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS", value: "true"},
		{name: "legacy-env-does-not-enable", content: "# no SaaS selection\n", environment: "SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", value: "true"},
		{name: "official-false-not-overlaid", content: "[network.saas]\nallow_monitors=false\n[integrations.saas]\nenabled=true\n", environment: "SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS", value: "true"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			preserveOperatorPolicyGlobals(t)
			root, _ := initializedUserModule(t)
			// Keep a complete historical modular tree with no official SaaS
			// assignment, so each case explicitly supplies its own precedence.
			for _, relative := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml"} {
				path := filepath.Join(root, relative)
				raw, err := os.ReadFile(path) // #nosec G304 -- fixed fixture paths within the test-owned root
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.ReplaceAll(string(raw), "unconfigured-v1", ""), "\n")
				for index, line := range lines {
					if strings.HasPrefix(strings.TrimSpace(line), "allow_monitors =") {
						lines[index] = "# official SaaS selection omitted by this fixture"
					}
				}
				if err := writeModuleFixture(path, []byte(strings.Join(lines, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeModuleFixture(filepath.Join(root, "modules", userModuleName), []byte(scenario.content), 0600); err != nil {
				t.Fatal(err)
			}
			if scenario.environment != "" {
				t.Setenv(scenario.environment, scenario.value)
			}
			before := intentFixtureFiles(t, root)
			global, load := GlobalConfig, CurrentLoadState()
			preview, err := PreviewConfiguration(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("SaaS allowlists selected: %t", scenario.want)
			if !strings.Contains(strings.Join(preview.ModulePlan, "\n"), want) {
				t.Fatalf("preview lost TOML alias precedence: %v", preview.ModulePlan)
			}
			edit, err := BeginUserModuleEdit(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			proposal, err := edit.Prepare(t.Context(), []byte(scenario.content+"# reviewed candidate\n"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(proposal.Review().ModulePlan, "\n"), want) {
				t.Fatal("editor review lost TOML alias precedence")
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) || GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) {
				t.Fatal("read-only alias review changed source or globals")
			}
			if scenario.environment == "" {
				if err := proposal.Publish(t.Context(), proposal.Review().ApprovalID, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
				if err := ParseConfigForInspection(root); err != nil {
					t.Fatal(err)
				}
				if GlobalConfig.AllowSaaSMonitors != scenario.want {
					t.Fatal("published editor proposal differs from reviewed TOML semantics")
				}
			}
		})
	}
}
