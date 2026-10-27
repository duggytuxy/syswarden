package config

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestActivationPolicyCapturePreservesSourcesAndGlobalState(t *testing.T) {
	root, _ := initializedUserModule(t)
	before, _, err := captureModuleInputs(root, userTOMLTarget(), nil)
	if err != nil {
		t.Fatal(err)
	}
	files := intentFixtureFiles(t, root)
	global, load := GlobalConfig, CurrentLoadState()
	policy, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	review := policy.Review()
	if !isLowerHex(review.Digest, 64) || review.InputCount != 7 || !strings.Contains(effectText(review.Effects), "No managed threat list") {
		t.Fatalf("unexpected capture review: %+v", review)
	}
	effective, err := policy.Configuration(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if effective.InstallProfile != UnconfiguredInstallProfile || effective.ListChoice != "4" || effective.EnableWG || effective.WAAPEnabled || effective.Hardening {
		t.Fatal("inactive effective policy changed")
	}
	again, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil || again.Review().Digest != review.Digest {
		t.Fatal("unchanged capture digest is unstable", err)
	}
	if err := before.revalidate(root, false, nil); err != nil {
		t.Fatal("capture changed metadata", err)
	}
	if !reflect.DeepEqual(files, intentFixtureFiles(t, root)) || GlobalConfig != global || !reflect.DeepEqual(load, CurrentLoadState()) {
		t.Fatal("capture changed files or global load state")
	}
}

func TestActivationPolicyEffectiveMergeAndReturnedCopies(t *testing.T) {
	root, _ := initializedUserModule(t)
	content := "[network]\npolicy_mode='host'\n[network.blocklists]\nlist_choice='1'\n" +
		"[integrations.ha]\npeer_cert_sha256=['" + strings.Repeat("a", 64) + "']\n" +
		"[user]\nprofile_name='PRIVATE-NAME'\n" +
		"[private_extension]\ncredential='PRIVATE-CREDENTIAL'\n" +
		"[[operator_policy.rules]]\nid='operator-web'\nfamily='ipv4'\ndirection='ingress'\nprotocol='tcp'\ndestination_port=8443\nsource='192.0.2.0/24'\naction='accept'\n"
	if err := writeModuleFixture(filepath.Join(root, "modules", userModuleName), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeModuleFixture(filepath.Join(root, "modules", "zz-local.toml"), []byte("[network.blocklists]\nlist_choice='2'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	review := policy.Review()
	if review.InputCount != 8 || review.UnknownKeyCount != 1 || !strings.Contains(effectText(review.Effects), "Critical Data-Shield") {
		t.Fatalf("effective lexical override lost: %+v", review)
	}
	wire, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"PRIVATE-", "private_extension", "192.0.2.", root} {
		if strings.Contains(string(wire), private) {
			t.Fatal("review disclosed private input")
		}
	}
	first, err := policy.Configuration(t.Context())
	if err != nil || first.ListChoice != "2" || len(first.HAPeerCertSHA256) != 1 || len(first.OperatorPolicy.Rules) != 1 || first.operatorPolicySource == nil {
		t.Fatal("effective configuration or provenance is incomplete", err)
	}
	review.ModulePlan[0] = "changed"
	review.Effects[0].Detail = "changed"
	first.ListChoice = "4"
	first.HAPeerCertSHA256[0] = "changed"
	first.OperatorPolicy.Rules[0].Source = "198.51.100.0/24"
	first.operatorPolicySource.policy.Rules[0].Source = "203.0.113.0/24"
	first.operatorPolicySource.identity.digest[0] ^= 1
	second, err := policy.Configuration(t.Context())
	if err != nil || second.ListChoice != "2" || second.HAPeerCertSHA256[0] != strings.Repeat("a", 64) || second.OperatorPolicy.Rules[0].Source != "192.0.2.0/24" || second.operatorPolicySource.policy.Rules[0].Source != "192.0.2.0/24" {
		t.Fatal("returned configuration aliases immutable capture", err)
	}
	if policy.Review().ModulePlan[0] == "changed" || policy.Review().Effects[0].Detail == "changed" {
		t.Fatal("returned review aliases immutable capture")
	}
}

func TestActivationPolicyUsesRuntimeSaaSAlias(t *testing.T) {
	preserveOperatorPolicyGlobals(t)
	root, _ := initializedUserModule(t)
	// A historical profile may contain the deprecated SaaS alias. The effective
	// capture must resolve its TOML semantics exactly like the runtime loader.
	for _, relative := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml"} {
		path := filepath.Join(root, relative)
		raw, err := os.ReadFile(path) // #nosec G304 -- fixed fixture paths in the test-owned configuration root
		if err != nil {
			t.Fatal(err)
		}
		raw = []byte(strings.ReplaceAll(string(raw), "unconfigured-v1", ""))
		lines := strings.Split(string(raw), "\n")
		for index, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "allow_monitors =") {
				lines[index] = "# no official SaaS assignment"
			}
		}
		if err := writeModuleFixture(path, []byte(strings.Join(lines, "\n")), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeModuleFixture(filepath.Join(root, "modules", userModuleName), []byte("[integrations.saas]\nenabled=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Configuration(t.Context())
	if err != nil || !effective.AllowSaaSMonitors {
		t.Fatal("effective capture lost the historical SaaS alias", err)
	}
	if err := ParseConfigForInspection(root); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(effective, GlobalConfig) {
		t.Fatal("capture differs from read-only runtime interpretation")
	}
}

func TestActivationPolicyRejectsAllModularEnvironmentNamespaces(t *testing.T) {
	for _, name := range []string{
		"SYSWARDEN_CORE", "SYSWARDEN_CORE_FIREWALL_BACKEND", "SYSWARDEN_NETWORK_WHITELIST_IPS",
		"SYSWARDEN_NETWORK_BLOCKLISTS_CUSTOM_URL", "SYSWARDEN_SECURITY_HONEYPORTS", "SYSWARDEN_WAAP_BRUTEFORCE_LOGS",
		"SYSWARDEN_INTEGRATIONS_SAAS_ENABLED", "SYSWARDEN_INTEGRATIONS_ABUSEIPDB_API_KEY", "SYSWARDEN_USER_PROFILE_NAME",
		"SYSWARDEN_SSH_HARDENING", "SYSWARDEN_OPERATOR_POLICY_RULES", "SYSWARDEN_SCHEMA_VERSION",
	} {
		for _, value := range []string{"", "PRIVATE-ENVIRONMENT"} {
			t.Run(name+"/"+value, func(t *testing.T) {
				root, _ := initializedUserModule(t)
				policy, err := CaptureActivationPolicy(t.Context(), root)
				if err != nil {
					t.Fatal(err)
				}
				before := intentFixtureFiles(t, root)
				global, load := GlobalConfig, CurrentLoadState()
				t.Setenv(name, value)
				for _, run := range []func() error{
					func() error { _, err := CaptureActivationPolicy(t.Context(), root); return err },
					func() error { return policy.Revalidate(t.Context()) },
					func() error { _, err := policy.Configuration(t.Context()); return err },
				} {
					if err := run(); err == nil || !strings.Contains(err.Error(), "TOML-only") || strings.Contains(err.Error(), "PRIVATE-") {
						t.Fatal("configuration environment silently ignored or disclosed", err)
					}
				}
				if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) || global != GlobalConfig || !reflect.DeepEqual(load, CurrentLoadState()) {
					t.Fatal("environment refusal changed source or globals")
				}
			})
		}
	}
}

func TestActivationPolicyAllowsLifecycleEnvironmentWithoutChangingPolicy(t *testing.T) {
	root, _ := initializedUserModule(t)
	before, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SYSWARDEN_PKG_INSTALL", "SYSWARDEN_NATIVE_INSTALL_PHASE", "SYSWARDEN_OFFLINE_QUALIFICATION", "SYSWARDEN_PACKAGE_NAME"} {
		t.Setenv(name, "lifecycle-fixture")
	}
	after, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil || after.Review().Digest != before.Review().Digest {
		t.Fatal("lifecycle environment changed policy binding", err)
	}
	if err := before.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestActivationPolicyRefusesSourceAndBarrierDrift(t *testing.T) {
	for _, scenario := range []string{"bytes", "same-bytes-replacement", "mode", "new-module", "missing-module", "root-replacement", "pending-edit", "pending-migration"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			policy, err := CaptureActivationPolicy(t.Context(), root)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "modules", userModuleName)
			switch scenario {
			case "bytes":
				err = os.WriteFile(path, []byte("[network.blocklists]\nlist_choice='2'\n"), 0600)
			case "same-bytes-replacement":
				var content []byte
				content, err = os.ReadFile(path) // #nosec G304 -- fixed fixture path in the test-owned root
				if err == nil {
					err = writeSecureFileAtomically(filepath.Dir(path), userModuleName, content)
				}
			case "mode":
				// Change only the fixed module inside this private fixture root.
				var fixtureRoot *os.Root
				fixtureRoot, err = os.OpenRoot(root)
				if err == nil {
					defer fixtureRoot.Close()
					err = fixtureRoot.Chmod("modules/99-user.toml", 0640)
				}
			case "new-module":
				err = writeModuleFixture(filepath.Join(root, "modules", "zz-local.toml"), []byte("# new policy input\n"), 0600)
			case "missing-module":
				err = os.Remove(filepath.Join(root, "modules", "10-network.toml"))
			case "root-replacement":
				err = os.Rename(root, root+"-retained")
				if err == nil {
					err = EnsureDefaults(root)
				}
			case "pending-edit":
				err = writeModuleFixture(filepath.Join(root, moduleEditIntentName), []byte("retained intent"), 0600)
			case "pending-migration":
				err = writeModuleFixture(filepath.Join(root, migrationMarkerName), []byte("retained migration"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := intentFixtureFiles(t, root)
			global, load := GlobalConfig, CurrentLoadState()
			if err := policy.Revalidate(t.Context()); err == nil {
				t.Fatal("stale capture accepted")
			}
			if effective, err := policy.Configuration(t.Context()); err == nil || effective != nil {
				t.Fatal("stale capture released effective configuration")
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) || global != GlobalConfig || !reflect.DeepEqual(load, CurrentLoadState()) {
				t.Fatal("drift refusal mutated source or globals")
			}
			if scenario == "bytes" || scenario == "same-bytes-replacement" || scenario == "mode" || scenario == "new-module" || scenario == "root-replacement" {
				updated, err := CaptureActivationPolicy(t.Context(), root)
				if err != nil || updated.Review().Digest == policy.Review().Digest {
					t.Fatal("changed source retained the previous binding", err)
				}
			}
		})
	}
}

func TestActivationPolicyRefusesInvalidIncompleteAndCompatibilityInputs(t *testing.T) {
	for _, scenario := range []string{"missing-master", "missing-user", "invalid", "historical-ha", "historical-generated-ha", "retired-whitelist", "symlink", "hardlink", "oversize", "oversize-master", "oversize-generated-module"} {
		t.Run(scenario, func(t *testing.T) {
			root, _ := initializedUserModule(t)
			path := filepath.Join(root, "modules", userModuleName)
			var err error
			switch scenario {
			case "missing-master":
				err = os.Remove(filepath.Join(root, "config.toml"))
			case "missing-user":
				err = os.Remove(path)
			case "invalid":
				err = os.WriteFile(path, []byte("[invalid\n"), 0600)
			case "historical-ha":
				err = os.WriteFile(path, []byte("[integrations.ha]\nenabled=true\ntoken=''\npeer_ips=[]\n"), 0600)
			case "historical-generated-ha":
				var models map[string]string
				if err = json.Unmarshal(historicalDefaultModelsV4028, &models); err != nil {
					t.Fatal(err)
				}
				for relative, content := range models {
					if err = writeModuleFixture(filepath.Join(root, relative), []byte(strings.ReplaceAll(content, "/etc/syswarden/config", root)), 0600); err != nil {
						break
					}
				}
			case "retired-whitelist":
				err = os.WriteFile(path, []byte("[network]\nwhitelist_ips=['0.0.0.0']\n"), 0600)
			case "symlink":
				err = os.Symlink(userModuleName, filepath.Join(root, "modules", "zz-link.toml"))
			case "hardlink":
				err = os.Link(path, filepath.Join(root, "retained-link"))
			case "oversize", "oversize-master", "oversize-generated-module":
				if scenario == "oversize-master" {
					path = filepath.Join(root, "config.toml")
				} else if scenario == "oversize-generated-module" {
					path = filepath.Join(root, "modules", "10-network.toml")
				}
				err = os.WriteFile(path, []byte(strings.Repeat("#", int(maximumUserModuleSize)+1)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := intentFixtureFiles(t, root)
			global, load := GlobalConfig, CurrentLoadState()
			policy, err := CaptureActivationPolicy(t.Context(), root)
			if err == nil || policy != nil {
				t.Fatal("unsafe or normalization-dependent capture accepted")
			}
			if strings.HasPrefix(scenario, "oversize") && !strings.Contains(err.Error(), "byte limit") {
				t.Fatal("oversized input reached parsing instead of bounded capture", err)
			}
			if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) || global != GlobalConfig || !reflect.DeepEqual(load, CurrentLoadState()) {
				t.Fatal("refused capture rewrote original evidence or globals")
			}
		})
	}
}

func TestActivationPolicyRequiresCompleteCapturedHistoricalAndStandardInventory(t *testing.T) {
	for _, profile := range []string{"", StandardInstallProfile} {
		for _, missing := range []string{"config.toml", "modules/00-core.toml", "modules/10-network.toml", "modules/20-security.toml", "modules/30-waap.toml", "modules/40-integrations.toml", "modules/99-user.toml"} {
			t.Run(profile+"/"+missing, func(t *testing.T) {
				root, _ := initializedUserModule(t)
				for _, relative := range []string{"config.toml", "modules/00-core.toml"} {
					path := filepath.Join(root, relative)
					raw, err := os.ReadFile(path) // #nosec G304 -- exact configuration fixture path under the test-owned root
					if err != nil {
						t.Fatal(err)
					}
					if err := writeModuleFixture(path, []byte(strings.ReplaceAll(string(raw), UnconfiguredInstallProfile, profile)), 0600); err != nil {
						t.Fatal(err)
					}
				}
				// Model a complete earlier observation followed by loss before the
				// bounded capture. Historical/default semantics cannot replace it.
				complete, _, err := captureModuleInputs(root, userTOMLTarget(), nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := requireCompleteActivationPolicy(complete); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(root, missing)); err != nil {
					t.Fatal(err)
				}
				captured, _, err := captureModuleInputs(root, userTOMLTarget(), nil)
				if err != nil {
					t.Fatal("cannot capture the actual incomplete historical fixture", err)
				}
				if err := requireCompleteActivationPolicy(captured); err == nil {
					t.Fatal("incomplete captured policy inherited fresh/default authority")
				}
				before := intentFixtureFiles(t, root)
				global, load := GlobalConfig, CurrentLoadState()
				if policy, err := CaptureActivationPolicy(t.Context(), root); err == nil || policy != nil || !strings.Contains(err.Error(), "complete existing modular configuration") {
					t.Fatal("incomplete historical policy reached activation decoding", err)
				}
				if err := captured.revalidate(root, false, nil); err != nil {
					t.Fatal("refusal changed captured metadata", err)
				}
				if !reflect.DeepEqual(before, intentFixtureFiles(t, root)) || global != GlobalConfig || !reflect.DeepEqual(load, CurrentLoadState()) {
					t.Fatal("incomplete capture refusal changed source or global state")
				}
			})
		}
	}
}

func TestActivationPolicyRejectsInvalidContextAndRoot(t *testing.T) {
	root, _ := initializedUserModule(t)
	policy, err := CaptureActivationPolicy(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{nil, cancelledPreviewContext()} {
		if _, err := CaptureActivationPolicy(ctx, root); err == nil {
			t.Fatal("invalid capture context accepted")
		}
		if err := policy.Revalidate(ctx); err == nil {
			t.Fatal("invalid revalidation context accepted")
		}
		if _, err := policy.Configuration(ctx); err == nil {
			t.Fatal("invalid configuration context accepted")
		}
	}
	for _, invalid := range []string{"relative", root + "/../config", filepath.Join(root, "absent")} {
		if _, err := CaptureActivationPolicy(t.Context(), invalid); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	for _, unavailable := range []*ActivationPolicy{nil, {}} {
		if err := unavailable.Revalidate(t.Context()); err == nil {
			t.Fatal("unavailable policy accepted")
		}
		if _, err := unavailable.Configuration(t.Context()); err == nil {
			t.Fatal("unavailable policy released configuration")
		}
		if !reflect.DeepEqual(unavailable.Review(), ActivationPolicyReview{}) {
			t.Fatal("unavailable policy invented review")
		}
	}
}
