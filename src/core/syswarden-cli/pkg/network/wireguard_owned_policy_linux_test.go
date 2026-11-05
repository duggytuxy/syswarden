//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

type ownedPolicyTestRunner struct {
	base   *retirementNFTRunner
	shared []byte
}

func (r *ownedPolicyTestRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if strings.Join(args, " ") == "-a -j list chain inet filter forward" && r.shared != nil {
		return r.shared, nil
	}
	return r.base.Run(ctx, args...)
}
func ownedPolicyTestHost(t *testing.T) (legacyWireGuardRecoveryHost, *ownedPolicyTestRunner) {
	t.Helper()
	host, state := newManifestLegacyWireGuardTestHost(t)
	state.tablePresent = false
	runner := &ownedPolicyTestRunner{base: &retirementNFTRunner{state: state, currentTable: exactWireGuardNFTJSON()}}
	host.nftRunner = runner
	host.guard = func() (func() error, error) {
		t.Fatal("assessment acquired mutation guard")
		return nil, errors.New("unexpected guard")
	}
	host.nftBatch = func(context.Context, string) ([]byte, error) {
		t.Fatal("assessment executed nft mutation")
		return nil, errors.New("unexpected batch")
	}
	return host, runner
}
func ownedPolicyFixtureFiles(t *testing.T, host legacyWireGuardRecoveryHost) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, name := range append(wireguardstate.ArtifactPaths(), wireguardstate.ManifestPath) {
		content, err := legacyTestFiles(t, host.filesystemRoot).ReadFile(strings.TrimPrefix(name, "/"))
		if err != nil {
			t.Fatal(err)
		}
		result[name] = content
	}
	return result
}
func TestOwnedWireGuardPolicyAssessmentIsReadOnlyAndRedacted(t *testing.T) {
	for _, kind := range []string{"inactive", "active", "enabled", "interface", "owned-table", "scoped-v2"} {
		t.Run(kind, func(t *testing.T) {
			host, runner := ownedPolicyTestHost(t)
			switch kind {
			case "active":
				host.commandOutput = fakeLegacyWireGuardServiceOutput(true, false, false)
			case "enabled":
				host.commandOutput = fakeLegacyWireGuardServiceOutput(false, true, false)
			case "interface":
				prior := host.commandOutput
				host.commandOutput = func(name string, args ...string) ([]byte, error) {
					if name == "wg" {
						return []byte("wg-syswarden\n"), nil
					}
					return prior(name, args...)
				}
			case "owned-table":
				runner.base.state.tablePresent = true
			case "scoped-v2":
				files := legacyTestFiles(t, host.filesystemRoot)
				original, err := files.ReadFile(strings.TrimPrefix(wireguardstate.ServerConfigurationPath, "/"))
				if err != nil {
					t.Fatal(err)
				}
				target, err := wireguardstate.ScopedServerConfiguration(original)
				if err != nil {
					t.Fatal(err)
				}
				if err := files.WriteFile(strings.TrimPrefix(wireguardstate.ServerConfigurationPath, "/"), target, 0600); err != nil {
					t.Fatal(err)
				}
				manifest, err := wireguardstate.CaptureManifest(host.filesystemRoot, host.expectedUID, host.expectedGID)
				if err != nil {
					t.Fatal(err)
				}
				wire, err := canonicalWireGuardManifestBytes(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := files.WriteFile(strings.TrimPrefix(wireguardstate.ManifestPath, "/"), wire, 0600); err != nil {
					t.Fatal(err)
				}
				runner.base.state.tablePresent = true
				runner.base.currentTable = scopedWireGuardNFTJSON()
			}
			before := ownedPolicyFixtureFiles(t, host)
			assessment, err := host.inspectOwnedPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if !assessment.ReadOnly || assessment.Schema != ownedWireGuardPolicyAssessmentSchema {
				t.Fatal("missing read-only boundary")
			}
			if kind == "scoped-v2" {
				if assessment.State != "scoped-v2" || len(assessment.Blockers) != 0 {
					t.Fatal("v2 was mislabeled as v1")
				}
			} else {
				if assessment.State != "v1-transition-required" || len(assessment.Blockers) == 0 {
					t.Fatal("v1 was cleared for migration")
				}
				if kind != "inactive" && len(assessment.Blockers) < 2 {
					t.Fatal("runtime or service precondition was omitted")
				}
			}
			wire, err := RenderOwnedWireGuardPolicyAssessment(assessment)
			if err != nil {
				t.Fatal(err)
			}
			input := validWireGuardRenderInput()
			for _, secret := range []string{input.ServerPriv, input.ClientPriv, input.PresharedKey} {
				if bytes.Contains(wire, []byte(secret)) {
					t.Fatal("assessment disclosed a credential")
				}
			}
			if !reflect.DeepEqual(before, ownedPolicyFixtureFiles(t, host)) || len(runner.base.state.batches) != 0 {
				t.Fatal("assessment changed owned state")
			}
			again, err := host.inspectOwnedPolicy()
			if err != nil || !reflect.DeepEqual(assessment, again) {
				t.Fatal("stable assessment was not deterministic", err)
			}
		})
	}
}
func TestOwnedWireGuardPolicyAssessmentRefusesDriftAndForeignState(t *testing.T) {
	for _, kind := range []string{"service-drift", "file-drift", "foreign-table", "unknown-shared-version", "unconfigured-shared", "manager-inactive", "pending-forwarding"} {
		t.Run(kind, func(t *testing.T) {
			host, runner := ownedPolicyTestHost(t)
			switch kind {
			case "service-drift":
				count := 0
				prior := host.commandOutput
				host.commandOutput = func(name string, args ...string) ([]byte, error) {
					if strings.Contains(strings.Join(args, " "), "--property=ActiveState") {
						count++
						if count > 1 {
							return []byte("active\n"), nil
						}
					}
					return prior(name, args...)
				}
			case "file-drift":
				original := host.commandOutput
				changed := false
				host.commandOutput = func(name string, args ...string) ([]byte, error) {
					if !changed {
						changed = true
						if err := legacyTestFiles(t, host.filesystemRoot).WriteFile(strings.TrimPrefix(wireguardstate.ClientConfigurationPath, "/"), []byte("changed\n"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					return original(name, args...)
				}
			case "foreign-table":
				runner.base.state.tablePresent = true
				runner.base.currentTable = bytes.Replace(exactWireGuardNFTJSON(), []byte("syswarden-wg-v1:"), []byte("administrator:"), 1)
			case "unknown-shared-version":
				runner.shared = bytes.ReplaceAll(sharedForwardFixture(strings.Repeat("a", 64)), []byte("syswarden-wg-forward-v1:"), []byte("syswarden-wg-forward-v9:"))
			case "unconfigured-shared":
				runner.shared = sharedForwardFixture(strings.Repeat("a", 64))
			case "manager-inactive":
				host.managerState = func() (string, error) { return "INACTIVE", nil }
			case "pending-forwarding":
				if err := legacyTestFiles(t, host.filesystemRoot).WriteFile(strings.TrimPrefix(wireGuardForwardingTransitionPath, "/"), []byte("pending\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := host.inspectOwnedPolicy(); err == nil {
				t.Fatal("accepted changed or incompatible state")
			}
			if len(runner.base.state.batches) != 0 {
				t.Fatal("assessment changed nft state")
			}
		})
	}
}
func TestOwnedWireGuardPolicyRendererRefusesApplyClaims(t *testing.T) {
	host, _ := ownedPolicyTestHost(t)
	assessment, err := host.inspectOwnedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"schema", "read-only", "state", "blockers"} {
		changed := assessment
		switch kind {
		case "schema":
			changed.Schema = "unknown"
		case "read-only":
			changed.ReadOnly = false
		case "state":
			changed.State = "safe-to-apply"
		case "blockers":
			changed.Blockers = nil
		}
		if _, err := RenderOwnedWireGuardPolicyAssessment(changed); err == nil {
			t.Fatal("accepted unsupported assessment", kind)
		}
	}
}

func TestOwnedWireGuardPolicyOpenRCNeverExecutesStatusScripts(t *testing.T) {
	host, _ := ownedPolicyTestHost(t)
	host.isAlpine = func() bool { return true }
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		if name != "wg" || strings.Join(args, " ") != "show interfaces" {
			t.Fatal("read-only assessment attempted a service script", name, args)
		}
		return []byte("\n"), nil
	}
	assessment, err := host.inspectOwnedPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if assessment.ServiceManager != "openrc" || assessment.Service.ActiveState != "unobserved" || assessment.Service.EnabledState != "unobserved" ||
		!strings.Contains(strings.Join(assessment.Blockers, "\n"), "bounded OpenRC") {
		t.Fatal("assessment inferred unobserved OpenRC state")
	}
}
