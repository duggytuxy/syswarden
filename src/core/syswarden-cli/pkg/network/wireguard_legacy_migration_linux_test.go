//go:build linux

package network

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func migrationTestHost(t *testing.T) (legacyWireGuardRecoveryHost, *retirementNFTRunner, map[string][]byte) {
	t.Helper()
	host, state := newLegacyWireGuardTestHost(t, "wg-syswarden", []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}, {Direction: "oifname", Handle: 18}})
	contents := historicalGeneratedTestState(t, host)
	runner := &retirementNFTRunner{state: state}
	host.nftRunner = runner
	host.migrationNFTPath = func() (string, error) { return "/usr/sbin/nft", nil }
	host.migrationTruePath = func() (string, error) { return "/usr/bin/true", nil }
	host.migrationToken = func() (string, error) { return strings.Repeat("b", 64), nil }
	return host, runner, contents
}

func TestLegacyWireGuardMigrationPreservesKeysAndClientAndAllowsOwnedReuse(t *testing.T) {
	for _, withTable := range []bool{true, false} {
		host, runner, contents := migrationTestHost(t)
		runner.state.tablePresent = withTable
		plan, err := host.inspectMigration()
		if err != nil {
			t.Fatal(err)
		}
		wire, err := RenderLegacyWireGuardMigrationPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		privateSnapshot, err := wireguardstate.InspectLegacyMigration(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Files.OriginalContents != nil {
			t.Fatal("plan retained private file bytes")
		}
		original, err := generatedStateFromMigration(privateSnapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{original.input.ServerPriv, original.input.ClientPriv, original.input.PresharedKey} {
			if bytes.Contains(wire, []byte(key)) {
				t.Fatal("migration plan disclosed private material")
			}
		}
		digest, err := LegacyWireGuardMigrationPlanSHA256(plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := host.applyMigration(digest); err != nil {
			t.Fatal(err)
		}
		if runner.state.tablePresent || len(runner.state.forwardRules["wg-syswarden"]) != 0 {
			t.Fatal("historical kernel state retained")
		}
		manifest, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID)
		if err != nil {
			t.Fatal(err)
		}
		server, err := wireguardstate.ReadVerifiedArtifact(host.filesystemRoot, manifest, wireguardstate.ServerConfigurationPath, host.expectedUID, host.expectedGID)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := wireguardstate.ParseServerConfiguration(server)
		if err != nil || identity.OwnershipToken != strings.Repeat("b", 64) {
			t.Fatal("new hooks not bound to ownership", err)
		}
		if !bytes.Contains(server, []byte("PrivateKey = "+original.input.ServerPriv+"\n")) {
			t.Fatal("server private key changed")
		}
		for path, expected := range contents {
			backup, err := legacyTestFiles(t, host.filesystemRoot).ReadFile(strings.TrimPrefix(wireguardstate.LegacyMigrationBackupPath(path), "/"))
			if err != nil || !bytes.Equal(backup, expected) {
				t.Fatal("original private backup changed", err)
			}
			if path != wireguardstate.ServerConfigurationPath {
				actual, err := legacyTestFiles(t, host.filesystemRoot).ReadFile(strings.TrimPrefix(path, "/"))
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("migration changed client or forwarding content", err)
				}
			}
		}
		complete, err := host.inspectMigration()
		if err != nil || complete.State != "complete" {
			t.Fatal("migration did not complete", err)
		}
		digest, err = LegacyWireGuardMigrationPlanSHA256(complete)
		if err != nil {
			t.Fatal(err)
		}
		batchCount := len(runner.state.batches)
		if _, err := host.applyMigration(digest); err != nil {
			t.Fatal(err)
		}
		repeat, err := host.inspectMigration()
		if err != nil || !reflect.DeepEqual(complete, repeat) || len(runner.state.batches) != batchCount {
			t.Fatal("repeat changed migrated state", err)
		}
	}
}

func TestLegacyWireGuardMigrationBlockersAndDriftPreserveEvidence(t *testing.T) {
	for _, kind := range []string{"active-service", "historical-wg0", "foreign-wg0-rules", "duplicate-current-rule", "client-drift-under-guard", "nft-failure", "forwarding-transition"} {
		t.Run(kind, func(t *testing.T) {
			host, runner, contents := migrationTestHost(t)
			switch kind {
			case "active-service":
				host.commandOutput = fakeLegacyWireGuardServiceOutput(true, true, false)
			case "historical-wg0":
				writeHistoricalWireGuardTestConfiguration(t, host.filesystemRoot, "wg0")
			case "foreign-wg0-rules":
				runner.state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 31}}
			case "duplicate-current-rule":
				runner.state.forwardRules["wg-syswarden"] = append(runner.state.forwardRules["wg-syswarden"], LegacyWireGuardForwardRuleEvidence{Direction: "iifname", Handle: 31})
			case "client-drift-under-guard":
				host.guard = func() (func() error, error) {
					clientPath := filepath.Join(host.filesystemRoot, wireguardstate.ClientConfigurationPath)
					wire := bytes.Replace(contents[wireguardstate.ClientConfigurationPath], []byte("192.0.2.15"), []byte("192.0.2.16"), 1)
					if err := os.WriteFile(clientPath, wire, 0600); err != nil {
						t.Fatal(err)
					}
					return func() error { return nil }, nil
				}
			case "nft-failure":
				runner.state.batchErr = errors.New("injected nft failure")
			case "forwarding-transition":
				if err := os.WriteFile(filepath.Join(host.filesystemRoot, wireGuardForwardingTransitionPath), []byte("pending\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := host.inspectMigration()
			if err == nil {
				digest, digestErr := LegacyWireGuardMigrationPlanSHA256(plan)
				if digestErr != nil {
					t.Fatal(digestErr)
				}
				_, err = host.applyMigration(digest)
			}
			if err == nil {
				t.Fatal("unsafe migration accepted")
			}
			server, err := os.ReadFile(filepath.Join(host.filesystemRoot, wireguardstate.ServerConfigurationPath))
			if err != nil || !bytes.Equal(server, contents[wireguardstate.ServerConfigurationPath]) {
				t.Fatal("original server lost on refusal", err)
			}
			if _, err := os.Lstat(filepath.Join(host.filesystemRoot, wireguardstate.ManifestPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("ownership created on refusal")
			}
		})
	}
}

func TestLegacyWireGuardRetirementThenMigrationOfBothUnmanifestedGenerations(t *testing.T) {
	host, _, _ := migrationTestHost(t)
	writeHistoricalWireGuardTestConfiguration(t, host.filesystemRoot, "wg0")
	retirementApply(t, host)
	plan, err := host.inspectMigration()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardMigrationPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.applyMigration(digest); err != nil {
		t.Fatal(err)
	}
	if _, err := wireguardstate.ReadAndVerify(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
		t.Fatal(err)
	}
	if err := inspectLegacyWireGuardConflict(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(filepath.Join(host.filesystemRoot, legacyWireGuardArchivePath))
	if err != nil || !bytes.Equal(archived, historicalWireGuardTestConfiguration("wg0")) {
		t.Fatal("wg0 private archive changed", err)
	}
}
