//go:build linux

package network

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

type retirementNFTRunner struct {
	state         *fakeLegacyWireGuardNFTState
	absentChain   bool
	currentTable  []byte
	failInventory bool
}

func (runner *retirementNFTRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	switch strings.Join(args, " ") {
	case "-a -j list chains":
		if runner.failInventory {
			return nil, errors.New("inventory denied")
		}
		if runner.absentChain {
			return []byte(`{"nftables":[]}`), nil
		}
		return []byte(`{"nftables":[{"chain":{"family":"inet","table":"filter","name":"forward","handle":2}}]}`), nil
	case "-a -j list table inet syswarden_wg":
		if runner.currentTable != nil {
			return runner.currentTable, nil
		}
	case "-a -j list chain inet filter forward":
		if runner.absentChain {
			return nil, errors.New("absent chain must not be queried")
		}
	}
	return runner.state.Run(ctx, args...)
}
func retirementTestHost(t *testing.T) (legacyWireGuardRecoveryHost, *retirementNFTRunner) {
	t.Helper()
	host, state := newManifestLegacyWireGuardTestHost(t)
	writeHistoricalWireGuardTestConfiguration(t, host.filesystemRoot, "wg0")
	runner := &retirementNFTRunner{state: state}
	host.nftRunner = runner
	return host, runner
}
func retirementApply(t *testing.T, host legacyWireGuardRecoveryHost) LegacyWireGuardRetirementPlan {
	t.Helper()
	plan, err := host.inspectRetirement()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.applyRetirement(digest); err != nil {
		t.Fatal(err)
	}
	return plan
}
func retirementPath(host legacyWireGuardRecoveryHost, path string) string {
	return filepath.Join(host.filesystemRoot, path)
}
func requireHistoricalConfigRetained(t *testing.T, host legacyWireGuardRecoveryHost) {
	t.Helper()
	wire, err := os.ReadFile(retirementPath(host, legacyWireGuardConfigurationPath))
	if err != nil || !bytes.Equal(wire, historicalWireGuardTestConfiguration("wg0")) {
		t.Fatalf("historical evidence lost: %v", err)
	}
}

func TestLegacyWireGuardRetirementDualGenerationAndRepeatedExecution(t *testing.T) {
	for _, kind := range []string{"table-and-both-generations", "table-only", "postdown-removed-table", "no-firewall-state"} {
		t.Run(kind, func(t *testing.T) {
			host, runner := retirementTestHost(t)
			if kind == "table-and-both-generations" || kind == "postdown-removed-table" {
				runner.state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}, {Direction: "oifname", Handle: 18}}
				runner.state.forwardRules["wg-syswarden"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "oifname", Handle: 19}}
			}
			if kind == "postdown-removed-table" || kind == "no-firewall-state" {
				runner.state.tablePresent = false
			}
			if kind == "no-firewall-state" {
				runner.absentChain = true
			}
			ownershipBefore, err := inspectLegacyWireGuardOwnership(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil {
				t.Fatal(err)
			}
			plan := retirementApply(t, host)
			if plan.State != "pending" || !plan.SafeToApply {
				t.Fatalf("unexpected plan: %#v", plan)
			}
			if runner.state.tablePresent || len(runner.state.forwardRules["wg0"])+len(runner.state.forwardRules["wg-syswarden"]) != 0 {
				t.Fatal("historical kernel state retained")
			}
			if _, err := os.Lstat(retirementPath(host, legacyWireGuardConfigurationPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old configuration still in activation path")
			}
			wire, err := os.ReadFile(retirementPath(host, legacyWireGuardArchivePath))
			if err != nil || !bytes.Equal(wire, historicalWireGuardTestConfiguration("wg0")) {
				t.Fatalf("private backup not byte-identical: %v", err)
			}
			ownershipAfter, err := inspectLegacyWireGuardOwnership(host.filesystemRoot, host.expectedUID, host.expectedGID)
			if err != nil || !reflect.DeepEqual(ownershipBefore, ownershipAfter) {
				t.Fatalf("current ownership changed: %v", err)
			}
			archiveInfo, err := os.Stat(retirementPath(host, legacyWireGuardArchivePath))
			if err != nil || archiveInfo.Mode().Perm() != 0600 {
				t.Fatal("archive privacy lost")
			}
			batches := len(runner.state.batches)
			repeat := retirementApply(t, host)
			if repeat.State != "retired" || len(runner.state.batches) != batches {
				t.Fatal("repeated retirement changed kernel state")
			}
			if err := inspectLegacyWireGuardConflict(host.filesystemRoot, host.expectedUID, host.expectedGID); err != nil {
				t.Fatal(err)
			}
			for _, script := range runner.state.batches {
				if strings.Contains(script, "handle 90") || strings.Contains(script, "delete table inet filter") {
					t.Fatal("administrator state was selected")
				}
			}
		})
	}
}

func TestLegacyWireGuardRetirementActiveOldVPNIsActionableAndReadOnly(t *testing.T) {
	host, runner := retirementTestHost(t)
	inactive := host.commandOutput
	active := fakeLegacyWireGuardServiceOutput(true, true, true)
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "wg-quick@wg0.service") || name == "wg" {
			return active(name, args...)
		}
		return inactive(name, args...)
	}
	plan, err := host.inspectRetirement()
	if err != nil {
		t.Fatal(err)
	}
	if plan.SafeToApply || len(plan.Blockers) != 3 || plan.CurrentService.ActiveState != "inactive" {
		t.Fatalf("incorrect runtime blockers: %#v", plan)
	}
	digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.applyRetirement(digest); err == nil {
		t.Fatal("active old VPN was retired")
	}
	if len(runner.state.batches) != 0 {
		t.Fatal("blocked plan mutated nftables")
	}
	requireHistoricalConfigRetained(t, host)
	wire, err := RenderLegacyWireGuardRetirementPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"PrivateKey", "PresharedKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("plan exposes configuration contents")
		}
	}
}

func TestLegacyWireGuardRetirementRejectsUnprovenInputs(t *testing.T) {
	for _, kind := range []string{"duplicate-rule", "unmanifested-modern", "bad-template", "symlink", "hardlink", "unsafe-mode", "archive-exists", "archive-symlink", "archive-public", "nft-inventory-failure", "egress-mismatch", "pending-transaction"} {
		t.Run(kind, func(t *testing.T) {
			host, runner := retirementTestHost(t)
			oldPath := retirementPath(host, legacyWireGuardConfigurationPath)
			archiveDir := retirementPath(host, legacyWireGuardArchiveDirectory)
			switch kind {
			case "duplicate-rule":
				runner.state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}, {Direction: "iifname", Handle: 18}}
			case "unmanifested-modern":
				if err := os.Remove(retirementPath(host, wireguardstate.ManifestPath)); err != nil {
					t.Fatal(err)
				}
			case "bad-template":
				if err := os.WriteFile(oldPath, append(historicalWireGuardTestConfiguration("wg0"), []byte("SaveConfig = true\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(oldPath, oldPath+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("wg0.conf.real", oldPath); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(oldPath, oldPath+".link"); err != nil {
					t.Fatal(err)
				}
			case "unsafe-mode":
				if err := os.Chmod(oldPath, 0640); err != nil {
					t.Fatal(err)
				} // #nosec G302 -- deliberate unsafe fixture rejected before mutation
			case "archive-exists":
				if err := os.Mkdir(archiveDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(retirementPath(host, legacyWireGuardArchivePath), historicalWireGuardTestConfiguration("wg0"), 0600); err != nil {
					t.Fatal(err)
				}
			case "archive-symlink":
				if err := os.Symlink(t.TempDir(), archiveDir); err != nil {
					t.Fatal(err)
				}
			case "archive-public":
				if err := os.Mkdir(archiveDir, 0755); err != nil {
					t.Fatal(err)
				} // #nosec G301 -- deliberate public directory must be rejected
			case "nft-inventory-failure":
				runner.failInventory = true
			case "egress-mismatch":
				if err := os.WriteFile(oldPath, bytes.ReplaceAll(historicalWireGuardTestConfiguration("wg0"), []byte("ens3"), []byte("eth9")), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending-transaction":
				if err := os.WriteFile(retirementPath(host, wireguardstate.TransactionPath), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := host.inspectRetirement(); err == nil {
				t.Fatal("unproven retirement accepted")
			}
			if _, err := host.applyRetirement(strings.Repeat("a", 64)); err == nil || len(runner.state.batches) != 0 {
				t.Fatalf("rejected input mutated state: %v", err)
			}
		})
	}
}

func TestLegacyWireGuardRetirementRefusesDriftAndCanRetryAfterCleanup(t *testing.T) {
	for _, kind := range []string{"stale-digest", "guard-drift", "nft-failure", "replacement-table", "archive-collision-after-cleanup"} {
		t.Run(kind, func(t *testing.T) {
			host, runner := retirementTestHost(t)
			plan, err := host.inspectRetirement()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := LegacyWireGuardRetirementPlanSHA256(plan)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "stale-digest":
				runner.state.tableHandle = 42
			case "guard-drift":
				host.guard = func() (func() error, error) { runner.state.tableHandle = 42; return func() error { return nil }, nil }
			case "nft-failure":
				runner.state.batchErr = errors.New("rejected batch")
			case "replacement-table":
				runner.state.replaceAfterApply = true
			case "archive-collision-after-cleanup":
				host.nftBatch = func(ctx context.Context, script string) ([]byte, error) {
					wire, err := runner.state.apply(ctx, script)
					if err != nil {
						return wire, err
					}
					if err := os.Mkdir(retirementPath(host, legacyWireGuardArchiveDirectory), 0700); err != nil {
						return nil, err
					}
					return nil, nil
				}
			}
			if _, err := host.applyRetirement(digest); err == nil {
				t.Fatal("drift or failure accepted")
			}
			requireHistoricalConfigRetained(t, host)
			if kind == "stale-digest" || kind == "guard-drift" {
				if len(runner.state.batches) != 0 {
					t.Fatal("drift mutated nftables")
				}
			}
			if kind == "archive-collision-after-cleanup" {
				if runner.state.tablePresent {
					t.Fatal("failure injection did not follow cleanup")
				}
				host.nftBatch = runner.state.apply
				retry := retirementApply(t, host)
				if retry.TableAction != "absent" || len(runner.state.batches) != 1 {
					t.Fatal("retry attempted cleanup of absent table")
				}
			}
		})
	}
}

func TestLegacyWireGuardRetirementWithoutCurrentInstallation(t *testing.T) {
	host, state := newLegacyWireGuardTestHost(t, "wg0", nil)
	host.nftRunner = &retirementNFTRunner{state: state}
	plan := retirementApply(t, host)
	if plan.Ownership.State != "no-manifest" {
		t.Fatal("unexpected current ownership")
	}
}

func TestLegacyWireGuardConflictPreventsFreshAndRepeatedMutations(t *testing.T) {
	for _, kind := range []string{"install", "reconcile", "disabled", "removal", "preflight"} {
		t.Run(kind, func(t *testing.T) {
			harness := installWireGuardTransactionHarness(t)
			if kind == "reconcile" || kind == "disabled" {
				if err := SetupWireguard(); err != nil {
					t.Fatal(err)
				}
				harness.expectTransaction = false
			}
			writeHistoricalWireGuardTestConfiguration(t, harness.root, "wg0")
			events := append([]string(nil), harness.events...)
			var err error
			switch kind {
			case "disabled":
				config.GlobalConfig.EnableWG = false
				err = SetupWireguard()
			case "removal":
				err = PreflightWireGuardRemoval()
			case "preflight":
				err = PreflightWireguard()
			default:
				err = SetupWireguard()
			}
			if err == nil || !strings.Contains(err.Error(), "--retire-legacy-wg0") {
				t.Fatalf("missing retirement guidance: %v", err)
			}
			// Guards and read-only backend inspection may occur; no keys, ownership,
			// runtime forwarding, activation or nft cleanup may be changed.
			for _, event := range harness.events[len(events):] {
				if event != "guard" && event != "unguard" && !strings.HasPrefix(event, "preflight:") {
					t.Fatalf("unexpected event on blocked mutation: %s (%v)", event, harness.events)
				}
			}
			if kind == "install" {
				inventory, err := wireguardstate.Inspect(harness.root)
				if err != nil || !inventory.Empty() {
					t.Fatalf("blocked install published ownership: %#v %v", inventory, err)
				}
			}
		})
	}
}

func TestLegacyWireGuardConflictPreservesUnrelatedAdministratorVPN(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	writeHistoricalWireGuardTestConfiguration(t, harness.root, "wg0")
	if err := os.Chmod(filepath.Join(harness.root, "etc/wireguard"), 0700); err != nil { // #nosec G302 -- private test directory must reproduce the owner-only production mode
		t.Fatal(err)
	}
	path := filepath.Join(harness.root, "etc/wireguard/wg0.conf")
	unrelated := []byte("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 192.0.2.1/24\n")
	if err := os.WriteFile(path, unrelated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- path is the fixed administrator fixture beneath t.TempDir
	if err != nil || !bytes.Equal(after, unrelated) {
		t.Fatal("administrator configuration changed")
	}
}

func TestRetirementChainInventoryDoesNotInventAbsence(t *testing.T) {
	for _, wire := range []string{`{}`, `{"nftables":null}`, `{"nftables":[]} {}`, `{"nftables":[{"chain":{"name":"forward"}}]}`, `{"nftables":[{"chain":{"family":"inet","table":"filter","name":"forward","handle":0}}]}`} {
		if _, err := retirementForwardChainHandle([]byte(wire)); err == nil {
			t.Fatalf("invalid inventory accepted: %s", wire)
		}
	}
}

func TestRetirementPlanDigestChangesOnObservedState(t *testing.T) {
	host, _ := retirementTestHost(t)
	plan, err := host.inspectRetirement()
	if err != nil {
		t.Fatal(err)
	}
	first, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.ForwardChainHandle++
	second, err := LegacyWireGuardRetirementPlanSHA256(plan)
	if err != nil || first == second {
		t.Fatal("chain identity is not digest-bound")
	}
	if _, err := host.applyRetirement(fmt.Sprintf("%064d", 0)); err == nil {
		t.Fatal("unreviewed digest accepted")
	}
}

func TestLegacyWireGuardRetirementPreservesCurrentTokenizedTable(t *testing.T) {
	host, runner := retirementTestHost(t)
	runner.currentTable = exactWireGuardNFTJSON()
	runner.state.forwardRules["wg0"] = []LegacyWireGuardForwardRuleEvidence{{Direction: "iifname", Handle: 17}}
	plan := retirementApply(t, host)
	if plan.TableAction != "preserve-exact-current" || !runner.state.tablePresent || len(runner.state.batches) != 1 || strings.Contains(runner.state.batches[0], "delete table") {
		t.Fatal("current manifest-bound table was not preserved")
	}
	inactive := host.commandOutput
	active := fakeLegacyWireGuardServiceOutput(true, true, false)
	host.commandOutput = func(name string, args ...string) ([]byte, error) {
		if name == "wg" {
			return []byte("wg-syswarden\n"), nil
		}
		if strings.Contains(strings.Join(args, " "), "wg-quick@wg-syswarden.service") {
			return active(name, args...)
		}
		return inactive(name, args...)
	}
	after := retirementApply(t, host)
	if !after.SafeToApply || after.State != "retired" || len(runner.state.batches) != 1 {
		t.Fatal("completed retirement not repeatable with current VPN active")
	}
}

func TestLegacyWireGuardRemovalPreflightLeavesPendingTransactionToVerifiedRecovery(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	writeHistoricalWireGuardTestConfiguration(t, harness.root, "wg0")
	if err := os.WriteFile(filepath.Join(harness.root, wireguardstate.TransactionPath), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := PreflightWireGuardRemoval(); err != nil {
		t.Fatalf("pending transaction recovery was blocked by historical preflight: %v", err)
	}
	// This preflight does not authorize the malformed transaction. The existing
	// operation-aware state machine must verify it before changing owned state.
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || !inventory.Transaction {
		t.Fatal("pending ownership evidence was changed")
	}
}
