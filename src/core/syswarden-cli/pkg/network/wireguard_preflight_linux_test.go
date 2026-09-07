//go:build linux

package network

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func TestReadOnlyPreflightAcceptsOnlyRepairableInactiveStaleTable_SW2_WG_001(t *testing.T) {
	previousNFTPreflight := wireGuardNFTActivationPreflight
	previousStalePreflight := wireGuardTokenizedNFTReadOnlyPreflight
	t.Cleanup(func() {
		wireGuardNFTActivationPreflight = previousNFTPreflight
		wireGuardTokenizedNFTReadOnlyPreflight = previousStalePreflight
	})

	provenanceMismatch := errors.New("existing WireGuard nftables table provenance mismatch")
	wireGuardNFTActivationPreflight = func(wireGuardNFTExpectation) error { return provenanceMismatch }
	staleCalls := 0
	wireGuardTokenizedNFTReadOnlyPreflight = func(identity wireguardstate.ServerConfigurationIdentity) error {
		staleCalls++
		if identity != exactWireGuardNFTIdentity() {
			t.Fatalf("stale preflight identity = %#v", identity)
		}
		return nil
	}
	expectation := wireGuardNFTExpectation{AllowExisting: true, Identity: exactWireGuardNFTIdentity()}
	if err := preflightWireGuardNFTState(expectation, wireGuardServiceState{}); err != nil {
		t.Fatalf("repairable inactive stale table = %v", err)
	}
	if staleCalls != 1 {
		t.Fatalf("inactive stale-table preflights = %d, want 1", staleCalls)
	}

	for name, baseline := range map[string]wireGuardServiceState{
		"active service":    {Active: true, Interface: true},
		"present interface": {Interface: true},
	} {
		t.Run(name, func(t *testing.T) {
			before := staleCalls
			err := preflightWireGuardNFTState(expectation, baseline)
			if !errors.Is(err, provenanceMismatch) || staleCalls != before {
				t.Fatalf("unsafe stale fallback: err=%v calls=%d want=%d", err, staleCalls, before)
			}
		})
	}
}

func TestRepairableInactiveStaleTablePreflightIsReadOnlyAndExact_SW2_WG_001(t *testing.T) {
	expected := exactWireGuardNFTIdentity()
	expected.OwnershipToken = strings.Repeat("b", 64)
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{family: "inet", name: "syswarden_wg", handle: 7}},
		detail: exactWireGuardNFTJSON(),
	}
	if err := attestRepairableTokenizedWireGuardNFTTableWithRunner(runner, expected); err != nil {
		t.Fatal(err)
	}
	if len(runner.deleteCalls) != 0 {
		t.Fatalf("read-only stale preflight deleted nftables state: %v", runner.deleteCalls)
	}

	exact := string(exactWireGuardNFTJSON())
	marker := `,"comment":"syswarden-wg-v1:` + strings.Repeat("a", 64) + `"`
	for name, detail := range map[string]string{
		"unmarked":    strings.Replace(exact, marker, "", 1),
		"extra state": strings.Replace(exact, `"handle":7}`, `"handle":7,"flags":["owner"]}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			candidate := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{family: "inet", name: "syswarden_wg", handle: 7}},
				detail: []byte(detail),
			}
			if err := attestRepairableTokenizedWireGuardNFTTableWithRunner(candidate, expected); err == nil || len(candidate.deleteCalls) != 0 {
				t.Fatalf("unsafe table accepted: err=%v deletes=%v", err, candidate.deleteCalls)
			}
		})
	}
}

func TestDisabledPreflightAcceptsOwnedActiveStaleStateWithoutMutation_SW2_WG_001(t *testing.T) {
	harness, manifestBefore := prepareEnabledWireGuardForDisable(t, false)
	previousTokenizedPreflight := wireGuardTokenizedNFTReadOnlyPreflight
	t.Cleanup(func() { wireGuardTokenizedNFTReadOnlyPreflight = previousTokenizedPreflight })
	provenanceMismatch := errors.New("existing WireGuard nftables table provenance mismatch")
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		if !expectation.AllowExisting || expectation.RequirePresent {
			t.Fatalf("disabled nftables expectation = %#v", expectation)
		}
		return provenanceMismatch
	}
	tokenizedCalls := 0
	wireGuardTokenizedNFTReadOnlyPreflight = func(identity wireguardstate.ServerConfigurationIdentity) error {
		tokenizedCalls++
		if identity.OwnershipToken != strings.Repeat("a", 64) || identity.ActiveInterface != "ens3" {
			t.Fatalf("disabled stale-table identity = %#v", identity)
		}
		return nil
	}

	stateBefore := harness.serviceState
	if err := PreflightWireguard(); err != nil {
		t.Fatalf("disabled active stale-table preflight: %v", err)
	}
	if tokenizedCalls != 1 || harness.serviceState != stateBefore || harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 {
		t.Fatalf(
			"disabled preflight mutated state: tokenized=%d state=%#v rollback=%d cleanup=%d",
			tokenizedCalls, harness.serviceState, harness.rollbackCalls, harness.nftCleanupCalls,
		)
	}
	manifestAfter, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !reflect.DeepEqual(manifestAfter, manifestBefore) {
		t.Fatalf("disabled preflight changed manifest: before=%#v after=%#v err=%v", manifestBefore, manifestAfter, err)
	}
}

func TestDisabledPreflightRefusesUnattestedTableWithoutMutation_SW2_WG_001(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	previousTokenizedPreflight := wireGuardTokenizedNFTReadOnlyPreflight
	t.Cleanup(func() { wireGuardTokenizedNFTReadOnlyPreflight = previousTokenizedPreflight })
	provenanceMismatch := errors.New("existing WireGuard nftables table provenance mismatch")
	unmarked := errors.New("table has no exact tokenized ownership marker")
	wireGuardNFTActivationPreflight = func(wireGuardNFTExpectation) error { return provenanceMismatch }
	wireGuardTokenizedNFTReadOnlyPreflight = func(wireguardstate.ServerConfigurationIdentity) error {
		return unmarked
	}

	stateBefore := harness.serviceState
	err := PreflightWireguard()
	if err == nil || !errors.Is(err, provenanceMismatch) || !errors.Is(err, unmarked) {
		t.Fatalf("disabled unattested-table preflight = %v", err)
	}
	if harness.serviceState != stateBefore || harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 {
		t.Fatalf(
			"disabled refusal mutated state: state=%#v rollback=%d cleanup=%d",
			harness.serviceState, harness.rollbackCalls, harness.nftCleanupCalls,
		)
	}
}

func TestDisabledPreflightRefusesUnownedRuntimeWithoutMutation_SW2_WG_001(t *testing.T) {
	for name, state := range map[string]wireGuardServiceState{
		"active":       {Alpine: false, Active: true, Enabled: true, Interface: true},
		"enabled only": {Alpine: false, Enabled: true},
	} {
		t.Run(name, func(t *testing.T) {
			harness := installWireGuardTransactionHarness(t)
			config.GlobalConfig.EnableWG = false
			harness.serviceState = state
			wireGuardNFTActivationPreflight = func(wireGuardNFTExpectation) error {
				t.Fatal("nftables absence was inspected after unowned runtime refusal")
				return nil
			}

			err := PreflightWireguard()
			if err == nil || !strings.Contains(err.Error(), "without an ownership manifest") {
				t.Fatalf("unowned disabled runtime preflight = %v", err)
			}
			if harness.serviceState != state || harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 {
				t.Fatalf(
					"unowned runtime refusal mutated state: state=%#v rollback=%d cleanup=%d",
					harness.serviceState, harness.rollbackCalls, harness.nftCleanupCalls,
				)
			}
		})
	}
}

func testPreflightWireguardLeavesPendingTransactionUntouched(t *testing.T, enabled bool) {
	t.Helper()
	previousConfig := config.GlobalConfig
	previousRoot := wireGuardFilesystemRoot
	previousBackendPreflight := wireGuardFirewallBackendPreflight
	previousManagerState := wireGuardManagerRuntimeState
	previousServiceInspector := wireGuardServiceInspector
	previousNFTPreflight := wireGuardNFTActivationPreflight
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardFilesystemRoot = previousRoot
		wireGuardFirewallBackendPreflight = previousBackendPreflight
		wireGuardManagerRuntimeState = previousManagerState
		wireGuardServiceInspector = previousServiceInspector
		wireGuardNFTActivationPreflight = previousNFTPreflight
	})

	root := t.TempDir()
	wireguardDirectory := filepath.Join(root, "etc", "wireguard")
	if err := os.MkdirAll(wireguardDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wireguardDirectory, 0700); err != nil { // #nosec G302 -- owner-only mode secures the private WireGuard fixture directory
		t.Fatal(err)
	}
	transactionPath := filepath.Join(root, strings.TrimPrefix(wireguardstate.TransactionPath, "/"))
	const transactionSentinel = "pending-transaction-must-remain-byte-exact\n"
	if err := os.WriteFile(transactionPath, []byte(transactionSentinel), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(transactionPath)
	if err != nil {
		t.Fatal(err)
	}

	config.GlobalConfig = &config.Config{EnableWG: enabled, FirewallBackend: "nftables"}
	wireGuardFilesystemRoot = root
	wireGuardFirewallBackendPreflight = func(string) error { return nil }
	wireGuardManagerRuntimeState = func() (string, error) {
		t.Fatal("service-manager inspection ran after pending transaction refusal")
		return "", nil
	}
	wireGuardServiceInspector = func() (wireGuardServiceState, error) {
		t.Fatal("service inspection ran after pending transaction refusal")
		return wireGuardServiceState{}, nil
	}
	wireGuardNFTActivationPreflight = func(wireGuardNFTExpectation) error {
		t.Fatal("nftables inspection ran after pending transaction refusal")
		return nil
	}

	err = PreflightWireguard()
	if err == nil || !strings.Contains(err.Error(), "transaction") || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("pending transaction preflight = %v", err)
	}
	afterWire, readErr := os.ReadFile(transactionPath) // #nosec G304 -- transactionPath is the fixed journal beneath the private test root
	after, statErr := os.Stat(transactionPath)
	if readErr != nil || statErr != nil {
		t.Fatalf("pending transaction disappeared: read=%v stat=%v", readErr, statErr)
	}
	if string(afterWire) != transactionSentinel || !os.SameFile(before, after) ||
		before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("read-only preflight changed pending transaction: before=%#v after=%#v content=%q", before, after, afterWire)
	}
}

func TestPreflightWireguardLeavesPendingTransactionUntouched_SW2_WG_001(t *testing.T) {
	for name, enabled := range map[string]bool{"enabled": true, "disabled": false} {
		t.Run(name, func(t *testing.T) {
			testPreflightWireguardLeavesPendingTransactionUntouched(t, enabled)
		})
	}
}
