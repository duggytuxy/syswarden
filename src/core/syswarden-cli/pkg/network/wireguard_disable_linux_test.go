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

func prepareEnabledWireGuardForDisable(t *testing.T, alpine bool) (*wireGuardTransactionHarness, wireguardstate.Manifest) {
	t.Helper()
	harness := installWireGuardTransactionHarness(t)
	if alpine {
		if err := os.MkdirAll(filepath.Join(harness.root, "etc/init.d"), 0755); err != nil { // #nosec G301 -- fixture models the protected system OpenRC directory mode
			t.Fatal(err)
		}
		wireGuardIsAlpine = func() bool { return true }
		harness.serviceState = wireGuardServiceState{Alpine: true}
	}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("prepare enabled WireGuard state: %v", err)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	config.GlobalConfig.EnableWG = false
	harness.expectTransaction = false
	harness.events = nil
	harness.rollbackCalls = 0
	harness.nftCleanupCalls = 0
	return harness, manifest
}

func assertWireGuardKeysPreserved(
	t *testing.T,
	before wireguardstate.Manifest,
	after wireguardstate.Manifest,
) {
	t.Helper()
	for _, path := range []string{
		wireguardstate.ServerConfigurationPath,
		wireguardstate.ClientConfigurationPath,
	} {
		beforeArtifact, err := wireGuardManifestArtifact(before, path)
		if err != nil {
			t.Fatal(err)
		}
		afterArtifact, err := wireGuardManifestArtifact(after, path)
		if err != nil {
			t.Fatal(err)
		}
		if beforeArtifact != afterArtifact {
			t.Fatalf("manifest-bound key artifact %s changed: before=%#v after=%#v", path, beforeArtifact, afterArtifact)
		}
	}
	if !reflect.DeepEqual(before.OpenRCServiceLink, after.OpenRCServiceLink) {
		t.Fatalf("OpenRC service-link ownership changed: before=%#v after=%#v", before.OpenRCServiceLink, after.OpenRCServiceLink)
	}
}

func TestSetupWireGuardDisabledRoutesThroughReconciler_SW2_WGSTATE_001(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousReconciler := wireGuardDisabledReconciler
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardDisabledReconciler = previousReconciler
	})
	config.GlobalConfig = &config.Config{EnableWG: false}
	called := 0
	wireGuardDisabledReconciler = func() error {
		called++
		return nil
	}
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("disabled reconciler calls = %d, want 1", called)
	}
}

func TestDisabledWireGuardStopsRuntimeAndPreservesManifestBoundKeys_SW2_WGSTATE_001(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		t.Run(map[bool]string{false: "systemd", true: "openrc"}[alpine], func(t *testing.T) {
			harness, before := prepareEnabledWireGuardForDisable(t, alpine)
			if err := SetupWireguard(); err != nil {
				t.Fatalf("disable WireGuard: %v", err)
			}
			wantState := wireGuardServiceState{Alpine: alpine}
			if harness.serviceState != wantState || harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
				t.Fatalf(
					"disabled state=%#v service reconciliations=%d nft cleanups=%d",
					harness.serviceState, harness.rollbackCalls, harness.nftCleanupCalls,
				)
			}
			if !reflect.DeepEqual(harness.events, []string{"rollback-service", "cleanup-nft"}) {
				t.Fatalf("disabled reconciliation order = %v", harness.events)
			}
			after, err := wireguardstate.ReadAndVerify(
				harness.root, networkTestUID(t), networkTestGID(t),
			)
			if err != nil {
				t.Fatal(err)
			}
			assertWireGuardKeysPreserved(t, before, after)
			state, err := inspectWireGuardForwardingPersistence(after, exactWireGuardNFTIdentity())
			if err != nil || state.BootEnabled || !state.BaselineKnown || state.Baseline != "0" {
				t.Fatalf("disabled forwarding persistence=%#v err=%v", state, err)
			}
			if !reflect.DeepEqual(harness.runtimeForwarding, []string{"0"}) {
				t.Fatalf("runtime forwarding reconciliation = %v", harness.runtimeForwarding)
			}
		})
	}
}

func TestDisabledWireGuardAlreadyInactiveIsIdempotent_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	harness.serviceState = wireGuardServiceState{Alpine: false}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("first already-disabled reconciliation: %v", err)
	}
	if harness.rollbackCalls != 0 || harness.nftCleanupCalls != 1 {
		t.Fatalf("first idempotent reconciliation service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("second already-disabled reconciliation: %v", err)
	}
	if harness.rollbackCalls != 0 || harness.nftCleanupCalls != 2 {
		t.Fatalf("second idempotent reconciliation service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
	after, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t))
	if err != nil {
		t.Fatal(err)
	}
	assertWireGuardKeysPreserved(t, before, after)
	if !reflect.DeepEqual(harness.runtimeForwarding, []string{"0", "0"}) {
		t.Fatalf("idempotent runtime reconciliation = %v", harness.runtimeForwarding)
	}
}

func TestDisabledWireGuardMutationsStayInsideActivationGuard_SW2_WGSTATE_001(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	locked := false
	wireGuardNFTActivationGuard = func() (func() error, error) {
		if locked {
			t.Fatal("disabled reconciliation acquired the activation guard recursively")
		}
		locked = true
		return func() error {
			if !locked {
				t.Fatal("disabled reconciliation released the activation guard twice")
			}
			locked = false
			return nil
		}, nil
	}
	serviceReconciler := wireGuardServiceRollback
	wireGuardServiceRollback = func(target wireGuardServiceState) error {
		if !locked {
			t.Fatal("service disable ran outside the activation guard")
		}
		return serviceReconciler(target)
	}
	tableCleanup := wireGuardReservedNFTCleanup
	wireGuardReservedNFTCleanup = func(identity wireguardstate.ServerConfigurationIdentity) error {
		if !locked {
			t.Fatal("nftables cleanup ran outside the activation guard")
		}
		return tableCleanup(identity)
	}
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	if locked || harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("guarded disable result: locked=%v service=%d nft=%d", locked, harness.rollbackCalls, harness.nftCleanupCalls)
	}
}

func TestDisabledWireGuardServiceFailurePreventsTableCleanup_SW2_WGSTATE_001(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	sentinel := errors.New("service stop failed")
	wireGuardServiceRollback = func(wireGuardServiceState) error {
		harness.rollbackCalls++
		return sentinel
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "stop and disable") {
		t.Fatalf("service failure result = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 0 || !harness.serviceState.ready() {
		t.Fatalf(
			"service failure safety: service=%d nft=%d state=%#v",
			harness.rollbackCalls, harness.nftCleanupCalls, harness.serviceState,
		)
	}
}

func TestDisabledWireGuardNeverMutatesUnownedOrPartialState_SW2_WGSTATE_001(t *testing.T) {
	t.Run("absent ownership", func(t *testing.T) {
		harness := installWireGuardTransactionHarness(t)
		config.GlobalConfig.EnableWG = false
		if err := SetupWireguard(); err != nil {
			t.Fatal(err)
		}
		if harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 {
			t.Fatalf("absent ownership caused mutation: service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
		}
	})

	t.Run("partial ownership", func(t *testing.T) {
		harness := installWireGuardTransactionHarness(t)
		config.GlobalConfig.EnableWG = false
		directory := filepath.Join(harness.root, "etc/wireguard")
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "wg-syswarden.conf"), []byte("partial\n"), 0600); err != nil {
			t.Fatal(err)
		}
		err := SetupWireguard()
		if err == nil || !strings.Contains(err.Error(), "unmanifested or partial") {
			t.Fatalf("partial generated-state result = %v", err)
		}
		if harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 {
			t.Fatalf("partial ownership caused mutation: service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
		}
	})

	t.Run("unmarked table", func(t *testing.T) {
		harness, _ := prepareEnabledWireGuardForDisable(t, false)
		currentFailure := errors.New("table has no manifest-bound marker")
		staleFailure := errors.New("table has no exact tokenized marker")
		previousStaleCleanup := wireGuardStaleNFTCleanup
		t.Cleanup(func() { wireGuardStaleNFTCleanup = previousStaleCleanup })
		deleteCalls := 0
		wireGuardReservedNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
			return currentFailure
		}
		wireGuardStaleNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
			if harness.serviceState.Active || harness.serviceState.Interface {
				t.Fatal("stale-table recovery was attempted while WireGuard was active")
			}
			deleteCalls++
			return staleFailure
		}
		err := SetupWireguard()
		if err == nil || !errors.Is(err, staleFailure) || !strings.Contains(err.Error(), currentFailure.Error()) {
			t.Fatalf("unmarked table result = %v", err)
		}
		if deleteCalls != 1 || harness.rollbackCalls != 1 || harness.serviceState.Active || harness.serviceState.Interface {
			t.Fatalf("unmarked table safety: attempts=%d service=%d state=%#v", deleteCalls, harness.rollbackCalls, harness.serviceState)
		}
	})
}

func TestDisabledWireGuardCleanupFailureRemainsRetryable_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	currentFailure := errors.New("current table cleanup failed")
	staleFailure := errors.New("stale table cleanup failed")
	previousStaleCleanup := wireGuardStaleNFTCleanup
	t.Cleanup(func() { wireGuardStaleNFTCleanup = previousStaleCleanup })
	attempts := 0
	staleAttempts := 0
	wireGuardReservedNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
		attempts++
		if attempts == 1 {
			return currentFailure
		}
		return nil
	}
	wireGuardStaleNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
		staleAttempts++
		if harness.serviceState.Active || harness.serviceState.Interface {
			t.Fatal("stale cleanup ran before the interface was stopped")
		}
		return staleFailure
	}

	err := SetupWireguard()
	if err == nil || !errors.Is(err, staleFailure) || !strings.Contains(err.Error(), currentFailure.Error()) {
		t.Fatalf("first cleanup result = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.serviceState != (wireGuardServiceState{Alpine: false}) {
		t.Fatalf("failed cleanup did not retain a safe retry state: service=%d state=%#v", harness.rollbackCalls, harness.serviceState)
	}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if attempts != 2 || staleAttempts != 1 || harness.rollbackCalls != 1 {
		t.Fatalf("cleanup retry counts: current=%d stale=%d service=%d", attempts, staleAttempts, harness.rollbackCalls)
	}
	after, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t))
	if err != nil {
		t.Fatal(err)
	}
	assertWireGuardKeysPreserved(t, before, after)
}
