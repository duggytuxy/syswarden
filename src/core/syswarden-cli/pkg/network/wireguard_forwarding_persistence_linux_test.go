//go:build linux

package network

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func currentWireGuardForwardingState(
	t *testing.T,
) (wireguardstate.Manifest, wireGuardForwardingPersistenceState) {
	t.Helper()
	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil {
		t.Fatal(err)
	}
	state, err := inspectWireGuardForwardingPersistence(manifest, identity)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, state
}

func TestWireGuardForwardingTransitionRecoversEveryMutationBoundary_SW2_WGSTATE_001(t *testing.T) {
	for _, point := range []string{
		"journal-published",
		"forwarding-staged",
		"manifest-staged",
		"forwarding-exchanged",
		"manifest-exchanged",
	} {
		t.Run(point, func(t *testing.T) {
			_, _ = prepareEnabledWireGuardForDisable(t, false)
			_, before := currentWireGuardForwardingState(t)
			identity := exactWireGuardNFTIdentity()
			target, err := canonicalWireGuardForwardingContent(identity, false, true, "0")
			if err != nil {
				t.Fatal(err)
			}
			previousFault := wireGuardForwardingTransitionFault
			t.Cleanup(func() { wireGuardForwardingTransitionFault = previousFault })
			sentinel := errors.New("synthetic transition interruption")
			fired := false
			wireGuardForwardingTransitionFault = func(got string) error {
				if got == point && !fired {
					fired = true
					return sentinel
				}
				return nil
			}
			err = transitionWireGuardForwardingPersistenceGuarded(identity, target)
			if err == nil || !errors.Is(err, sentinel) || !fired {
				t.Fatalf("fault %s result = %v fired=%v", point, err, fired)
			}
			_, recovered := currentWireGuardForwardingState(t)
			if point == "manifest-exchanged" {
				if recovered.BootEnabled || !bytes.Equal(recovered.Content, target) {
					t.Fatalf("committed recovery state = %#v", recovered)
				}
			} else if !recovered.BootEnabled || !bytes.Equal(recovered.Content, before.Content) {
				t.Fatalf("rolled-back recovery state = %#v, want %#v", recovered, before)
			}
			if pending, err := wireGuardForwardingTransitionPending(); err != nil || pending {
				t.Fatalf("transition debt after recovery: pending=%v err=%v", pending, err)
			}
			wireGuardForwardingTransitionFault = func(string) error { return nil }
			if err := transitionWireGuardForwardingPersistenceGuarded(identity, target); err != nil {
				t.Fatalf("retry after %s: %v", point, err)
			}
			_, final := currentWireGuardForwardingState(t)
			if final.BootEnabled || !final.BaselineKnown || final.Baseline != "0" || !bytes.Equal(final.Content, target) {
				t.Fatalf("retry did not converge: %#v", final)
			}
		})
	}
}

func TestWireGuardForwardingTransitionRecoversDirectorySyncFailure_SW2_WGSTATE_001(t *testing.T) {
	tests := []struct {
		name  string
		match func(string) bool
	}{
		{
			name: "journal",
			match: func(name string) bool {
				return name == filepath.Base(wireGuardForwardingTransitionPath)
			},
		},
		{
			name: "forwarding-stage",
			match: func(name string) bool {
				return strings.HasPrefix(name, ".99-syswarden-wireguard.conf.stage-")
			},
		},
		{
			name: "manifest-stage",
			match: func(name string) bool {
				return strings.HasPrefix(name, ".syswarden-ownership-v1.json.stage-")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness, _ := prepareEnabledWireGuardForDisable(t, false)
			_, before := currentWireGuardForwardingState(t)
			identity := exactWireGuardNFTIdentity()
			target, err := canonicalWireGuardForwardingContent(identity, false, true, "0")
			if err != nil {
				t.Fatal(err)
			}
			previousSync := wireGuardExactFileDirectorySync
			t.Cleanup(func() { wireGuardExactFileDirectorySync = previousSync })
			sentinel := errors.New("synthetic directory durability failure")
			fired := false
			wireGuardExactFileDirectorySync = func(directory *os.File, name string) error {
				if test.match(name) && !fired {
					fired = true
					return sentinel
				}
				return directory.Sync()
			}

			err = transitionWireGuardForwardingPersistenceGuarded(identity, target)
			if err == nil || !errors.Is(err, sentinel) || !fired {
				t.Fatalf("%s directory sync result = %v fired=%v", test.name, err, fired)
			}
			_, recovered := currentWireGuardForwardingState(t)
			if !recovered.BootEnabled || !bytes.Equal(recovered.Content, before.Content) {
				t.Fatalf("%s directory sync recovery = %#v, want %#v", test.name, recovered, before)
			}
			if pending, pendingErr := wireGuardForwardingTransitionPending(); pendingErr != nil || pending {
				t.Fatalf("%s directory sync left transition debt: pending=%v err=%v", test.name, pending, pendingErr)
			}
			for _, pattern := range []string{
				filepath.Join(harness.root, "etc/sysctl.d/.99-syswarden-wireguard.conf.stage-*"),
				filepath.Join(harness.root, "etc/wireguard/.syswarden-ownership-v1.json.stage-*"),
			} {
				matches, globErr := filepath.Glob(pattern)
				if globErr != nil || len(matches) != 0 {
					t.Fatalf("%s directory sync residue for %s = %v err=%v", test.name, pattern, matches, globErr)
				}
			}
		})
	}
}

func TestDisabledLegacyWireGuardNeutralizesBootWithoutGuessingRuntime_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	identity := exactWireGuardNFTIdentity()
	if err := transitionWireGuardForwardingPersistenceGuarded(
		identity, []byte(wireGuardForwardingSetting),
	); err != nil {
		t.Fatalf("prepare legacy v4.04.2 forwarding artifact: %v", err)
	}
	harness.runtimeForwarding = nil
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	after, state := currentWireGuardForwardingState(t)
	assertWireGuardKeysPreserved(t, before, after)
	if state.BootEnabled || state.BaselineKnown || state.Legacy ||
		bytes.Contains(state.Content, []byte("net.ipv4.ip_forward = 1")) {
		t.Fatalf("legacy forwarding persistence was not safely neutralized: %#v", state)
	}
	if len(harness.runtimeForwarding) != 0 {
		t.Fatalf("legacy state forced an unattested runtime value: %v", harness.runtimeForwarding)
	}
}

func TestDisabledWireGuardRuntimeFailureKeepsBootNeutralAndRetries_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	sentinel := errors.New("pinned runtime write failed")
	harness.runtimeForwardErr = sentinel
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "retry is safe") {
		t.Fatalf("runtime failure result = %v", err)
	}
	afterFailure, state := currentWireGuardForwardingState(t)
	assertWireGuardKeysPreserved(t, before, afterFailure)
	if state.BootEnabled || !state.BaselineKnown || state.Baseline != "0" {
		t.Fatalf("runtime failure left unsafe boot persistence: %#v", state)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("runtime failure lifecycle service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
	harness.runtimeForwardErr = nil
	if err := SetupWireguard(); err != nil {
		t.Fatalf("runtime reconciliation retry: %v", err)
	}
	if !reflect.DeepEqual(harness.runtimeForwarding, []string{"0", "0"}) || harness.rollbackCalls != 1 {
		t.Fatalf("runtime retry calls=%v service=%d", harness.runtimeForwarding, harness.rollbackCalls)
	}
}

func TestWireGuardReenableRestoresBootPersistenceAndPreservesKeys_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	_, disabled := currentWireGuardForwardingState(t)
	if disabled.BootEnabled {
		t.Fatal("test precondition did not neutralize boot persistence")
	}
	config.GlobalConfig.EnableWG = true
	harness.events = nil
	harness.expectTransaction = false
	if err := SetupWireguard(); err != nil {
		t.Fatalf("re-enable WireGuard: %v", err)
	}
	after, enabled := currentWireGuardForwardingState(t)
	assertWireGuardKeysPreserved(t, before, after)
	if !enabled.BootEnabled || !enabled.BaselineKnown || enabled.Baseline != "0" || enabled.Legacy {
		t.Fatalf("re-enabled forwarding persistence = %#v", enabled)
	}
	if !harness.serviceState.ready() {
		t.Fatalf("WireGuard runtime was not re-enabled: %#v", harness.serviceState)
	}
}

func TestWireGuardPersistenceFailureAfterActivationRollsBackToDisabledState_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	_, disabled := currentWireGuardForwardingState(t)
	config.GlobalConfig.EnableWG = true
	harness.expectTransaction = false
	harness.events = nil
	previousFault := wireGuardForwardingTransitionFault
	t.Cleanup(func() { wireGuardForwardingTransitionFault = previousFault })
	sentinel := errors.New("persistence stage failed")
	wireGuardForwardingTransitionFault = func(point string) error {
		if point == "forwarding-staged" {
			return sentinel
		}
		return nil
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("persistence failure after activation = %v", err)
	}
	after, recovered := currentWireGuardForwardingState(t)
	assertWireGuardKeysPreserved(t, before, after)
	if harness.serviceState != (wireGuardServiceState{Alpine: false}) ||
		!bytes.Equal(recovered.Content, disabled.Content) || recovered.BootEnabled {
		t.Fatalf("failed re-enable recovery: service=%#v persistence=%#v", harness.serviceState, recovered)
	}
	if pending, err := wireGuardForwardingTransitionPending(); err != nil || pending {
		t.Fatalf("failed re-enable left transition debt: pending=%v err=%v", pending, err)
	}
}

func TestSetupWireGuardManifestExchangeFaultRestoresNeutralPersistenceAndRuntime_SW2_WGSTATE_001(t *testing.T) {
	harness, before := prepareEnabledWireGuardForDisable(t, false)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	_, disabled := currentWireGuardForwardingState(t)
	config.GlobalConfig.EnableWG = true
	harness.expectTransaction = false
	harness.events = nil
	harness.rollbackCalls = 0
	harness.nftCleanupCalls = 0
	harness.sysctlRestoreCalls = 0

	previousFault := wireGuardForwardingTransitionFault
	t.Cleanup(func() { wireGuardForwardingTransitionFault = previousFault })
	sentinel := errors.New("persistence manifest exchange failed")
	fired := false
	wireGuardForwardingTransitionFault = func(point string) error {
		if point == "manifest-exchanged" && !fired {
			fired = true
			return sentinel
		}
		return nil
	}

	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !fired {
		t.Fatalf("manifest-exchanged setup result = %v fired=%v", err, fired)
	}
	after, recovered := currentWireGuardForwardingState(t)
	assertWireGuardKeysPreserved(t, before, after)
	if harness.serviceState != (wireGuardServiceState{Alpine: false}) || harness.rollbackCalls != 1 {
		t.Fatalf("failed re-enable service recovery: state=%#v rollbacks=%d", harness.serviceState, harness.rollbackCalls)
	}
	if harness.sysctlRestoreCalls != 1 {
		t.Fatalf("failed re-enable runtime forwarding restores = %d, want 1", harness.sysctlRestoreCalls)
	}
	if !bytes.Equal(recovered.Content, disabled.Content) || recovered.BootEnabled {
		t.Fatalf("failed re-enable persistence recovery: got=%#v want=%#v", recovered, disabled)
	}
	if pending, err := wireGuardForwardingTransitionPending(); err != nil || pending {
		t.Fatalf("failed re-enable left transition debt: pending=%v err=%v", pending, err)
	}
	if strings.Contains(strings.Join(harness.events, ","), "qr") {
		t.Fatal("failed persistence publication reached the success-only QR step")
	}
}

func TestNeutralizedForwardingArtifactRemainsRemovableByManifest_SW2_WGSTATE_001(t *testing.T) {
	_, _ = prepareEnabledWireGuardForDisable(t, false)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	forwardingPath := filepath.Join(
		wireGuardFilesystemRoot, strings.TrimPrefix(wireguardstate.ForwardingConfigurationPath, "/"),
	)
	content, err := os.ReadFile(forwardingPath) // #nosec G304 -- fixture root and fixed owned path
	if err != nil || bytes.Contains(content, []byte(wireGuardForwardingSetting)) {
		t.Fatalf("neutral boot artifact content=%q err=%v", content, err)
	}
	if err := wireguardstate.RemoveOwnedArtifacts(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	); err != nil {
		t.Fatalf("remove neutral manifest-bound bundle: %v", err)
	}
	if _, err := os.Lstat(forwardingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("neutral forwarding artifact remains after removal: %v", err)
	}
}

func TestForwardingCrashRecoveryPrecedesExactOwnershipRemoval_SW2_WGSTATE_001(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	identity := exactWireGuardNFTIdentity()
	target, err := canonicalWireGuardForwardingContent(identity, false, true, "0")
	if err != nil {
		t.Fatal(err)
	}
	previousFault := wireGuardForwardingTransitionFault
	t.Cleanup(func() { wireGuardForwardingTransitionFault = previousFault })
	crashMarker := &struct{}{}
	crashed := false
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered != crashMarker {
					t.Fatalf("unexpected transition panic: %v", recovered)
				}
				crashed = true
			}
		}()
		wireGuardForwardingTransitionFault = func(point string) error {
			if point == "forwarding-exchanged" {
				panic(crashMarker)
			}
			return nil
		}
		if err := transitionWireGuardForwardingPersistenceGuarded(identity, target); err != nil {
			t.Fatalf("transition returned before simulated crash: %v", err)
		}
	}()
	if !crashed {
		t.Fatal("forwarding transition did not reach the simulated crash boundary")
	}
	wireGuardForwardingTransitionFault = func(string) error { return nil }
	if pending, err := wireGuardForwardingTransitionPending(); err != nil || !pending {
		t.Fatalf("simulated crash debt: pending=%v err=%v", pending, err)
	}
	if err := RecoverPendingWireGuardForwardingState(); err != nil {
		t.Fatalf("recover forwarding persistence before removal: %v", err)
	}
	if err := RecoverPendingWireGuardForwardingState(); err != nil {
		t.Fatalf("repeat forwarding recovery: %v", err)
	}
	if _, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err != nil {
		t.Fatalf("ownership state after forwarding recovery: %v", err)
	}
	prepared, err := wireguardstate.PrepareRemoval(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !prepared {
		t.Fatalf("prepare ownership removal after forwarding recovery: prepared=%v err=%v", prepared, err)
	}
	finalized, err := wireguardstate.FinalizeRemoval(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !finalized {
		t.Fatalf("finalize ownership removal after forwarding recovery: finalized=%v err=%v", finalized, err)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || !inventory.Empty() {
		t.Fatalf("ownership inventory after removal = %#v err=%v", inventory, err)
	}
	for _, pattern := range []string{
		filepath.Join(harness.root, "etc/sysctl.d/.99-syswarden-wireguard.conf.stage-*"),
		filepath.Join(harness.root, "etc/wireguard/.syswarden-ownership-v1.json.stage-*"),
		filepath.Join(harness.root, "etc/wireguard/.syswarden-forwarding-transition-v1.json"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) != 0 {
			t.Fatalf("forwarding transition residue for %s = %v err=%v", pattern, matches, err)
		}
	}
}

func TestSetupAndDisableRecoverPendingForwardingUnderSingleGuard_SW2_WGSTATE_001(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		name := "disable"
		if enabled {
			name = "setup"
		}
		t.Run(name, func(t *testing.T) {
			harness, _ := prepareEnabledWireGuardForDisable(t, false)
			identity := exactWireGuardNFTIdentity()
			target, err := canonicalWireGuardForwardingContent(identity, false, true, "0")
			if err != nil {
				t.Fatal(err)
			}
			previousFault := wireGuardForwardingTransitionFault
			t.Cleanup(func() { wireGuardForwardingTransitionFault = previousFault })
			crashMarker := &struct{}{}
			crashed := false
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						if recovered != crashMarker {
							t.Fatalf("unexpected transition panic: %v", recovered)
						}
						crashed = true
					}
				}()
				wireGuardForwardingTransitionFault = func(point string) error {
					if point == "forwarding-exchanged" {
						panic(crashMarker)
					}
					return nil
				}
				_ = transitionWireGuardForwardingPersistenceGuarded(identity, target)
			}()
			if !crashed {
				t.Fatal("forwarding transition did not reach the simulated crash boundary")
			}
			wireGuardForwardingTransitionFault = func(string) error { return nil }
			if pending, pendingErr := wireGuardForwardingTransitionPending(); pendingErr != nil || !pending {
				t.Fatalf("simulated crash debt: pending=%v err=%v", pending, pendingErr)
			}

			config.GlobalConfig.EnableWG = enabled
			harness.expectTransaction = false
			locked := false
			acquisitions := 0
			releases := 0
			wireGuardNFTActivationGuard = func() (func() error, error) {
				acquisitions++
				if locked {
					return nil, errors.New("recursive recovery guard acquisition")
				}
				locked = true
				return func() error {
					releases++
					if pending, pendingErr := wireGuardForwardingTransitionPending(); pendingErr != nil || pending {
						t.Errorf("forwarding recovery was not complete before guard release: pending=%v err=%v", pending, pendingErr)
					}
					locked = false
					return nil
				}, nil
			}
			if err := SetupWireguard(); err != nil {
				t.Fatalf("%s after pending forwarding recovery: %v", name, err)
			}
			if locked || acquisitions != 1 || releases != 1 {
				t.Fatalf("%s recovery guard lifecycle: locked=%v acquisitions=%d releases=%d", name, locked, acquisitions, releases)
			}
		})
	}
}

func TestForwardingRecoveryPreservesCorruptJournalWithoutMutation_SW2_WGSTATE_001(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	path := filepath.Join(
		harness.root, strings.TrimPrefix(wireGuardForwardingTransitionPath, "/"),
	)
	const corrupt = "unattested forwarding transition must remain byte exact\n"
	if err := os.WriteFile(path, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	err = RecoverPendingWireGuardForwardingState()
	if err == nil || !strings.Contains(err.Error(), "recover attested WireGuard forwarding persistence") {
		t.Fatalf("corrupt forwarding journal recovery = %v", err)
	}
	afterWire, readErr := os.ReadFile(path) // #nosec G304 -- path is the fixed journal beneath the private test root
	after, statErr := os.Stat(path)
	if readErr != nil || statErr != nil || string(afterWire) != corrupt || !os.SameFile(before, after) ||
		before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("corrupt forwarding journal changed: before=%#v after=%#v content=%q read=%v stat=%v", before, after, afterWire, readErr, statErr)
	}
}
