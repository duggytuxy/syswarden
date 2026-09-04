//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
	"time"
)

type wireGuardTransactionHarness struct {
	root               string
	events             []string
	preflightCalls     int
	failPreflightAt    int
	preflightFailure   error
	afterPreflight     func(int)
	commandCalls       int
	sysctlCalls        int
	sysctlRestoreCalls int
	activationCalls    int
	rollbackCalls      int
	nftCleanupCalls    int
	expectTransaction  bool
	serviceState       wireGuardServiceState
	sysctlRestoreError error
	forwardingCloseErr error
	runtimeForwarding  []string
	runtimeForwardErr  error
}

type harnessWireGuardForwarding struct {
	harness *wireGuardTransactionHarness
	t       *testing.T
	applied bool
}

func (forwarding *harnessWireGuardForwarding) Apply() error {
	forwarding.applied = true
	forwarding.harness.sysctlCalls++
	forwarding.harness.events = append(forwarding.harness.events, "sysctl")
	inventory, err := wireguardstate.Inspect(forwarding.harness.root)
	if err != nil || !inventory.Manifest || inventory.Transaction != forwarding.harness.expectTransaction {
		forwarding.t.Fatalf("forwarding mutation lacks durable state: inventory=%#v err=%v", inventory, err)
	}
	return nil
}

func (forwarding *harnessWireGuardForwarding) Restore() error {
	if !forwarding.applied {
		return nil
	}
	forwarding.harness.sysctlRestoreCalls++
	forwarding.harness.events = append(forwarding.harness.events, "restore-sysctl")
	if forwarding.harness.sysctlRestoreError != nil {
		return forwarding.harness.sysctlRestoreError
	}
	forwarding.applied = false
	return nil
}

func (forwarding *harnessWireGuardForwarding) Close() error {
	return forwarding.harness.forwardingCloseErr
}

func (*harnessWireGuardForwarding) OriginalValue() string { return "0" }

func installWireGuardTransactionHarness(t *testing.T) *wireGuardTransactionHarness {
	t.Helper()
	harness := &wireGuardTransactionHarness{root: t.TempDir(), failPreflightAt: -1, expectTransaction: true}
	if err := os.Mkdir(filepath.Join(harness.root, "etc"), 0755); err != nil { // #nosec G301 -- fixture models the protected system configuration directory mode
		t.Fatal(err)
	}

	previousConfig := config.GlobalConfig
	previousRoot := wireGuardFilesystemRoot
	previousUID := wireGuardExpectedOwnerUID
	previousGID := wireGuardExpectedOwnerGID
	previousClassifier := wireGuardManagerRuntimeState
	previousAlpine := wireGuardIsAlpine
	previousPreflight := wireGuardFirewallBackendPreflight
	previousPrepare := wireGuardServicePrepare
	previousActivator := wireGuardServiceActivator
	previousInspector := wireGuardServiceInspector
	previousAbsentOpenRCInspector := wireGuardAbsentOpenRCServiceInspector
	previousRollback := wireGuardServiceRollback
	previousCleanup := wireGuardReservedNFTCleanup
	previousGuard := wireGuardNFTActivationGuard
	previousNFTPreflight := wireGuardNFTActivationPreflight
	previousNFTExecutable := wireGuardNFTExecutablePath
	previousTrueExecutable := wireGuardTrueExecutablePath
	previousToken := wireGuardOwnershipToken
	previousOutput := wireGuardCommandOutput
	previousInputOutput := wireGuardCommandInputOutput
	previousForwarding := wireGuardForwardingTransactionFactory
	previousRuntimeForwarding := wireGuardForwardingRuntimeReconciler
	previousQR := wireGuardQRCodeRender
	previousServiceDefinition := attestWireGuardServiceDefinition
	previousHookExecutables := wireGuardServerHookExecutableAttestor
	previousAfterCommit := wireGuardAfterOwnershipCommit
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		wireGuardFilesystemRoot = previousRoot
		wireGuardExpectedOwnerUID = previousUID
		wireGuardExpectedOwnerGID = previousGID
		wireGuardManagerRuntimeState = previousClassifier
		wireGuardIsAlpine = previousAlpine
		wireGuardFirewallBackendPreflight = previousPreflight
		wireGuardServicePrepare = previousPrepare
		wireGuardServiceActivator = previousActivator
		wireGuardServiceInspector = previousInspector
		wireGuardAbsentOpenRCServiceInspector = previousAbsentOpenRCInspector
		wireGuardServiceRollback = previousRollback
		wireGuardReservedNFTCleanup = previousCleanup
		wireGuardNFTActivationGuard = previousGuard
		wireGuardNFTActivationPreflight = previousNFTPreflight
		wireGuardNFTExecutablePath = previousNFTExecutable
		wireGuardTrueExecutablePath = previousTrueExecutable
		wireGuardOwnershipToken = previousToken
		wireGuardCommandOutput = previousOutput
		wireGuardCommandInputOutput = previousInputOutput
		wireGuardForwardingTransactionFactory = previousForwarding
		wireGuardForwardingRuntimeReconciler = previousRuntimeForwarding
		wireGuardQRCodeRender = previousQR
		attestWireGuardServiceDefinition = previousServiceDefinition
		wireGuardServerHookExecutableAttestor = previousHookExecutables
		wireGuardAfterOwnershipCommit = previousAfterCommit
	})

	config.GlobalConfig = &config.Config{
		EnableWG: true, FirewallBackend: "nftables", WGPort: "51820", WGSubnet: "10.66.0.0/16",
	}
	wireGuardFilesystemRoot = harness.root
	wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID = networkTestIdentity(t)
	wireGuardManagerRuntimeState = func() (string, error) { return "ACTIVE", nil }
	wireGuardIsAlpine = func() bool { return false }
	harness.serviceState = wireGuardServiceState{Alpine: false}
	wireGuardFirewallBackendPreflight = func(backend string) error {
		harness.preflightCalls++
		harness.events = append(harness.events, fmt.Sprintf("preflight:%d", harness.preflightCalls))
		if backend != "nftables" {
			t.Fatalf("backend = %q", backend)
		}
		if harness.preflightCalls == harness.failPreflightAt {
			return harness.preflightFailure
		}
		if harness.afterPreflight != nil {
			harness.afterPreflight(harness.preflightCalls)
		}
		return nil
	}
	wireGuardServiceActivator = func(baseline wireGuardServiceState) error {
		if baseline != harness.serviceState {
			t.Fatalf("activation baseline = %#v, want %#v", baseline, harness.serviceState)
		}
		harness.activationCalls++
		harness.events = append(harness.events, "activate")
		inventory, err := wireguardstate.Inspect(harness.root)
		if err != nil || !inventory.Manifest || inventory.Transaction != harness.expectTransaction {
			t.Fatalf("activation did not retain durable rollback state: inventory=%#v err=%v", inventory, err)
		}
		harness.serviceState = wireGuardServiceState{Alpine: baseline.Alpine, Active: true, Enabled: true, Interface: true}
		return nil
	}
	wireGuardServicePrepare = func() error { return nil }
	wireGuardAbsentOpenRCServiceInspector = func() (wireGuardServiceState, error) {
		return harness.serviceState, nil
	}
	attestWireGuardServiceDefinition = func() error { return nil }
	wireGuardServerHookExecutableAttestor = func(wireguardstate.ServerConfigurationIdentity) error { return nil }
	wireGuardAfterOwnershipCommit = func() {}
	wireGuardServiceInspector = func() (wireGuardServiceState, error) { return harness.serviceState, nil }
	wireGuardServiceRollback = func(target wireGuardServiceState) error {
		harness.rollbackCalls++
		harness.events = append(harness.events, "rollback-service")
		harness.serviceState = target
		return nil
	}
	wireGuardReservedNFTCleanup = func(identity wireguardstate.ServerConfigurationIdentity) error {
		harness.nftCleanupCalls++
		harness.events = append(harness.events, "cleanup-nft")
		if identity.ActiveInterface != "ens3" || identity.OwnershipToken != strings.Repeat("a", 64) {
			t.Fatalf("unexpected cleanup identity: %#v", identity)
		}
		return nil
	}
	wireGuardNFTActivationGuard = func() (func() error, error) {
		return func() error { return nil }, nil
	}
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		if expectation.RequirePresent != harness.serviceState.Active ||
			(harness.serviceState.Active && !expectation.AllowExisting) ||
			(!harness.serviceState.Active && harness.expectTransaction && expectation.AllowExisting) {
			t.Fatalf("unexpected nftables presence contract: expectation=%#v service=%#v", expectation, harness.serviceState)
		}
		if expectation.Identity.ActiveInterface != "ens3" || expectation.Identity.OwnershipToken != strings.Repeat("a", 64) {
			t.Fatalf("unexpected nftables identity: %#v", expectation.Identity)
		}
		return nil
	}
	wireGuardNFTExecutablePath = func() (string, error) { return "/usr/sbin/nft", nil }
	wireGuardTrueExecutablePath = func() (string, error) { return "/usr/bin/true", nil }
	wireGuardOwnershipToken = func() (string, error) { return strings.Repeat("a", 64), nil }
	serverPrivate := testWireGuardKey(1)
	serverPublic := testWireGuardKey(2)
	clientPrivate := testWireGuardKey(3)
	clientPublic := testWireGuardKey(4)
	preshared := testWireGuardKey(5)
	privateKeyCalls := 0
	wireGuardCommandOutput = func(name string, args ...string) ([]byte, error) {
		harness.commandCalls++
		command := strings.Join(append([]string{name}, args...), " ")
		switch command {
		case "wg genkey":
			privateKeyCalls++
			if privateKeyCalls == 1 {
				return []byte(serverPrivate + "\n"), nil
			}
			return []byte(clientPrivate + "\n"), nil
		case "wg genpsk":
			return []byte(preshared + "\n"), nil
		case "ip route get 8.8.8.8":
			return []byte("8.8.8.8 via 192.0.2.1 dev ens3 src 192.0.2.10\n"), nil
		default:
			if name == "curl" {
				return []byte("203.0.113.10\n"), nil
			}
			return nil, fmt.Errorf("unexpected command %s", command)
		}
	}
	wireGuardCommandInputOutput = func(input string, name string, args ...string) ([]byte, error) {
		harness.commandCalls++
		if name != "wg" || !reflect.DeepEqual(args, []string{"pubkey"}) {
			return nil, fmt.Errorf("unexpected input command %s %v", name, args)
		}
		switch input {
		case serverPrivate:
			return []byte(serverPublic + "\n"), nil
		case clientPrivate:
			return []byte(clientPublic + "\n"), nil
		default:
			return nil, fmt.Errorf("unexpected private key input")
		}
	}
	wireGuardForwardingTransactionFactory = func() (wireGuardForwardingTransaction, error) {
		return &harnessWireGuardForwarding{harness: harness, t: t}, nil
	}
	wireGuardForwardingRuntimeReconciler = func(value string) error {
		harness.runtimeForwarding = append(harness.runtimeForwarding, value)
		return harness.runtimeForwardErr
	}
	wireGuardQRCodeRender = func(string) error {
		harness.events = append(harness.events, "qr")
		return nil
	}
	return harness
}

func TestSetupWireGuardPublishesAttestedTransactionBeforeMutation_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	wantEvents := []string{
		"preflight:1",
		"preflight:2",
		"preflight:3",
		"preflight:4",
		"sysctl",
		"preflight:5",
		"activate",
		"preflight:6",
		"preflight:7",
		"qr",
	}
	if !reflect.DeepEqual(harness.events, wantEvents) {
		t.Fatalf("transaction events:\n got: %v\nwant: %v", harness.events, wantEvents)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 3 {
		t.Fatalf("manifest artifact count = %d", len(manifest.Artifacts))
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Transaction {
		t.Fatal("transaction journal remains after successful post-activation attestation")
	}
	for _, logical := range wireguardstate.ArtifactPaths() {
		info, err := os.Lstat(filepath.Join(harness.root, strings.TrimPrefix(logical, "/")))
		if err != nil {
			t.Fatalf("generated artifact %s is missing: %v", logical, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("generated artifact %s is not exact: mode=%v", logical, info.Mode())
		}
	}
}

func TestSetupWireGuardKeepsProtectedClientFileWhenOptionalQRRendererIsAbsent_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	wireGuardQRCodeRender = func(string) error {
		harness.events = append(harness.events, "qr-unavailable")
		return errors.New("qrencode is not installed")
	}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("optional QR renderer failure aborted WireGuard setup: %v", err)
	}
	if !strings.Contains(strings.Join(harness.events, ","), "qr-unavailable") {
		t.Fatalf("optional QR renderer was not attempted: %v", harness.events)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	clientPresent := false
	for _, path := range inventory.Artifacts {
		if path == wireguardstate.ClientConfigurationPath {
			clientPresent = true
			break
		}
	}
	if err != nil || !clientPresent {
		t.Fatalf("protected client configuration is unavailable after QR warning: inventory=%#v err=%v", inventory, err)
	}
}

func TestSetupWireGuardReusesOnlyFullyAttestedState_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	before, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t))
	if err != nil {
		t.Fatal(err)
	}
	commandCalls := harness.commandCalls
	harness.events = nil
	harness.preflightCalls = 0
	harness.expectTransaction = false
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	after, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("reused state identity changed:\n before=%#v\n after=%#v", before, after)
	}
	if harness.commandCalls != commandCalls {
		t.Fatalf("reuse regenerated key/network inputs: before=%d after=%d", commandCalls, harness.commandCalls)
	}
	wantEvents := []string{"preflight:1", "preflight:2", "sysctl", "preflight:3", "activate", "preflight:4", "preflight:5", "qr"}
	if !reflect.DeepEqual(harness.events, wantEvents) {
		t.Fatalf("reuse events:\n got: %v\nwant: %v", harness.events, wantEvents)
	}
}

func TestSetupWireGuardReuseFinalAttestationRejectsLateRuntimeDrift_SW2_WGSTATE_001(t *testing.T) {
	tests := []struct {
		name         string
		installDrift func(*testing.T, *wireGuardTransactionHarness) error
	}{
		{
			name: "service",
			installDrift: func(t *testing.T, harness *wireGuardTransactionHarness) error {
				t.Helper()
				inspect := wireGuardServiceInspector
				calls := 0
				wireGuardServiceInspector = func() (wireGuardServiceState, error) {
					calls++
					if calls == 4 {
						harness.serviceState = wireGuardServiceState{Alpine: false, Enabled: true}
					}
					return inspect()
				}
				return errors.New("late service drift must fail final attestation")
			},
		},
		{
			name: "table",
			installDrift: func(t *testing.T, _ *wireGuardTransactionHarness) error {
				t.Helper()
				sentinel := errors.New("late manifest-bound table drift")
				preflight := wireGuardNFTActivationPreflight
				calls := 0
				wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
					calls++
					if calls == 3 {
						return sentinel
					}
					return preflight(expectation)
				}
				return sentinel
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := installWireGuardTransactionHarness(t)
			if err := SetupWireguard(); err != nil {
				t.Fatalf("initial setup: %v", err)
			}
			baseline := harness.serviceState
			harness.events = nil
			harness.preflightCalls = 0
			harness.rollbackCalls = 0
			harness.nftCleanupCalls = 0
			harness.sysctlRestoreCalls = 0
			harness.expectTransaction = false
			sentinel := test.installDrift(t, harness)

			err := SetupWireguard()
			if err == nil || (test.name == "table" && !errors.Is(err, sentinel)) ||
				!strings.Contains(err.Error(), "final WireGuard runtime attestation") {
				t.Fatalf("late %s drift result = %v", test.name, err)
			}
			if harness.serviceState != baseline || harness.rollbackCalls != 1 ||
				harness.nftCleanupCalls != 0 || harness.sysctlRestoreCalls != 1 {
				t.Fatalf(
					"late %s drift compensation: state=%#v baseline=%#v rollback=%d cleanup=%d forwarding=%d",
					test.name, harness.serviceState, baseline, harness.rollbackCalls,
					harness.nftCleanupCalls, harness.sysctlRestoreCalls,
				)
			}
			if strings.Contains(strings.Join(harness.events, ","), "qr") {
				t.Fatalf("late %s drift emitted success output: %v", test.name, harness.events)
			}
		})
	}
}

func TestSetupWireGuardFreshOpenRCOwnsOnlyExclusivelyCreatedServiceLink_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	initDirectory := filepath.Join(harness.root, "etc/init.d")
	if err := os.MkdirAll(initDirectory, 0755); err != nil { // #nosec G301 -- fixture models the protected system OpenRC directory mode
		t.Fatal(err)
	}
	wireGuardIsAlpine = func() bool { return true }
	harness.serviceState = wireGuardServiceState{Alpine: true}
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OpenRCServiceLink == nil || manifest.OpenRCServiceLink.Inode == 0 {
		t.Fatalf("fresh OpenRC link lacks exact ownership provenance: %#v", manifest.OpenRCServiceLink)
	}
	linkPath := filepath.Join(harness.root, strings.TrimPrefix(wireguardstate.OpenRCServiceLinkPath, "/"))
	if target, err := os.Readlink(linkPath); err != nil || target != wireguardstate.OpenRCServiceLinkTarget {
		t.Fatalf("owned OpenRC service link: target=%q err=%v", target, err)
	}
	if err := wireguardstate.RemoveOwnedArtifacts(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(linkPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("manifest-owned OpenRC link remained after exact removal: %v", err)
	}
}

func TestSetupWireGuardPreexistingExactOpenRCLinkIsNeverAdopted_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	initDirectory := filepath.Join(harness.root, "etc/init.d")
	if err := os.MkdirAll(initDirectory, 0755); err != nil { // #nosec G301 -- fixture models the protected system OpenRC directory mode
		t.Fatal(err)
	}
	linkPath := filepath.Join(harness.root, strings.TrimPrefix(wireguardstate.OpenRCServiceLinkPath, "/"))
	if err := os.Symlink(wireguardstate.OpenRCServiceLinkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	wireGuardIsAlpine = func() bool { return true }
	harness.serviceState = wireGuardServiceState{Alpine: true}
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OpenRCServiceLink != nil {
		t.Fatalf("preexisting operator link was adopted: %#v", manifest.OpenRCServiceLink)
	}
	if err := wireguardstate.RemoveOwnedArtifacts(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(linkPath)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("preexisting exact operator link changed during removal: before=%v after=%v err=%v", before, after, err)
	}
}

func TestSetupWireGuardActiveReuseRequiresOwnedTableBeforeForwardingMutation_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	sysctlCalls := harness.sysctlCalls
	activationCalls := harness.activationCalls
	sentinel := errors.New("owned table absent")
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		if expectation.RequirePresent {
			return sentinel
		}
		return nil
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before activation") {
		t.Fatalf("active reuse without table error = %v", err)
	}
	if harness.sysctlCalls != sysctlCalls || harness.activationCalls != activationCalls {
		t.Fatalf("absent reuse table caused mutation: forwarding %d->%d activation %d->%d", sysctlCalls, harness.sysctlCalls, activationCalls, harness.activationCalls)
	}
	if !harness.serviceState.ready() {
		t.Fatalf("preexisting active service was changed: %#v", harness.serviceState)
	}
}

func TestSetupWireGuardInactiveReuseRetiresOnlyManifestBoundTableBeforeRestart_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatalf("initial setup: %v", err)
	}
	harness.serviceState = wireGuardServiceState{Alpine: false}
	harness.expectTransaction = false
	harness.activationCalls = 0
	harness.nftCleanupCalls = 0
	harness.preflightCalls = 0
	harness.events = nil
	if err := SetupWireguard(); err != nil {
		t.Fatalf("inactive reusable setup: %v", err)
	}
	if harness.activationCalls != 1 || harness.nftCleanupCalls != 1 || !harness.serviceState.ready() {
		t.Fatalf("inactive restart counts: activate=%d cleanup=%d state=%#v", harness.activationCalls, harness.nftCleanupCalls, harness.serviceState)
	}
	wantPrefix := []string{"preflight:1", "cleanup-nft", "preflight:2", "sysctl", "preflight:3"}
	if len(harness.events) < len(wantPrefix) || !reflect.DeepEqual(harness.events[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("inactive restart provenance order: got %v want prefix %v", harness.events, wantPrefix)
	}
}

func TestSetupWireGuardInactiveReuseRecoversOnlyExactTokenizedStaleTable_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatalf("initial setup: %v", err)
	}
	harness.serviceState = wireGuardServiceState{Alpine: false}
	harness.expectTransaction = false
	markerMismatch := errors.New("ownership marker does not match the manifest-bound token")
	wireGuardReservedNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
		harness.events = append(harness.events, "cleanup-current-token")
		return markerMismatch
	}
	previousStaleCleanup := wireGuardStaleNFTCleanup
	t.Cleanup(func() { wireGuardStaleNFTCleanup = previousStaleCleanup })
	staleCleanupCalls := 0
	wireGuardStaleNFTCleanup = func(identity wireguardstate.ServerConfigurationIdentity) error {
		staleCleanupCalls++
		harness.events = append(harness.events, "cleanup-stale-token")
		if identity != exactWireGuardNFTIdentity() {
			t.Fatalf("stale cleanup identity = %#v", identity)
		}
		return nil
	}
	if err := SetupWireguard(); err != nil {
		t.Fatalf("inactive stale-table recovery: %v", err)
	}
	if staleCleanupCalls != 1 || !harness.serviceState.ready() {
		t.Fatalf("stale recovery calls=%d state=%#v", staleCleanupCalls, harness.serviceState)
	}
	wantOrder := []string{"cleanup-current-token", "cleanup-stale-token"}
	joined := strings.Join(harness.events, ",")
	if !strings.Contains(joined, strings.Join(wantOrder, ",")) {
		t.Fatalf("stale recovery order = %v", harness.events)
	}
}

func TestSetupWireGuardPostActivationDriftRollsBackServiceThenOwnedNFT_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	sentinel := errors.New("firewalld became active")
	harness.failPreflightAt = 6
	harness.preflightFailure = sentinel
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "after WireGuard activation") {
		t.Fatalf("post-activation drift error = %v", err)
	}
	if harness.activationCalls != 1 || harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("rollback counts: activate=%d service=%d nft=%d", harness.activationCalls, harness.rollbackCalls, harness.nftCleanupCalls)
	}
	wantTail := []string{"activate", "preflight:6", "rollback-service", "cleanup-nft", "restore-sysctl"}
	if got := harness.events[len(harness.events)-len(wantTail):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("rollback order: got %v want %v", got, wantTail)
	}
	if _, err := wireguardstate.ReadAndVerify(harness.root, networkTestUID(t), networkTestGID(t)); err != nil {
		t.Fatalf("retryable generated state was not retained after safe rollback: %v", err)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || inventory.Transaction {
		t.Fatalf("post-drift transaction was not recovered: inventory=%#v err=%v", inventory, err)
	}
	if harness.sysctlRestoreCalls != 1 {
		t.Fatalf("sysctl restore calls = %d, want 1", harness.sysctlRestoreCalls)
	}
}

func TestSetupWireGuardReuseRollbackPreservesPreexistingActiveEnabledServiceAndTable_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatal(err)
	}
	harness.events = nil
	harness.preflightCalls = 0
	harness.failPreflightAt = 4
	harness.preflightFailure = errors.New("post-activation backend drift")
	harness.rollbackCalls = 0
	harness.nftCleanupCalls = 0
	harness.sysctlRestoreCalls = 0
	harness.expectTransaction = false
	err := SetupWireguard()
	if err == nil || !errors.Is(err, harness.preflightFailure) {
		t.Fatalf("reuse post-activation drift error = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 0 || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("reuse preservation counts: rollback=%d cleanup=%d forwarding=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
	if !harness.serviceState.ready() {
		t.Fatalf("preexisting service state was not preserved: %#v", harness.serviceState)
	}
}

func TestSetupWireGuardPostActivationRequiresEnabledActiveInterfaceState_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	wireGuardServiceActivator = func(_ wireGuardServiceState) error {
		harness.activationCalls++
		harness.events = append(harness.events, "activate")
		harness.serviceState = wireGuardServiceState{Alpine: false, Active: true, Interface: true, Enabled: false}
		return nil
	}
	err := SetupWireguard()
	if err == nil || !strings.Contains(err.Error(), "service attestation failed") {
		t.Fatalf("inexact post-activation service state error = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("inexact service rollback counts: service=%d nft=%d forwarding=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
}

func TestSetupWireGuardActivationFailureRollsBackPartialServiceState_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	sentinel := errors.New("service activation partially failed")
	wireGuardServiceActivator = func(_ wireGuardServiceState) error {
		harness.activationCalls++
		harness.events = append(harness.events, "activate")
		return sentinel
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "activate WireGuard service") {
		t.Fatalf("activation error = %v", err)
	}
	if harness.activationCalls != 1 || harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 ||
		harness.sysctlRestoreCalls != 1 {
		t.Fatalf("rollback counts: activate=%d service=%d nft=%d sysctl=%d", harness.activationCalls, harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
	wantTail := []string{"activate", "preflight:6", "rollback-service", "cleanup-nft", "restore-sysctl"}
	if got := harness.events[len(harness.events)-len(wantTail):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("partial activation rollback order: got %v want %v", got, wantTail)
	}
}

func TestSetupWireGuardCommitFailureRollsBackActivationAndSysctl_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	harness.afterPreflight = func(call int) {
		if call != 6 {
			return
		}
		clientPath := filepath.Join(harness.root, "etc/wireguard/clients/admin-pc.conf")
		if err := os.WriteFile(clientPath, []byte("post-activation drift\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := SetupWireguard()
	if err == nil || !strings.Contains(err.Error(), "commit WireGuard ownership transaction") {
		t.Fatalf("ownership commit drift error = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("commit rollback counts: service=%d nft=%d sysctl=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
	wantOrder := []string{"activate", "preflight:6", "rollback-service", "cleanup-nft", "restore-sysctl"}
	if got := harness.events[len(harness.events)-len(wantOrder):]; !reflect.DeepEqual(got, wantOrder) {
		t.Fatalf("commit rollback order: got %v want %v", got, wantOrder)
	}
}

func TestSetupWireGuardPostCommitDriftCannotReturnSuccessOrLeaveUnprovenRuntime_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	sentinel := errors.New("backend drifted after ownership commit")
	locked := false
	guardAcquisitions := 0
	guardReleases := 0
	wireGuardNFTActivationGuard = func() (func() error, error) {
		guardAcquisitions++
		if locked {
			return nil, fmt.Errorf("recursive test guard acquisition")
		}
		locked = true
		return func() error {
			guardReleases++
			if !locked {
				return fmt.Errorf("duplicate test guard release")
			}
			if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 || harness.sysctlRestoreCalls != 1 {
				t.Errorf(
					"guard released before compensation completed: service=%d nft=%d sysctl=%d",
					harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls,
				)
			}
			inventory, inspectErr := wireguardstate.Inspect(harness.root)
			if inspectErr != nil || !inventory.Empty() {
				t.Errorf("guard released before ownership cleanup completed: inventory=%#v err=%v", inventory, inspectErr)
			}
			harness.events = append(harness.events, "guard-release")
			locked = false
			return nil
		}, nil
	}
	tablePresent := false
	activate := wireGuardServiceActivator
	wireGuardServiceActivator = func(baseline wireGuardServiceState) error {
		if err := activate(baseline); err != nil {
			return err
		}
		tablePresent = true
		return nil
	}
	nftPreflight := wireGuardNFTActivationPreflight
	wireGuardNFTActivationPreflight = func(expectation wireGuardNFTExpectation) error {
		if err := nftPreflight(expectation); err != nil {
			return err
		}
		if expectation.RequirePresent != tablePresent {
			t.Fatalf("nftables presence = %v, expectation=%#v", tablePresent, expectation)
		}
		return nil
	}
	cleanup := wireGuardReservedNFTCleanup
	wireGuardReservedNFTCleanup = func(identity wireguardstate.ServerConfigurationIdentity) error {
		if !tablePresent {
			t.Fatal("post-commit compensation attempted to remove an absent owned table")
		}
		if err := cleanup(identity); err != nil {
			return err
		}
		tablePresent = false
		return nil
	}
	wireGuardAfterOwnershipCommit = func() {
		harness.events = append(harness.events, "post-commit-drift")
		inventory, err := wireguardstate.Inspect(harness.root)
		if err != nil {
			t.Fatal(err)
		}
		if inventory.Transaction || !inventory.Manifest {
			t.Fatalf("drift was not injected after durable commit: inventory=%#v", inventory)
		}
		harness.failPreflightAt = harness.preflightCalls + 1
		harness.preflightFailure = sentinel
	}

	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "after ownership commit") {
		t.Fatalf("post-commit drift result = %v", err)
	}
	if harness.serviceState.ready() || tablePresent || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("uncompensated runtime: service=%#v table=%v sysctl-restores=%d", harness.serviceState, tablePresent, harness.sysctlRestoreCalls)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("post-commit compensation counts: service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
	wantTail := []string{
		"activate", "preflight:6", "post-commit-drift", "preflight:7",
		"rollback-service", "cleanup-nft", "restore-sysctl", "guard-release",
	}
	if got := harness.events[len(harness.events)-len(wantTail):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("post-commit compensation order: got %v want %v", got, wantTail)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || !inventory.Empty() {
		t.Fatalf("post-commit compensation left generated state or transaction debris: inventory=%#v err=%v", inventory, err)
	}
	if strings.Contains(strings.Join(harness.events, ","), "qr") {
		t.Fatal("post-commit drift was reported as success")
	}
	if locked || guardAcquisitions != 1 || guardReleases != 1 {
		t.Fatalf("complete setup guard lifecycle: locked=%v acquisitions=%d releases=%d", locked, guardAcquisitions, guardReleases)
	}
}

func TestSetupWireGuardForwardingRestoreFailureRetainsReloadDebt_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	drift := errors.New("backend drift after ownership commit")
	restoreFailure := errors.New("forwarding restoration failed")
	harness.sysctlRestoreError = restoreFailure
	wireGuardAfterOwnershipCommit = func() {
		harness.failPreflightAt = harness.preflightCalls + 1
		harness.preflightFailure = drift
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, drift) || !errors.Is(err, restoreFailure) {
		t.Fatalf("post-commit forwarding restoration result = %v", err)
	}
	operation, present, inspectErr := wireguardstate.InspectTransaction(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if inspectErr != nil || !present || operation != wireguardstate.TransactionOperationRemovePendingReload {
		t.Fatalf("forwarding failure lost reload debt: operation=%q present=%v err=%v", operation, present, inspectErr)
	}
	if recovered, err := wireguardstate.Recover(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err == nil || recovered {
		t.Fatalf("general recovery consumed forwarding reload debt: recovered=%v err=%v", recovered, err)
	}
	prepared, err := wireguardstate.PrepareRemoval(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !prepared {
		t.Fatalf("retry durable removal preparation: prepared=%v err=%v", prepared, err)
	}
	// This boundary represents a successful retry of the exact runtime restore.
	finalized, err := wireguardstate.FinalizeRemoval(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !finalized {
		t.Fatalf("finalize after forwarding retry: finalized=%v err=%v", finalized, err)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || !inventory.Empty() {
		t.Fatalf("forwarding retry left generated state: inventory=%#v err=%v", inventory, err)
	}
}

func TestSetupWireGuardPostCommitCleanupFailureRetainsOwnershipEvidence_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	drift := errors.New("backend drift after commit")
	cleanupFailure := errors.New("owned nftables cleanup did not converge")
	wireGuardAfterOwnershipCommit = func() {
		harness.failPreflightAt = harness.preflightCalls + 1
		harness.preflightFailure = drift
	}
	wireGuardReservedNFTCleanup = func(wireguardstate.ServerConfigurationIdentity) error {
		harness.nftCleanupCalls++
		return cleanupFailure
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, drift) || !errors.Is(err, cleanupFailure) {
		t.Fatalf("post-commit cleanup failure result = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("failed cleanup compensation counts: service=%d nft=%d sysctl=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
	if _, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err != nil {
		t.Fatalf("ownership evidence was destroyed after unproven nftables cleanup: %v", err)
	}
	inventory, err := wireguardstate.Inspect(harness.root)
	if err != nil || inventory.Transaction {
		t.Fatalf("retained ownership state is not durably committed: inventory=%#v err=%v", inventory, err)
	}
}

func TestSetupWireGuardServiceRollbackFailureStillAttemptsOwnedNFTCleanup_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	drift := errors.New("post-activation backend drift")
	serviceFailure := errors.New("service rollback failed")
	harness.failPreflightAt = 6
	harness.preflightFailure = drift
	wireGuardServiceRollback = func(wireGuardServiceState) error {
		harness.rollbackCalls++
		harness.events = append(harness.events, "rollback-service")
		return serviceFailure
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, drift) || !errors.Is(err, serviceFailure) {
		t.Fatalf("service rollback failure result = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("compensation stopped early: service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
}

func TestSetupWireGuardGuardReleaseFailureRetainsVerifiedCommit_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	sentinel := errors.New("activation guard release failed")
	acquisitions := 0
	releases := 0
	wireGuardNFTActivationGuard = func() (func() error, error) {
		acquisitions++
		return func() error {
			releases++
			return sentinel
		}, nil
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "after verified commit") {
		t.Fatalf("activation guard release error = %v", err)
	}
	if harness.rollbackCalls != 0 || harness.nftCleanupCalls != 0 || harness.sysctlRestoreCalls != 0 {
		t.Fatalf("verified commit was rolled back after release uncertainty: service=%d nft=%d sysctl=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
	}
	if !harness.serviceState.ready() {
		t.Fatalf("verified WireGuard runtime was not retained: %#v", harness.serviceState)
	}
	if _, err := wireguardstate.ReadAndVerify(
		harness.root, networkTestUID(t), networkTestGID(t),
	); err != nil {
		t.Fatalf("verified ownership evidence was not retained: %v", err)
	}
	if acquisitions != 1 || releases != 1 {
		t.Fatalf("release uncertainty retried the guard: acquisitions=%d releases=%d", acquisitions, releases)
	}
}

func TestSetupWireGuardSerializesCompleteTransitionAgainstDisable_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	token := make(chan struct{}, 1)
	token <- struct{}{}
	secondAttempt := make(chan struct{})
	var acquisitions atomic.Int32
	wireGuardNFTActivationGuard = func() (func() error, error) {
		attempt := acquisitions.Add(1)
		if attempt == 2 {
			close(secondAttempt)
		}
		<-token
		released := false
		return func() error {
			if released {
				return fmt.Errorf("test WireGuard guard released twice")
			}
			released = true
			token <- struct{}{}
			return nil
		}, nil
	}

	setupPaused := make(chan struct{})
	resumeSetup := make(chan struct{})
	wireGuardAfterOwnershipCommit = func() {
		close(setupPaused)
		<-resumeSetup
	}
	setupDone := make(chan error, 1)
	go func() { setupDone <- SetupWireguard() }()
	select {
	case <-setupPaused:
	case <-time.After(2 * time.Second):
		t.Fatal("setup did not reach the ownership commit boundary")
	}

	disableDone := make(chan error, 1)
	go func() { disableDone <- reconcileDisabledWireGuard() }()
	select {
	case <-secondAttempt:
	case <-time.After(2 * time.Second):
		t.Fatal("disable did not attempt to acquire the shared guard")
	}
	select {
	case err := <-disableDone:
		t.Fatalf("disable escaped the setup guard before setup completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(resumeSetup)
	select {
	case err := <-setupDone:
		if err != nil {
			t.Fatalf("guarded setup: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("guarded setup did not complete")
	}
	select {
	case err := <-disableDone:
		if err != nil {
			t.Fatalf("serialized disable: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serialized disable did not complete after setup released the guard")
	}

	if acquisitions.Load() != 2 {
		t.Fatalf("shared guard acquisitions = %d, want one setup and one disable acquisition", acquisitions.Load())
	}
	if harness.serviceState.Active || harness.serviceState.Enabled || harness.serviceState.Interface {
		t.Fatalf("serialized disable did not converge after setup: %#v", harness.serviceState)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 {
		t.Fatalf("serialized disable mutations: service=%d nft=%d", harness.rollbackCalls, harness.nftCleanupCalls)
	}
}

func TestSetupWireGuardRejectsPartialStateBeforeKeyOrHostMutation_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	serverPath := filepath.Join(harness.root, "etc/wireguard/wg-syswarden.conf")
	if err := os.MkdirAll(filepath.Dir(serverPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(serverPath), 0755); err != nil { // #nosec G302 -- adversarial fixture deliberately preserves an unsafe partial-state directory mode
		t.Fatal(err)
	}
	if err := os.WriteFile(serverPath, []byte("unmanifested\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := SetupWireguard()
	if err == nil || !strings.Contains(err.Error(), "unmanifested or partial") {
		t.Fatalf("partial-state error = %v", err)
	}
	if harness.commandCalls != 0 || harness.sysctlCalls != 0 || harness.activationCalls != 0 {
		t.Fatalf("partial state caused mutation: commands=%d sysctl=%d activate=%d", harness.commandCalls, harness.sysctlCalls, harness.activationCalls)
	}
	content, err := os.ReadFile(serverPath) // #nosec G304 -- serverPath is confined to the private transaction harness root
	if err != nil || string(content) != "unmanifested\n" {
		t.Fatalf("partial state changed: content=%q err=%v", content, err)
	}
	info, err := os.Stat(filepath.Dir(serverPath))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("partial-state directory metadata changed: mode=%v", info.Mode())
	}
}

type fakeWireGuardNFTRunner struct {
	tables      []fakeWireGuardNFTTable
	detail      []byte
	deleteCalls [][]string
	retain      bool
	replace     bool
	listErr     error
}

type fakeWireGuardNFTTable struct {
	family string
	name   string
	handle uint64
}

func (runner *fakeWireGuardNFTRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	if reflect.DeepEqual(args, []string{"-a", "-j", "list", "tables"}) {
		if runner.listErr != nil {
			return []byte("inventory failed"), runner.listErr
		}
		parts := make([]string, 0, len(runner.tables))
		for _, table := range runner.tables {
			parts = append(parts, fmt.Sprintf(`{"table":{"family":%q,"name":%q,"handle":%d}}`, table.family, table.name, table.handle))
		}
		return []byte(`{"nftables":[` + strings.Join(parts, ",") + `]}`), nil
	}
	if reflect.DeepEqual(args, []string{"-a", "-j", "list", "table", "inet", "syswarden_wg"}) {
		return append([]byte(nil), runner.detail...), nil
	}
	if len(args) == 5 && reflect.DeepEqual(args[:4], []string{"delete", "table", "inet", "handle"}) {
		runner.deleteCalls = append(runner.deleteCalls, append([]string(nil), args...))
		if !runner.retain {
			remaining := runner.tables[:0]
			for _, table := range runner.tables {
				if fmt.Sprint(table.handle) != args[4] {
					remaining = append(remaining, table)
				}
			}
			runner.tables = append([]fakeWireGuardNFTTable(nil), remaining...)
			if runner.replace {
				runner.tables = append(runner.tables, fakeWireGuardNFTTable{family: "inet", name: "syswarden_wg", handle: 99})
			}
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected nft arguments: %v", args)
}

func exactWireGuardNFTIdentity() wireguardstate.ServerConfigurationIdentity {
	return wireguardstate.ServerConfigurationIdentity{
		NFTPath: "/usr/sbin/nft", TruePath: "/usr/bin/true",
		OwnershipToken: strings.Repeat("a", 64), ActiveInterface: "ens3",
	}
}

func exactWireGuardNFTJSON() []byte {
	return []byte(`{"nftables":[
{"metainfo":{"json_schema_version":1}},
{"table":{"family":"inet","name":"syswarden_wg","comment":"syswarden-wg-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","handle":7}},
{"chain":{"family":"inet","table":"syswarden_wg","name":"prerouting","type":"nat","hook":"prerouting","prio":-100,"policy":"accept","handle":8}},
{"chain":{"family":"inet","table":"syswarden_wg","name":"postrouting","type":"nat","hook":"postrouting","prio":100,"policy":"accept","handle":9}},
{"chain":{"family":"inet","table":"syswarden_wg","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"accept","handle":10}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"postrouting","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"ens3"}},{"masquerade":null}],"handle":11}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"wg-syswarden"}},{"accept":null}],"handle":12}},
{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"wg-syswarden"}},{"accept":null}],"handle":13}}
]}`)
}

func TestWireGuardOwnedNFTCleanupDeletesOnlyReservedExactTable_SW2_FWBACKEND_001(t *testing.T) {
	identity := exactWireGuardNFTIdentity()
	identityAttestations := 0
	runtimeAttestations := 0
	reattestIdentity := func() error { identityAttestations++; return nil }
	reattestRuntime := func() error { runtimeAttestations++; return nil }
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}, {"ip", "syswarden_wg", 8}},
		detail: exactWireGuardNFTJSON(), replace: true,
	}
	if err := cleanupWireGuardReservedNFTTableWithRunner(
		runner, identity, reattestIdentity, reattestRuntime,
	); err != nil {
		t.Fatal(err)
	}
	if identityAttestations != 3 || runtimeAttestations != 3 {
		t.Fatalf("owned cleanup attestations: identity=%d runtime=%d, want 3 each", identityAttestations, runtimeAttestations)
	}
	if !reflect.DeepEqual(runner.deleteCalls, [][]string{{"delete", "table", "inet", "handle", "7"}}) {
		t.Fatalf("delete calls = %v", runner.deleteCalls)
	}
	if len(runner.tables) != 3 || runner.tables[2].handle != 99 {
		t.Fatalf("operator replacement was not preserved: %v", runner.tables)
	}

	residual := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(), retain: true,
	}
	if err := cleanupWireGuardReservedNFTTableWithRunner(
		residual, identity, func() error { return nil }, func() error { return nil },
	); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("residual cleanup error = %v", err)
	}
	failure := errors.New("inventory unavailable")
	failed := &fakeWireGuardNFTRunner{listErr: failure}
	if err := cleanupWireGuardReservedNFTTableWithRunner(
		failed, identity, func() error { return nil }, func() error { return nil },
	); err == nil || !errors.Is(err, failure) || len(failed.deleteCalls) != 0 {
		t.Fatalf("inventory failure was not fail closed: err=%v deletes=%v", err, failed.deleteCalls)
	}
	unlinkedIdentity := errors.New("ownership manifest identity changed")
	unlinked := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
	}
	if err := cleanupWireGuardReservedNFTTableWithRunner(
		unlinked, identity, func() error { return unlinkedIdentity }, func() error { return nil },
	); err == nil || !errors.Is(err, unlinkedIdentity) || len(unlinked.deleteCalls) != 0 {
		t.Fatalf("cleanup without exact linked manifest was not refused: err=%v deletes=%v", err, unlinked.deleteCalls)
	}
}

func TestWireGuardOwnedNFTCleanupRejectsLateIdentityAndRuntimeDrift_SW2_FWBACKEND_001(t *testing.T) {
	for _, test := range []struct {
		name            string
		identityChanges bool
		runtimeStarts   bool
	}{
		{name: "manifest identity changes", identityChanges: true},
		{name: "runtime starts immediately before delete", runtimeStarts: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := exactWireGuardNFTIdentity()
			identityAttestations := 0
			runtimeAttestations := 0
			sentinel := errors.New("late owned-table cleanup drift")
			reattestIdentity := func() error {
				identityAttestations++
				if test.identityChanges && identityAttestations == 3 {
					return sentinel
				}
				return nil
			}
			reattestRuntime := func() error {
				runtimeAttestations++
				if test.runtimeStarts && runtimeAttestations == 3 {
					return sentinel
				}
				return nil
			}
			runner := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
			}
			err := cleanupWireGuardReservedNFTTableWithRunner(
				runner, expected, reattestIdentity, reattestRuntime,
			)
			if err == nil || !errors.Is(err, sentinel) || len(runner.deleteCalls) != 0 {
				t.Fatalf(
					"late cleanup drift was not fail-closed: err=%v identity=%d runtime=%d deletes=%v",
					err, identityAttestations, runtimeAttestations, runner.deleteCalls,
				)
			}
		})
	}
}

func TestWireGuardAttestedOrphanCleanupDeletesOnlyExactTokenizedTable_SW2_FWBACKEND_001(t *testing.T) {
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}, {"ip", "syswarden_wg", 8}},
		detail: exactWireGuardNFTJSON(),
	}
	attestations := 0
	runtimeAttestations := 0
	if err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(runner, func() error {
		attestations++
		return nil
	}, func() error {
		runtimeAttestations++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attestations != 2 || runtimeAttestations != 2 {
		t.Fatalf("orphan attestations: ownership=%d runtime=%d, want 2 each", attestations, runtimeAttestations)
	}
	if !reflect.DeepEqual(runner.deleteCalls, [][]string{{"delete", "table", "inet", "handle", "7"}}) {
		t.Fatalf("delete calls = %v", runner.deleteCalls)
	}
	if len(runner.tables) != 2 || runner.tables[0].name != "operator" || runner.tables[1].family != "ip" {
		t.Fatalf("unrelated operator tables were not preserved: %v", runner.tables)
	}
}

func TestWireGuardStaleRemovalCleanupUsesGuardedManifestIdentity_SW2_FWBACKEND_001(t *testing.T) {
	previousGuard := wireGuardNFTActivationGuard
	previousIdentity := wireGuardServerIdentityInspector
	previousCleanup := wireGuardStaleNFTCleanup
	t.Cleanup(func() {
		wireGuardNFTActivationGuard = previousGuard
		wireGuardServerIdentityInspector = previousIdentity
		wireGuardStaleNFTCleanup = previousCleanup
	})

	identity := wireguardstate.ServerConfigurationIdentity{
		OwnershipToken:  strings.Repeat("a", 64),
		ActiveInterface: "ens3",
	}
	var order []string
	wireGuardNFTActivationGuard = func() (func() error, error) {
		order = append(order, "guard")
		return func() error {
			order = append(order, "release")
			return nil
		}, nil
	}
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) {
		order = append(order, "identity")
		return identity, nil
	}
	wireGuardStaleNFTCleanup = func(actual wireguardstate.ServerConfigurationIdentity) error {
		order = append(order, "cleanup")
		if actual != identity {
			t.Fatalf("stale cleanup identity = %#v, want %#v", actual, identity)
		}
		return nil
	}

	if err := CleanupAttestedStaleWireGuardNFTStateForRemoval(); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(order, ","), "guard,identity,cleanup,release"; got != want {
		t.Fatalf("stale removal cleanup order = %q, want %q", got, want)
	}
}

func TestWireGuardAttestedOrphanCleanupIsNoopWhenReservedTableIsAbsent_SW2_FWBACKEND_001(t *testing.T) {
	runner := &fakeWireGuardNFTRunner{tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}}}
	attestations := 0
	runtimeAttestations := 0
	if err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(runner, func() error {
		attestations++
		return nil
	}, func() error {
		runtimeAttestations++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attestations != 1 || runtimeAttestations != 1 || len(runner.deleteCalls) != 0 {
		t.Fatalf("absent table result: ownership=%d runtime=%d deletes=%v", attestations, runtimeAttestations, runner.deleteCalls)
	}
}

func TestWireGuardAttestedOrphanCleanupRejectsUnmarkedHistoricalAndChangedState_SW2_FWBACKEND_001(t *testing.T) {
	exact := string(exactWireGuardNFTJSON())
	marker := `,"comment":"syswarden-wg-v1:` + strings.Repeat("a", 64) + `"`
	legacyV4028 := strings.Replace(exact, marker, "", 1)
	for name, detail := range map[string]string{
		"v4.02.8 unmarked table": legacyV4028,
		"uppercase token":        strings.Replace(exact, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"invalid interface":      strings.Replace(exact, `"right":"ens3"`, `"right":"bad interface"`, 1),
		"additional rule":        strings.Replace(exact, `]}`, `,{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"operator0"}},{"accept":null}],"handle":14}}]}`, 1),
		"malformed JSON":         `{`,
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: []byte(detail),
			}
			err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(
				runner, func() error { return nil }, func() error { return nil },
			)
			if err == nil || len(runner.deleteCalls) != 0 {
				t.Fatalf("changed orphan state was not preserved: err=%v deletes=%v", err, runner.deleteCalls)
			}
		})
	}
}

func TestWireGuardAttestedOrphanCleanupReattestsEvidenceAndHandleBeforeMutation_SW2_FWBACKEND_001(t *testing.T) {
	sentinel := errors.New("ownership evidence appeared")
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
	}
	attestations := 0
	err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(runner, func() error {
		attestations++
		if attestations == 2 {
			return sentinel
		}
		return nil
	}, func() error { return nil })
	if err == nil || !errors.Is(err, sentinel) || len(runner.deleteCalls) != 0 {
		t.Fatalf("late ownership evidence was not fail-closed: err=%v deletes=%v", err, runner.deleteCalls)
	}

	mismatch := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 8}}, detail: exactWireGuardNFTJSON(),
	}
	if err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(
		mismatch, func() error { return nil }, func() error { return nil },
	); err == nil || len(mismatch.deleteCalls) != 0 {
		t.Fatalf("inventory/detail handle mismatch was not refused: err=%v deletes=%v", err, mismatch.deleteCalls)
	}

	retained := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(), retain: true,
	}
	if err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(
		retained, func() error { return nil }, func() error { return nil },
	); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("retained table result = %v", err)
	}
}

func TestWireGuardAttestedOrphanCleanupRejectsRuntimeStartBeforeDelete_SW2_FWBACKEND_001(t *testing.T) {
	for _, signal := range []string{"service became active", "interface appeared"} {
		t.Run(signal, func(t *testing.T) {
			runner := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
			}
			runtimeAttestations := 0
			sentinel := errors.New(signal)
			err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(
				runner,
				func() error { return nil },
				func() error {
					runtimeAttestations++
					if runtimeAttestations == 2 {
						return sentinel
					}
					return nil
				},
			)
			if err == nil || !errors.Is(err, sentinel) || runtimeAttestations != 2 || len(runner.deleteCalls) != 0 {
				t.Fatalf("external runtime start was not fail-closed: err=%v attestations=%d deletes=%v", err, runtimeAttestations, runner.deleteCalls)
			}
		})
	}
}

func TestWireGuardAttestedOrphanCleanupRejectsReplacementAfterDelete_SW2_FWBACKEND_001(t *testing.T) {
	runner := &fakeWireGuardNFTRunner{
		tables:  []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}},
		detail:  exactWireGuardNFTJSON(),
		replace: true,
	}
	err := cleanupAttestedOrphanedWireGuardNFTTableWithRunner(
		runner, func() error { return nil }, func() error { return nil },
	)
	if err == nil || !strings.Contains(err.Error(), "replacement inet syswarden_wg table") ||
		!reflect.DeepEqual(runner.deleteCalls, [][]string{{"delete", "table", "inet", "handle", "7"}}) {
		t.Fatalf("replacement table was not detected: err=%v deletes=%v tables=%v", err, runner.deleteCalls, runner.tables)
	}
}

func TestWireGuardInactiveCleanupReconcilesExactStaleTokenOnly_SW2_FWBACKEND_001(t *testing.T) {
	expected := exactWireGuardNFTIdentity()
	expected.OwnershipToken = strings.Repeat("b", 64)
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}},
		detail: exactWireGuardNFTJSON(),
	}
	identityAttestations := 0
	runtimeAttestations := 0
	err := cleanupAttestedInactiveWireGuardNFTTableWithRunner(
		runner,
		expected,
		func() error { identityAttestations++; return nil },
		func() error { runtimeAttestations++; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if identityAttestations != 2 || runtimeAttestations != 3 {
		t.Fatalf("stale cleanup attestations: identity=%d runtime=%d", identityAttestations, runtimeAttestations)
	}
	if !reflect.DeepEqual(runner.deleteCalls, [][]string{{"delete", "table", "inet", "handle", "7"}}) {
		t.Fatalf("stale cleanup delete calls = %v", runner.deleteCalls)
	}
}

func TestWireGuardInactiveCleanupRejectsRuntimeStartImmediatelyBeforeDelete_SW2_FWBACKEND_001(t *testing.T) {
	expected := exactWireGuardNFTIdentity()
	expected.OwnershipToken = strings.Repeat("b", 64)
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
	}
	runtimeAttestations := 0
	sentinel := errors.New("runtime became active immediately before delete")
	err := cleanupAttestedInactiveWireGuardNFTTableWithRunner(
		runner,
		expected,
		func() error { return nil },
		func() error {
			runtimeAttestations++
			if runtimeAttestations == 3 {
				return sentinel
			}
			return nil
		},
	)
	if err == nil || !errors.Is(err, sentinel) || runtimeAttestations != 3 || len(runner.deleteCalls) != 0 {
		t.Fatalf(
			"late runtime activation was not fail-closed: err=%v attestations=%d deletes=%v",
			err, runtimeAttestations, runner.deleteCalls,
		)
	}
}

func TestWireGuardInactiveCleanupPreservesUnmarkedActiveAndCurrentTables_SW2_FWBACKEND_001(t *testing.T) {
	expected := exactWireGuardNFTIdentity()
	expected.OwnershipToken = strings.Repeat("b", 64)
	exact := string(exactWireGuardNFTJSON())
	marker := `,"comment":"syswarden-wg-v1:` + strings.Repeat("a", 64) + `"`
	for name, test := range map[string]struct {
		detail       string
		expected     wireguardstate.ServerConfigurationIdentity
		runtimeError error
	}{
		"unmarked historical table": {
			detail: strings.Replace(exact, marker, "", 1), expected: expected,
		},
		"active runtime": {
			detail: exact, expected: expected, runtimeError: errors.New("service is active"),
		},
		"current manifest table": {
			detail: exact, expected: exactWireGuardNFTIdentity(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeWireGuardNFTRunner{
				tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: []byte(test.detail),
			}
			err := cleanupAttestedInactiveWireGuardNFTTableWithRunner(
				runner,
				test.expected,
				func() error { return nil },
				func() error { return test.runtimeError },
			)
			if err == nil || len(runner.deleteCalls) != 0 {
				t.Fatalf("protected table result: err=%v deletes=%v", err, runner.deleteCalls)
			}
		})
	}
}

func TestExistingWireGuardNFTTableRequiresExactOwnedSemantics_SW2_FWBACKEND_001(t *testing.T) {
	wire := exactWireGuardNFTJSON()
	identity := exactWireGuardNFTIdentity()
	if handle, err := validateExistingWireGuardNFTTable(wire, identity); err != nil || handle != 7 {
		t.Fatalf("exact owned table rejected: %v", err)
	}
	sharedHandleNamespaces := strings.NewReplacer(
		`"handle":7`, `"handle":1`,
		`"handle":8`, `"handle":1`,
		`"handle":11`, `"handle":1`,
	).Replace(string(wire))
	if handle, err := validateExistingWireGuardNFTTable([]byte(sharedHandleNamespaces), identity); err != nil || handle != 1 {
		t.Fatalf("valid cross-namespace nftables handles rejected: handle=%d err=%v", handle, err)
	}
	for name, changed := range map[string]string{
		"egress drift":     strings.ReplaceAll(string(wire), `"right":"ens3"`, `"right":"eth9"`),
		"extra rule":       strings.Replace(string(wire), `]}`, `,{"rule":{"family":"inet","table":"syswarden_wg","chain":"forward","expr":[]}}]}`, 1),
		"policy drift":     strings.Replace(string(wire), `"policy":"accept"`, `"policy":"drop"`, 1),
		"token drift":      strings.Replace(string(wire), strings.Repeat("a", 64), strings.Repeat("b", 64), 1),
		"unknown field":    strings.Replace(string(wire), `"handle":8`, `"handle":8,"comment":"operator"`, 1),
		"duplicate handle": strings.Replace(string(wire), `"handle":13`, `"handle":12`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateExistingWireGuardNFTTable([]byte(changed), identity); err == nil {
				t.Fatal("changed reserved nftables state was accepted")
			}
		})
	}
}

func TestPinnedWireGuardForwardingTransactionRestoresExactValueAndRejectsPathSwap_SW2_WGSTATE_001(t *testing.T) {
	t.Run("apply and restore", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ip_forward")
		if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil { // #nosec G306 -- private fixture models the kernel sysctl file mode
			t.Fatal(err)
		}
		transaction, err := openPinnedWireGuardForwardingTransaction(path, networkTestUID(t))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = transaction.Close() }()
		if err := transaction.Apply(); err != nil {
			t.Fatal(err)
		}
		if wire, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(wire)) != "1" { // #nosec G304 -- path is confined to this private test directory
			t.Fatalf("forwarding apply: content=%q err=%v", wire, err)
		}
		if err := transaction.Restore(); err != nil {
			t.Fatal(err)
		}
		if wire, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(wire)) != "0" { // #nosec G304 -- path is confined to this private test directory
			t.Fatalf("forwarding restore: content=%q err=%v", wire, err)
		}
	})

	t.Run("path swap", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "ip_forward")
		original := filepath.Join(directory, "ip_forward.original")
		if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil { // #nosec G306 -- private fixture models the kernel sysctl file mode
			t.Fatal(err)
		}
		transaction, err := openPinnedWireGuardForwardingTransaction(path, networkTestUID(t))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = transaction.Close() }()
		if err := os.Rename(path, original); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("0\n"), 0644); err != nil { // #nosec G306 -- private fixture models the kernel sysctl file mode
			t.Fatal(err)
		}
		if err := transaction.Apply(); err == nil || !strings.Contains(err.Error(), "path identity changed") {
			t.Fatalf("forwarding path swap accepted: %v", err)
		}
		if wire, err := os.ReadFile(path); err != nil || string(wire) != "0\n" { // #nosec G304 -- path is confined to this private test directory
			t.Fatalf("replacement forwarding file changed: content=%q err=%v", wire, err)
		}
	})
}
