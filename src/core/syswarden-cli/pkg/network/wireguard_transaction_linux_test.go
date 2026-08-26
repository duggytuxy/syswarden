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
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
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
	wantEvents := []string{"preflight:1", "preflight:2", "sysctl", "preflight:3", "activate", "preflight:4", "qr"}
	if !reflect.DeepEqual(harness.events, wantEvents) {
		t.Fatalf("reuse events:\n got: %v\nwant: %v", harness.events, wantEvents)
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
		"rollback-service", "cleanup-nft", "restore-sysctl",
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

func TestSetupWireGuardGuardReleaseFailureRollsBackActivation_SW2_FWBACKEND_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	sentinel := errors.New("activation guard release failed")
	wireGuardNFTActivationGuard = func() (func() error, error) {
		return func() error { return sentinel }, nil
	}
	err := SetupWireguard()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "release WireGuard nftables activation guard") {
		t.Fatalf("activation guard release error = %v", err)
	}
	if harness.rollbackCalls != 1 || harness.nftCleanupCalls != 1 || harness.sysctlRestoreCalls != 1 {
		t.Fatalf("guard release rollback counts: service=%d nft=%d sysctl=%d", harness.rollbackCalls, harness.nftCleanupCalls, harness.sysctlRestoreCalls)
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
	previousIdentity := wireGuardServerIdentityInspector
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) { return identity, nil }
	t.Cleanup(func() { wireGuardServerIdentityInspector = previousIdentity })
	runner := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "operator", 2}, {"inet", "syswarden_wg", 7}, {"ip", "syswarden_wg", 8}},
		detail: exactWireGuardNFTJSON(), replace: true,
	}
	if err := cleanupWireGuardReservedNFTTableWithRunner(runner, identity); err != nil {
		t.Fatal(err)
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
	if err := cleanupWireGuardReservedNFTTableWithRunner(residual, identity); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("residual cleanup error = %v", err)
	}
	failure := errors.New("inventory unavailable")
	failed := &fakeWireGuardNFTRunner{listErr: failure}
	if err := cleanupWireGuardReservedNFTTableWithRunner(failed, identity); err == nil || !errors.Is(err, failure) || len(failed.deleteCalls) != 0 {
		t.Fatalf("inventory failure was not fail closed: err=%v deletes=%v", err, failed.deleteCalls)
	}
	wireGuardServerIdentityInspector = func() (wireguardstate.ServerConfigurationIdentity, error) {
		changed := identity
		changed.OwnershipToken = strings.Repeat("b", 64)
		return changed, nil
	}
	unlinked := &fakeWireGuardNFTRunner{
		tables: []fakeWireGuardNFTTable{{"inet", "syswarden_wg", 7}}, detail: exactWireGuardNFTJSON(),
	}
	if err := cleanupWireGuardReservedNFTTableWithRunner(unlinked, identity); err == nil || len(unlinked.deleteCalls) != 0 {
		t.Fatalf("cleanup without exact linked manifest was not refused: err=%v deletes=%v", err, unlinked.deleteCalls)
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
