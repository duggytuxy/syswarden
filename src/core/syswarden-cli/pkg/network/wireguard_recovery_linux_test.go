//go:build linux

package network

import (
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
	"time"
)

func prepareWireGuardRecoveryRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{
		{path: "etc", mode: 0755},
		{path: "etc/wireguard", mode: 0700},
		{path: "etc/wireguard/clients", mode: 0700},
		{path: "etc/sysctl.d", mode: 0755},
	} {
		if err := os.Mkdir(filepath.Join(root, directory.path), directory.mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func useWireGuardRecoveryRoot(t *testing.T, root string) {
	t.Helper()
	previousRoot := wireGuardFilesystemRoot
	previousUID := wireGuardExpectedOwnerUID
	previousGID := wireGuardExpectedOwnerGID
	previousGuard := wireGuardNFTActivationGuard
	wireGuardFilesystemRoot = root
	wireGuardExpectedOwnerUID = networkTestUID(t)
	wireGuardExpectedOwnerGID = networkTestGID(t)
	wireGuardNFTActivationGuard = func() (func() error, error) {
		return func() error { return nil }, nil
	}
	t.Cleanup(func() {
		wireGuardFilesystemRoot = previousRoot
		wireGuardExpectedOwnerUID = previousUID
		wireGuardExpectedOwnerGID = previousGID
		wireGuardNFTActivationGuard = previousGuard
	})
}

func TestRecoverPendingWireguardStateRollsBackAttestedPublicationAndIsIdempotent_SW2_WGSTATE_001(t *testing.T) {
	root := prepareWireGuardRecoveryRoot(t)
	useWireGuardRecoveryRoot(t, root)
	publication, err := wireguardstate.StageOwnedArtifacts(
		root,
		map[string][]byte{
			wireguardstate.ServerConfigurationPath:     []byte("server\n"),
			wireguardstate.ClientConfigurationPath:     []byte("client\n"),
			wireguardstate.ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
		},
		networkTestUID(t), networkTestGID(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })

	if err := RecoverPendingWireguardState(); err != nil {
		t.Fatalf("recover attested publication: %v", err)
	}
	inventory, err := wireguardstate.Inspect(root)
	if err != nil || !inventory.Empty() {
		t.Fatalf("recovered publication inventory = %#v, %v", inventory, err)
	}
	if err := RecoverPendingWireguardState(); err != nil {
		t.Fatalf("repeat recovery was not idempotent: %v", err)
	}
}

func TestRecoverPendingWireguardStateWaitsForActivePublication_SW2_WGSTATE_001(t *testing.T) {
	root := prepareWireGuardRecoveryRoot(t)
	useWireGuardRecoveryRoot(t, root)

	previousGuard := wireGuardNFTActivationGuard
	guardToken := make(chan struct{}, 1)
	guardToken <- struct{}{}
	acquisitionStarted := make(chan struct{}, 2)
	wireGuardNFTActivationGuard = func() (func() error, error) {
		acquisitionStarted <- struct{}{}
		<-guardToken
		return func() error {
			guardToken <- struct{}{}
			return nil
		}, nil
	}
	t.Cleanup(func() { wireGuardNFTActivationGuard = previousGuard })

	activePublicationRelease, err := wireGuardNFTActivationGuard()
	if err != nil {
		t.Fatal(err)
	}
	<-acquisitionStarted
	publicationReleased := false
	t.Cleanup(func() {
		if !publicationReleased {
			_ = activePublicationRelease()
		}
	})

	uid, gid := networkTestIdentity(t)
	publication, err := wireguardstate.StageOwnedArtifacts(
		root,
		map[string][]byte{
			wireguardstate.ServerConfigurationPath:     []byte("server\n"),
			wireguardstate.ClientConfigurationPath:     []byte("client\n"),
			wireguardstate.ForwardingConfigurationPath: []byte("net.ipv4.ip_forward = 1\n"),
		},
		uid, gid,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = publication.Rollback() })

	recoveryResult := make(chan error, 1)
	go func() { recoveryResult <- RecoverPendingWireguardState() }()
	select {
	case <-acquisitionStarted:
	case err := <-recoveryResult:
		t.Fatalf("recovery bypassed the shared guard: %v", err)
	case <-time.After(time.Second):
		t.Fatal("recovery did not attempt to acquire the shared guard")
	}
	select {
	case err := <-recoveryResult:
		t.Fatalf("recovery completed during an active publication: %v", err)
	default:
	}

	if err := publication.Publish(); err != nil {
		t.Fatal(err)
	}
	manifest, err := wireguardstate.CaptureManifest(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	stagedManifest, err := publication.StageManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := stagedManifest.Publish(); err != nil {
		t.Fatal(err)
	}
	if err := publication.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := activePublicationRelease(); err != nil {
		t.Fatal(err)
	}
	publicationReleased = true

	select {
	case err := <-recoveryResult:
		if err != nil {
			t.Fatalf("recovery after publication commit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("recovery remained blocked after publication commit")
	}
	inventory, err := wireguardstate.Inspect(root)
	if err != nil || !inventory.Manifest || inventory.Transaction {
		t.Fatalf("committed publication changed by recovery: inventory=%#v err=%v", inventory, err)
	}
}
func TestRecoverPendingWireguardStateRefusesCorruptJournalWithoutMutation_SW2_WGSTATE_001(t *testing.T) {
	root := prepareWireGuardRecoveryRoot(t)
	useWireGuardRecoveryRoot(t, root)
	path := filepath.Join(root, strings.TrimPrefix(wireguardstate.TransactionPath, "/"))
	const sentinel = "unattested transaction must remain byte exact\n"
	if err := os.WriteFile(path, []byte(sentinel), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := RecoverPendingWireguardState(); err == nil || !strings.Contains(err.Error(), "attest pending") {
		t.Fatalf("corrupt transaction recovery = %v", err)
	}
	afterWire, readErr := os.ReadFile(path) // #nosec G304 -- path is the fixed journal beneath the private test root
	after, statErr := os.Stat(path)
	if readErr != nil || statErr != nil || string(afterWire) != sentinel || !os.SameFile(before, after) ||
		before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("corrupt journal changed: before=%#v after=%#v content=%q read=%v stat=%v", before, after, afterWire, readErr, statErr)
	}
}

func TestRecoverPendingWireguardStatePreservesExternalReloadDebt_SW2_WGSTATE_001(t *testing.T) {
	harness := installWireGuardTransactionHarness(t)
	if err := SetupWireguard(); err != nil {
		t.Fatalf("prepare committed WireGuard state: %v", err)
	}
	prepared, err := wireguardstate.PrepareRemoval(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if err != nil || !prepared {
		t.Fatalf("prepare external reload debt: prepared=%v err=%v", prepared, err)
	}

	err = RecoverPendingWireguardState()
	if err == nil || !strings.Contains(err.Error(), "unproven external-runtime reload debt") {
		t.Fatalf("external reload debt recovery = %v", err)
	}
	operation, present, inspectErr := wireguardstate.InspectTransaction(
		harness.root, networkTestUID(t), networkTestGID(t),
	)
	if inspectErr != nil || !present || operation != wireguardstate.TransactionOperationRemovePendingReload {
		t.Fatalf("external reload debt changed: operation=%q present=%v err=%v", operation, present, inspectErr)
	}
}
