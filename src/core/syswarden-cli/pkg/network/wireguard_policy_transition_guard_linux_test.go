//go:build linux

package network

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func plantPendingPolicyEvidence(t *testing.T, root string) []byte {
	t.Helper()
	content := []byte("incomplete policy intent must be retained\n")
	if err := writeFilesystemFixture(t, filepath.Join(root, wireguardstate.PolicyTransitionPath), content, 0600); err != nil {
		t.Fatal(err)
	}
	return content
}

func TestPendingWireGuardPolicyStopsAllLifecycleBeforeRuntime(t *testing.T) {
	root := prepareWireGuardRecoveryRoot(t)
	useWireGuardRecoveryRoot(t, root)
	evidence := plantPendingPolicyEvidence(t, root)
	for name, run := range map[string]func() error{
		"install-preflight":       PreflightLegacyWireGuardConflict,
		"legacy-fallback-cleanup": CleanupAttestedStaleOrLegacyWireGuardNFTStateForRemoval,
		"removal-preflight":       PreflightWireGuardRemoval,
		"ownership-recovery":      RecoverPendingWireguardState,
		"forwarding-recovery":     RecoverPendingWireGuardForwardingState,
		"filesystem-recovery":     recoverWireGuardFilesystemBinding,
		"setup":                   SetupWireguard,
		"owned-runtime-cleanup":   CleanupOwnedWireGuardNFTState,
		"stale-runtime-cleanup":   CleanupAttestedStaleWireGuardNFTStateForRemoval,
		"orphan-runtime-cleanup":  CleanupAttestedOrphanedWireGuardNFTStateForRemoval,
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil || !strings.Contains(err.Error(), "policy") {
				t.Fatalf("missing policy refusal: %v", err)
			}
			current, err := readFilesystemFixture(t, filepath.Join(root, wireguardstate.PolicyTransitionPath))
			if err != nil || !bytes.Equal(current, evidence) {
				t.Fatalf("pending evidence altered: %v", err)
			}
		})
	}
}

func TestPendingPolicyPrecedesOtherwiseRecoverableFilesystemBinding(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	removeFilesystemBindingsForTest(t)
	previous := wireGuardFilesystemBindingFault
	t.Cleanup(func() { wireGuardFilesystemBindingFault = previous })
	interrupted := errors.New("prepared binding interruption")
	wireGuardFilesystemBindingFault = func(point string) error {
		if point == "manifest-staged" {
			return interrupted
		}
		return nil
	}
	if err := bindVerifiedWireGuardFilesystems(); !errors.Is(err, interrupted) {
		t.Fatalf("fixture did not interrupt: %v", err)
	}
	wireGuardFilesystemBindingFault = func(string) error { return nil }
	paths := []string{wireguardstate.ManifestPath, wireGuardFilesystemBindingPath, "/etc/wireguard/" + wireGuardFilesystemBindingStage}
	before := make(map[string][]byte)
	for _, path := range paths {
		content, err := readFilesystemFixture(t, filepath.Join(harness.root, path))
		if err != nil {
			t.Fatal(err)
		}
		before[path] = content
	}
	plantPendingPolicyEvidence(t, harness.root)
	if err := RecoverPendingWireGuardForwardingState(); err == nil || !strings.Contains(err.Error(), "policy") {
		t.Fatalf("missing policy refusal: %v", err)
	}
	for _, path := range paths {
		content, err := readFilesystemFixture(t, filepath.Join(harness.root, path))
		if err != nil || !bytes.Equal(content, before[path]) {
			t.Fatalf("binding changed before policy recovery at %s: %v", path, err)
		}
	}
	// Removing only this synthetic fixture allows the independent binding to
	// resume, proving its refusal was caused by policy debt rather than damage.
	if err := os.Remove(filepath.Join(harness.root, wireguardstate.PolicyTransitionPath)); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPendingWireGuardForwardingState(); err != nil {
		t.Fatal(err)
	}
}
