//go:build linux

package network

import (
	"errors"
	"fmt"
	"syswarden-cli/pkg/wireguardstate"
)

var wireGuardDisabledReconciler = reconcileDisabledWireGuard

func readDisabledWireGuardIdentity() (wireguardstate.Manifest, wireguardstate.ServerConfigurationIdentity, bool, error) {
	if pending, err := wireGuardForwardingTransitionPending(); err != nil {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("inspect WireGuard forwarding transition: %w", err)
	} else if pending {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("a WireGuard forwarding persistence transition requires recovery")
	}
	inventory, err := wireguardstate.Inspect(wireGuardFilesystemRoot)
	if err != nil {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("inspect disabled WireGuard ownership state: %w", err)
	}
	if inventory.Empty() {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false, nil
	}
	if inventory.Transaction {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("refusing disabled WireGuard reconciliation while an ownership transaction requires recovery: %#v", inventory)
	}
	if !inventory.Manifest {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("refusing disabled WireGuard reconciliation for unmanifested or partial generated state: %#v", inventory)
	}

	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("verify disabled WireGuard ownership state: %w", err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false, err
	}
	identity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil {
		return wireguardstate.Manifest{}, wireguardstate.ServerConfigurationIdentity{}, false,
			fmt.Errorf("parse manifest-bound WireGuard identity before disabled reconciliation: %w", err)
	}
	return manifest, identity, true, nil
}

func inspectDisabledWireGuardServiceState(manifest wireguardstate.Manifest, alpine bool) (wireGuardServiceState, error) {
	if !alpine {
		return wireGuardServiceInspector()
	}
	_, linkPresent, err := wireguardstate.InspectOpenRCServiceLink(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireGuardServiceState{}, fmt.Errorf("inspect OpenRC WireGuard service link before disabled reconciliation: %w", err)
	}
	if manifest.OpenRCServiceLink != nil && !linkPresent {
		return wireGuardServiceState{}, fmt.Errorf("manifest-owned OpenRC WireGuard service link is absent")
	}
	if !linkPresent {
		return wireGuardAbsentOpenRCServiceInspector()
	}
	return wireGuardServiceInspector()
}

// reconcileDisabledWireGuard converges only runtime state attributed by the
// exact generated-state manifest. The forwarding artifact and its manifest
// identity may be advanced atomically to a boot-neutral state, while the
// manifest-bound keys remain unchanged for re-enable. This function never
// guesses the operator's pre-SysWarden global ip_forward value.
func reconcileDisabledWireGuard() (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire complete disabled WireGuard reconciliation guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release complete disabled WireGuard reconciliation guard: %w", err))
		}
	}()

	if err := recoverPendingWireGuardForwardingStateLocked(); err != nil {
		return fmt.Errorf("recover interrupted WireGuard forwarding persistence before disable: %w", err)
	}
	_, expectedIdentity, owned, err := readDisabledWireGuardIdentity()
	if err != nil {
		return err
	}
	if !owned {
		fmt.Println("[INFO] WireGuard is disabled in SYSWARDEN configuration; no manifest-bound runtime requires reconciliation.")
		return nil
	}

	managerState, err := wireGuardManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before disabled WireGuard reconciliation: %w", err)
	}
	if managerState != "ACTIVE" {
		return fmt.Errorf("disabled WireGuard reconciliation requires an attestable active service manager; state is %s", managerState)
	}

	currentManifest, currentIdentity, stillOwned, err := readDisabledWireGuardIdentity()
	if err != nil {
		return fmt.Errorf("reattest WireGuard ownership under disabled reconciliation guard: %w", err)
	}
	if !stillOwned || currentIdentity != expectedIdentity {
		return fmt.Errorf("WireGuard ownership identity changed before disabled reconciliation")
	}
	manifest := currentManifest

	alpine := wireGuardIsAlpine()
	baseline, err := inspectDisabledWireGuardServiceState(manifest, alpine)
	if err != nil {
		return fmt.Errorf("inspect exact WireGuard service state before disable: %w", err)
	}
	if baseline.Alpine != alpine {
		return fmt.Errorf("service-manager identity changed during disabled WireGuard reconciliation")
	}
	target := wireGuardServiceState{Alpine: alpine}
	if baseline != target {
		if err := attestWireGuardServiceDefinition(); err != nil {
			return fmt.Errorf("attest exact WireGuard service definition before disable: %w", err)
		}
		if err := wireGuardServerHookExecutableAttestor(expectedIdentity); err != nil {
			return fmt.Errorf("attest manifest-bound WireGuard hooks before disable: %w", err)
		}
		if err := wireGuardServiceRollback(target); err != nil {
			return fmt.Errorf("stop and disable exact WireGuard service: %w", err)
		}
	}

	current, err := inspectDisabledWireGuardServiceState(manifest, alpine)
	if err != nil || current != target {
		if err == nil {
			err = fmt.Errorf("state mismatch: got %#v want %#v", current, target)
		}
		return fmt.Errorf("verify WireGuard service is disabled and its interface is absent: %w", err)
	}
	_, currentIdentity, stillOwned, err = readDisabledWireGuardIdentity()
	if err != nil {
		return fmt.Errorf("reattest WireGuard ownership after service disable: %w", err)
	}
	if !stillOwned || currentIdentity != expectedIdentity {
		return fmt.Errorf("WireGuard ownership identity changed after service disable")
	}

	if err := wireGuardReservedNFTCleanup(expectedIdentity); err != nil {
		if staleErr := wireGuardStaleNFTCleanup(expectedIdentity); staleErr != nil {
			return fmt.Errorf(
				"retire disabled WireGuard nftables state: manifest-bound cleanup failed: %v; exact tokenized stale-table recovery failed: %w",
				err, staleErr,
			)
		}
	}
	if err := wireGuardNFTActivationPreflight(wireGuardNFTExpectation{
		AllowExisting: false,
		Identity:      expectedIdentity,
	}); err != nil {
		return fmt.Errorf("verify reserved WireGuard nftables state is absent after disable: %w", err)
	}
	persistence, err := inspectWireGuardForwardingPersistence(manifest, expectedIdentity)
	if err != nil {
		return fmt.Errorf("inspect manifest-bound WireGuard forwarding persistence before disable: %w", err)
	}
	neutralContent, err := canonicalWireGuardForwardingContent(
		expectedIdentity, false, persistence.BaselineKnown, persistence.Baseline,
	)
	if err != nil {
		return err
	}
	if err := transitionWireGuardForwardingPersistence(expectedIdentity, neutralContent); err != nil {
		return fmt.Errorf("neutralize manifest-bound WireGuard forwarding persistence: %w", err)
	}
	if persistence.BaselineKnown {
		if err := wireGuardForwardingRuntimeReconciler(persistence.Baseline); err != nil {
			return fmt.Errorf(
				"restore attested pre-enable net.ipv4.ip_forward baseline %s; boot persistence is already neutralized and retry is safe: %w",
				persistence.Baseline, err,
			)
		}
	} else {
		fmt.Println("[WARN] WireGuard forwarding boot persistence is disabled; runtime net.ipv4.ip_forward remains unchanged because this legacy state has no attested pre-enable baseline.")
	}
	if _, currentIdentity, stillOwned, err = readDisabledWireGuardIdentity(); err != nil {
		return fmt.Errorf("verify preserved WireGuard generated state after disable: %w", err)
	} else if !stillOwned || currentIdentity != expectedIdentity {
		return fmt.Errorf("manifest-bound WireGuard generated state changed during disable")
	}

	fmt.Println("[INFO] WireGuard is disabled; the exact service and interface are inactive, nftables and boot forwarding state are neutralized, and manifest-bound keys are preserved.")
	return nil
}
