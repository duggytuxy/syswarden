//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"syswarden-cli/config"
	"syswarden-cli/pkg/wireguardstate"
)

var wireGuardTokenizedNFTReadOnlyPreflight = attestRepairableTokenizedWireGuardNFTTable

func attestRepairableTokenizedWireGuardNFTTableWithRunner(
	runner wireGuardNFTCommandRunner,
	expected wireguardstate.ServerConfigurationIdentity,
) error {
	if runner == nil {
		return fmt.Errorf("tokenized WireGuard nftables preflight runner is unavailable")
	}
	if !wireGuardInterfaceName.MatchString(expected.ActiveInterface) ||
		!wireGuardOwnershipTokenName.MatchString(expected.OwnershipToken) {
		return fmt.Errorf("invalid manifest-bound WireGuard nftables preflight identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), wireGuardCommandTimeout)
	defer cancel()
	present, inventoryHandle, err := wireGuardReservedNFTTableIdentity(ctx, runner)
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("tokenized stale-table preflight has no reserved WireGuard nftables table")
	}
	wire, err := runner.Run(ctx, "-a", "-j", "list", "table", "inet", "syswarden_wg")
	if err != nil {
		return fmt.Errorf("inspect reserved WireGuard table for tokenized recovery: %w", err)
	}
	staleIdentity, tableHandle, err := identifyAttestedOrphanedWireGuardNFTTable(wire)
	if err != nil {
		return fmt.Errorf("refuse unproven tokenized WireGuard nftables recovery: %w", err)
	}
	if tableHandle != inventoryHandle {
		return fmt.Errorf("tokenized WireGuard nftables table handle changed during preflight")
	}
	if sameWireGuardNFTTableIdentity(staleIdentity, expected) {
		return fmt.Errorf("tokenized WireGuard nftables fallback received the current manifest-bound table unexpectedly")
	}
	return nil
}

func attestRepairableTokenizedWireGuardNFTTable(expected wireguardstate.ServerConfigurationIdentity) error {
	return attestRepairableTokenizedWireGuardNFTTableWithRunner(execWireGuardNFTCommandRunner{}, expected)
}

func preflightWireGuardNFTState(
	expectation wireGuardNFTExpectation,
	baseline wireGuardServiceState,
) error {
	currentErr := wireGuardNFTActivationPreflight(expectation)
	if currentErr == nil {
		return nil
	}
	if !expectation.AllowExisting || expectation.RequirePresent || baseline.Active || baseline.Interface {
		return currentErr
	}
	if staleErr := wireGuardTokenizedNFTReadOnlyPreflight(expectation.Identity); staleErr != nil {
		return fmt.Errorf(
			"no safe WireGuard nftables reconciliation is available: %w; %s",
			errors.Join(
				fmt.Errorf("manifest-bound table attestation: %w", currentErr),
				fmt.Errorf("exact tokenized inactive-table attestation: %w", staleErr),
			),
			legacyWireGuardRecoveryDryRunHint(),
		)
	}
	return nil
}

func preflightDisabledWireGuardNFTState(identity wireguardstate.ServerConfigurationIdentity) error {
	expectation := wireGuardNFTExpectation{AllowExisting: true, Identity: identity}
	currentErr := wireGuardNFTActivationPreflight(expectation)
	if currentErr == nil {
		return nil
	}
	if staleErr := wireGuardTokenizedNFTReadOnlyPreflight(identity); staleErr != nil {
		return fmt.Errorf(
			"no safe disabled WireGuard nftables reconciliation is available: %w; %s",
			errors.Join(
				fmt.Errorf("manifest-bound table attestation: %w", currentErr),
				fmt.Errorf("exact tokenized table attestation: %w", staleErr),
			),
			legacyWireGuardRecoveryDryRunHint(),
		)
	}
	return nil
}

func preflightDisabledWireGuard() error {
	manifest, identity, owned, err := readDisabledWireGuardIdentity()
	if err != nil {
		return err
	}
	managerState, err := wireGuardManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before disabled WireGuard inspection: %w", err)
	}
	if managerState != "ACTIVE" {
		return fmt.Errorf("disabled WireGuard preflight requires an attestable active service manager; state is %s", managerState)
	}
	alpine := wireGuardIsAlpine()
	baseline, err := inspectDisabledWireGuardServiceState(manifest, alpine)
	if err != nil {
		return fmt.Errorf("inspect exact WireGuard service state before firewall mutation: %w", err)
	}
	if baseline.Alpine != alpine {
		return fmt.Errorf("service-manager identity changed during disabled WireGuard preflight")
	}
	target := wireGuardServiceState{Alpine: alpine}
	if !owned {
		if baseline != target {
			return fmt.Errorf(
				"refusing active or enabled wg-syswarden runtime without an ownership manifest: %#v",
				baseline,
			)
		}
		if err := wireGuardNFTActivationPreflight(wireGuardNFTExpectation{}); err != nil {
			return fmt.Errorf("reserved WireGuard nftables state exists without an ownership manifest: %w", err)
		}
		return nil
	}
	if baseline != target {
		if err := attestWireGuardServiceDefinition(); err != nil {
			return fmt.Errorf("attest exact WireGuard service definition before firewall mutation: %w", err)
		}
		if err := wireGuardServerHookExecutableAttestor(identity); err != nil {
			return fmt.Errorf("attest exact WireGuard hook executables before firewall mutation: %w", err)
		}
	}
	if err := preflightDisabledWireGuardNFTState(identity); err != nil {
		return fmt.Errorf("attest disabled WireGuard nftables state before firewall mutation: %w", err)
	}
	return nil
}

// inspectWireGuardStateForPreflight verifies reusable generated state without
// running durable transaction recovery. Recovery belongs to the later mutation
// phase; a pending transaction must stop callers before they change firewall
// policy.
func inspectWireGuardStateForPreflight() (wireguardstate.Manifest, bool, error) {
	if pending, err := wireGuardForwardingTransitionPending(); err != nil {
		return wireguardstate.Manifest{}, false, fmt.Errorf("inspect WireGuard forwarding transition: %w", err)
	} else if pending {
		return wireguardstate.Manifest{}, false, fmt.Errorf("pending WireGuard forwarding persistence transition requires recovery during the mutation phase")
	}
	inventory, err := wireguardstate.Inspect(wireGuardFilesystemRoot)
	if err != nil {
		return wireguardstate.Manifest{}, false, fmt.Errorf("inspect WireGuard ownership state: %w", err)
	}
	if inventory.Transaction {
		return wireguardstate.Manifest{}, false, fmt.Errorf(
			"pending WireGuard state transaction requires recovery during the mutation phase: %#v",
			inventory,
		)
	}
	if inventory.Empty() {
		return wireguardstate.Manifest{}, false, nil
	}
	if !inventory.Manifest {
		return wireguardstate.Manifest{}, false, fmt.Errorf(
			"refusing unmanifested or partial WireGuard generated state: %#v",
			inventory,
		)
	}
	manifest, err := wireguardstate.ReadAndVerify(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return wireguardstate.Manifest{}, false, fmt.Errorf("verify existing WireGuard ownership state: %w", err)
	}
	return manifest, true, nil
}

// PreflightWireguard performs the read-only WireGuard checks needed before a
// reload is allowed to replace firewall policy. SetupWireguard repeats the
// relevant attestations under its activation guard before making any WireGuard
// change.
func PreflightWireguard() error {
	if config.GlobalConfig == nil {
		return fmt.Errorf("WireGuard preflight requires a loaded configuration")
	}
	if !config.GlobalConfig.EnableWG {
		return preflightDisabledWireGuard()
	}
	backend := configuredWireGuardFirewallBackend()
	if backend != "nftables" {
		return fmt.Errorf("WireGuard setup requires core.firewall_backend=nftables; configured backend is %q", backend)
	}
	if err := wireGuardFirewallBackendPreflight(backend); err != nil {
		return fmt.Errorf("firewall backend preflight failed before WireGuard inspection: %w", err)
	}

	manifest, reused, err := inspectWireGuardStateForPreflight()
	if err != nil {
		return err
	}
	managerState, err := wireGuardManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before WireGuard inspection: %w", err)
	}
	if managerState != "ACTIVE" {
		return fmt.Errorf("WireGuard preflight requires an attestable active service manager; state is %s", managerState)
	}

	alpine := wireGuardIsAlpine()
	var openRCLinkPresent bool
	if alpine {
		_, openRCLinkPresent, err = wireguardstate.InspectOpenRCServiceLink(
			wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil {
			return fmt.Errorf("inspect OpenRC WireGuard service-link baseline: %w", err)
		}
	}
	var baseline wireGuardServiceState
	if alpine && !openRCLinkPresent {
		baseline, err = wireGuardAbsentOpenRCServiceInspector()
	} else {
		baseline, err = wireGuardServiceInspector()
	}
	if err != nil {
		return fmt.Errorf("capture exact WireGuard service state before firewall mutation: %w", err)
	}
	if baseline.Alpine != alpine {
		return fmt.Errorf("service-manager identity changed during WireGuard preflight")
	}
	if !reused && baseline.Active {
		return fmt.Errorf("refusing to adopt an active preexisting WireGuard service without an ownership manifest")
	}
	if alpine && reused && manifest.OpenRCServiceLink == nil && !openRCLinkPresent {
		return fmt.Errorf("reusable WireGuard state has no OpenRC service link and no ownership proof")
	}

	expectation := wireGuardNFTExpectation{AllowExisting: reused, RequirePresent: reused && baseline.Active}
	if reused {
		server, err := wireguardstate.ReadVerifiedArtifact(
			wireGuardFilesystemRoot, manifest, wireguardstate.ServerConfigurationPath,
			wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
		)
		if err != nil {
			return err
		}
		identity, err := wireguardstate.ParseServerConfiguration(server)
		if err != nil {
			return fmt.Errorf("parse exact WireGuard runtime ownership identity: %w", err)
		}
		expectation.Identity = identity
		if err := attestWireGuardServiceDefinition(); err != nil {
			return fmt.Errorf("attest exact WireGuard service definition before firewall mutation: %w", err)
		}
		if err := wireGuardServerHookExecutableAttestor(identity); err != nil {
			return fmt.Errorf("attest exact WireGuard hook executables before firewall mutation: %w", err)
		}
	}
	if err := preflightWireGuardNFTState(expectation, baseline); err != nil {
		return fmt.Errorf("attest reserved WireGuard nftables state before firewall mutation: %w", err)
	}
	return nil
}
