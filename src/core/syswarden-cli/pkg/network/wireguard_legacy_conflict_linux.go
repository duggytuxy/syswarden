//go:build linux

package network

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syswarden-cli/pkg/wireguardstate"
)

const legacyWireGuardRetirementHint = "inspect explicit retirement with 'sudo syswarden recover-wireguard --retire-legacy-wg0'; preserve the configuration, ownership manifest and removal barrier"

// PreflightLegacyWireGuardConflict runs before installation configuration or
// dependency changes. A pending ownership transaction retains priority: the
// operation-aware recovery must finish before ordinary reconciliation checks.
func PreflightLegacyWireGuardConflict() error {
	inventory, err := wireguardstate.Inspect(wireGuardFilesystemRoot)
	if err != nil {
		return err
	}
	if inventory.Transaction {
		return nil
	}
	return preflightLegacyWireGuardConflict()
}

// preflightLegacyWireGuardConflict prevents a second managed generation from
// being installed or reconciled while the old configuration can recreate the
// reserved table at boot. An unrelated administrator wg0 does not claim that
// namespace and is left alone. This function never logs configuration contents
// or changes services, keys or nftables.
func preflightLegacyWireGuardConflict() error {
	return inspectLegacyWireGuardConflict(wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID)
}

func inspectLegacyWireGuardConflict(root string, uid, gid uint32) error {
	configuration, err := captureLegacyWireGuardConfiguration(root, "/etc/wireguard/wg0.conf", uid, gid)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot rule out historical WireGuard generation conflict before mutation: %w", err)
	}
	if !bytes.Contains(configuration.content, []byte("syswarden_wg")) {
		return nil
	}
	return fmt.Errorf("historical wg0 configuration still claims the reserved SysWarden nftables namespace and can recreate it at boot; %s", legacyWireGuardRetirementHint)
}
