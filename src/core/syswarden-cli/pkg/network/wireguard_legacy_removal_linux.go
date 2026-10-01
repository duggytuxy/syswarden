//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"syswarden-cli/pkg/system"
	"syswarden-cli/pkg/wireguardstate"
)

// CleanupAttestedStaleOrLegacyWireGuardNFTStateForRemoval extends removal's
// tokenized fallback only when the retained modern manifest also proves the
// exact historical table lineage. Unmanifested installations still require
// explicit operator recovery; a reserved name alone never authorizes deletion.
func CleanupAttestedStaleOrLegacyWireGuardNFTStateForRemoval() error {
	staleErr := CleanupAttestedStaleWireGuardNFTStateForRemoval()
	if staleErr == nil {
		return nil
	}
	requireRemoval := func() error {
		if err := system.RequireRemovalTombstone(); err != nil {
			return err
		}
		return system.ReattestFirewallStatePreparedForRemoval()
	}
	if err := productionLegacyWireGuardRecoveryHost().remove(requireRemoval); err != nil {
		return errors.Join(staleErr, fmt.Errorf("exact manifest-bound historical cleanup failed: %w; %s", err, legacyWireGuardRecoveryDryRunHint()))
	}
	return nil
}

func (host legacyWireGuardRecoveryHost) remove(requireRemoval func() error) error {
	if requireRemoval == nil {
		return fmt.Errorf("legacy removal requires an attested removal barrier and stopped services")
	}
	if err := requireRemoval(); err != nil {
		return err
	}
	plan, err := host.inspect()
	if err != nil {
		return err
	}
	if plan.Ownership.State != "verified-manifest" || plan.Configuration.Source != "verified-current-manifest" || plan.HistoricalInterface != "wg-syswarden" {
		return fmt.Errorf("automatic historical cleanup requires the retained verified current WireGuard manifest")
	}
	digest, err := LegacyWireGuardRecoveryPlanSHA256(plan)
	if err != nil {
		return err
	}
	// Keep the public recovery path's complete, digest-bound reattestation.
	// Removal additionally rechecks its durable barrier and prepared services
	// after acquiring the same firewall guard and immediately before the batch.
	originalGuard, originalBatch := host.guard, host.nftBatch
	host.guard = func() (func() error, error) {
		release, err := originalGuard()
		if err != nil {
			return nil, err
		}
		if err := requireRemoval(); err != nil {
			return nil, errors.Join(err, release())
		}
		return release, nil
	}
	host.nftBatch = func(ctx context.Context, script string) ([]byte, error) {
		if err := requireRemoval(); err != nil {
			return nil, err
		}
		return originalBatch(ctx, script)
	}
	_, err = host.apply(digest)
	return err
}

// PreflightWireGuardRemoval rejects unmanifested artifacts before a new
// removal barrier can strand an installation whose ownership cannot be proved.
// A durable transaction is left to the operation-aware removal recovery path.
func PreflightWireGuardRemoval() error {
	return preflightWireGuardRemovalInventory(func() (wireguardstate.Inventory, error) {
		return wireguardstate.Inspect(wireGuardFilesystemRoot)
	})
}

func preflightWireGuardRemovalInventory(inspect func() (wireguardstate.Inventory, error)) error {
	inventory, err := inspect()
	if err != nil {
		return fmt.Errorf("inspect WireGuard state before publishing removal barrier: %w", err)
	}
	if !inventory.Empty() && !inventory.Manifest && !inventory.Transaction {
		return fmt.Errorf("historical or partial WireGuard files have no ownership manifest; no new removal barrier was created; preserve the configuration and keys and %s", legacyWireGuardRecoveryDryRunHint())
	}
	return nil
}
