//go:build linux

package system

import (
	"fmt"

	"syswarden-cli/pkg/wireguardstate"
)

type wireGuardRemovalTail struct {
	requireBarrier         func() error
	reattestServices       func() error
	cleanupOwnedNFT        func() error
	inspectTransaction     func() (wireguardstate.TransactionOperation, bool, error)
	inspectOwnedState      func() (bool, error)
	prepareOwnedArtifacts  func() (bool, error)
	finalizeOwnedArtifacts func() (bool, error)
	classifyRuntime        func(bool) (serviceManagerState, error)
	isAlpine               func() bool
	reloadSysctl           func() error
}

func productionWireGuardRemovalTail(cleanupOwnedNFT func() error) wireGuardRemovalTail {
	return wireGuardRemovalTail{
		requireBarrier:   RequireRemovalTombstone,
		reattestServices: ReattestFirewallStatePreparedForRemoval,
		cleanupOwnedNFT:  cleanupOwnedNFT,
		inspectTransaction: func() (wireguardstate.TransactionOperation, bool, error) {
			return wireguardstate.InspectTransaction("/", 0, 0)
		},
		inspectOwnedState: func() (bool, error) {
			inventory, err := wireguardstate.Inspect("/")
			if err != nil {
				return false, err
			}
			if inventory.Transaction {
				return false, fmt.Errorf("a recoverable WireGuard transaction is pending")
			}
			return !inventory.Empty(), nil
		},
		prepareOwnedArtifacts: func() (bool, error) {
			return wireguardstate.PrepareRemoval("/", 0, 0)
		},
		finalizeOwnedArtifacts: func() (bool, error) {
			return wireguardstate.FinalizeRemoval("/", 0, 0)
		},
		classifyRuntime: classifyServiceManagerRuntime,
		isAlpine:        IsAlpine,
		reloadSysctl: func() error {
			executor := hostFirewallExecutor()
			path, err := resolveFirewallExecutable(executor, "sysctl")
			if err != nil {
				return err
			}
			if _, err := executor.output(path, "--system"); err != nil {
				return fmt.Errorf("reload sysctl after exact WireGuard removal: %w", err)
			}
			return nil
		},
	}
}

func (tail wireGuardRemovalTail) validate() error {
	if tail.requireBarrier == nil || tail.reattestServices == nil || tail.cleanupOwnedNFT == nil ||
		tail.inspectTransaction == nil || tail.inspectOwnedState == nil ||
		tail.prepareOwnedArtifacts == nil || tail.finalizeOwnedArtifacts == nil ||
		tail.classifyRuntime == nil || tail.isAlpine == nil ||
		tail.reloadSysctl == nil {
		return fmt.Errorf("WireGuard removal dependencies are incomplete")
	}
	return nil
}

func (tail wireGuardRemovalTail) remove() error {
	if err := tail.validate(); err != nil {
		return err
	}
	if err := tail.requireBarrier(); err != nil {
		return fmt.Errorf("WireGuard removal requires the durable removal tombstone: %w", err)
	}
	if err := tail.reattestServices(); err != nil {
		return fmt.Errorf("WireGuard removal requires prepared services: %w", err)
	}
	operation, transactionPending, err := tail.inspectTransaction()
	if err != nil {
		return fmt.Errorf("inspect durable WireGuard transaction before removal: %w", err)
	}
	if transactionPending {
		switch operation {
		case wireguardstate.TransactionOperationRemovePendingReload:
		case wireguardstate.TransactionOperationRemove:
			return fmt.Errorf("refusing unproven WireGuard removal transaction without durable nftables-cleanup evidence")
		case wireguardstate.TransactionOperationPublish:
			return fmt.Errorf("refusing host removal while a WireGuard publication transaction is pending")
		default:
			return fmt.Errorf("refusing unknown WireGuard transaction operation %q", operation)
		}
	}
	ownedState := transactionPending
	if !transactionPending {
		ownedState, err = tail.inspectOwnedState()
		if err != nil {
			return fmt.Errorf("inspect exact owned WireGuard state before removal: %w", err)
		}
	}
	alpine := tail.isAlpine()
	managerState, err := tail.classifyRuntime(alpine)
	if err != nil {
		return fmt.Errorf("attest service-manager runtime before WireGuard removal: %w", err)
	}
	if managerState != serviceManagerActive && managerState != serviceManagerOffline {
		return fmt.Errorf("refusing WireGuard removal with manager state %s", managerState)
	}
	if managerState == serviceManagerOffline && ownedState {
		return fmt.Errorf("refusing owned WireGuard runtime cleanup without an active service-manager runtime; ownership evidence is retained")
	}
	if ownedState && !transactionPending {
		if err := tail.cleanupOwnedNFT(); err != nil {
			return fmt.Errorf(
				"remove exact owned WireGuard nftables state before ownership evidence; the durable removal tombstone and WireGuard manifest are retained: %w",
				err,
			)
		}
	}
	if err := tail.requireBarrier(); err != nil {
		return fmt.Errorf("reattest removal barrier after WireGuard nftables cleanup: %w", err)
	}
	if err := tail.reattestServices(); err != nil {
		return fmt.Errorf("reattest stopped WireGuard service before ownership evidence removal: %w", err)
	}
	changed, err := tail.prepareOwnedArtifacts()
	if err != nil {
		return fmt.Errorf(
			"prepare exact owned WireGuard artifact removal after nftables cleanup; the durable removal tombstone and transaction debt are retained: %w",
			err,
		)
	}
	if transactionPending && !changed {
		return fmt.Errorf("pending WireGuard removal transaction disappeared before external runtime reconciliation")
	}
	if changed && managerState == serviceManagerActive {
		if err := tail.reloadSysctl(); err != nil {
			return fmt.Errorf(
				"reload sysctl after exact WireGuard artifact removal; the durable removal debt is retained for retry: %w",
				err,
			)
		}
	}
	if changed {
		finalized, err := tail.finalizeOwnedArtifacts()
		if err != nil {
			return fmt.Errorf(
				"finalize exact WireGuard removal after external runtime reconciliation; the durable removal debt is retained: %w",
				err,
			)
		}
		if !finalized {
			return fmt.Errorf("WireGuard removal debt disappeared before verified finalization")
		}
	}
	if err := tail.reattestServices(); err != nil {
		return fmt.Errorf("reattest services after exact WireGuard artifact removal: %w", err)
	}
	if err := tail.requireBarrier(); err != nil {
		return fmt.Errorf("reattest removal barrier after WireGuard artifact removal: %w", err)
	}
	return nil
}

// RemoveOwnedWireGuardArtifactsForRemoval removes the exact nftables state
// while the ownership manifest is still available, prepares durable removal
// of only manifest-attributed artifacts, reloads external runtime state, and
// then finalizes the retained removal debt. The caller supplies the network
// cleanup callback to avoid a system/network import cycle.
func RemoveOwnedWireGuardArtifactsForRemoval(cleanupOwnedNFT func() error) error {
	return productionWireGuardRemovalTail(cleanupOwnedNFT).remove()
}
