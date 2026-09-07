//go:build linux

package network

import (
	"errors"
	"fmt"
	"syswarden-cli/pkg/wireguardstate"
)

// RecoverPendingWireguardState recovers only a fully attested bounded
// publication or immediate-removal transaction. It intentionally leaves an
// external-reload removal debt for an operator-assisted recovery because a new
// process cannot prove that the required external runtime reload completed.
func RecoverPendingWireguardState() (resultErr error) {
	release, err := wireGuardNFTActivationGuard()
	if err != nil {
		return fmt.Errorf("acquire WireGuard state recovery guard: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release WireGuard state recovery guard: %w", err))
		}
	}()
	return recoverPendingWireguardStateLocked()
}

func recoverPendingWireguardStateLocked() error {
	operation, present, err := wireguardstate.InspectTransaction(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return fmt.Errorf("attest pending WireGuard state transaction: %w", err)
	}
	if !present {
		return nil
	}
	if operation == wireguardstate.TransactionOperationRemovePendingReload {
		return fmt.Errorf(
			"pending WireGuard removal retains an unproven external-runtime reload debt",
		)
	}
	if operation != wireguardstate.TransactionOperationPublish &&
		operation != wireguardstate.TransactionOperationRemove {
		return fmt.Errorf("refusing unsupported WireGuard recovery operation %q", operation)
	}

	if _, err := wireguardstate.Recover(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	); err != nil {
		return fmt.Errorf("recover attested WireGuard state transaction: %w", err)
	}
	operation, present, err = wireguardstate.InspectTransaction(
		wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID,
	)
	if err != nil {
		return fmt.Errorf("reattest WireGuard state transaction after recovery: %w", err)
	}
	if present {
		return fmt.Errorf("WireGuard state transaction %q remains after recovery", operation)
	}
	return nil
}
