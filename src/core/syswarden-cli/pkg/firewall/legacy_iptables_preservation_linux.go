//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
)

// This receipt authorizes preservation of the exact reviewed administrator
// remainder only. It never authorizes another deletion, and a new boot, rule
// change or missing original evidence requires a fresh independent review.
func authorizeLegacyIPTablesPreservation(ctx context.Context) error {
	root, err := os.OpenRoot("/")
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	host := nftPersistenceFilesystem{root: root}
	epoch, err := currentNFTRemovalEpoch()
	if err != nil {
		return err
	}
	var observer *legacyIPTablesObserver
	observe := func(ctx context.Context) (legacyIPTablesObservation, error) {
		if observer == nil {
			observer, err = newLegacyIPTablesObserver()
			if err != nil {
				return legacyIPTablesObservation{}, err
			}
		}
		current, _, _, err := observer.observe(ctx)
		return current, err
	}
	if err := authorizeLegacyIPTablesPreservationUsing(ctx, host, epoch, observe); err == nil {
		return nil
	}
	if err := requireNoOwnedOperatorIPTables(); err != nil {
		return err
	}
	if err := authorizeOperatorIPTablesPreservationUsing(ctx, host, epoch, observe); err != nil {
		return err
	}
	repeated, err := currentNFTRemovalEpoch()
	if err != nil || repeated != epoch {
		return fmt.Errorf("administrator iptables preservation epoch changed during inspection")
	}
	return requireNoOwnedOperatorIPTables()
}

func authorizeLegacyIPTablesPreservationUsing(ctx context.Context, host nftPersistenceFilesystem, epoch nftRemovalEpoch, observe func(context.Context) (legacyIPTablesObservation, error)) error {
	if observe == nil {
		return fmt.Errorf("historical iptables preservation requires an independent observer")
	}
	directory, err := host.openDirectory(legacyIPTablesBackupRoot)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	info, err := directory.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("historical iptables preservation receipts are not private")
	}
	descriptor, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = descriptor.Close() }()
	entries, err := descriptor.ReadDir(129)
	if err != nil || len(entries) > 128 {
		return fmt.Errorf("historical iptables preservation receipt inventory is unavailable or unbounded")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !validLegacyRetirementDigest(entry.Name()) {
			return fmt.Errorf("historical iptables receipt inventory contains an unexpected entry")
		}
		record, _, err := readLegacyIPTablesRecord(host, entry.Name())
		if err != nil {
			return err
		}
		if record.Epoch != epoch {
			continue
		}
		origin, err := inspectLegacyIPTablesInputs(host, record.InputPath, epoch)
		if err != nil {
			return err
		}
		plan, review, err := bindLegacyIPTablesRecovery(origin, record.Producers, record)
		if err != nil || review != entry.Name() {
			return fmt.Errorf("historical iptables preservation receipt differs from its exact original review")
		}
		current, err := observe(ctx)
		if err != nil {
			return err
		}
		canonical, err := legacyIPTablesObservationBytes(current)
		if err != nil {
			return err
		}
		if bytes.Equal(canonical, plan.after) {
			return origin.verify(host, epoch)
		}
	}
	return fmt.Errorf("shared iptables rules have no exact independently reviewed administrator remainder")
}

var legacyIPTablesPreservationCheck = authorizeLegacyIPTablesPreservation

func preflightLegacyIPTablesDocument(ctx context.Context, document nftJSONDocument) error {
	if err := preflightLegacyIPTablesBackend(ctx); err != nil {
		return err
	}
	if err := preflightLegacyIPTablesRules(document); err != nil {
		if ordinary := legacyIPTablesOwnedPreflightCheck(ctx); ordinary == nil {
			return nil
		}
		if preserved := legacyIPTablesPreservationCheck(ctx); preserved != nil {
			return fmt.Errorf("%w; no exact administrator preservation receipt is available; after independently verifying that every remaining rule is administrator-owned, inspect recover-removal --preserve-operator-iptables", err)
		}
	}
	return nil
}
