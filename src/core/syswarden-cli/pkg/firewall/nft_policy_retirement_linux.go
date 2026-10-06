//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

type nftPolicyOwnershipInspection struct {
	record     nftPersistenceGraphSourceRecord
	inputs     nftCurrentPersistenceInputs
	source     string
	digest     string
	backupPlan string
}

// This reads a private receipt emitted by the actual authoritative writer.
// A matching historical model without a receipt is not adopted here.
func inspectNFTPolicyOwnership(host nftPersistenceFilesystem) (nftPolicyOwnershipInspection, error) {
	inspection, receipt, err := inspectNFTPolicyReceipt(host)
	if err != nil {
		return inspection, err
	}
	source, err := host.snapshot(legacyNFTIncludePath)
	if err != nil || source.identity == nil || source.identity.Mode().Perm() != 0600 {
		return inspection, fmt.Errorf("current policy source is missing or has changed private metadata")
	}
	decoded, err := decodeNFTPolicyOwnership(receipt)
	if err != nil {
		return inspection, err
	}
	emptyOperator, err := compileOperatorPolicy(nil)
	if err != nil {
		return inspection, err
	}
	var preservation *nftPreservedOperatorInputs
	if decoded.Generation.OperatorChain != emptyOperator.chain {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		preservation, err = authorizeNFTOperatorPolicyRemoval(ctx, nil)
		if err != nil {
			return inspection, err
		}
	}
	inspection.inputs, err = currentNFTInputsFromPreservedOwnership(source.content, receipt, preservation)
	if err != nil {
		return inspection, err
	}
	return inspection, inspection.verify(host)
}

// Reopening a receipt does not require its source to remain active. Recovery
// must independently validate that source through the exact durable graph.
func inspectNFTPolicyReceipt(host nftPersistenceFilesystem) (nftPolicyOwnershipInspection, []byte, error) {
	var empty nftPolicyOwnershipInspection
	path := nftStateDirectory + "/" + nftPolicyOwnershipName
	receipt, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || receipt.identity == nil || receipt.identity.Mode().Perm() != 0600 {
		return empty, nil, fmt.Errorf("current policy lacks exact private writer ownership; preserve its source for explicit historical recovery")
	}
	decoded, err := decodeNFTPolicyOwnership(receipt.content)
	if err != nil {
		return empty, nil, err
	}
	bound, err := bindNFTPersistenceGraphSource(path, receipt, attrs, receipt.content)
	if err != nil {
		return empty, nil, err
	}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return empty, nil, err
	}
	inspection := nftPolicyOwnershipInspection{record: bound, source: decoded.SourceSHA256, digest: nftSHA256Hex(encoded)}
	return inspection, receipt.content, inspection.verify(host)
}

func (inspection nftPolicyOwnershipInspection) verify(host nftPersistenceFilesystem) error {
	path := nftStateDirectory + "/" + nftPolicyOwnershipName
	if inspection.backupPlan != "" {
		record := nftPersistenceGraphFileRecord(inspection.record, inspection.backupPlan)
		retired, err := legacyRetirementSourceState(host, record)
		if err != nil {
			return err
		}
		if retired {
			backup := legacyRetirementBackupDirectory(record)
			intent, err := readLegacyRetirementFileRecord(host, backup)
			if err != nil || intent != record {
				return fmt.Errorf("retired writer receipt lacks its exact durable intent")
			}
			path = backup + "/original"
		}
	}
	receipt, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || receipt.identity == nil || receipt.identity.Mode().Perm() != 0600 {
		return fmt.Errorf("current writer ownership is unavailable during retirement")
	}
	actual, err := bindNFTPersistenceGraphSource(inspection.record.Artifact.Path, receipt, attrs, receipt.content)
	if err != nil || actual != inspection.record {
		return fmt.Errorf("current writer ownership changed after retirement preparation")
	}
	record, err := decodeNFTPolicyOwnership(receipt.content)
	if err != nil || record.SourceSHA256 != inspection.source {
		return fmt.Errorf("current writer ownership no longer binds the reviewed source")
	}
	encoded, err := json.Marshal(actual)
	if err != nil || nftSHA256Hex(encoded) != inspection.digest {
		return fmt.Errorf("current writer ownership identity differs from the reviewed authority")
	}
	return nil
}

// Shared loader entry points are supplied separately and remain protected.
// The caller must independently attest their completeness and the stopped
// product loader before applying the returned plan under its removal locks.
func prepareNFTOwnedCurrentPersistencePlan(host nftPersistenceFilesystem, sharedEntries []string, producers string) (nftHistoricalPersistencePlan, nftPolicyOwnershipInspection, error) {
	var empty nftHistoricalPersistencePlan
	origin, err := inspectNFTPolicyOwnership(host)
	if err != nil {
		return empty, origin, err
	}
	if slices.Contains(sharedEntries, legacyNFTIncludePath) {
		return empty, origin, fmt.Errorf("a shared loader uses the product source as its entry point; preserve that loader configuration for bounded recovery")
	}
	entries := append(append([]string(nil), sharedEntries...), legacyNFTIncludePath)
	plan, err := prepareNFTRecognizedPersistencePlan(host, entries, nftHistoricalPersistenceBinding{
		Schema: nftHistoricalPersistenceSchema, Origins: origin.digest, Producers: producers,
		Current: &origin.inputs, ProductEntry: true,
	})
	if err != nil {
		return empty, origin, err
	}
	if plan.binding.Source.Artifact.SHA256 != origin.source {
		return empty, origin, fmt.Errorf("product policy source changed after writer ownership inspection")
	}
	return plan, origin, origin.verify(host)
}
