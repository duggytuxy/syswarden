//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"reflect"
	"syscall"
)

const nftRemovalProgressKind = "nft-removal-progress"
const nftRemovalProgressPath = nftStateDirectory + "/" + nftRemovalProgressKind + ".json"

type nftRemovalProgress struct {
	Schema    string                          `json:"schema"`
	Plan      string                          `json:"persistence_plan_sha256"`
	Origin    string                          `json:"writer_evidence_sha256"`
	Producers string                          `json:"producer_evidence_sha256"`
	Writer    nftPersistenceGraphSourceRecord `json:"writer_receipt"`
}

func encodeNFTRemovalProgress(plan nftHistoricalPersistencePlan, writer nftPersistenceGraphSourceRecord) ([]byte, error) {
	if plan.binding.Current == nil || !plan.binding.ProductEntry || !validLegacyRetirementDigest(plan.sha256) ||
		!validLegacyRetirementDigest(plan.binding.Origins) || !validLegacyRetirementDigest(plan.binding.Producers) {
		return nil, fmt.Errorf("removal progress lacks current writer and producer evidence")
	}
	encoded, err := json.Marshal(writer)
	if err != nil || nftSHA256Hex(encoded) != plan.binding.Origins || writer.Artifact.Path != nftStateDirectory+"/"+nftPolicyOwnershipName || writer.Artifact.Mode != 0600 || writer.EditedSHA256 != writer.Artifact.SHA256 {
		return nil, fmt.Errorf("removal progress does not bind the exact original writer receipt")
	}
	return json.Marshal(nftRemovalProgress{"syswarden-nft-removal-progress-v2", plan.sha256, plan.binding.Origins, plan.binding.Producers, writer})
}

// A fixed private reference selects one exact graph. Never search for the
// newest backup or infer authority from a now-missing active configuration.
func readNFTRemovalProgress(host nftPersistenceFilesystem) (nftHistoricalPersistencePlan, nftPolicyOwnershipInspection, bool, error) {
	var empty nftHistoricalPersistencePlan
	var origin nftPolicyOwnershipInspection
	snapshot, err := host.snapshot(nftRemovalProgressPath)
	if errors.Is(err, fs.ErrNotExist) {
		return empty, origin, false, nil
	}
	if err != nil || snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 16384 {
		return empty, origin, true, fmt.Errorf("removal progress is unavailable or not a bounded private record")
	}
	var progress nftRemovalProgress
	if json.Unmarshal(snapshot.content, &progress) != nil || !validLegacyRetirementDigest(progress.Plan) {
		return empty, origin, true, fmt.Errorf("removal progress is invalid; preserve the exact record for recovery")
	}
	plan, err := readNFTHistoricalPersistencePlan(host, progress.Plan)
	if err != nil {
		return empty, origin, true, err
	}
	canonical, err := encodeNFTRemovalProgress(plan, progress.Writer)
	if err != nil || !bytes.Equal(canonical, snapshot.content) {
		return empty, origin, true, fmt.Errorf("removal progress differs from its durable source graph")
	}
	origin = nftPolicyOwnershipInspection{record: progress.Writer, inputs: *plan.binding.Current,
		source: plan.binding.Source.Artifact.SHA256, digest: plan.binding.Origins, backupPlan: plan.sha256}
	if err := validateLegacyRetirementFileRecord(nftPersistenceGraphFileRecord(origin.record, plan.sha256), host.expectedUID, host.expectedGID); err != nil {
		return empty, origin, true, err
	}
	return plan, origin, true, origin.verify(host)
}

// Publish only after both referenced records are durable and before any
// active file change. A concurrent or corrupt reference is never overwritten.
func bindNFTRemovalProgress(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, guard func() error, ops legacyRetirementFileOps) error {
	if !validLegacyRetirementOperations(guard, ops) {
		return fmt.Errorf("removal progress requires its complete authority guard")
	}
	if err := guard(); err != nil {
		return err
	}
	durable, err := readNFTHistoricalPersistencePlan(host, plan.sha256)
	if err != nil || !reflect.DeepEqual(durable, plan) {
		return fmt.Errorf("removal progress cannot precede its exact durable source graph")
	}
	_, writer, present, err := readNFTRemovalProgress(host)
	if err != nil {
		return err
	}
	if !present {
		writer, _, err = inspectNFTPolicyReceipt(host)
	}
	if err != nil {
		return err
	}
	content, err := encodeNFTRemovalProgress(plan, writer.record)
	if err != nil {
		return err
	}
	directory, err := host.openDirectory(nftStateDirectory)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	fd, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	identity, err := fd.Stat()
	if err != nil {
		return err
	}
	before, err := host.snapshot(nftRemovalProgressPath)
	if errors.Is(err, fs.ErrNotExist) {
		state, stateErr := inspectNFTPersistenceGraphState(host, plan.graph)
		if stateErr != nil || len(state.edited) != 0 || len(state.retired) != 0 {
			return fmt.Errorf("removal progress cannot be recreated after active file changes")
		}
		if err := guard(); err != nil {
			return err
		}
		if err := publishLegacyRetirementJSON(directory, fd, nftRemovalProgressKind, content, ops); err != nil {
			return err
		}
	} else if err != nil || before.identity == nil || before.identity.Mode().Perm() != 0600 || !bytes.Equal(before.content, content) {
		return fmt.Errorf("existing removal progress differs from the exact prepared plan")
	}
	file, err := directory.OpenFile(nftRemovalProgressKind+".json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	current, readErr := host.snapshot(nftRemovalProgressPath)
	if statErr != nil || readErr != nil || !sameNFTPersistenceIdentity(opened, current.identity) || !bytes.Equal(current.content, content) {
		_ = file.Close()
		return fmt.Errorf("removal progress changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), file.Close(), ops.sync(fd)); err != nil {
		return err
	}
	if err := attestLegacyRetirementDirectory(host, nftStateDirectory, identity); err != nil {
		return err
	}
	recovered, _, present, err := readNFTRemovalProgress(host)
	if err != nil || !present || !reflect.DeepEqual(recovered, plan) {
		return fmt.Errorf("removal progress changed during publication or synchronization")
	}
	return guard()
}

func applyNFTOwnedRemovalSources(host nftPersistenceFilesystem, plan nftHistoricalPersistencePlan, guard func(string, string) error, ops legacyRetirementFileOps) error {
	if guard == nil || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("owned source retirement requires complete guards and durable operations")
	}
	wrapped := ops
	wrapped.checkpoint = func(phase string) error {
		if phase == "historical-source-binding-durable" {
			if err := bindNFTRemovalProgress(host, plan, func() error { return guard(plan.binding.Origins, plan.binding.Producers) }, ops); err != nil {
				return err
			}
		}
		return ops.checkpoint(phase)
	}
	return applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, wrapped)
}
