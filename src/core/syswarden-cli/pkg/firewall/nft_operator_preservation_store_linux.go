//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

type nftOperatorPreservationRecord struct {
	Schema           string                          `json:"schema"`
	Plan             nftOperatorPreservationPlan     `json:"plan"`
	Reviewed         string                          `json:"reviewed_plan_sha256"`
	OriginalCounters []nftOperatorCounterObservation `json:"original_counter_observations"`
	ReceiverCounters []nftOperatorCounterObservation `json:"receiver_counter_observations"`
}

func nftOperatorPreservationDirectory(key string) string {
	return legacyRetirementBackupRoot + "/operator-policy/" + key
}

func encodeNFTOperatorPreservationRecord(host nftPersistenceFilesystem, record nftOperatorPreservationRecord) ([]byte, error) {
	_, digest, err := encodeNFTOperatorPreservationPlan(host, record.Plan)
	if err != nil || record.Schema != nftOperatorPreservationSchema || digest != record.Reviewed {
		return nil, fmt.Errorf("operator preservation decision differs from its exact reviewed plan")
	}
	model, err := prepareNFTOperatorReceiver(record.Plan.Binding.Rules)
	if err != nil {
		return nil, err
	}
	compiled, err := compileOperatorPolicy(record.Plan.Binding.Rules)
	if err != nil {
		return nil, err
	}
	if len(record.OriginalCounters) != len(model.rules) || len(record.ReceiverCounters) != len(model.rules) {
		return nil, fmt.Errorf("operator preservation counter observations are incomplete")
	}
	for i, expected := range model.rules {
		if record.ReceiverCounters[i].Rule != expected.comment || record.OriginalCounters[i].Rule != compiled.verification.rules[i].comment {
			return nil, fmt.Errorf("operator preservation counter observations refer to a different policy")
		}
	}
	wire, err := json.Marshal(record)
	if err != nil || len(wire) > 2<<20 {
		return nil, fmt.Errorf("operator preservation decision exceeds its byte bound")
	}
	return wire, nil
}

func readNFTOperatorPreservationRecord(host nftPersistenceFilesystem, key string) (nftOperatorPreservationRecord, error) {
	var empty nftOperatorPreservationRecord
	if !validLegacyRetirementDigest(key) {
		return empty, fmt.Errorf("operator preservation requires an exact proof digest")
	}
	for _, path := range []string{legacyRetirementBackupRoot, legacyRetirementBackupRoot + "/operator-policy", nftOperatorPreservationDirectory(key)} {
		directory, err := host.openDirectory(path)
		if err != nil {
			return empty, err
		}
		info, statErr := directory.Stat(".")
		closeErr := directory.Close()
		if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
			return empty, fmt.Errorf("operator preservation decision directory is not private")
		}
	}
	snapshot, err := host.snapshot(nftOperatorPreservationDirectory(key) + "/plan.json")
	if err != nil {
		return empty, err
	}
	if snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 2<<20 {
		return empty, fmt.Errorf("operator preservation decision is not bounded and private")
	}
	var record nftOperatorPreservationRecord
	if err := json.Unmarshal(snapshot.content, &record); err != nil {
		return empty, fmt.Errorf("operator preservation decision has invalid encoding")
	}
	canonical, err := encodeNFTOperatorPreservationRecord(host, record)
	if err != nil || !bytes.Equal(canonical, snapshot.content) {
		return empty, fmt.Errorf("operator preservation decision has noncanonical or inconsistent evidence")
	}
	_, actual, err := encodeNFTOperatorPreservationBinding(host, record.Plan.Binding)
	if err != nil || actual != key {
		return empty, fmt.Errorf("operator preservation decision refers to a different binding")
	}
	return record, nil
}

func (inspection *nftOperatorPreservationInspection) authorize(ctx context.Context) error {
	if err := inspection.verify(ctx); err != nil {
		return err
	}
	record, err := readNFTOperatorPreservationRecord(inspection.host, inspection.key)
	if err != nil {
		return fmt.Errorf("administrator policy has no exact reviewed independent preservation decision: %w", err)
	}
	if !equalNFTOperatorBindings(inspection.host, inspection.binding, record.Plan.Binding) {
		return fmt.Errorf("administrator preservation differs from its reviewed source or enabled loader")
	}
	return inspection.verify(ctx)
}

// Only the private decision is published. This function never writes active
// configuration, changes rules, stops a service, reloads a shared loader or
// creates a product ownership receipt. Each removal phase must reauthorize the
// receiver, including within the global kernel generation fence.
func (inspection *nftOperatorPreservationInspection) apply(ctx context.Context, reviewed string, ops legacyRetirementFileOps) error {
	if inspection == nil || !validLegacyRetirementDigest(reviewed) || !validLegacyRetirementOperations(func() error { return nil }, ops) {
		return fmt.Errorf("operator preservation requires an exact reviewed digest and complete operations")
	}
	if err := inspection.verify(ctx); err != nil {
		return err
	}
	if existing, err := readNFTOperatorPreservationRecord(inspection.host, inspection.key); err == nil {
		if existing.Reviewed != reviewed || !equalNFTOperatorBindings(inspection.host, existing.Plan.Binding, inspection.binding) {
			return fmt.Errorf("existing operator preservation decision differs from this review")
		}
		return inspection.syncRecord(ctx, ops)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	plan, err := inspection.plan(ctx)
	if err != nil {
		return err
	}
	guard := func() error {
		current, err := inspection.plan(ctx)
		if err != nil {
			return err
		}
		_, actual, err := encodeNFTOperatorPreservationPlan(inspection.host, current)
		if err != nil || actual != reviewed {
			return fmt.Errorf("operator preservation plan changed after review")
		}
		return nil
	}
	if err := guard(); err != nil {
		return err
	}
	original, err := inspection.dependencies.runner.Run(ctx, nil, "-j", "list", "table", "inet", "syswarden")
	if err != nil {
		return err
	}
	_, originalCounters, err := normalizeNFTOperatorRuntime(original, inspection.binding.Rules)
	if err != nil {
		return err
	}
	live, err := inspection.dependencies.runner.Run(ctx, nil, "-j", "list", "table", "inet", inspection.model.table)
	if err != nil {
		return err
	}
	receiverCounters, err := inspection.model.inspect(live)
	if err != nil {
		return err
	}
	record := nftOperatorPreservationRecord{nftOperatorPreservationSchema, plan, reviewed, originalCounters, receiverCounters}
	wire, err := encodeNFTOperatorPreservationRecord(inspection.host, record)
	if err != nil {
		return err
	}
	path := nftOperatorPreservationDirectory(inspection.key)
	if err := ensureLegacyRetirementPrivateDirectory(inspection.host, path, ops); err != nil {
		return err
	}
	directory, err := inspection.host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	descriptor, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = descriptor.Close() }()
	identity, err := descriptor.Stat()
	if err != nil {
		return err
	}
	wrapped := ops
	wrapped.checkpoint = func(phase string) error {
		if err := ops.checkpoint(phase); err != nil {
			return err
		}
		if err := attestLegacyRetirementDirectory(inspection.host, path, identity); err != nil {
			return err
		}
		return guard()
	}
	if err := guard(); err != nil {
		return err
	}
	if err := publishLegacyRetirementJSON(directory, descriptor, "plan", wire, wrapped); err != nil {
		return err
	}
	if err := attestLegacyRetirementDirectory(inspection.host, path, identity); err != nil {
		return err
	}
	if err := ops.checkpoint("operator-preservation-published"); err != nil {
		return err
	}
	return inspection.syncRecord(ctx, ops)
}

func (inspection *nftOperatorPreservationInspection) syncRecord(ctx context.Context, ops legacyRetirementFileOps) error {
	if err := inspection.authorize(ctx); err != nil {
		return err
	}
	path := nftOperatorPreservationDirectory(inspection.key)
	if err := prepareLegacyRetirementPrivateDirectory(inspection.host, path, ops, false); err != nil {
		return err
	}
	directory, err := inspection.host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	descriptor, err := directory.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = descriptor.Close() }()
	file, err := directory.OpenFile("plan.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	snapshot, readErr := inspection.host.snapshot(path + "/plan.json")
	if statErr != nil || readErr != nil || !sameNFTPersistenceIdentity(opened, snapshot.identity) {
		_ = file.Close()
		return fmt.Errorf("operator preservation decision changed before synchronization")
	}
	if err := errors.Join(ops.sync(file), file.Close(), ops.sync(descriptor)); err != nil {
		return err
	}
	if err := inspection.authorize(ctx); err != nil {
		return err
	}
	return ops.checkpoint("operator-preservation-durable")
}
