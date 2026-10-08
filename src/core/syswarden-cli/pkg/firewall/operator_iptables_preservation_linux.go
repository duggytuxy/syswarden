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
	"time"
)

const operatorIPTablesSchema = "syswarden-operator-iptables-preservation-v1"
const operatorIPTablesRoot = legacyRetirementBackupRoot + "/operator-iptables-v1"

// This explicit administrator decision grants preservation only. It cannot
// transfer ownership, authorize deletion, or survive a new boot or rule change.
type operatorIPTablesRecord struct {
	Schema      string          `json:"schema"`
	Epoch       nftRemovalEpoch `json:"epoch"`
	Observation json.RawMessage `json:"observation"`
}

type OperatorIPTablesPreservationSummary struct {
	Schema                                     string `json:"schema"`
	PlanSHA256                                 string `json:"plan_sha256"`
	RuleCount                                  int    `json:"rule_count"`
	PrivateDecision                            string `json:"private_decision"`
	RequiresAdministratorOwnershipConfirmation bool   `json:"requires_administrator_ownership_confirmation"`
	ChangesRules                               bool   `json:"changes_rules"`
	GrantsDeletionAuthority                    bool   `json:"grants_deletion_authority"`
	RequiresReviewAfterReboot                  bool   `json:"requires_review_after_reboot"`
}

type operatorIPTablesInspection struct {
	host    nftPersistenceFilesystem
	record  operatorIPTablesRecord
	digest  string
	count   int
	epoch   func() (nftRemovalEpoch, error)
	observe func(context.Context) (legacyIPTablesObservation, error)
	guard   func(context.Context) error
}

func encodeOperatorIPTablesRecord(record operatorIPTablesRecord) ([]byte, string, error) {
	if record.Schema != operatorIPTablesSchema || len(record.Epoch.BootID) != 36 || record.Epoch.Inode == 0 || len(record.Observation) == 0 || len(record.Observation) > 1<<20 {
		return nil, "", fmt.Errorf("administrator iptables preservation decision is incomplete or unbounded")
	}
	content, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	return content, nftSHA256Hex(content), nil
}

func inspectOperatorIPTablesUsing(ctx context.Context, host nftPersistenceFilesystem, epoch func() (nftRemovalEpoch, error), observe func(context.Context) (legacyIPTablesObservation, error), guard func(context.Context) error) (*operatorIPTablesInspection, error) {
	if epoch == nil || observe == nil || guard == nil {
		return nil, fmt.Errorf("administrator iptables preservation requires complete read-only guards")
	}
	if err := guard(ctx); err != nil {
		return nil, err
	}
	currentEpoch, err := epoch()
	if err != nil {
		return nil, err
	}
	current, err := observe(ctx)
	if err != nil {
		return nil, err
	}
	if len(current.rules) == 0 {
		return nil, fmt.Errorf("no shared iptables rules require administrator preservation")
	}
	canonical, err := legacyIPTablesObservationBytes(current)
	if err != nil {
		return nil, err
	}
	record := operatorIPTablesRecord{operatorIPTablesSchema, currentEpoch, canonical}
	_, digest, err := encodeOperatorIPTablesRecord(record)
	if err != nil {
		return nil, err
	}
	inspection := &operatorIPTablesInspection{host, record, digest, len(current.rules), epoch, observe, guard}
	return inspection, inspection.verify(ctx)
}

func (inspection *operatorIPTablesInspection) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := inspection.guard(ctx); err != nil {
		return err
	}
	epoch, err := inspection.epoch()
	if err != nil || epoch != inspection.record.Epoch {
		return fmt.Errorf("administrator iptables review belongs to a different boot or network namespace")
	}
	current, err := inspection.observe(ctx)
	if err != nil {
		return err
	}
	canonical, err := legacyIPTablesObservationBytes(current)
	if err != nil || !bytes.Equal(canonical, inspection.record.Observation) {
		return fmt.Errorf("shared iptables policy changed after review; inspect a fresh preservation plan")
	}
	_, digest, err := encodeOperatorIPTablesRecord(inspection.record)
	if err != nil || digest != inspection.digest {
		return fmt.Errorf("administrator iptables preservation binding changed")
	}
	if err := inspection.guard(ctx); err != nil {
		return err
	}
	repeated, err := inspection.epoch()
	if err != nil || repeated != epoch {
		return fmt.Errorf("administrator iptables namespace changed during inspection")
	}
	return nil
}

func (inspection *operatorIPTablesInspection) summary() OperatorIPTablesPreservationSummary {
	return OperatorIPTablesPreservationSummary{operatorIPTablesSchema, inspection.digest, inspection.count, operatorIPTablesRoot + "/" + inspection.digest + "/kernel.json", true, false, false, true}
}

func readOperatorIPTablesRecord(host nftPersistenceFilesystem, digest string) (operatorIPTablesRecord, nftPersistenceRead, error) {
	var empty operatorIPTablesRecord
	if !validLegacyRetirementDigest(digest) {
		return empty, nftPersistenceRead{}, fmt.Errorf("invalid administrator iptables decision digest")
	}
	for _, parent := range []string{legacyRetirementBackupRoot, operatorIPTablesRoot} {
		directory, err := host.openDirectory(parent)
		if err != nil {
			return empty, nftPersistenceRead{}, err
		}
		info, statErr := directory.Stat(".")
		closeErr := directory.Close()
		if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
			return empty, nftPersistenceRead{}, fmt.Errorf("administrator iptables decision parent is not private")
		}
	}
	path := operatorIPTablesRoot + "/" + digest
	directory, err := host.openDirectory(path)
	if err != nil {
		return empty, nftPersistenceRead{}, err
	}
	info, statErr := directory.Stat(".")
	closeErr := directory.Close()
	if statErr != nil || closeErr != nil || info.Mode().Perm() != 0700 {
		return empty, nftPersistenceRead{}, fmt.Errorf("administrator iptables decision directory is not private")
	}
	snapshot, err := host.snapshot(path + "/kernel.json")
	if err != nil {
		return empty, snapshot, err
	}
	if snapshot.identity == nil || snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 2<<20 {
		return empty, snapshot, fmt.Errorf("administrator iptables decision is not private and bounded")
	}
	var record operatorIPTablesRecord
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil {
		return empty, snapshot, fmt.Errorf("invalid administrator iptables decision encoding")
	}
	content, actual, err := encodeOperatorIPTablesRecord(record)
	if err != nil || actual != digest || !bytes.Equal(content, snapshot.content) {
		return empty, snapshot, fmt.Errorf("administrator iptables decision differs from its exact review")
	}
	return record, snapshot, nil
}

func (inspection *operatorIPTablesInspection) apply(ctx context.Context, reviewed string, confirmed bool, ops legacyRetirementFileOps) error {
	if !confirmed || reviewed != inspection.digest || !validLegacyRetirementDigest(reviewed) || !validLegacyRetirementOperations(func() error { return inspection.verify(ctx) }, ops) {
		return fmt.Errorf("administrator iptables preservation requires the exact reviewed digest and explicit ownership confirmation")
	}
	if err := inspection.verify(ctx); err != nil {
		return err
	}
	path := operatorIPTablesRoot + "/" + reviewed
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
	guard := func() error {
		if err := attestLegacyRetirementDirectory(inspection.host, path, identity); err != nil {
			return err
		}
		return inspection.verify(ctx)
	}
	if err := guard(); err != nil {
		return err
	}
	_, snapshot, err := readOperatorIPTablesRecord(inspection.host, reviewed)
	if errors.Is(err, fs.ErrNotExist) {
		content, _, err := encodeOperatorIPTablesRecord(inspection.record)
		if err != nil {
			return err
		}
		wrapped := ops
		wrapped.checkpoint = func(phase string) error {
			if err := ops.checkpoint(phase); err != nil {
				return err
			}
			return guard()
		}
		if err := publishLegacyRetirementJSON(directory, descriptor, "kernel", content, wrapped); err != nil {
			return err
		}
		_, snapshot, err = readOperatorIPTablesRecord(inspection.host, reviewed)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := syncLegacyFail2banNFTIntent(inspection.host, path, snapshot); err != nil {
		return err
	}
	return guard()
}

// Refuse every IPv4 compatibility ownership entry, including pending writes.
// Preservation cannot override the existing manifest-bound cleanup route.
func requireNoOwnedOperatorIPTables() error {
	owned, _, _, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return err
	}
	return requireNoOwnedOperatorIPTablesRules(owned)
}

func requireNoOwnedOperatorIPTablesRules(owned map[string]linuxWrapperRule) error {
	for _, rule := range owned {
		if rule.backend == "iptables" {
			return fmt.Errorf("manifest-bound IPv4 compatibility rules require their existing cleanup before administrator preservation")
		}
	}
	return nil
}

func openOperatorIPTablesPreservation(ctx context.Context) (*operatorIPTablesInspection, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("administrator iptables preservation requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*operatorIPTablesInspection, error) { _ = root.Close(); return nil, err }
	observer, err := newLegacyIPTablesObserver()
	if err != nil {
		return fail(err)
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := preflightLegacyIPTablesBackend(ctx); err != nil {
			return err
		}
		if err := requireNoOwnedOperatorIPTables(); err != nil {
			return err
		}
		// Inspection must be possible before removal publishes its barrier.
		// The ordinary removal path still attests and stops every producer.
		return attestHistoricalRecoveryInspection()
	}
	inspection, err := inspectOperatorIPTablesUsing(ctx, nftPersistenceFilesystem{root: root}, currentNFTRemovalEpoch, func(ctx context.Context) (legacyIPTablesObservation, error) {
		current, _, _, err := observer.observe(ctx)
		return current, err
	}, guard)
	if err != nil {
		return fail(err)
	}
	return inspection, nil
}

func InspectOperatorIPTablesPreservation(ctx context.Context) (OperatorIPTablesPreservationSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	inspection, err := openOperatorIPTablesPreservation(ctx)
	if err != nil {
		return OperatorIPTablesPreservationSummary{}, err
	}
	defer func() { _ = inspection.host.root.Close() }()
	return inspection.summary(), nil
}

func ApplyOperatorIPTablesPreservation(ctx context.Context, reviewed string, confirmed bool) (OperatorIPTablesPreservationSummary, error) {
	var empty OperatorIPTablesPreservationSummary
	if !confirmed || !validLegacyRetirementDigest(reviewed) {
		return empty, fmt.Errorf("administrator iptables preservation requires exact review and ownership confirmation")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return empty, err
	}
	defer releaseNFTReloadGuard(lock)
	inspection, err := openOperatorIPTablesPreservation(ctx)
	if err != nil {
		return empty, err
	}
	defer func() { _ = inspection.host.root.Close() }()
	if err := inspection.apply(ctx, reviewed, confirmed, defaultLegacyRetirementFileOps()); err != nil {
		return empty, err
	}
	return inspection.summary(), nil
}

func authorizeOperatorIPTablesPreservationUsing(ctx context.Context, host nftPersistenceFilesystem, epoch nftRemovalEpoch, observe func(context.Context) (legacyIPTablesObservation, error)) error {
	if observe == nil {
		return fmt.Errorf("administrator preservation requires a read-only observer")
	}
	current, err := observe(ctx)
	if err != nil {
		return err
	}
	canonical, err := legacyIPTablesObservationBytes(current)
	if err != nil {
		return err
	}
	expected := operatorIPTablesRecord{operatorIPTablesSchema, epoch, canonical}
	_, digest, err := encodeOperatorIPTablesRecord(expected)
	if err != nil {
		return err
	}
	record, _, err := readOperatorIPTablesRecord(host, digest)
	if err != nil {
		return err
	}
	if record.Epoch != epoch || !bytes.Equal(record.Observation, canonical) {
		return fmt.Errorf("administrator iptables policy no longer matches its private review")
	}
	return nil
}
