//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

const (
	sshRuntimeRecoveryName       = "runtime-recovery-intent.json"
	sshRuntimeRecoveryReloadName = "runtime-recovery-reload.json"
	sshRuntimeRecoveryDomain     = "syswarden-ssh-restore-original-v1"
)

type sshRuntimeRecoveryIntent struct {
	Schema      int                `json:"schema"`
	Domain      string             `json:"domain"`
	Transaction string             `json:"transaction"`
	Plan        string             `json:"plan_sha256"`
	Parser      string             `json:"parser_sha256"`
	Target      string             `json:"target_sha256"`
	Records     map[string]string  `json:"original_records"`
	Before      sshStoredInventory `json:"before"`
}

// These observations never assert loaded policy, authenticated access or
// completed recovery. Even a successful restoring request keeps the fence.
type sshRuntimeRecoveryResult struct {
	Transaction           string
	RecoverySHA256        string
	IntentDurable         bool
	ConfigurationRestored bool
	RequestReturned       bool
	RecoveryRequired      bool
}

func sshRuntimeRecoveryPhase(step int, done bool) string {
	suffix := "intent"
	if done {
		suffix = "complete"
	}
	return fmt.Sprintf("runtime-recovery-%02d-%s.json", step, suffix)
}

// Only original activation history and this operation's fixed phase names are
// accepted. Every record is pinned by inode, bytes, metadata and attributes.
func observeSSHRuntimeRecoveryRecords(journal *sshJournal) (map[string]string, error) {
	if err := journal.recheck(); err != nil {
		return nil, err
	}
	names, err := sshDirectoryNames(journal.directory, 17)
	if err != nil {
		return nil, err
	}
	records := make(map[string]string, len(names))
	allowed := map[string]bool{sshMarkerName: true, sshPreparedRecord: true,
		sshActivationIntentName: true, sshAccessEvidenceName: true, sshAccessIssuanceName: true,
		sshRuntimeRecoveryName: true, sshRuntimeRecoveryReloadName: true}
	for step := 1; step <= 3; step++ {
		allowed[sshPublicationName(step, false)], allowed[sshPublicationName(step, true)] = true, true
	}
	for step := 1; step <= 2; step++ {
		allowed[sshRuntimeRecoveryPhase(step, false)], allowed[sshRuntimeRecoveryPhase(step, true)] = true, true
	}
	for _, name := range names {
		if !allowed[name] {
			return nil, ErrInventoryUnsafe
		}
		image, err := readSSHPrivateChild(journal.directory, name, journal.uid, maxSSHJournalBytes)
		if err != nil {
			return nil, err
		}
		records[name] = sshImageDigest(image)
	}
	return records, journal.recheck()
}

func recheckSSHRuntimeRecoveryRecords(journal *sshJournal, expected map[string]string) error {
	current, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

// Reconstruct only the sealed original publication. The stored baseline is
// independently bound by recovery approval, never inferred from current files.
func validateSSHRuntimeRecovery(journal *sshJournal, intent sshRuntimeRecoveryIntent, original, parser string,
	records map[string]string) (sshPreparation, migrationPlan, error) {
	fail := func(err error) (sshPreparation, migrationPlan, error) {
		return sshPreparation{}, migrationPlan{}, errors.Join(ErrInventoryChanged, err)
	}
	if intent.Schema != 1 || intent.Domain != sshRuntimeRecoveryDomain || intent.Plan != original ||
		intent.Parser != parser || !lowerDigest.MatchString(intent.Target) {
		return fail(ErrInventoryUnsafe)
	}
	expected := map[string]bool{sshMarkerName: true, sshPreparedRecord: true, sshActivationIntentName: true}
	for step := 1; step <= 3; step++ {
		expected[sshPublicationName(step, false)], expected[sshPublicationName(step, true)] = true, true
	}
	if _, exists := intent.Records[sshAccessEvidenceName]; exists {
		expected[sshAccessEvidenceName] = true
	}
	if _, exists := intent.Records[sshAccessIssuanceName]; exists {
		expected[sshAccessIssuanceName] = true
	}
	if len(intent.Records) != len(expected) {
		return fail(ErrInventoryUnsafe)
	}
	for name := range records {
		if name == sshRuntimeRecoveryName || name == sshRuntimeRecoveryReloadName ||
			name == sshRuntimeRecoveryPhase(1, false) || name == sshRuntimeRecoveryPhase(1, true) ||
			name == sshRuntimeRecoveryPhase(2, false) || name == sshRuntimeRecoveryPhase(2, true) {
			continue
		}
		if !expected[name] {
			return fail(ErrInventoryChanged)
		}
	}
	for name := range expected {
		if !lowerDigest.MatchString(intent.Records[name]) || records[name] != intent.Records[name] {
			return fail(ErrInventoryChanged)
		}
	}
	prepared, err := journal.read()
	if err != nil || prepared.Transaction != intent.Transaction || prepared.PlanSHA256 != original || prepared.ParserSHA256 != parser {
		return fail(err)
	}
	digest, err := sshActivationDigest(prepared)
	if err != nil {
		return fail(err)
	}
	plan, err := recoverSSHPlan(journal, prepared, digest)
	if err != nil {
		return fail(err)
	}
	if err := plan.selection.Authorize(plan.intent.Owner, plan.intent.Profile); err != nil {
		return fail(err)
	}
	if err := intent.Before.validate(); err != nil {
		return fail(err)
	}
	dropStage, err := sshDropStagePath(prepared.Transaction)
	if err != nil || intent.Before.Nodes[dropStage] != (sshStoredStamp{}) {
		return fail(err)
	}
	baseline := intent.Before
	baseline.Nodes = maps.Clone(baseline.Nodes)
	delete(baseline.Nodes, dropStage)
	position, err := matchSSHRecordedPublication(journal, prepared, baseline)
	if err != nil || position != (sshPublicationPosition{3, "complete"}) {
		return fail(err)
	}
	wire, err := journal.readRecord(sshActivationIntentName)
	if err != nil {
		return fail(err)
	}
	var activation sshActivationIntent
	if err := json.Unmarshal(wire, &activation); err != nil || !lowerDigest.MatchString(activation.Target) {
		return fail(err)
	}
	stage, err := sshMainStagePath(prepared.Transaction)
	if err != nil {
		return fail(err)
	}
	originalRecords := maps.Clone(intent.Records)
	delete(originalRecords, sshActivationIntentName)
	delete(originalRecords, sshAccessEvidenceName)
	delete(originalRecords, sshAccessIssuanceName)
	owned := &sshOwnedPublication{journal, prepared, plan, stage, baseline, originalRecords}
	wanted, err := makeSSHActivationIntent(owned, activation.Target)
	if err != nil || wanted != activation {
		return fail(err)
	}
	canonical, err := json.Marshal(wanted)
	if err != nil || !bytes.Equal(wire, canonical) {
		return fail(err)
	}
	return prepared, plan, nil
}

// Internal engine reached by the root-only original-restoration adapter.
// No installer or forward activation is enabled. Empty recoveryApproval means
// inspection only. Application
// requires its separate digest, never just the original migration approval.
// A partial inverse can resume only with exactly the same history and target.
// A reload intent always prohibits replay, even if dispatch may not have run.
func recoverSSHActivatedConfiguration(ctx context.Context, journal *sshJournal, original, parser, recoveryApproval string,
	run sshParserRun, parserCheck func() error, bind sshActivationBind, ops sshPublicationOps) (result sshRuntimeRecoveryResult, err error) {
	if ctx == nil || journal == nil || journal.retained != nil || run == nil || parserCheck == nil || bind == nil ||
		ops.sync == nil || ops.rename == nil || !lowerDigest.MatchString(original) || !lowerDigest.MatchString(parser) ||
		(recoveryApproval != "" && !lowerDigest.MatchString(recoveryApproval)) {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := errors.Join(ctx.Err(), parserCheck()); err != nil {
		return result, err
	}
	records, err := observeSSHRuntimeRecoveryRecords(journal)
	if err != nil {
		return result, err
	}
	if _, exists := records[sshRuntimeRecoveryReloadName]; exists {
		return result, errors.New("SSH restoring reload may have been requested; retain history and obtain fresh runtime and access evidence before another operation")
	}
	var intent sshRuntimeRecoveryIntent
	fresh := records[sshRuntimeRecoveryName] == ""
	if fresh {
		var evidence *sshFileImage
		if _, exists := records[sshAccessEvidenceName]; exists {
			image, err := readSSHPrivateChild(journal.directory, sshAccessEvidenceName, journal.uid, maxSSHAccessEvidenceBytes)
			if err != nil {
				return result, err
			}
			evidence = &image // Preserve it; it cannot authorize recovery or access.
		}
		var issuance *sshFileImage
		if _, exists := records[sshAccessIssuanceName]; exists {
			image, err := readSSHPrivateChild(journal.directory, sshAccessIssuanceName, journal.uid, maxSSHAccessIssuanceBytes)
			if err != nil {
				return result, err
			}
			issuance = &image // Preserve opaque history even after expiry or revocation.
		}
		a, err := inspectSSHActivationAccessHistory(journal, original, parser, evidence, issuance)
		if err != nil {
			return result, err
		}
		before, err := stableSSHRollback(journal, a.owned.prepared.Transaction)
		if err != nil {
			return result, err
		}
		intent = sshRuntimeRecoveryIntent{1, sshRuntimeRecoveryDomain, a.owned.prepared.Transaction, original, parser, "", maps.Clone(records), before}
	} else {
		wire, err := journal.readRecord(sshRuntimeRecoveryName)
		if err != nil {
			return result, err
		}
		if err := json.Unmarshal(wire, &intent); err != nil {
			return result, ErrInventoryUnsafe
		}
		canonical, err := json.Marshal(intent)
		if err != nil || !bytes.Equal(wire, canonical) {
			return result, ErrInventoryUnsafe
		}
	}
	current, err := stableSSHRollback(journal, intent.Transaction)
	if err != nil {
		return result, err
	}
	// A fresh target is independently approved, not equated with the historical
	// activation target. Before resume, its original socket generation must hold.
	baseFence := func() error {
		return errors.Join(ctx.Err(), parserCheck(), recheckSSHRuntimeRecoveryRecords(journal, records))
	}
	guard := sshRollbackInventoryGuard(ctx, journal, intent.Transaction, current, parserCheck, baseFence)
	lease, bindErr := bind(ctx, guard)
	if lease != nil {
		defer func() { err = errors.Join(err, lease.Close()) }()
	}
	if err := errors.Join(bindErr, guard()); err != nil {
		return result, err
	}
	if lease == nil || !lowerDigest.MatchString(lease.identity()) {
		return result, ErrInventoryUnsafe
	}
	if fresh {
		intent.Target = lease.identity()
	} else if intent.Target != lease.identity() {
		return result, ErrInventoryChanged
	}
	prepared, plan, err := validateSSHRuntimeRecovery(journal, intent, original, parser, records)
	if err != nil {
		return result, err
	}
	digest, err := sshActivationDigest(prepared)
	if err != nil {
		return result, err
	}
	start := sshRollbackStart{1, prepared.Transaction, digest, 3, intent.Before}
	position, _, err := matchSSHRecordedRollback(journal, prepared, start, current, sshRuntimeRecoveryPhase)
	if err != nil {
		return result, err
	}
	fence := func() error {
		if lease.identity() != intent.Target {
			return ErrInventoryChanged
		}
		return errors.Join(baseFence(), lease.check())
	}
	guard = sshRollbackInventoryGuard(ctx, journal, intent.Transaction, current, parserCheck, fence)
	if err := errors.Join(verifySSHRollbackCandidates(ctx, plan, run, guard), checkSSHRollbackBudget(current, prepared), guard()); err != nil {
		return result, err
	}
	recoveryDigest, err := sshActivationDigest(intent)
	if err != nil {
		return result, err
	}
	if recoveryApproval == "" {
		return sshRuntimeRecoveryResult{Transaction: intent.Transaction, RecoverySHA256: recoveryDigest, RecoveryRequired: true}, nil
	}
	if recoveryApproval != recoveryDigest {
		return result, errors.New("SSH recovery inputs no longer match the separately approved restore-original plan")
	}
	result.Transaction, result.RecoverySHA256, result.RecoveryRequired = intent.Transaction, recoveryDigest, true
	defer func() { journal.poisoned = true }()
	write := func(name string, value any) error {
		if err := guard(); err != nil {
			return err
		}
		wire, err := json.Marshal(value)
		if err != nil {
			return err
		}
		image, err := journal.writeRecordImage(name, wire)
		if err != nil {
			return err
		}
		records[name] = sshImageDigest(image)
		return guard()
	}
	if fresh {
		if err := write(sshRuntimeRecoveryName, intent); err != nil {
			return result, err
		}
	}
	// Repair durability explicitly on resume before another inode transition.
	if err := syncSSHRollbackGuarded(ctx, journal, intent.Transaction, current, parserCheck, ops, fence); err != nil {
		return result, err
	}
	result.IntentDurable = true
	next := position.Step + 1
	if position.State == "before" || position.State == "after" {
		next = position.Step
	}
	for step := next; step <= 2; step++ {
		phase, readErr := journal.readSSHPhase(sshRuntimeRecoveryPhase(step, false), step, false, prepared, digest)
		if errors.Is(readErr, unix.ENOENT) {
			phase = sshPublicationRecord{1, prepared.Transaction, digest, step, current, nil}
			if err := write(sshRuntimeRecoveryPhase(step, false), phase); err != nil {
				return result, err
			}
		} else if readErr != nil {
			return result, readErr
		}
		if reflect.DeepEqual(phase.Before, current) {
			current, err = executeSSHRollbackGuarded(ctx, journal, phase, prepared, 3, parserCheck, ops, fence)
			if err != nil {
				return result, err
			}
		} else if err := checkSSHRollbackTransition(phase.Before, current, prepared, 3, step); err != nil {
			return result, err
		}
		guard = sshRollbackInventoryGuard(ctx, journal, intent.Transaction, current, parserCheck, fence)
		if err := syncSSHRollbackGuarded(ctx, journal, intent.Transaction, current, parserCheck, ops, fence); err != nil {
			return result, err
		}
		phase.After = &current
		if err := write(sshRuntimeRecoveryPhase(step, true), phase); err != nil {
			return result, err
		}
	}
	if !matchesSSHRecovery(current, MainPath, prepared.MainBefore) || current.Nodes[DropInPath] != (sshStoredStamp{}) {
		return result, ErrInventoryChanged
	}
	if err := verifySSHOriginal(ctx, plan, run, guard); err != nil {
		return result, err
	}
	result.ConfigurationRestored = true
	restored, err := sshActivationDigest(current)
	if err != nil {
		return result, err
	}
	// This immutable boundary is separate from the file recovery intent. Its
	// presence prohibits signal replay even after an unacknowledged write.
	if err := write(sshRuntimeRecoveryReloadName, sshRuntimeRecoveryReload{1, recoveryDigest, restored, intent.Target}); err != nil {
		return result, err
	}
	// request owns the runtime checks through signal dispatch and observation.
	// Its consumed lease must not be checked again as if it were unattempted.
	// request serializes the target under its own mutex. Its policy callback
	// must not reenter identity/check and deadlock that mutex. Check identity
	// again only after request returns and releases its ownership lock.
	requestGuard := sshRollbackInventoryGuard(ctx, journal, intent.Transaction, current, parserCheck, baseFence)
	requestErr := lease.request(ctx, requestGuard)
	if lease.identity() != intent.Target {
		requestErr = errors.Join(requestErr, ErrInventoryChanged)
	}
	if err := errors.Join(requestErr, requestGuard()); err != nil {
		return result, err
	}
	result.RequestReturned = true
	return result, nil
}
