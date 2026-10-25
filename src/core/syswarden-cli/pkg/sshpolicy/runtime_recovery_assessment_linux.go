//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"
)

// RecoveryAssessment observes a restored graph after a recorded reload intent.
// Record presence is not proof of durability, signal delivery, policy consumption
// or authenticated access. RecoveryRequired remains true even on success.
type RecoveryAssessment struct {
	Schema                int             `json:"schema"`
	PlanSHA256            string          `json:"plan_sha256"`
	RecoverySHA256        string          `json:"recovery_sha256"`
	Transaction           string          `json:"transaction"`
	ReloadIntentSHA256    string          `json:"reload_intent_sha256"`
	RecordedTargetSHA256  string          `json:"recorded_target_sha256"`
	RestoredSHA256        string          `json:"restored_sha256"`
	ConfigurationRestored bool            `json:"configuration_restored"`
	ParserVerified        bool            `json:"parser_verified"`
	ReloadIntentObserved  bool            `json:"reload_intent_observed"`
	RecoveryRequired      bool            `json:"recovery_required"`
	RuntimeActivated      bool            `json:"runtime_activated"`
	AccessVerified        bool            `json:"access_verified"`
	Endpoints             EndpointSummary `json:"endpoints"`
}

// Keep the existing writer's exact field order and encoding. The read-only
// observer must accept existing canonical records without migrating history.
type sshRuntimeRecoveryReload struct {
	Schema   int    `json:"schema"`
	Recovery string `json:"recovery_sha256"`
	Restored string `json:"restored_sha256"`
	Target   string `json:"target_sha256"`
}

func assessSSHRuntimeRecovery(ctx context.Context, journal *sshJournal, original, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver) (RecoveryAssessment, error) {
	return withSSHRestoredAccessAssessment(ctx, journal, original, recovery, parser, run, parserCheck, observe, nil, nil, nil)
}

type sshRestoredAccessAssessment struct {
	journal  *sshJournal
	plan     migrationPlan
	records  map[string]string
	issuance *sshFileImage
	evidence *sshFileImage
}

func withSSHRestoredAccessAssessment(ctx context.Context, journal *sshJournal, original, recovery, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver, issuance, evidence *sshFileImage,
	action func(*sshRestoredAccessAssessment, RecoveryAssessment, func() error) error) (RecoveryAssessment, error) {
	if err := validSSHRecoveryRequest(ctx, original, recovery, true); err != nil {
		return RecoveryAssessment{}, err
	}
	if journal == nil || journal.retained != nil || !lowerDigest.MatchString(parser) || run == nil || parserCheck == nil || observe == nil {
		return RecoveryAssessment{}, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := errors.Join(ctx.Err(), parserCheck()); err != nil {
		return RecoveryAssessment{}, err
	}
	records, err := observeSSHRuntimeRecoveryRecordsWithAccess(journal, issuance, evidence)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	wire, err := journal.readRecord(sshRuntimeRecoveryName)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	var intent sshRuntimeRecoveryIntent
	if err := json.Unmarshal(wire, &intent); err != nil {
		return RecoveryAssessment{}, ErrInventoryUnsafe
	}
	canonical, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(wire, canonical) || digestBytes(wire) != recovery {
		return RecoveryAssessment{}, errors.Join(ErrInventoryChanged, err)
	}
	prepared, plan, err := validateSSHRuntimeRecovery(journal, intent, original, parser, records)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	// No missing completion, extra phase or original record may be inferred
	// from matching live files. Require the full recorded inverse transition.
	if len(records) != len(intent.Records)+6 {
		return RecoveryAssessment{}, ErrInventoryChanged
	}
	current, err := stableSSHRollback(journal, prepared.Transaction)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	preparedDigest, err := sshActivationDigest(prepared)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	start := sshRollbackStart{1, prepared.Transaction, preparedDigest, 3, intent.Before}
	position, _, err := matchSSHRecordedRollback(journal, prepared, start, current, sshRuntimeRecoveryPhase)
	if err != nil || position != (sshPublicationPosition{2, "complete"}) ||
		!matchesSSHRecovery(current, MainPath, prepared.MainBefore) || current.Nodes[DropInPath] != (sshStoredStamp{}) {
		return RecoveryAssessment{}, errors.Join(ErrInventoryChanged, err)
	}
	restored, err := sshActivationDigest(current)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	reloadWire, err := journal.readRecord(sshRuntimeRecoveryReloadName)
	if err != nil {
		return RecoveryAssessment{}, err
	}
	want, err := json.Marshal(sshRuntimeRecoveryReload{1, recovery, restored, intent.Target})
	if err != nil || !bytes.Equal(reloadWire, want) {
		return RecoveryAssessment{}, errors.Join(ErrInventoryChanged, err)
	}
	a := &sshRestoredAccessAssessment{journal: journal, plan: plan, records: records, issuance: issuance, evidence: evidence}
	baseFence := func() error {
		if err := errors.Join(ctx.Err(), parserCheck()); err != nil {
			return err
		}
		currentRecords, err := observeSSHRuntimeRecoveryRecordsWithAccess(journal, a.issuance, a.evidence)
		if err != nil || !reflect.DeepEqual(currentRecords, a.records) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return ctx.Err()
	}
	guard := sshRollbackInventoryGuard(ctx, journal, prepared.Transaction, current, parserCheck, baseFence)
	if err := verifySSHRollbackCandidates(ctx, plan, run, guard); err != nil {
		return RecoveryAssessment{}, err
	}
	if err := verifySSHOriginal(ctx, plan, run, guard); err != nil {
		return RecoveryAssessment{}, err
	}
	inventory, err := collectInventory(journal.root, journal.uid)
	if err := errors.Join(err, guard()); err != nil {
		return RecoveryAssessment{}, err
	}
	endpoints, err := observeSSHEndpoints(ctx, inventory, parser, run, guard, observe)
	if err := errors.Join(err, guard()); err != nil {
		return RecoveryAssessment{}, err
	}
	if endpoints.ConfigurationVerified || endpoints.RuntimeActivated || endpoints.AccessVerified ||
		endpoints.Listeners.ConfigurationVerified || endpoints.Listeners.RuntimeActivated || endpoints.Listeners.AccessVerified ||
		endpoints.Listeners.Process.ConfigurationVerified || endpoints.Listeners.Process.RuntimeActivated || endpoints.Listeners.Process.AccessVerified ||
		endpoints.Listeners.Process.Manager.RuntimeActivated || endpoints.Listeners.Process.Manager.AccessVerified {
		return RecoveryAssessment{}, ErrInventoryUnsafe
	}
	summary := RecoveryAssessment{Schema: 1, PlanSHA256: original, RecoverySHA256: recovery, Transaction: prepared.Transaction,
		ReloadIntentSHA256: digestBytes(reloadWire), RecordedTargetSHA256: intent.Target, RestoredSHA256: restored,
		ConfigurationRestored: true, ParserVerified: true, ReloadIntentObserved: true, RecoveryRequired: true, Endpoints: endpoints}
	if action != nil {
		// Re-observe endpoints at each publication boundary. The observer gets
		// only the base file/parser guard, never this enclosing action guard.
		// Snapshot equality is a drift fence, not causal policy consumption.
		actionGuard := func() error {
			if err := guard(); err != nil {
				return err
			}
			observed, err := observeSSHEndpoints(ctx, inventory, parser, run, guard, observe)
			if err != nil || !reflect.DeepEqual(observed, endpoints) {
				return errors.Join(ErrInventoryChanged, err)
			}
			return errors.Join(ctx.Err(), guard())
		}
		if err := action(a, summary, actionGuard); err != nil {
			return RecoveryAssessment{}, err
		}
		if err := actionGuard(); err != nil {
			return RecoveryAssessment{}, err
		}
	}
	if err := guard(); err != nil {
		return RecoveryAssessment{}, err
	}
	return summary, nil
}

// AssessSystemdRecovery reopens existing fixed-path history without changing
// files, repairing synchronization, sending signals or attempting authentication.
func AssessSystemdRecovery(ctx context.Context, original, recovery string) (RecoveryAssessment, error) {
	if err := validSSHRecoveryRequest(ctx, original, recovery, true); err != nil {
		return RecoveryAssessment{}, err
	}
	if os.Geteuid() != 0 {
		return RecoveryAssessment{}, fmt.Errorf("SSH restoration assessment requires root")
	}
	return assessSSHRecoverySession(ctx, original, recovery, openSSHRecoverySession, observeSSHConfiguredListeners)
}

func assessSSHRecoverySession(ctx context.Context, original, recovery string,
	open func(context.Context) (*sshRecoverySession, error), observe sshEndpointObserver) (summary RecoveryAssessment, err error) {
	defer func() {
		if err != nil {
			summary = RecoveryAssessment{}
		}
	}()
	if err := validSSHRecoveryRequest(ctx, original, recovery, true); err != nil {
		return summary, err
	}
	if open == nil || observe == nil {
		return summary, ErrInventoryUnsafe
	}
	session, openErr := open(ctx)
	if session != nil && session.close != nil {
		defer func() { err = errors.Join(err, session.close()) }()
	}
	if openErr != nil {
		return summary, openErr
	}
	if session == nil || session.close == nil {
		return summary, ErrInventoryUnsafe
	}
	return assessSSHRuntimeRecovery(ctx, session.journal, original, recovery, session.parser, session.run, session.check, observe)
}
