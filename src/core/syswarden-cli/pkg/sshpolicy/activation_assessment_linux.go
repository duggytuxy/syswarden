//go:build linux

package sshpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"time"
)

// ActivationAssessment reports current observations after a recorded attempt.
// It cannot establish whether the signal was sent, whether the daemon consumed
// that policy, or whether access works. RecoveryRequired is always true on
// success. This is not authority to retry, roll back or retire the journal.
type ActivationAssessment struct {
	Schema           int             `json:"schema"`
	Publication      OwnedSummary    `json:"publication"`
	Endpoints        EndpointSummary `json:"endpoints"`
	IntentSHA256     string          `json:"intent_sha256"`
	TargetSHA256     string          `json:"target_sha256"`
	IntentObserved   bool            `json:"intent_observed"`
	RecoveryRequired bool            `json:"recovery_required"`
}

type sshActivationAssessment struct {
	owned  *sshOwnedPublication
	intent sshFileImage
	target string
}

func (a *sshActivationAssessment) recheck() error {
	return recheckSSHActivation(a.owned, a.intent)
}

func inspectSSHActivationHistory(journal *sshJournal, approved, parser string) (*sshActivationAssessment, error) {
	if journal == nil || journal.retained != nil || !lowerDigest.MatchString(approved) || !lowerDigest.MatchString(parser) {
		return nil, ErrInventoryUnsafe
	}
	records, err := observeSSHOwnedRecordSet(journal, true)
	if err != nil {
		return nil, err
	}
	image, err := readSSHPrivateChild(journal.directory, sshActivationIntentName, journal.uid, 2048)
	if err != nil || sshImageDigest(image) != records[sshActivationIntentName] {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	var intent sshActivationIntent
	if err := json.Unmarshal(image.data, &intent); err != nil || intent.Schema != 1 || !lowerDigest.MatchString(intent.Target) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	// The writer has one canonical encoding. Re-encoding rejects unknown,
	// duplicate, case-folded and omitted fields without repairing evidence.
	wire, err := json.Marshal(intent)
	if err != nil || !bytes.Equal(wire, image.data) {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	prepared, err := journal.read()
	if err != nil || prepared.PlanSHA256 != approved || prepared.ParserSHA256 != parser {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	preparedDigest, err := sshActivationDigest(prepared)
	if err != nil {
		return nil, err
	}
	plan, err := recoverSSHPlan(journal, prepared, preparedDigest)
	if err != nil {
		return nil, err
	}
	if err := plan.selection.Authorize(plan.intent.Owner, plan.intent.Profile); err != nil {
		return nil, err
	}
	stage, err := sshMainStagePath(prepared.Transaction)
	if err != nil {
		return nil, err
	}
	current, err := stableSSHPublication(journal.root, journal.uid, stage)
	if err != nil {
		return nil, err
	}
	// This is the only activation-aware caller of the history-only matcher.
	// Exact membership above excludes rollback/retirement and incomplete files.
	position, err := matchSSHRecordedPublication(journal, prepared, current)
	if err != nil || position != (sshPublicationPosition{3, "complete"}) {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	original := maps.Clone(records)
	delete(original, sshActivationIntentName)
	owned := &sshOwnedPublication{journal, prepared, plan, stage, current, original}
	expected, err := makeSSHActivationIntent(owned, intent.Target)
	if err != nil || intent != expected {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	assessment := &sshActivationAssessment{owned, image, intent.Target}
	return assessment, assessment.recheck()
}

func assessSSHActivation(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver) (ActivationAssessment, error) {
	return withSSHActivationAssessment(ctx, journal, approved, parser, run, parserCheck, observe, nil)
}

// The private action runs inside the original journal lock and inode guards.
// It may derive a request but cannot turn an observation into activation proof.
func withSSHActivationAssessment(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, observe sshEndpointObserver,
	action func(context.Context, *sshActivationAssessment, ActivationAssessment, func() error) error) (ActivationAssessment, error) {
	if ctx == nil || run == nil || parserCheck == nil || observe == nil {
		return ActivationAssessment{}, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := errors.Join(ctx.Err(), parserCheck()); err != nil {
		return ActivationAssessment{}, err
	}
	a, err := inspectSSHActivationHistory(journal, approved, parser)
	if err != nil {
		return ActivationAssessment{}, err
	}
	guard := func() error { return errors.Join(ctx.Err(), parserCheck(), a.recheck()) }
	if err := verifySSHRollbackCandidates(ctx, a.owned.plan, run, guard); err != nil {
		return ActivationAssessment{}, err
	}
	if err := verifySSHCurrentPublication(ctx, a.owned.plan, run, guard); err != nil {
		return ActivationAssessment{}, err
	}
	inventory, err := collectInventory(journal.root, journal.uid)
	if err := errors.Join(err, guard()); err != nil {
		return ActivationAssessment{}, err
	}
	endpoints, err := observeSSHEndpoints(ctx, inventory, parser, run, guard, observe)
	if err := errors.Join(err, guard()); err != nil {
		return ActivationAssessment{}, err
	}
	// An endpoint observation is current state, not continuity with the original
	// target or an acknowledgement of the recorded attempt. Keep false proof
	// fields even when the read-only observation itself succeeds.
	if endpoints.ConfigurationVerified || endpoints.RuntimeActivated || endpoints.AccessVerified ||
		endpoints.Listeners.ConfigurationVerified || endpoints.Listeners.RuntimeActivated || endpoints.Listeners.AccessVerified ||
		endpoints.Listeners.Process.ConfigurationVerified || endpoints.Listeners.Process.RuntimeActivated || endpoints.Listeners.Process.AccessVerified ||
		endpoints.Listeners.Process.Manager.RuntimeActivated || endpoints.Listeners.Process.Manager.AccessVerified {
		return ActivationAssessment{}, ErrInventoryUnsafe
	}
	summary := ActivationAssessment{Schema: 1, IntentSHA256: digestBytes(a.intent.data), TargetSHA256: a.target,
		IntentObserved: true, RecoveryRequired: true, Endpoints: endpoints, Publication: OwnedSummary{
			Schema: 1, PlanSHA256: approved, ParserSHA256: parser, Transaction: a.owned.prepared.Transaction,
			Profile: a.owned.plan.intent.Profile, ContextsVerified: len(a.owned.plan.intent.Contexts),
			OwnershipVerified: true, PublicationObserved: true, ParserVerified: true,
		}}
	if action != nil {
		if err := action(ctx, a, summary, guard); err != nil {
			return ActivationAssessment{}, err
		}
	}
	if err := guard(); err != nil {
		return ActivationAssessment{}, err
	}
	return summary, nil
}

// AssessSystemdActivation reopens a protected journal at fixed live paths and
// observes current systemd endpoints without signalling or authenticating. The
// independent original plan is required. No record is created, synced, cleared
// or adopted, even after an interrupted write. All errors return no summary.
func AssessSystemdActivation(approved string) (summary ActivationAssessment, err error) {
	defer func() {
		if err != nil {
			summary = ActivationAssessment{}
		}
	}()
	if os.Geteuid() != 0 || !lowerDigest.MatchString(approved) {
		return summary, fmt.Errorf("SSH activation assessment requires root and the original lowercase plan SHA-256")
	}
	root, err := os.Open("/")
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, daemon.file.Close()) }()
	journal, err := openSSHJournal(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, journal.Close()) }()
	return assessSSHActivation(context.Background(), journal, approved, daemon.digest,
		daemon.run, func() error { return daemon.recheck(root, 0) }, observeSSHConfiguredListeners)
}
