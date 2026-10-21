//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
)

const sshActivationIntentName = "activation-intent.json"

// This private boundary records uncertainty before handing control to a live
// activation adapter. No production adapter or CLI entry is enabled here.
// Returned status is not proof of policy consumption or authenticated access.
type sshActivationResult struct {
	Transaction      string
	IntentDurable    bool
	RequestReturned  bool
	RecoveryRequired bool
}

type sshActivationIntent struct {
	Schema      int    `json:"schema"`
	Transaction string `json:"transaction"`
	Prepared    string `json:"prepared_sha256"`
	Plan        string `json:"plan_sha256"`
	Parser      string `json:"parser_sha256"`
	Publication string `json:"publication_sha256"`
	Records     string `json:"records_sha256"`
	Target      string `json:"target_sha256"`
}

// A future production binder must hold the verified manager/process resources
// through Close, qualify the exact operation and recheck them immediately before
// dispatch. A saved observation or caller-supplied summary cannot be a binder.
// request must honor ctx and the policy guard; its return is not an activation
// acknowledgement. Even an error can occur after the runtime request was sent.
type sshActivationLease interface {
	identity() string
	check() error
	request(context.Context, func() error) error
	Close() error
}

// The binding guard applies before intent publication. request receives a new
// guard that additionally binds the durable intent; it must use that guard.
type sshActivationBind func(context.Context, func() error) (sshActivationLease, error)

func sshActivationDigest(value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}

func makeSSHActivationIntent(owned *sshOwnedPublication, target string) (sshActivationIntent, error) {
	if owned == nil || !lowerDigest.MatchString(target) {
		return sshActivationIntent{}, ErrInventoryUnsafe
	}
	prepared, err := sshActivationDigest(owned.prepared)
	if err != nil {
		return sshActivationIntent{}, err
	}
	publication, err := sshActivationDigest(owned.inventory)
	if err != nil {
		return sshActivationIntent{}, err
	}
	records, err := sshActivationDigest(owned.records)
	if err != nil {
		return sshActivationIntent{}, err
	}
	return sshActivationIntent{1, owned.prepared.Transaction, prepared,
		owned.prepared.PlanSHA256, owned.prepared.ParserSHA256, publication, records, target}, nil
}

// Presence, including malformed or unreadable evidence, prohibits file-only
// recovery. Never infer that a runtime request was not sent from a missing
// completion record, a failed command or a later inactive daemon.
func (journal *sshJournal) requireNoSSHActivation() error {
	if err := journal.recheck(); err != nil {
		return err
	}
	var state unix.Stat_t
	err := unix.Fstatat(int(journal.directory.Fd()), sshActivationIntentName, &state, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(err, unix.ENOENT) {
		return errors.Join(errors.New("SSH activation may have been attempted; runtime-aware recovery is required and all evidence must be retained"), err)
	}
	return journal.recheck()
}

func recheckSSHActivation(owned *sshOwnedPublication, intent sshFileImage) error {
	current, err := stableSSHPublication(owned.journal.root, owned.journal.uid, owned.stage)
	if err != nil || !reflect.DeepEqual(current, owned.inventory) {
		return errors.Join(ErrInventoryChanged, err)
	}
	records, err := observeSSHOwnedRecordSet(owned.journal, true)
	if err != nil || records[sshActivationIntentName] != sshImageDigest(intent) {
		return errors.Join(ErrInventoryChanged, err)
	}
	delete(records, sshActivationIntentName)
	if !reflect.DeepEqual(records, owned.records) {
		return ErrInventoryChanged
	}
	return nil
}

func attemptSSHActivation(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error, bind sshActivationBind) (result sshActivationResult, err error) {
	if ctx == nil || bind == nil || parserCheck == nil {
		return result, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var owned *sshOwnedPublication
	_, err = withSSHOwnedObservation(ctx, journal, approved, parser, run, parserCheck,
		func(_ context.Context, publication *sshOwnedPublication, _ func() error) error {
			owned = publication
			return nil
		})
	if err != nil {
		return result, err
	}
	// The original journal lock remains held after the read-only verifier.
	guard := func() error { return errors.Join(ctx.Err(), parserCheck(), owned.recheck()) }
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
	target := lease.identity()
	record, err := makeSSHActivationIntent(owned, target)
	if err != nil {
		return result, err
	}
	wire, err := json.Marshal(record)
	if err != nil {
		return result, err
	}
	if err := errors.Join(lease.check(), guard()); err != nil || lease.identity() != target {
		return result, errors.Join(ErrInventoryChanged, err)
	}
	// From this point a failed write can still leave visible durable intent.
	// Never retry dispatch or clear the marker based on this function's result.
	result.Transaction, result.RecoveryRequired = record.Transaction, true
	defer func() {
		// Any attempted activation needs a newly opened runtime-aware recovery
		// path. Neither a successful request nor a close error clears this fence.
		journal.poisoned = true
	}()
	intent, err := journal.writeRecordImage(sshActivationIntentName, wire)
	if err != nil {
		return result, err
	}
	result.IntentDurable = true
	policyGuard := func() error { return errors.Join(ctx.Err(), parserCheck(), recheckSSHActivation(owned, intent)) }
	if err := errors.Join(lease.check(), policyGuard()); err != nil || lease.identity() != target {
		return result, errors.Join(ErrInventoryChanged, err)
	}
	requestErr := lease.request(ctx, policyGuard)
	if err := errors.Join(requestErr, policyGuard()); err != nil {
		return result, err
	}
	result.RequestReturned = true
	return result, nil
}
