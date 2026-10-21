//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"
)

// OwnedSummary reports a fresh observation of a completed configuration
// publication. It does not authorize an update, repair uncertain durability,
// activate a daemon or establish that a new connection can authenticate.
type OwnedSummary struct {
	Schema              int    `json:"schema"`
	PlanSHA256          string `json:"plan_sha256"`
	ParserSHA256        string `json:"parser_sha256"`
	Transaction         string `json:"transaction"`
	Profile             string `json:"profile"`
	ContextsVerified    int    `json:"contexts_verified"`
	OwnershipVerified   bool   `json:"ownership_verified"`
	PublicationObserved bool   `json:"publication_observed"`
	ParserVerified      bool   `json:"parser_verified"`
	RuntimeActivated    bool   `json:"runtime_activated"`
	AccessVerified      bool   `json:"access_verified"`
}

// VerifyOwned examines an existing journal and live configuration through fixed
// protected paths. It creates no files, does not sync or recover a failed write,
// and only invokes the installed parser's syntax/effective modes. The original
// approved plan must be supplied independently, not inferred from a filename.
func VerifyOwned(approved string) (summary OwnedSummary, err error) {
	if os.Geteuid() != 0 || !lowerDigest.MatchString(approved) {
		return summary, fmt.Errorf("owned SSH verification requires root and the original lowercase plan SHA-256")
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
	return verifySSHOwnedPublication(context.Background(), journal, approved, daemon.digest,
		daemon.run, func() error { return daemon.recheck(root, 0) })
}

type sshOwnedPublication struct {
	journal   *sshJournal
	prepared  sshPreparation
	plan      migrationPlan
	stage     string
	inventory sshStoredInventory
	records   map[string]string
}

// Bind every original record's inode, bytes, mode, attributes and link count.
// Exact directory membership refuses incomplete, mixed and unknown histories.
// A copied valid record cannot replace a record during parser verification.
func observeSSHOwnedRecords(journal *sshJournal) (map[string]string, error) {
	return observeSSHOwnedRecordSet(journal, false)
}

func observeSSHOwnedRecordSet(journal *sshJournal, activation bool) (map[string]string, error) {
	if err := journal.recheck(); err != nil {
		return nil, err
	}
	count := 8
	if activation {
		count++
	}
	names, err := sshDirectoryNames(journal.directory, count)
	if err != nil || len(names) != count {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	expected := map[string]bool{sshMarkerName: true, sshPreparedRecord: true}
	for step := 1; step <= 3; step++ {
		expected[sshPublicationName(step, false)] = true
		expected[sshPublicationName(step, true)] = true
	}
	if activation {
		expected[sshActivationIntentName] = true
	}
	records := make(map[string]string, count)
	for _, name := range names {
		if !expected[name] {
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

func inspectSSHOwnedPublication(journal *sshJournal, approved, parser string) (*sshOwnedPublication, error) {
	if journal == nil || journal.retained != nil || !lowerDigest.MatchString(approved) || !lowerDigest.MatchString(parser) {
		return nil, ErrInventoryUnsafe
	}
	records, err := observeSSHOwnedRecords(journal)
	if err != nil {
		return nil, err
	}
	prepared, err := journal.read()
	if err != nil {
		return nil, err
	}
	if prepared.PlanSHA256 != approved || prepared.ParserSHA256 != parser {
		return nil, ErrInventoryChanged
	}
	data, err := json.Marshal(prepared)
	if err != nil {
		return nil, err
	}
	plan, err := recoverSSHPlan(journal, prepared, digestBytes(data))
	if err != nil {
		return nil, err
	}
	// Historical defaults and a matching generated file do not establish the
	// administrator's independent TOML choice required by issue422.
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
	position, err := matchSSHPublication(journal, prepared, current)
	if err != nil || position != (sshPublicationPosition{3, "complete"}) {
		return nil, errors.Join(ErrInventoryChanged, err)
	}
	if err := checkSSHPublicationIsolation(plan, prepared.Transaction); err != nil {
		return nil, err
	}
	owned := &sshOwnedPublication{journal, prepared, plan, stage, current, records}
	return owned, owned.recheck()
}

func (owned *sshOwnedPublication) recheck() error {
	current, err := stableSSHPublication(owned.journal.root, owned.journal.uid, owned.stage)
	if err != nil || !reflect.DeepEqual(current, owned.inventory) {
		return errors.Join(ErrInventoryChanged, err)
	}
	records, err := observeSSHOwnedRecords(owned.journal)
	if err != nil || !reflect.DeepEqual(records, owned.records) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

// Revalidation is separate from apply: a repeated apply must still refuse an
// occupied journal. Observation must not turn an uncertain fsync, incomplete
// activation or a retained recovery image into an accepted runtime policy.
func verifySSHOwnedPublication(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error) (OwnedSummary, error) {
	return withSSHOwnedObservation(ctx, journal, approved, parser, run, parserCheck, nil)
}

// Keep dependent observations inside the same verified ownership lifetime.
// The private callback receives a fresh guard, never a serialized authority.
func withSSHOwnedObservation(ctx context.Context, journal *sshJournal, approved, parser string,
	run sshParserRun, parserCheck func() error,
	observe func(context.Context, *sshOwnedPublication, func() error) error) (OwnedSummary, error) {
	if ctx == nil || run == nil || parserCheck == nil {
		return OwnedSummary{}, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := errors.Join(ctx.Err(), parserCheck()); err != nil {
		return OwnedSummary{}, err
	}
	owned, err := inspectSSHOwnedPublication(journal, approved, parser)
	if err != nil {
		return OwnedSummary{}, err
	}
	guard := func() error {
		return errors.Join(ctx.Err(), parserCheck(), owned.recheck())
	}
	// Reconstruct original, intermediate and final graphs from the protected
	// history. Never treat the live post-migration graph as an original plan.
	if err := verifySSHRollbackCandidates(ctx, owned.plan, run, guard); err != nil {
		return OwnedSummary{}, err
	}
	if err := verifyPublishedSSH(ctx, journal, owned.plan, owned.stage, owned.inventory, run, guard); err != nil {
		return OwnedSummary{}, err
	}
	if err := guard(); err != nil {
		return OwnedSummary{}, err
	}
	if observe != nil {
		if err := errors.Join(observe(ctx, owned, guard), guard()); err != nil {
			return OwnedSummary{}, err
		}
	}
	return OwnedSummary{
		Schema: 1, PlanSHA256: approved, ParserSHA256: parser, Transaction: owned.prepared.Transaction,
		Profile: owned.plan.intent.Profile, ContextsVerified: len(owned.plan.intent.Contexts),
		OwnershipVerified: true, PublicationObserved: true, ParserVerified: true,
	}, nil
}
