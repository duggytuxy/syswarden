//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"time"
)

// Only the production constructor binds these operations to the inspected
// service. The narrow adapter also lets interruption tests replace transport
// without weakening the service, source or removal guards in that constructor.
type legacyFail2banRuntimeRetirementAdapter struct {
	guard   func(context.Context) error
	record  func() (legacyFail2banQuiescenceRecord, error)
	claims  func(context.Context) ([]legacyFail2banNFTClaim, error)
	read    func(context.Context) (legacyFail2banRuntimeSnapshot, error)
	quiesce func(context.Context, func(context.Context) error, legacyRetirementFileOps) error
	observe func(context.Context, string) ([]byte, error)
	runner  func(legacyFail2banNFTTransition) (nftCommandRunner, error)
	actions legacyFail2banConfiguredActions
}

func newLegacyFail2banRuntimeRetirementAdapter(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, inspection *legacyFail2banServiceInspection, liveGuard func(context.Context) error) (legacyFail2banRuntimeRetirementAdapter, error) {
	var adapter legacyFail2banRuntimeRetirementAdapter
	if inspection == nil || liveGuard == nil {
		return adapter, fmt.Errorf("Fail2ban runtime retirement requires inspected service and removal guards")
	}
	executable, err := newExecNFTCommandRunner()
	if err != nil {
		return adapter, err
	}
	pinned, valid := executable.(execNFTCommandRunner)
	if !valid {
		return adapter, fmt.Errorf("Fail2ban runtime retirement requires a pinned nftables executable")
	}
	adapter.guard = func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := liveGuard(ctx); err != nil {
			return err
		}
		return inspection.verify(ctx)
	}
	adapter.record = func() (legacyFail2banQuiescenceRecord, error) {
		return makeLegacyFail2banQuiescenceRecord(host, plan, inspection)
	}
	adapter.claims = func(ctx context.Context) ([]legacyFail2banNFTClaim, error) {
		return inspectLegacyFail2banNFTClaims(ctx, host, plan, inspection)
	}
	adapter.read = inspection.readRuntime
	adapter.quiesce = func(ctx context.Context, guard func(context.Context) error, ops legacyRetirementFileOps) error {
		return quiesceVerifiedLegacyFail2banPlan(ctx, host, plan, inspection, guard, ops)
	}
	adapter.observe = func(ctx context.Context, table string) ([]byte, error) {
		return observeLegacyFail2banNFT(ctx, pinned, table)
	}
	adapter.runner = func(kernel legacyFail2banNFTTransition) (nftCommandRunner, error) {
		return bindLegacyFail2banNFTRunner(kernel, pinned)
	}
	adapter.actions = inspection.actions
	return adapter, nil
}

func (adapter legacyFail2banRuntimeRetirementAdapter) valid() bool {
	return adapter.guard != nil && adapter.record != nil && adapter.claims != nil && adapter.read != nil &&
		adapter.quiesce != nil && adapter.observe != nil && adapter.runner != nil && adapter.actions != nil
}

// Preparation is read-only. The digest covers source ownership, exact service
// invocation, every original kernel object and the complete bounded commands.
func prepareLegacyFail2banRuntimeRetirement(ctx context.Context, adapter legacyFail2banRuntimeRetirementAdapter) (legacyFail2banNFTJournalRecord, string, error) {
	return prepareLegacyFail2banRuntimeRetirementSchema(ctx, adapter, legacyFail2banCompleteNFTJournalSchema)
}

// Reobserving an existing review must retain its original planner semantics.
// A new default cannot broaden an old intent or make its unchanged state fail
// solely because a later planner supports complete dedicated-table retirement.
func prepareLegacyFail2banRuntimeRetirementSchema(ctx context.Context, adapter legacyFail2banRuntimeRetirementAdapter, schema string) (legacyFail2banNFTJournalRecord, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var empty legacyFail2banNFTJournalRecord
	planner := prepareLegacyFail2banNFTTransition
	switch schema {
	case legacyFail2banNFTJournalSchema:
	case legacyFail2banCompleteNFTJournalSchema:
		planner = prepareLegacyFail2banCompleteNFTTransition
	default:
		return empty, "", fmt.Errorf("unsupported historical Fail2ban runtime review schema")
	}
	if !adapter.valid() {
		return empty, "", fmt.Errorf("incomplete Fail2ban runtime retirement adapter")
	}
	if err := adapter.guard(ctx); err != nil {
		return empty, "", err
	}
	quiescence, err := adapter.record()
	if err != nil {
		return empty, "", err
	}
	claims, err := adapter.claims(ctx)
	if err != nil {
		return empty, "", err
	}
	byTable := make(map[string][]legacyFail2banNFTClaim)
	for _, claim := range claims {
		table := "syswarden_f2b"
		if claim.profile == "nftables-allports" {
			table = "f2b-table"
		} else if claim.profile != "syswarden-nft" {
			return empty, "", fmt.Errorf("unsupported Fail2ban runtime action profile")
		}
		byTable[table] = append(byTable[table], claim)
	}
	var tables []string
	for table := range byTable {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var plans []legacyFail2banNFTTransition
	for _, table := range tables {
		content, err := adapter.observe(ctx, table)
		if err != nil {
			return empty, "", err
		}
		plan, err := planner(content, byTable[table])
		if err != nil {
			return empty, "", err
		}
		plans = append(plans, plan)
	}
	record := makeLegacyFail2banNFTJournalRecord(quiescence, plans)
	record.Schema = schema
	content, _, _, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil {
		return empty, "", err
	}
	if err := adapter.guard(ctx); err != nil {
		return empty, "", err
	}
	return record, fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func verifyLegacyFail2banKernelObservations(ctx context.Context, adapter legacyFail2banRuntimeRetirementAdapter, plans []legacyFail2banNFTTransition, allowAfter, requireAfter bool) error {
	for _, plan := range plans {
		content, err := adapter.observe(ctx, plan.table)
		if err != nil {
			return err
		}
		entries, err := legacyFail2banNFTEntries(content, plan.family, plan.table)
		if err != nil {
			return err
		}
		current, err := json.Marshal(entries)
		settled := bytes.Equal(current, plan.after)
		if allowAfter && !requireAfter && legacyFail2banRetiresWholeTable(plan) {
			intermediate, intermediateErr := legacyFail2banTableIntermediate(plan)
			if intermediateErr != nil {
				return intermediateErr
			}
			settled = settled || bytes.Equal(current, intermediate)
		}
		if err != nil || requireAfter && !bytes.Equal(current, plan.after) || !bytes.Equal(current, plan.before) && !(allowAfter && settled) {
			return fmt.Errorf("Fail2ban kernel state changed outside the reviewed retirement plan; inspect a new bounded plan")
		}
	}
	return adapter.guard(ctx)
}

func legacyFail2banTargetsAbsent(live legacyFail2banRuntimeSnapshot, targets map[string]bool) bool {
	for name := range targets {
		if _, present := live.jails[name]; present {
			return false
		}
	}
	return true
}

// Keep configuration files in place until targeted runtime retirement is
// complete. Every kernel write independently verifies target absence, unrelated
// live protection, original service identity and durable reviewed evidence.
// The caller must additionally guard locks, removal barriers and persistence.
func applyLegacyFail2banRuntimeRetirement(ctx context.Context, host nftPersistenceFilesystem, filePlan legacyFail2banRetirementPlan, adapter legacyFail2banRuntimeRetirementAdapter, record legacyFail2banNFTJournalRecord, reviewedDigest string, ops legacyRetirementFileOps) (*legacyFail2banNFTJournal, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if !adapter.valid() || !validLegacyRetirementOperations(func() error { return adapter.guard(ctx) }, ops) {
		return nil, fmt.Errorf("incomplete Fail2ban runtime retirement guards")
	}
	content, quiescenceDigest, plans, err := encodeLegacyFail2banNFTJournalRecord(record)
	if err != nil || !validLegacyRetirementDigest(reviewedDigest) || fmt.Sprintf("%x", sha256.Sum256(content)) != reviewedDigest || record.Quiescence.FilePlan != filePlan.sha256 {
		return nil, fmt.Errorf("Fail2ban runtime retirement requires the exact reviewed digest")
	}
	if err := adapter.guard(ctx); err != nil {
		return nil, err
	}
	currentRecord, err := adapter.record()
	if err != nil || !reflect.DeepEqual(record.Quiescence, currentRecord) {
		return nil, fmt.Errorf("Fail2ban runtime intent differs from the inspected sources or service invocation")
	}
	path := legacyFail2banPlanPath(filePlan.sha256) + "/runtime/" + quiescenceDigest
	_, err = host.snapshot(path + "/kernel/" + reviewedDigest + "/kernel.json")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if errors.Is(err, fs.ErrNotExist) {
		fresh, digest, err := prepareLegacyFail2banRuntimeRetirementSchema(ctx, adapter, record.Schema)
		if err != nil || digest != reviewedDigest || !reflect.DeepEqual(fresh, record) {
			return nil, fmt.Errorf("Fail2ban runtime state changed since review; no target was modified")
		}
	} else if _, err := readLegacyFail2banNFTIntent(ctx, host, record.Quiescence, reviewedDigest, adapter.guard); err != nil {
		return nil, err
	}
	intent, intentErr := host.snapshot(path + "/intent.json")
	quiescenceBytes, _, err := encodeLegacyFail2banQuiescenceRecord(record.Quiescence)
	resuming := intentErr == nil
	if err != nil || intentErr != nil && !errors.Is(intentErr, fs.ErrNotExist) || resuming && (intent.identity.Mode().Perm() != 0600 || !bytes.Equal(intent.content, quiescenceBytes)) {
		return nil, fmt.Errorf("Fail2ban quiescence recovery intent differs or is unavailable")
	}
	targets := make(map[string]bool)
	for _, name := range record.Quiescence.Targets {
		targets[name] = true
	}
	before, err := adapter.read(ctx)
	if err != nil {
		return nil, err
	}
	if err := verifyLegacyFail2banQuiescenceRuntime(adapter.actions, before, targets, resuming, false); err != nil {
		return nil, err
	}
	complete := false
	guard := func(ctx context.Context) error {
		if err := adapter.guard(ctx); err != nil {
			return err
		}
		live, err := adapter.read(ctx)
		if err != nil {
			return err
		}
		if err := verifyLegacyFail2banUnrelatedRuntime(before, live, targets); err != nil {
			return err
		}
		absent := legacyFail2banTargetsAbsent(live, targets)
		if complete && !absent {
			return fmt.Errorf("Fail2ban target reappeared before retirement completion")
		}
		return verifyLegacyFail2banKernelObservations(ctx, adapter, plans, resuming && absent, complete)
	}
	if err := persistLegacyFail2banPlanUsing(host, filePlan, func() error { return guard(ctx) }, ops); err != nil {
		return nil, err
	}
	journal, err := publishLegacyFail2banNFTIntent(ctx, host, record, guard, ops)
	if err != nil {
		return nil, err
	}
	if err := adapter.quiesce(ctx, guard, ops); err != nil {
		return nil, err
	}
	// The socket adapter completing a stop is not sufficient on its own.
	// Independently prove disappearance again before authorizing each write.
	resuming = true
	authorize := func(ctx context.Context, digest string) error {
		if err := journal.verifyTransition(ctx, digest); err != nil {
			return err
		}
		live, err := adapter.read(ctx)
		if err != nil {
			return err
		}
		if !legacyFail2banTargetsAbsent(live, targets) {
			return fmt.Errorf("Fail2ban target remains active before kernel retirement")
		}
		return verifyLegacyFail2banUnrelatedRuntime(before, live, targets)
	}
	for _, plan := range journal.plans {
		runner, err := adapter.runner(plan)
		if err != nil {
			return nil, err
		}
		if err := applyLegacyFail2banNFTTransition(ctx, runner, plan, authorize); err != nil {
			return nil, err
		}
		if err := ops.checkpoint("kernel-transition-confirmed"); err != nil {
			return nil, err
		}
	}
	complete = true
	if err := guard(ctx); err != nil {
		return nil, err
	}
	return journal, nil
}
