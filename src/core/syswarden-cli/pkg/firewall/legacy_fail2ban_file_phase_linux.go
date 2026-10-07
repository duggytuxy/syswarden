//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"
)

type legacyFail2banFileRetirementAdapter struct {
	guard      func(context.Context) error
	read       func(context.Context) (legacyFail2banRuntimeSnapshot, error)
	observe    func(context.Context, string) ([]byte, error)
	invocation func(legacyFail2banQuiescenceRecord) error
	actions    legacyFail2banConfiguredActions
}

func newLegacyFail2banFileRetirementAdapter(host nftPersistenceFilesystem, record legacyFail2banPlanRecord, inspection *legacyFail2banServiceInspection, liveGuard func(context.Context) error) (legacyFail2banFileRetirementAdapter, error) {
	var adapter legacyFail2banFileRetirementAdapter
	if inspection == nil || inspection.process == nil || liveGuard == nil {
		return adapter, fmt.Errorf("Fail2ban file retirement requires inspected service and removal guards")
	}
	executable, err := newExecNFTCommandRunner()
	if err != nil {
		return adapter, err
	}
	pinned, valid := executable.(execNFTCommandRunner)
	if !valid {
		return adapter, fmt.Errorf("Fail2ban file retirement requires a pinned nftables observer")
	}
	adapter.guard = func(ctx context.Context) error {
		if err := liveGuard(ctx); err != nil {
			return err
		}
		return inspection.verifyFileRetirement(ctx, record)
	}
	adapter.read = func(ctx context.Context) (legacyFail2banRuntimeSnapshot, error) {
		return inspection.readRuntimeFileRetirement(ctx, record)
	}
	adapter.observe = func(ctx context.Context, table string) ([]byte, error) {
		return observeLegacyFail2banNFT(ctx, pinned, table)
	}
	adapter.invocation = func(quiescence legacyFail2banQuiescenceRecord) error {
		return verifyLegacyFail2banFilePhaseInvocation(host, record, inspection, quiescence)
	}
	adapter.actions = inspection.actions
	return adapter, nil
}

func verifyLegacyFail2banFilePhaseInvocation(host nftPersistenceFilesystem, record legacyFail2banPlanRecord, inspection *legacyFail2banServiceInspection, quiescence legacyFail2banQuiescenceRecord) error {
	_, digest, err := encodeLegacyFail2banPlan(record, host.expectedUID, host.expectedGID)
	if err != nil || inspection == nil || inspection.process == nil || inspection.parser.digest != record.ParserSHA256 ||
		quiescence.FilePlan != digest || quiescence.Actions != fmt.Sprintf("%x", sha256.Sum256(inspection.actionsSource)) ||
		quiescence.Invocation != inspection.status.values["InvocationID"] || quiescence.PID != inspection.status.peer.Pid || quiescence.StartTicks != inspection.process.start {
		return fmt.Errorf("Fail2ban file retirement requires the original inspected service invocation; preserve evidence for a new recovery plan")
	}
	state, err := inspectLegacyFail2banPlanState(host, record)
	if err != nil {
		return err
	}
	selected, targets := make(map[string]bool), make(map[string]bool)
	for _, path := range record.Targets {
		selected[path] = true
	}
	for _, source := range state.baseline.sources {
		if !selected[source.path] {
			continue
		}
		match, exact := matchLegacyFail2banTemplate(source.path, source.snapshot.content)
		if !exact {
			return fmt.Errorf("Fail2ban file retirement lost complete source ownership evidence")
		}
		if match.kind == "jail" {
			if targets[match.jail] {
				return fmt.Errorf("Fail2ban file retirement has ambiguous jail provenance")
			}
			targets[match.jail] = true
		}
	}
	var names []string
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	actions, err := decodeLegacyFail2banConfiguredActions(inspection.actionsSource)
	if err != nil || !reflect.DeepEqual(actions, inspection.actions) || !reflect.DeepEqual(names, quiescence.Targets) {
		return fmt.Errorf("Fail2ban file retirement targets differ from original configuration")
	}
	original := legacyFail2banRuntimeSnapshot{jails: make(map[string]legacyFail2banRuntimeJail)}
	for name, values := range actions {
		original.jails[name] = legacyFail2banRuntimeJail{actions: values}
	}
	commands, err := planLegacyFail2banQuiescence(original, targets)
	if err != nil || !reflect.DeepEqual(commands, quiescence.Transitions) {
		return fmt.Errorf("Fail2ban file retirement lacks the exact original quiescence plan")
	}
	return nil
}

// File moves cannot use the fresh runtime guard: the original active paths
// deliberately disappear. This phase uses the separately verified original
// inode at its private backup, while keeping all retained process paths exact.
func finishLegacyFail2banFileRetirement(ctx context.Context, host nftPersistenceFilesystem, quiescence legacyFail2banQuiescenceRecord, kernelDigest string, adapter legacyFail2banFileRetirementAdapter, ops legacyRetirementFileOps) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	if adapter.guard == nil || adapter.read == nil || adapter.observe == nil || adapter.invocation == nil || adapter.actions == nil ||
		!validLegacyRetirementOperations(func() error { return adapter.guard(ctx) }, ops) {
		return fmt.Errorf("Fail2ban file retirement lacks complete runtime guards")
	}
	if err := adapter.invocation(quiescence); err != nil {
		return err
	}
	journal, err := readLegacyFail2banNFTIntent(ctx, host, quiescence, kernelDigest, adapter.guard)
	if err != nil {
		return err
	}
	targets := make(map[string]bool)
	for _, name := range quiescence.Targets {
		targets[name] = true
	}
	before, err := adapter.read(ctx)
	if err != nil {
		return err
	}
	if err := verifyLegacyFail2banQuiescenceRuntime(adapter.actions, before, targets, true, true); err != nil {
		return err
	}
	guard := func() error {
		if err := adapter.guard(ctx); err != nil {
			return err
		}
		if err := adapter.invocation(quiescence); err != nil {
			return err
		}
		current, err := adapter.read(ctx)
		if err != nil {
			return err
		}
		if !legacyFail2banTargetsAbsent(current, targets) {
			return fmt.Errorf("Fail2ban target is active before file retirement")
		}
		if err := verifyLegacyFail2banUnrelatedRuntime(before, current, targets); err != nil {
			return err
		}
		for _, plan := range journal.plans {
			if err := journal.verifyTransition(ctx, plan.sha256); err != nil {
				return err
			}
			observation, err := adapter.observe(ctx, plan.table)
			if err != nil {
				return err
			}
			entries, err := legacyFail2banNFTEntries(observation, plan.family, plan.table)
			if err != nil {
				return err
			}
			content, err := json.Marshal(entries)
			if err != nil || !bytes.Equal(content, plan.after) {
				return fmt.Errorf("Fail2ban kernel retirement is incomplete or changed before file retirement")
			}
		}
		return adapter.guard(ctx)
	}
	if err := resumeVerifiedLegacyFail2banFilePlan(host, quiescence.FilePlan, guard, ops); err != nil {
		return err
	}
	return guard()
}
