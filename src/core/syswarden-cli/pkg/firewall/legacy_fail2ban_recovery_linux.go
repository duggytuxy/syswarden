//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syswarden-cli/pkg/system"
)

// LegacyFail2banRecoverySummary deliberately excludes configuration contents,
// expanded actions, addresses, credentials and process identifiers.
type LegacyFail2banRecoverySummary struct {
	Schema                 string   `json:"schema"`
	FilePlanSHA256         string   `json:"file_plan_sha256"`
	PlanSHA256             string   `json:"plan_sha256"`
	Files                  []string `json:"files"`
	Jails                  []string `json:"jails"`
	KernelTransactions     int      `json:"kernel_transactions"`
	FileOnly               bool     `json:"file_only"`
	AlreadyComplete        bool     `json:"already_complete"`
	StopsProductServices   bool     `json:"stops_product_services"`
	PreservesSharedService bool     `json:"preserves_shared_fail2ban_service"`
	BackupDirectory        string   `json:"backup_directory"`
	CurrentRuntimeReviewed bool     `json:"current_runtime_reviewed,omitempty"`
	OriginalRuntimeIntent  string   `json:"original_runtime_intent_sha256,omitempty"`
	ReviewedCurrentBans    string   `json:"reviewed_current_bans_sha256,omitempty"`
}

type legacyFail2banRecoverySession struct {
	host       nftPersistenceFilesystem
	plan       legacyFail2banRetirementPlan
	inspection *legacyFail2banServiceInspection
	kernel     legacyFail2banNFTJournalRecord
	digest     string
	retired    bool
	fileOnly   bool
	completed  bool
	resume     *legacyUnusedResumeIntent
}

func (session *legacyFail2banRecoverySession) close() {
	if session.inspection != nil {
		_ = session.inspection.Close()
	}
	if session.host.root != nil {
		_ = session.host.root.Close()
	}
}

func legacyFail2banRecoverySummary(session *legacyFail2banRecoverySession) LegacyFail2banRecoverySummary {
	summary := LegacyFail2banRecoverySummary{
		Schema: "syswarden-legacy-fail2ban-recovery-v1", FilePlanSHA256: session.plan.sha256, PlanSHA256: session.digest,
		Files: append([]string(nil), session.plan.binding.Targets...), Jails: append([]string(nil), session.kernel.Quiescence.Targets...),
		KernelTransactions: len(session.kernel.Plans), FileOnly: session.fileOnly, AlreadyComplete: session.completed, StopsProductServices: !session.completed, PreservesSharedService: true,
		BackupDirectory: legacyFail2banPlanPath(session.plan.sha256),
	}
	if session.resume != nil {
		summary.CurrentRuntimeReviewed = true
		summary.OriginalRuntimeIntent = session.resume.record.OriginalIntent
		summary.ReviewedCurrentBans = session.resume.record.CurrentBans
	}
	return summary
}

// Only explicit operator recovery reaches these adapters. Ordinary package
// hooks remain read-only when historical ownership is unresolved.
func InspectLegacyFail2banRecovery(ctx context.Context) (LegacyFail2banRecoverySummary, error) {
	session, err := openLegacyFail2banRecovery(ctx, "", "")
	if err != nil {
		return LegacyFail2banRecoverySummary{}, err
	}
	defer session.close()
	return legacyFail2banRecoverySummary(session), nil
}

func ApplyLegacyFail2banRecovery(ctx context.Context, fileDigest, kernelDigest string, prepare func() error) (LegacyFail2banRecoverySummary, error) {
	return applyLegacyFail2banRecoveryMode(ctx, fileDigest, kernelDigest, prepare, false)
}

// This separate operation requires a new review of current protection. It
// cannot silently redefine the original plan or resume an active-jail removal.
func InspectUnusedLegacyFail2banResume(ctx context.Context, fileDigest string) (LegacyFail2banRecoverySummary, error) {
	if !validLegacyRetirementDigest(fileDigest) {
		return LegacyFail2banRecoverySummary{}, fmt.Errorf("unused Fail2ban resumption requires the original exact file-plan digest")
	}
	session, err := openLegacyFail2banRecoveryMode(ctx, fileDigest, "", true)
	if err != nil {
		return LegacyFail2banRecoverySummary{}, err
	}
	defer session.close()
	return legacyFail2banRecoverySummary(session), nil
}

func ApplyUnusedLegacyFail2banResume(ctx context.Context, fileDigest, reviewed string, prepare func() error) (LegacyFail2banRecoverySummary, error) {
	return applyLegacyFail2banRecoveryMode(ctx, fileDigest, reviewed, prepare, true)
}

func applyLegacyFail2banRecoveryMode(ctx context.Context, fileDigest, kernelDigest string, prepare func() error, resume bool) (LegacyFail2banRecoverySummary, error) {
	var empty LegacyFail2banRecoverySummary
	if !validLegacyRetirementDigest(fileDigest) || !validLegacyRetirementDigest(kernelDigest) || prepare == nil {
		return empty, fmt.Errorf("historical Fail2ban recovery requires both exact reviewed digests and product preparation")
	}
	session, err := openLegacyFail2banRecoveryMode(ctx, fileDigest, kernelDigest, resume)
	if err != nil {
		return empty, err
	}
	defer session.close()
	if session.plan.sha256 != fileDigest || session.digest != kernelDigest {
		return empty, fmt.Errorf("historical Fail2ban state changed since review; no recovery mutation was authorized")
	}
	// An exact completed file-only plan is a read-only acknowledgement.
	// Normal later ban activity must not trigger another product preparation
	// or redefine the original runtime baseline. Partial plans remain strict.
	if session.fileOnly && session.completed {
		return legacyFail2banRecoverySummary(session), nil
	}
	if err := prepare(); err != nil {
		return empty, err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return empty, err
	}
	defer releaseNFTReloadGuard(lock)
	if err := attestLegacyFail2banRecoveryProduct(); err != nil {
		return empty, err
	}
	var unusedDefinitionPlan *legacyFail2banPlanRecord
	if session.fileOnly {
		unusedDefinitionPlan = &session.plan.binding
	}
	persistence, err := bindLegacyFail2banRecoveryPersistenceUsing(ctx, session.host, unusedDefinitionPlan, &session.kernel)
	if err != nil {
		return empty, err
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := attestLegacyFail2banRecoveryProduct(); err != nil {
			return err
		}
		return persistence(ctx)
	}
	ops := defaultLegacyRetirementFileOps()
	if session.fileOnly {
		adapter, err := newLegacyFail2banUnusedAdapter(session.host, session.plan.binding, session.inspection, guard)
		if err != nil {
			return empty, err
		}
		if session.resume != nil {
			adapter.bindRuntime = legacyUnusedResumeBinder(*session.resume)
		}
		read := adapter.read
		adapter.read = func(ctx context.Context, published bool) (legacyFail2banRuntimeSnapshot, error) {
			live, err := read(ctx, published)
			if err != nil {
				return legacyFail2banRuntimeSnapshot{}, err
			}
			if session.resume != nil {
				if err := verifyLegacyUnusedResumeRuntime(ctx, fileDigest, *session.resume, live); err != nil {
					return legacyFail2banRuntimeSnapshot{}, err
				}
				return live, nil
			}
			content, err := encodeUnusedLegacyFail2banRuntime(fileDigest, live)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256(content)) != kernelDigest {
				return legacyFail2banRuntimeSnapshot{}, fmt.Errorf("unused Fail2ban runtime protection changed after review")
			}
			return live, nil
		}
		if err := retireUnusedLegacyFail2banFiles(ctx, session.host, session.plan, fileDigest, adapter, ops); err != nil {
			return empty, err
		}
		return legacyFail2banRecoverySummary(session), nil
	}
	if !session.retired {
		adapter, err := newLegacyFail2banRuntimeRetirementAdapter(session.host, session.plan, session.inspection, guard)
		if err != nil {
			return empty, err
		}
		if _, err := applyLegacyFail2banRuntimeRetirement(ctx, session.host, session.plan, adapter, session.kernel, kernelDigest, ops); err != nil {
			return empty, err
		}
	}
	adapter, err := newLegacyFail2banFileRetirementAdapter(session.host, session.plan.binding, session.inspection, guard)
	if err != nil {
		return empty, err
	}
	if err := finishLegacyFail2banFileRetirement(ctx, session.host, session.kernel.Quiescence, kernelDigest, adapter, ops); err != nil {
		return empty, err
	}
	state, err := inspectLegacyFail2banPlanState(session.host, session.plan.binding)
	if err != nil || len(state.retired) != len(session.plan.binding.Targets) {
		return empty, fmt.Errorf("historical Fail2ban recovery did not retire the complete reviewed inventory")
	}
	return legacyFail2banRecoverySummary(session), nil
}

func attestLegacyFail2banRecoveryProduct() error {
	if err := system.RequireRemovalTombstone(); err != nil {
		return err
	}
	if err := system.ReattestFirewallStatePreparedForRemoval(); err != nil {
		return err
	}
	return system.PreflightHistoricalHostRemoval()
}

func openLegacyFail2banRecovery(ctx context.Context, fileDigest, kernelDigest string) (*legacyFail2banRecoverySession, error) {
	return openLegacyFail2banRecoveryMode(ctx, fileDigest, kernelDigest, false)
}

func openLegacyFail2banRecoveryMode(ctx context.Context, fileDigest, kernelDigest string, resume bool) (*legacyFail2banRecoverySession, error) {
	return inspectLegacyFail2banRecoverySession(ctx, fileDigest, kernelDigest, resume, false)
}

// persistenceReview only exposes read-only inspection to the separate shared
// source recovery coordinator. It does not authorize runtime retirement.
func inspectLegacyFail2banRecoverySession(ctx context.Context, fileDigest, kernelDigest string, resume, persistenceReview bool) (*legacyFail2banRecoverySession, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("historical Fail2ban recovery requires root")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	session := &legacyFail2banRecoverySession{host: nftPersistenceFilesystem{root: root}}
	success := false
	defer func() {
		if !success {
			session.close()
		}
	}()
	parser, err := captureLegacyFail2banParser(session.host)
	if err != nil {
		return nil, err
	}
	probe := legacyFail2banConfigurationProbeUsingParser(session.host, parser)
	var recovery *legacyFail2banPlanRecord
	if fileDigest != "" {
		record, err := readLegacyFail2banPlan(session.host, fileDigest)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			state, err := inspectLegacyFail2banPlanState(session.host, record)
			if err != nil {
				return nil, err
			}
			session.plan = legacyFail2banRetirementPlan{sha256: fileDigest, binding: record, baseline: state.baseline, records: legacyFail2banPlanFileRecords(record, fileDigest)}
			session.retired = len(state.retired) > 0
			recovery = &record
		}
	}
	if recovery == nil {
		if resume {
			return nil, fmt.Errorf("unused Fail2ban resumption requires an existing original durable file plan")
		}
		inventory, err := inspectLegacyFail2banInventory(session.host)
		if err != nil {
			return nil, err
		}
		var paths []string
		for _, source := range inventory.sources {
			if _, matches := matchLegacyFail2banTemplate(source.path, source.snapshot.content); matches {
				paths = append(paths, source.path)
			}
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("no complete historical SysWarden Fail2ban templates were found; preserve custom or ambiguous files")
		}
		session.plan, err = prepareLegacyFail2banRetirement(session.host, paths, probe)
		if err != nil {
			return nil, err
		}
		if fileDigest != "" && session.plan.sha256 != fileDigest {
			return nil, fmt.Errorf("historical Fail2ban file inventory changed since review")
		}
	}
	if parser.digest != session.plan.binding.ParserSHA256 {
		return nil, fmt.Errorf("historical Fail2ban parser changed since review")
	}
	if err := revalidateLegacyFail2banPlanViews(session.host, session.plan.binding, probe); err != nil {
		return nil, err
	}
	view, err := probe(cloneLegacyFail2banInventory(session.plan.baseline), nil)
	if err != nil {
		return nil, err
	}
	session.inspection, err = inspectLegacyFail2banServiceForRecovery(ctx, session.host, parser, session.plan.baseline, view, recovery)
	if err != nil {
		return nil, err
	}
	fileOnly, err := legacyFail2banRecoveryUsesOnlyDefinitions(session.plan)
	if err != nil {
		return nil, err
	}
	if resume && !fileOnly {
		return nil, fmt.Errorf("current-runtime review cannot resume active-jail retirement; preserve its runtime journals")
	}
	if fileOnly {
		if persistenceReview {
			return nil, fmt.Errorf("unused definitions need no active Fail2ban persistence retirement")
		}
		if _, err := bindLegacyFail2banRecoveryPersistence(ctx, session.host, &session.plan.binding); err != nil {
			return nil, err
		}
		completedDigest, completed, err := inspectCompletedUnusedLegacyFail2banRecovery(session.host, session.plan)
		if err != nil {
			return nil, err
		}
		if completed {
			if resume {
				intent, complete, err := inspectLegacyUnusedResume(session.host, session.plan, nil, kernelDigest)
				if err != nil {
					return nil, fmt.Errorf("completed unused Fail2ban resumption lacks the exact prior review: %w", err)
				}
				if !complete {
					return nil, fmt.Errorf("unused Fail2ban resumption is no longer complete")
				}
				session.resume = &intent
				completedDigest = intent.digest
			}
			if completedDigest != kernelDigest {
				return nil, fmt.Errorf("completed unused Fail2ban recovery differs from the exact reviewed intent")
			}
			session.digest, session.fileOnly, session.completed = completedDigest, true, true
			success = true
			return session, nil
		}
		var live legacyFail2banRuntimeSnapshot
		if recovery != nil {
			live, err = session.inspection.readRuntimeFileRetirement(ctx, session.plan.binding)
		} else {
			live, err = session.inspection.readRuntime(ctx)
		}
		if err != nil {
			return nil, err
		}
		if err := verifyLegacyFail2banConfiguredRuntime(session.inspection.actions, live); err != nil {
			return nil, err
		}
		if resume {
			intent, complete, inspectErr := inspectLegacyUnusedResume(session.host, session.plan, &live, kernelDigest)
			if inspectErr != nil {
				return nil, fmt.Errorf("inspect explicit unused Fail2ban resumption: %w", inspectErr)
			}
			if complete {
				return nil, fmt.Errorf("unused Fail2ban retirement completed during review; retry its exact stored intent")
			}
			session.resume, session.digest = &intent, intent.digest
		} else {
			session.digest, err = inspectUnusedLegacyFail2banRecoveryIntent(session.host, session.plan, live)
		}
		if err != nil {
			return nil, err
		}
		if kernelDigest != "" && session.digest != kernelDigest {
			return nil, fmt.Errorf("unused Fail2ban runtime protection changed since review")
		}
		session.fileOnly = true
		success = true
		return session, nil
	}
	if recovery != nil {
		record, found, err := findLegacyFail2banRecoveryKernel(session.host, fileDigest, kernelDigest)
		if err != nil {
			return nil, err
		}
		if found {
			session.kernel = record
			session.digest = kernelDigest
		}
		if session.retired && !found {
			return nil, fmt.Errorf("retired Fail2ban files lack the exact reviewed kernel intent")
		}
	}
	if session.digest == "" {
		adapter, err := newLegacyFail2banRuntimeRetirementAdapter(session.host, session.plan, session.inspection, func(ctx context.Context) error { return ctx.Err() })
		if err != nil {
			return nil, err
		}
		session.kernel, session.digest, err = prepareLegacyFail2banRuntimeRetirement(ctx, adapter)
		if err != nil {
			return nil, err
		}
	}
	if kernelDigest != "" && session.digest != kernelDigest {
		return nil, fmt.Errorf("historical Fail2ban runtime changed since review")
	}
	if !persistenceReview {
		// The independently attested targets must exist before classifying
		// retained shared persistence. Names alone never establish ownership.
		if _, err := bindLegacyFail2banRecoveryPersistenceUsing(ctx, session.host, nil, &session.kernel); err != nil {
			return nil, err
		}
	}
	success = true
	return session, nil
}

// Lookup is bounded and content-addressed. Directory names never establish
// authority; the canonical intent and its original service binding do.
func findLegacyFail2banRecoveryKernel(host nftPersistenceFilesystem, fileDigest, kernelDigest string) (legacyFail2banNFTJournalRecord, bool, error) {
	var empty legacyFail2banNFTJournalRecord
	directory, err := host.openDirectory(legacyFail2banPlanPath(fileDigest) + "/runtime")
	if errors.Is(err, fs.ErrNotExist) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	defer func() { _ = directory.Close() }()
	file, err := directory.Open(".")
	if err != nil {
		return empty, false, err
	}
	names, readErr := file.Readdirnames(65)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > 64 {
		return empty, false, fmt.Errorf("historical Fail2ban runtime recovery inventory is unavailable or unbounded")
	}
	sort.Strings(names)
	found := false
	for _, name := range names {
		if !validLegacyRetirementDigest(name) {
			return empty, false, fmt.Errorf("unexpected historical Fail2ban runtime recovery entry")
		}
		snapshot, err := host.snapshot(legacyFail2banPlanPath(fileDigest) + "/runtime/" + name + "/kernel/" + kernelDigest + "/kernel.json")
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return empty, false, err
		}
		var record legacyFail2banNFTJournalRecord
		if json.Unmarshal(snapshot.content, &record) != nil {
			return empty, false, fmt.Errorf("invalid historical Fail2ban runtime recovery intent")
		}
		canonical, quiescence, _, err := encodeLegacyFail2banNFTJournalRecord(record)
		if err != nil || snapshot.identity.Mode().Perm() != 0600 || record.Quiescence.FilePlan != fileDigest || quiescence != name || !bytes.Equal(canonical, snapshot.content) || fmt.Sprintf("%x", sha256.Sum256(canonical)) != kernelDigest || found {
			return empty, false, fmt.Errorf("historical Fail2ban runtime intent does not match the exact reviewed digests")
		}
		empty, found = record, true
	}
	return empty, found, nil
}

func bindLegacyFail2banRecoveryPersistence(ctx context.Context, host nftPersistenceFilesystem, unused *legacyFail2banPlanRecord) (func(context.Context) error, error) {
	return bindLegacyFail2banRecoveryPersistenceUsing(ctx, host, unused, nil)
}

func bindLegacyFail2banRecoveryPersistenceUsing(ctx context.Context, host nftPersistenceFilesystem, unused *legacyFail2banPlanRecord, kernel *legacyFail2banNFTJournalRecord) (func(context.Context) error, error) {
	verifyUnused := func() error {
		if unused == nil {
			return nil
		}
		_, err := inspectUnusedLegacyFail2banPlan(host, *unused)
		return err
	}
	if err := verifyUnused(); err != nil {
		return nil, err
	}
	loader, err := inspectNFTPersistenceLoader(ctx, host)
	if err != nil {
		return nil, err
	}
	entries := append([]string(nil), loader.status.entries...)
	absent := []string{}
	for _, path := range knownNFTPersistenceEntryPoints {
		_, err := host.snapshot(path)
		if errors.Is(err, fs.ErrNotExist) {
			absent = append(absent, path)
			continue
		}
		if err != nil {
			return nil, err
		}
		present := false
		for _, entry := range entries {
			present = present || entry == path
		}
		if !present {
			entries = append(entries, path)
		}
	}
	graph, err := inspectNFTPersistenceGraph(entries, host.reader())
	if err != nil {
		return nil, err
	}
	for _, source := range graph.sources {
		content, err := host.read(source.path)
		if err != nil {
			return nil, err
		}
		if sha256.Sum256(content) != source.sha256 {
			return nil, fmt.Errorf("firewall persistence changed during Fail2ban recovery inspection")
		}
		if unused != nil {
			// No runtime objects are retired by this route. Removing unused
			// definitions must not require editing administrator persistence.
			continue
		}
		if kernel != nil {
			edit, err := planLegacyFail2banPersistence(content, *kernel)
			if err != nil {
				return nil, err
			}
			if len(edit.removed) != 0 {
				return nil, fmt.Errorf("persistent historical Fail2ban targets require explicit shared-source recovery with 'syswarden recover-removal --retire-legacy-fail2ban-persistence' before runtime retirement: %q", source.path)
			}
			continue
		}
		tokens, err := scanNFTPersistence(content)
		if err != nil {
			return nil, err
		}
		for _, token := range tokens {
			if token.kind != 'w' && token.kind != 'q' {
				continue
			}
			value := strings.ToLower(string(content[token.start:token.end]))
			if strings.Contains(value, "syswarden_f2b") || strings.Contains(value, "f2b-table") || strings.Contains(value, "fail2ban") {
				return nil, fmt.Errorf("persistent Fail2ban references require separate verified graph retirement before runtime recovery: %q", source.path)
			}
		}
	}
	return func(ctx context.Context) error {
		if err := loader.verify(ctx); err != nil {
			return err
		}
		if err := verifyNFTPersistenceGraph(graph, host.reader()); err != nil {
			return err
		}
		for _, path := range absent {
			if _, err := host.snapshot(path); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("a previously absent firewall persistence entry appeared")
			}
		}
		return verifyUnused()
	}, nil
}

// A definition-only recovery cannot quiesce a jail or mutate kernel rules.
// Exact templates must also have no enabled or disabled configuration consumer.
func legacyFail2banRecoveryUsesOnlyDefinitions(plan legacyFail2banRetirementPlan) (bool, error) {
	selected := make(map[string]bool, len(plan.binding.Targets))
	for _, path := range plan.binding.Targets {
		selected[path] = true
	}
	if len(selected) == 0 {
		return false, fmt.Errorf("Fail2ban recovery has no reviewed source inventory")
	}
	jail := false
	for _, source := range plan.baseline.sources {
		if !selected[source.path] {
			continue
		}
		match, exact := matchLegacyFail2banTemplate(source.path, source.snapshot.content)
		if !exact {
			return false, fmt.Errorf("Fail2ban recovery source is not a complete historical template")
		}
		if match.kind != "action" && match.kind != "filter" && match.kind != "jail" {
			return false, fmt.Errorf("Fail2ban recovery source has an unsupported template kind")
		}
		jail = jail || match.kind == "jail"
		delete(selected, source.path)
	}
	if len(selected) != 0 {
		return false, fmt.Errorf("Fail2ban recovery source evidence is incomplete")
	}
	return !jail, nil
}

// Bind the reviewed digest to the file inventory and all existing bans.
// Recovery cannot adopt a changed runtime as a new baseline after a file move.
func inspectUnusedLegacyFail2banRecoveryIntent(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan, live legacyFail2banRuntimeSnapshot) (string, error) {
	retired, err := inspectUnusedLegacyFail2banPlan(host, plan.binding)
	if err != nil {
		return "", err
	}
	content, err := encodeUnusedLegacyFail2banRuntime(plan.sha256, live)
	if err != nil {
		return "", err
	}
	original, err := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/unused-runtime.json")
	if errors.Is(err, fs.ErrNotExist) {
		if retired != "" {
			return "", fmt.Errorf("retired unused Fail2ban definitions lack their original runtime evidence")
		}
	} else if err != nil || original.identity.Mode().Perm() != 0600 {
		return "", fmt.Errorf("unused Fail2ban runtime protection differs from its original evidence")
	} else if !bytes.Equal(original.content, content) {
		if _, _, err := readOriginalUnusedLegacyRuntime(host, plan.sha256); err != nil {
			return "", err
		}
		return "", fmt.Errorf("unused Fail2ban runtime protection changed since the original review; preserve its evidence and inspect the remaining file-only recovery with 'sudo syswarden recover-removal --resume-unused-fail2ban --file-plan-sha256 %s'", plan.sha256)
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

// Completion never authorizes another file or runtime mutation. Every selected
// active path must be absent and every original inode, byte and private file
// intent must match the durable plan. The original runtime record is bound to
// the operator's reviewed digest, rather than silently replaced with live bans.
func inspectCompletedUnusedLegacyFail2banRecovery(host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan) (string, bool, error) {
	if _, err := inspectUnusedLegacyFail2banPlan(host, plan.binding); err != nil {
		return "", false, err
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil {
		return "", false, err
	}
	if len(state.retired) != len(plan.binding.Targets) {
		return "", false, nil
	}
	original, err := host.snapshot(legacyFail2banPlanPath(plan.sha256) + "/unused-runtime.json")
	if err != nil || original.identity.Mode().Perm() != 0600 || len(original.content) > 512 {
		return "", false, fmt.Errorf("completed unused Fail2ban recovery lacks its original private runtime intent")
	}
	var record legacyFail2banUnusedRuntimeRecord
	if json.Unmarshal(original.content, &record) != nil || record.Schema != "syswarden-unused-fail2ban-runtime-v1" || record.FilePlan != plan.sha256 || !validLegacyRetirementDigest(record.Bans) {
		return "", false, fmt.Errorf("completed unused Fail2ban recovery has an invalid runtime intent")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, original.content) {
		return "", false, fmt.Errorf("completed unused Fail2ban runtime intent is not canonical")
	}
	return fmt.Sprintf("%x", sha256.Sum256(canonical)), true, nil
}
