//go:build linux

package system

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

// A terminal boundary is reconstructed from the durable approved effects. It
// never captures the already replaced host as the original authority.
type apkTerminalBoundary interface {
	EffectPlanSHA256() string
	AttestResult(context.Context) error
	Close() error
}

type apkTerminalAuthority struct {
	handoff   apkNativeHandoffRecord
	ctx       context.Context
	host      string
	plan      apkExecutionPlan
	digest    string
	receipt   string
	prepared  *verifiedPreparedAPKTransition
	directory *pinnedServiceDirectory
	database  *apkDatabaseLock
	originals *apkOriginalPayloadCustody
	launchers *APKLauncherCustody
	lifecycle apkTerminalBoundary
	records   map[string][]byte
	closed    bool
}

func (authority *apkTerminalAuthority) launcherHost() string { return authority.host }
func (authority *apkTerminalAuthority) launcherProposal() apkLauncherLineageProposal {
	return authority.plan.LauncherLineage
}
func (authority *apkTerminalAuthority) launcherReference(ctx context.Context) (apkLauncherLifecycleReference, error) {
	if err := authority.Revalidate(ctx); err != nil {
		return apkLauncherLifecycleReference{}, err
	}
	return apkLauncherLifecycleReference{Schema: apkFreshLauncherSchema, Kind: "execution", PlanSHA256: authority.digest, ReceiptSHA256: authority.receipt}, nil
}

func (authority *apkTerminalAuthority) Close() error {
	if authority == nil || authority.closed {
		return nil
	}
	authority.closed = true
	var result error
	if authority.launchers != nil {
		result = errors.Join(result, authority.launchers.Close())
	}
	if authority.originals != nil {
		result = errors.Join(result, authority.originals.Close())
	}
	if apkExecutionValuePresent(authority.lifecycle) {
		result = errors.Join(result, authority.lifecycle.Close())
	}
	if authority.directory != nil {
		result = errors.Join(result, closeAPKExecutionDirectory(authority.directory))
	}
	if authority.prepared != nil {
		result = errors.Join(result, authority.prepared.Close())
	}
	if authority.database != nil {
		result = errors.Join(result, authority.database.Close())
	}
	return result
}

func (authority *apkTerminalAuthority) Revalidate(ctx context.Context) error {
	if ctx == nil || authority == nil || authority.closed || authority.database == nil || !authority.database.held || authority.prepared == nil || !apkExecutionValuePresent(authority.lifecycle) {
		return errors.New("APK terminal authority is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := authority.database.Revalidate(ctx); err != nil {
		return err
	}
	if err := inspectAPKTerminalInventory(authority.directory); err != nil {
		return err
	}
	for name, expected := range authority.records {
		current, err := readAPKTransitionBytes(authority.directory, name, int64(len(expected)))
		if err != nil || !bytes.Equal(current, expected) {
			return errors.Join(errors.New("APK terminal evidence changed"), err)
		}
	}
	for _, name := range []string{"unresolved.json", "pre-dispatch-refused.json", "terminal-unresolved.json"} {
		if _, err := authority.directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("APK terminal authority refuses unresolved failure debt")
		}
	}
	prepared := authority.prepared
	if err := verifySecurePackageForInstallation(prepared.candidate.file, prepared.candidate.path, prepared.candidate.artifact, prepared.candidate.uid); err != nil {
		return err
	}
	policy, err := prepared.services.policy(ctx)
	if err != nil || policy != prepared.plan.Policy {
		return errors.Join(errors.New("APK terminal runtime approval changed"), err)
	}
	installed, err := prepared.candidate.attestInstalled(ctx, prepared.candidate.target, prepared.candidate.uid)
	if err != nil || installed.version != prepared.plan.CandidateVersion || installed.cliSHA256 != prepared.plan.CandidateCLISHA256 {
		return errors.Join(errors.New("APK terminal installed candidate differs"), err)
	}
	if err := prepared.capability.verifyInstalledAt(ctx, authority.host, authority.database.proposal.Lock.UID, authority.database.proposal.Lock.GID); err != nil {
		return err
	}
	current, err := captureAPKTransitionHost(ctx, authority.host)
	if err != nil {
		return err
	}
	if err := attestAPKExecutionHost(prepared.snapshot, current, prepared.plan); err != nil {
		return err
	}
	if err := authority.originals.RevalidateRetained(ctx); err != nil {
		return err
	}
	if err := authority.launchers.Revalidate(); err != nil {
		return err
	}
	if err := authority.revalidateGates(ctx); err != nil {
		return err
	}
	if err := authority.lifecycle.AttestResult(ctx); err != nil {
		return err
	}
	if authority.lifecycle.EffectPlanSHA256() != authority.plan.EffectPlanSHA256 {
		return errors.New("APK terminal lifecycle proof differs from approval")
	}
	return errors.Join(ctx.Err(), authority.database.Revalidate(ctx), attestRetainedDirectoryParent(prepared.path, prepared.directory, false), attestRetainedDirectoryParent(filepath.Join(prepared.services.root, "execution-"+authority.digest), authority.directory, false))
}

type apkNativeResultRecord struct {
	Schema          string    `json:"schema"`
	PlanSHA256      string    `json:"plan_sha256"`
	ApprovalSHA256  string    `json:"approval_sha256"`
	HandoffSHA256   string    `json:"handoff_sha256"`
	OutputSHA256    string    `json:"output_sha256"`
	Acknowledgments [4]string `json:"acknowledgments"`
	NativeExited    bool      `json:"native_exited"`
}

func retainAPKNativeResult(directory *pinnedServiceDirectory, handoff *apkTransitionHandoff, output []byte) error {
	if handoff == nil || handoff.phases != 4 {
		return errors.New("APK native result requires four actual ordered acknowledgments")
	}
	record := apkNativeResultRecord{Schema: apkExecutionSchema, PlanSHA256: handoff.record.PlanSHA256, ApprovalSHA256: handoff.record.ApprovalSHA256, HandoffSHA256: handoff.digest, OutputSHA256: apkTransitionDigest(output), NativeExited: true}
	for index, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
		raw, err := readAPKTransitionBytes(directory, "native-hook-"+phase+".json", 16384)
		if err != nil {
			return err
		}
		record.Acknowledgments[index] = apkTransitionDigest(raw)
	}
	raw, err := apkExecutionJSON(record)
	if err != nil {
		return err
	}
	return writeAPKTransitionBytes(directory, "native-result.json", raw)
}

// This publication occurs only after the engine's complete deferred closure
// returned successfully. The record is necessary evidence, never sufficient
// acceptance: the terminal reader independently reattests the installed state.
func retainAPKExecutionClosure(ctx context.Context, rootPath, digest string) (result error) {
	if ctx == nil || !validSHA256(digest) {
		return errors.New("APK closure requires an exact execution identity")
	}
	parent, err := openAPKTransitionRoot(rootPath, false)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(parent)) }()
	if err := syscall.Flock(parent.fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(rootPath, "execution-"+digest))
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	completed, err := readAPKTransitionBytes(directory, "completed.json", 4096)
	if err != nil {
		return err
	}
	var event apkExecutionEvent
	if err := decodeAPKTransitionJSON(completed, &event); err != nil {
		return err
	}
	if event.Schema != apkExecutionSchema || event.State != "completed" || event.PlanSHA256 != digest || !validSHA256(event.ApprovalSHA256) || event.ProductAccepted {
		return errors.New("APK closure lacks exact engine completion")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	event.State = "resources-closed"
	raw, err := apkExecutionJSON(event)
	if err != nil {
		return err
	}
	return writeAPKTransitionBytes(directory, "resources-closed.json", raw)
}

func inspectAPKTransitionTerminal(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, factory func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error)) (_ *apkTerminalAuthority, result error) {
	if ctx == nil || !validSHA256(digest) || factory == nil {
		return nil, errors.New("APK terminal inspection requires exact execution and lifecycle authority")
	}
	authority := &apkTerminalAuthority{ctx: ctx, host: services.hostRoot, digest: digest, records: map[string][]byte{}}
	defer func() {
		if result != nil {
			result = errors.Join(result, authority.Close())
		}
	}()
	path := filepath.Join(services.root, "execution-"+digest)
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, err
	}
	authority.directory = directory
	read := func(name string, limit int64) ([]byte, error) {
		raw, err := readAPKTransitionBytes(directory, name, limit)
		if err == nil {
			authority.records[name] = raw
		}
		return raw, err
	}
	raw, err := read("execution-plan.json", 1<<20)
	if err != nil || apkTransitionDigest(raw) != digest {
		return nil, errors.New("APK terminal execution proposal changed")
	}
	if err := decodeAPKTransitionJSON(raw, &authority.plan); err != nil {
		return nil, err
	}
	plan := authority.plan
	if plan.Schema != apkExecutionSchema || plan.ProductAccepted || plan.DatabaseLock == nil || !validAPKLauncherLineageProposal(plan.LauncherLineage) || plan.OverlaySHA256 != apkTransitionDigest([]byte(apkExecutionOverlay)) {
		return nil, errors.New("APK terminal proposal is unsupported")
	}
	if plan.LauncherLineage.Absent {
		if plan.LauncherTransfer != nil || plan.LauncherTransferSHA256 != "" {
			return nil, errors.New("APK terminal transfer has no original lineage")
		}
	} else {
		if !validAPKLauncherTransferProposal(plan.LauncherTransfer) || plan.LauncherTransfer.Lineage != plan.LauncherLineage {
			return nil, errors.New("APK terminal ownership source is incomplete")
		}
		transfer, err := apkExecutionJSON(plan.LauncherTransfer)
		if err != nil || apkTransitionDigest(transfer) != plan.LauncherTransferSHA256 {
			return nil, errors.New("APK terminal ownership source differs from approval")
		}
	}
	authority.database, err = openAPKDatabaseLock(ctx, services.hostRoot, plan.DatabaseLock, true)
	if err != nil {
		return nil, err
	}
	authority.prepared, err = openRetainedAPKTransition(ctx, plan.PreparationSHA256, keys, attest, services, false)
	if err != nil {
		return nil, err
	}
	prepared := authority.prepared
	inventory, err := apkExecutionJSON(prepared.plan.Inventory)
	if err != nil {
		return nil, err
	}
	originals, err := apkExecutionOriginalLaunchers(prepared.snapshot)
	if err != nil {
		return nil, err
	}
	originalRaw, err := apkExecutionJSON(originals)
	if err != nil {
		return nil, err
	}
	arguments, err := apkExecutionArguments(prepared.candidate.path, prepared.plan.RetainedDependencyNames)
	if err != nil {
		return nil, err
	}
	if plan.CandidateSHA256 != prepared.plan.Artifact.SHA256 || plan.CandidateCLISHA256 != prepared.plan.CandidateCLISHA256 || plan.CandidateCapabilitySHA256 != prepared.plan.CandidateCapabilitySHA256 || plan.CandidateAPKChecksum != prepared.plan.CandidateAPKChecksum || plan.EffectPlanSHA256 != prepared.plan.EffectPlanSHA256 || plan.InventorySHA256 != apkTransitionDigest(inventory) || plan.OriginalLaunchersSHA256 != apkTransitionDigest(originalRaw) || plan.Installer != prepared.plan.Installer || !reflect.DeepEqual(plan.Arguments, arguments) {
		return nil, errors.New("APK terminal execution differs from authenticated preparation")
	}
	raw, err = read("execution-approval.json", 4096)
	if err != nil {
		return nil, err
	}
	var approval apkExecutionApproval
	if err := decodeAPKTransitionJSON(raw, &approval); err != nil {
		return nil, err
	}
	if approval.Schema != apkExecutionSchema || approval.Purpose != "explicit-native-execution" || approval.ExecutionPlanSHA256 != digest || approval.EffectPlanSHA256 != plan.EffectPlanSHA256 {
		return nil, errors.New("APK terminal lacks exact execution approval")
	}
	approvalSHA := apkTransitionDigest(raw)
	var completed apkExecutionEvent
	for _, state := range []string{"armed", "native-started", "observed", "completed", "resources-closed"} {
		raw, err = read(state+".json", 4096)
		if err != nil {
			return nil, err
		}
		var event apkExecutionEvent
		if err := decodeAPKTransitionJSON(raw, &event); err != nil {
			return nil, err
		}
		if event.Schema != apkExecutionSchema || event.State != state || event.PlanSHA256 != digest || event.ApprovalSHA256 != approvalSHA || event.ProductAccepted || event.Failure != "" {
			return nil, errors.New("APK terminal state chain is inconsistent")
		}
		if state == "completed" {
			completed = event
		}
		if state == "resources-closed" {
			event.State = "completed"
			if event != completed {
				return nil, errors.New("APK engine closure differs from completion")
			}
		}
	}
	for _, state := range []string{"armed", "native-started", "observed"} {
		var event apkExecutionEvent
		if decodeAPKTransitionJSON(authority.records[state+".json"], &event) != nil || event.NativeHandoffSHA256 != completed.NativeHandoffSHA256 {
			return nil, errors.New("APK terminal state chain changed handoff identity")
		}
	}
	if !validSHA256(completed.LauncherReceiptSHA256) || !validSHA256(completed.ObservationSHA256) || !validSHA256(completed.NativeHandoffSHA256) {
		return nil, errors.New("APK completion lacks independent result bindings")
	}
	authority.receipt = completed.LauncherReceiptSHA256
	raw, err = read("post-attestation.json", 16384)
	if err != nil || apkTransitionDigest(raw) != completed.ObservationSHA256 {
		return nil, errors.New("APK terminal post-attestation changed")
	}
	var observed apkExecutionObservation
	if decodeAPKTransitionJSON(raw, &observed) != nil || observed.Schema != apkExecutionSchema || observed.CandidateVersion != prepared.plan.CandidateVersion || observed.CandidateCLISHA256 != plan.CandidateCLISHA256 || observed.CandidateCapabilitySHA256 != plan.CandidateCapabilitySHA256 {
		return nil, errors.New("APK terminal candidate observation differs")
	}
	raw, err = read("native-handoff.json", 16384)
	if err != nil || apkTransitionDigest(raw) != completed.NativeHandoffSHA256 {
		return nil, errors.New("APK terminal handoff changed")
	}
	var handoff apkNativeHandoffRecord
	if decodeAPKTransitionJSON(raw, &handoff) != nil || handoff.Schema != apkNativeHandoffSchema || handoff.PlanSHA256 != digest || handoff.ApprovalSHA256 != approvalSHA || handoff.Helper.SHA256 != plan.CandidateCLISHA256 {
		return nil, errors.New("APK terminal handoff is inconsistent")
	}
	authority.handoff = handoff
	helper, err := openAPKExecutionHelper(directory, plan.CandidateCLISHA256)
	if err != nil {
		return nil, err
	}
	info, statErr := helper.Stat()
	closeErr := helper.Close()
	if statErr != nil || closeErr != nil {
		return nil, errors.Join(statErr, closeErr)
	}
	if apkTransitionStat(info.Sys().(*syscall.Stat_t)) != handoff.Helper.Identity {
		return nil, errors.New("APK terminal retained helper identity changed")
	}
	raw, err = read("native-result.json", 16384)
	if err != nil {
		return nil, err
	}
	var nativeResult apkNativeResultRecord
	if decodeAPKTransitionJSON(raw, &nativeResult) != nil || nativeResult.Schema != apkExecutionSchema || nativeResult.PlanSHA256 != digest || nativeResult.ApprovalSHA256 != approvalSHA || nativeResult.HandoffSHA256 != completed.NativeHandoffSHA256 || !nativeResult.NativeExited {
		return nil, errors.New("APK terminal has no bound successful native exit")
	}
	output, err := read("native-output.txt", 1<<20)
	if err != nil || apkTransitionDigest(output) != nativeResult.OutputSHA256 {
		return nil, errors.New("APK terminal diagnostics changed")
	}
	raw, err = read("native-child.json", 16384)
	if err != nil {
		return nil, err
	}
	var child apkNativeProcess
	if decodeAPKTransitionJSON(raw, &child) != nil || child.PID <= 1 {
		return nil, errors.New("APK terminal native child evidence is malformed")
	}
	for index, phase := range []string{"pre-commit", "pre-upgrade", "post-upgrade", "post-commit"} {
		raw, err = read("native-hook-"+phase+".json", 16384)
		if err != nil || apkTransitionDigest(raw) != nativeResult.Acknowledgments[index] {
			return nil, errors.New("APK terminal acknowledgement changed")
		}
		var ack apkNativeHookAcknowledgment
		if decodeAPKTransitionJSON(raw, &ack) != nil || ack.Native != child || ack.Helper.ParentPID != child.PID || ack.Helper.Executable.SHA256 != plan.CandidateCLISHA256 || ack.Request != (apkNativeHookPacket{apkNativeHandoffSchema, digest, completed.NativeHandoffSHA256, phase, "request"}) {
			return nil, errors.New("APK terminal acknowledgement ancestry or approval differs")
		}
		if phase != "post-upgrade" && ack.Helper.Executable != handoff.Helper {
			return nil, errors.New("APK terminal acknowledgement helper changed")
		}
		if phase == "post-commit" {
			database, err := read("native-post-commit-database.txt", maximumAPKInstalledDatabaseSize)
			if err != nil || apkTransitionDigest(database) != ack.DatabaseSHA256 {
				return nil, errors.New("APK terminal committed database evidence changed")
			}
		}
	}
	effectsRaw, err := readAPKTransitionBytes(prepared.directory, "native-effects.json", 1<<20)
	if err != nil {
		return nil, err
	}
	effects, err := verifyAPKTerminalEffectPlan(effectsRaw, prepared)
	if err != nil {
		return nil, err
	}
	if err := bindAPKOriginalRuntime(plan.OriginalPayload, effects.Installed.CLI.SHA256, effects.Installed.Core.SHA256); err != nil {
		return nil, err
	}
	authority.originals, err = reopenAPKOriginalPayloadAt(ctx, services.hostRoot, path, plan.OriginalPayload, plan.OriginalPayloadSHA256)
	if err != nil {
		return nil, err
	}
	authority.launchers, err = inspectAPKLaunchersForRemovalAt(ctx, services.hostRoot, digest, authority.receipt)
	if err != nil {
		return nil, err
	}
	binding := authority.launchers.record.Binding
	if binding != (apkLauncherCustodyBinding{PlanSHA256: digest, ApprovalSHA256: approvalSHA, CandidateSHA256: plan.CandidateSHA256, CandidateCLISHA256: plan.CandidateCLISHA256, CandidateCapabilitySHA256: plan.CandidateCapabilitySHA256, InventorySHA256: plan.InventorySHA256, OriginalSnapshotSHA256: plan.OriginalLaunchersSHA256}) {
		return nil, errors.New("APK terminal launcher receipt differs from execution")
	}
	if err := validateAPKLauncherTransferBinding(plan, authority.launchers.record); err != nil {
		return nil, err
	}
	if plan.LauncherTransfer != nil && (plan.LauncherTransfer.Native.Name != prepared.plan.PackageName || plan.LauncherTransfer.Native.Version != prepared.plan.InstalledVersion) {
		return nil, errors.New("APK terminal launcher transfer differs from original installed package")
	}
	authority.lifecycle, err = factory(ctx, prepared)
	if err != nil {
		return nil, err
	}
	return authority, authority.Revalidate(ctx)
}

// Finalize publishes only launcher custody and retires the exact owned refusal
// gate after independent terminal inspection. It never reruns APK, activates a
// runtime, restores payload or interprets failure as success.
func (authority *apkTerminalAuthority) Finalize(ctx context.Context) error {
	if err := authority.Revalidate(ctx); err != nil {
		return err
	}
	intent, err := authority.retirementBytes()
	if err != nil {
		return err
	}
	if err := writeAPKTerminalExact(authority.directory, "terminal-finalizing.json", intent); err != nil {
		return err
	}
	if err := publishAPKExecutionLauncherLineage(ctx, authority); err != nil {
		return err
	}
	if err := authority.Revalidate(ctx); err != nil {
		return err
	}
	if err := writeAPKTerminalExact(authority.directory, "terminal-retirement-intent.json", intent); err != nil {
		return err
	}
	// The actual APK lock remains held through reference publication, both owned
	// unlinks and directory synchronization. Exact recorded intent permits only
	// these same unlinks. Terminal reconstruction may recognize only the exact
	// already-recorded gate quarantine, after every independent outcome check.
	for _, item := range []struct {
		parent, name string
		expected     apkTransitionHostEntry
		mode         os.FileMode
	}{
		{authority.prepared.services.root, "active-hook", authority.handoff.Active, 0700},
		{filepath.Join(authority.host, apkTransitionGateDirectory), apkTransitionGateName, authority.handoff.Hook, 0755},
	} {
		if err := authority.database.Revalidate(ctx); err != nil {
			return err
		}
		directory, err := openExistingPinnedServiceDirectory(item.parent)
		if err != nil {
			return err
		}
		recordName := "terminal-retire-dispatcher.json"
		if item.name == apkTransitionGateName {
			recordName = "terminal-retire-gate.json"
		}
		err = retireAPKTerminalGate(ctx, directory, authority.directory, item.name, item.expected, item.mode, recordName, unix.Renameat2)
		err = errors.Join(err, closeAPKExecutionDirectory(directory))
		if err != nil {
			return err
		}
	}
	if err := authority.Revalidate(ctx); err != nil {
		return err
	}
	return writeAPKTerminalExact(authority.directory, "terminal-finalized.json", intent)
}

func writeAPKTerminalExact(directory *pinnedServiceDirectory, name string, raw []byte) error {
	err := writeAPKTransitionBytes(directory, name, raw)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, readErr := readAPKTransitionBytes(directory, name, int64(len(raw)))
	if readErr != nil || !bytes.Equal(existing, raw) {
		return errors.Join(errors.New("APK terminal operation conflicts with retained evidence"), readErr)
	}
	return directory.sync()
}

func (authority *apkTerminalAuthority) retirementBytes() ([]byte, error) {
	return apkExecutionJSON(struct {
		Schema                string `json:"schema"`
		PlanSHA256            string `json:"plan_sha256"`
		HandoffSHA256         string `json:"handoff_sha256"`
		LauncherReceiptSHA256 string `json:"launcher_receipt_sha256"`
	}{apkExecutionSchema, authority.digest, apkTransitionDigest(authority.records["native-handoff.json"]), authority.receipt})
}

func (authority *apkTerminalAuthority) revalidateGates(ctx context.Context) error {
	body, err := apkTransitionGateBytes(authority.digest)
	if err != nil {
		return err
	}
	if !bytes.Equal(authority.handoff.Hook.Content, body) || !bytes.Equal(authority.handoff.Active.Content, body) || authority.handoff.Hook.Path != apkTransitionGateName || authority.handoff.Active.Path != "active-hook" {
		return errors.New("APK terminal handoff gate differs from compiled dispatch")
	}
	intended, err := authority.retirementBytes()
	if err != nil {
		return err
	}
	raw, readErr := readAPKTransitionBytes(authority.directory, "terminal-retirement-intent.json", 4096)
	retiring := readErr == nil && bytes.Equal(raw, intended)
	if readErr == nil && !retiring || readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return errors.New("APK terminal gate retirement intent conflicts")
	}
	expectedRecovery := ""
	for _, member := range authority.prepared.plan.Inventory {
		if member.Path == apkTransitionGateDirectory+"/syswarden-recovery" {
			expectedRecovery = member.SHA256
		}
	}
	if expectedRecovery != APKRecoveryHookSHA256() {
		return errors.New("APK terminal selected recovery implementation is unsupported")
	}
	gatePresent := false
	for _, item := range []struct {
		parent, name string
		expected     apkTransitionHostEntry
		mode         os.FileMode
	}{
		{authority.prepared.services.root, "active-hook", authority.handoff.Active, 0700},
		{filepath.Join(authority.host, apkTransitionGateDirectory), apkTransitionGateName, authority.handoff.Hook, 0755},
	} {
		directory, err := openExistingPinnedServiceDirectory(item.parent)
		if err != nil {
			return err
		}
		observed, readErr := readAPKNativeHookMode(directory.root, item.name, item.mode)
		closeErr := closeAPKExecutionDirectory(directory)
		if closeErr != nil {
			return closeErr
		}
		if errors.Is(readErr, os.ErrNotExist) && retiring {
			continue
		}
		if readErr != nil || !reflect.DeepEqual(observed, item.expected) {
			return errors.Join(errors.New("APK terminal gate changed without exact retirement intent"), readErr)
		}
		if item.name == apkTransitionGateName {
			gatePresent = true
		}
	}
	var quarantine *apkTerminalGateQuarantine
	if retiring {
		quarantine, err = authority.inspectGateQuarantine(ctx)
		if err != nil {
			return err
		}
	}
	var proposal *apkNativeHookProposal
	if quarantine != nil {
		if gatePresent {
			return errors.New("APK terminal named gate conflicts with recorded quarantine")
		}
		proposal, err = captureAPKNativeHooksWithTerminalQuarantine(ctx, authority.host, nil, quarantine)
	} else if gatePresent {
		proposal, err = captureAPKNativeHooksWithGate(ctx, authority.host, &authority.handoff.Hook)
	} else {
		proposal, err = captureAPKNativeHooks(ctx, authority.host)
	}
	if err != nil {
		return err
	}
	if authority.plan.NativeHooks == nil {
		return errors.New("APK terminal original hook ancestry is missing")
	}
	for _, original := range authority.plan.NativeHooks.Entries {
		if len(original.Content) != 0 {
			continue
		}
		found := false
		for _, current := range proposal.Entries {
			if current.Path != original.Path {
				continue
			}
			found = true
			if current.Absent != original.Absent || !original.Absent && !apkLauncherSameParent(original.Identity, current.Identity) {
				return errors.New("APK terminal hook ancestry differs from the approved original")
			}
		}
		if !found {
			return errors.New("APK terminal original hook ancestry disappeared")
		}
	}
	return verifyAPKPostHookInventory(proposal, expectedRecovery)
}

func inspectAPKTerminalInventory(directory *pinnedServiceDirectory) error {
	file, err := directory.root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := file.Readdirnames(65)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(names) > 64 {
		return errors.New("APK terminal inventory exceeds its bound")
	}
	allowed := map[string]bool{}
	for _, name := range []string{"candidate-helper", "execution-plan.json", "execution-approval.json", "armed.json", "native-started.json", "observed.json", "completed.json", "resources-closed.json", "native-result.json", "native-output.txt", "post-attestation.json", "observed-host-snapshot.json", "native-child.json", "native-handoff.json", "native-gate-intent.json", "native-handoff.sock", "native-post-commit-database.txt", "native-hook-pre-commit.json", "native-hook-pre-upgrade.json", "native-hook-post-upgrade.json", "native-hook-post-commit.json", "original-runtime", "original-runtime.json", "launcher-prepared.json", "launcher-custody.json", "launcher-target-observation.json", "launcher-target-originals.json", "launcher-original-cli.bin", "launcher-original-tui.bin", "launcher-created-cli.json", "launcher-created-tui.json", "intent-launcher-created-cli.json", "intent-launcher-created-tui.json", "terminal-retirement-intent.json", "terminal-retire-dispatcher.json", "terminal-retire-gate.json", "terminal-finalized.json", "terminal-finalizing.json", "terminal-closed.json"} {
		allowed[name] = true
	}
	for _, name := range names {
		if !allowed[name] {
			return errors.New("APK terminal inventory contains unknown or unresolved evidence")
		}
	}
	return nil
}

// finalizeAPKTransition owns terminal resources and failure publication. Its
// caller cannot overlook a Close error after lineage publication. Recovery may
// inspect the retained debt, but never replay APK or remove this failure record.
func finalizeAPKTransition(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices) error {
	return finalizeAPKTransitionWith(ctx, digest, keys, attest, services, openAPKTerminalLifecycle)
}

// apkTerminalClosureRecord proves successful closure of every effect-bearing
// authority. Its metadata-only publisher retains no native, lifecycle or launcher
// capability. A finalized record without this positive proof is never sufficient.
type apkTerminalClosureRecord struct {
	Schema                string `json:"schema"`
	PlanSHA256            string `json:"plan_sha256"`
	HandoffSHA256         string `json:"handoff_sha256"`
	LauncherReceiptSHA256 string `json:"launcher_receipt_sha256"`
	FinalizedSHA256       string `json:"finalized_sha256"`
}

func finalizeAPKTransitionWith(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, factory func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error)) error {
	return finalizeAPKTransitionUsing(ctx, digest, keys, attest, services, factory, writeAPKTransitionBytes, publishAPKTerminalClosure)
}

func finalizeAPKTransitionUsing(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, factory func(context.Context, *verifiedPreparedAPKTransition) (apkTerminalBoundary, error), failureWriter func(*pinnedServiceDirectory, string, []byte) error, closurePublisher func(context.Context, string, apkTransitionIdentity, []byte, []byte) error) error {
	authority, err := inspectAPKTransitionTerminal(ctx, digest, keys, attest, services, factory)
	if err != nil {
		return err
	}
	path := filepath.Join(services.root, "execution-"+digest)
	// A completed finalization is immutable. A later inspection cannot start a
	// second resource-bearing finalization under its earlier positive proof.
	if _, err := authority.directory.root.Lstat("terminal-closed.json"); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(errors.New("APK terminal resources already have a closure record"), err, authority.Close())
	}
	info, identityErr := authority.directory.file.Stat()
	var identity apkTransitionIdentity
	if identityErr == nil {
		identity, identityErr = apkLauncherIdentity(info)
	}
	intent, intentErr := authority.retirementBytes()
	closure, closureErr := apkExecutionJSON(apkTerminalClosureRecord{apkExecutionSchema, digest, apkTransitionDigest(authority.records["native-handoff.json"]), authority.receipt, apkTransitionDigest(intent)})
	result := errors.Join(identityErr, intentErr, closureErr)
	if result == nil {
		result = authority.Finalize(ctx)
	}
	result = errors.Join(result, authority.Close(), ctx.Err())
	if result == nil {
		result = closurePublisher(ctx, path, identity, intent, closure)
	}
	if result == nil {
		return nil
	}
	// Failed closure never reaches the positive proof publisher. This best-effort
	// diagnostic is additional evidence, not the condition that protects removal.
	directory, openErr := openExistingPinnedServiceDirectory(path)
	if openErr == nil {
		var approved apkExecutionApproval
		raw, readErr := readAPKTransitionBytes(directory, "execution-approval.json", 4096)
		if readErr == nil {
			readErr = decodeAPKTransitionJSON(raw, &approved)
		}
		if readErr == nil && approved.ExecutionPlanSHA256 == digest {
			event, marshalErr := apkExecutionJSON(apkExecutionEvent{Schema: apkExecutionSchema, State: "terminal-unresolved", PlanSHA256: digest, ApprovalSHA256: apkTransitionDigest(raw), Failure: result.Error()})
			if marshalErr == nil {
				marshalErr = failureWriter(directory, "terminal-unresolved.json", event)
			}
			result = errors.Join(result, marshalErr)
		} else {
			result = errors.Join(result, errors.New("APK terminal failure custody could not be reattested"), readErr)
		}
		result = errors.Join(result, closeAPKExecutionDirectory(directory))
	}
	return &APKTransitionExecutionError{Directory: path, Unresolved: true, Cause: errors.Join(result, openErr)}
}

// publishAPKTerminalClosure is a metadata-only writer. All effect-bearing
// resources have already closed successfully. The proof file is synced and
// closed before its final name is published, then the directory is synced.
// Releasing this final read-only directory handle cannot grant new authority.
func publishAPKTerminalClosure(ctx context.Context, path string, expected apkTransitionIdentity, intent, closure []byte) error {
	return publishAPKTerminalClosureUsing(ctx, path, expected, intent, closure, (*pinnedServiceDirectory).sync)
}

func publishAPKTerminalClosureUsing(ctx context.Context, path string, expected apkTransitionIdentity, intent, closure []byte, publishSync func(*pinnedServiceDirectory) error) (result error) {
	if ctx == nil {
		return errors.New("APK terminal closure requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeAPKExecutionDirectory(directory)) }()
	info, err := directory.file.Stat()
	if err != nil {
		return err
	}
	current, err := apkLauncherIdentity(info)
	if err != nil || !apkLauncherSameParent(expected, current) || current.Mode != syscall.S_IFDIR|0700 {
		return errors.New("APK terminal closure directory changed")
	}
	if err := attestRetainedDirectoryParent(path, directory, false); err != nil {
		return err
	}
	for _, name := range []string{"terminal-finalizing.json", "terminal-retirement-intent.json", "terminal-finalized.json"} {
		raw, err := readAPKTransitionBytes(directory, name, 4096)
		if err != nil || !bytes.Equal(raw, intent) {
			return errors.Join(errors.New("APK terminal closure intent differs"), err)
		}
	}
	for _, name := range []string{"unresolved.json", "pre-dispatch-refused.json", "terminal-unresolved.json", "terminal-closed.json"} {
		if _, err := directory.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("APK terminal closure refuses existing completion or failure debt")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// A failed or interrupted metadata write leaves this exclusive pending name,
	// never a positive closure record. There is no automatic overwrite or retry.
	if err := writeAPKTransitionBytes(directory, "terminal-closed.pending", closure); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := attestRetainedDirectoryParent(path, directory, false); err != nil {
		return err
	}
	// Keep the already-synced pending name until the final name is durably
	// published. Failure here leaves pending debt, and a two-link proof is also
	// independently rejected by the removal reader.
	if err := unix.Linkat(directory.fd, "terminal-closed.pending", directory.fd, "terminal-closed.json", 0); err != nil {
		return err
	}
	if err := publishSync(directory); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pending, err := directory.root.Lstat("terminal-closed.pending")
	final, finalErr := directory.root.Lstat("terminal-closed.json")
	if err != nil || finalErr != nil || !os.SameFile(pending, final) || pending.Sys().(*syscall.Stat_t).Nlink != 2 {
		return errors.Join(errors.New("APK terminal closure metadata identity changed"), err, finalErr)
	}
	if err := directory.root.Remove("terminal-closed.pending"); err != nil {
		return err
	}
	// The final name and file data were synced before removing the debt name.
	// A final sync failure can only make pending reappear after a crash, which
	// safely refuses removal. It cannot undo successful effect-resource closure.
	return directory.sync()
}
