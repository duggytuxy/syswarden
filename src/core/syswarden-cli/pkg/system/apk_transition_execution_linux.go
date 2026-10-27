//go:build linux

package system

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const apkExecutionSchema = "syswarden-apk-execution/v1"
const apkExecutionOverlay = "usr/local/bin/syswarden\nusr/local/bin/syswarden-tui\n"
const apkExecutionHelper = "candidate-helper"
const maximumAPKExecutionHelperBytes = 64 << 20

// This interface is deliberately not constructed by production callers yet.
// Runtime TOML approval and preparation review are insufficient to implement it:
// the implementation must bind actual hook authority and full lifecycle effects.
type apkExecutionBoundary interface {
	EffectPlanSHA256() string
	Revalidate(context.Context) error
	PrepareLaunchers(context.Context, string, apkLauncherCustodyBinding, []apkTransitionHostEntry) (apkExecutionLaunchers, error)
	AttestResult(context.Context) error
	Close() error
}

// This check rejects typed nil capabilities; it grants no execution authority.
func apkExecutionValuePresent(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

type apkExecutionLaunchers interface {
	AttestUpgradeTargets() error
	Revalidate() error
	RefuseProductTargetDependencies() error
	Commit() (string, error)
	Close() error
}

type apkExecutionPlan struct {
	LauncherTargets           *apkLauncherTargetProposal `json:"launcher_targets,omitempty"`
	LauncherTargetsSHA256     string                     `json:"launcher_targets_sha256,omitempty"`
	Schema                    string                     `json:"schema"`
	PreparationSHA256         string                     `json:"preparation_sha256"`
	CandidateAPKChecksum      string                     `json:"candidate_apk_checksum"`
	CandidateSHA256           string                     `json:"candidate_sha256"`
	CandidateCLISHA256        string                     `json:"candidate_cli_sha256"`
	CandidateCapabilitySHA256 string                     `json:"candidate_capability_sha256"`
	InventorySHA256           string                     `json:"inventory_sha256"`
	EffectPlanSHA256          string                     `json:"effect_plan_sha256"`
	OriginalLaunchersSHA256   string                     `json:"original_launchers_sha256"`
	OverlaySHA256             string                     `json:"overlay_sha256"`
	Installer                 string                     `json:"installer"`
	Arguments                 []string                   `json:"arguments"`
	ProductAccepted           bool                       `json:"product_accepted"`
}

// Review identifies an immutable execution proposal. It grants no authority and
// is distinct from both preparation review and a successful native transaction.
type APKTransitionExecutionReview struct {
	PlanSHA256        string
	PreparationSHA256 string
	Directory         string
}

type apkExecutionApproval struct {
	Schema              string `json:"schema"`
	Purpose             string `json:"purpose"`
	ExecutionPlanSHA256 string `json:"execution_plan_sha256"`
	EffectPlanSHA256    string `json:"effect_plan_sha256"`
}

type apkExecutionEvent struct {
	Schema                string `json:"schema"`
	State                 string `json:"state"`
	PlanSHA256            string `json:"plan_sha256"`
	ApprovalSHA256        string `json:"approval_sha256"`
	LauncherReceiptSHA256 string `json:"launcher_receipt_sha256,omitempty"`
	ObservationSHA256     string `json:"observation_sha256,omitempty"`
	Failure               string `json:"failure,omitempty"`
	ProductAccepted       bool   `json:"product_accepted"`
}

type apkExecutionObservation struct {
	Schema                    string `json:"schema"`
	CandidateVersion          string `json:"candidate_version"`
	CandidateCLISHA256        string `json:"candidate_cli_sha256"`
	CandidateCapabilitySHA256 string `json:"candidate_capability_sha256"`
	HostSnapshotSHA256        string `json:"host_snapshot_sha256"`
}

// Unresolved includes every error after the durable native-started intent, even
// if process creation failed. Native state must be inspected, never replayed or
// automatically rolled back. Directory and original preparation are retained.
type APKTransitionExecutionError struct {
	Directory  string
	Unresolved bool
	Cause      error
}

func (failure *APKTransitionExecutionError) Error() string {
	return fmt.Sprintf("APK execution refused or incomplete; custody retained at %s (native outcome unresolved: %t); no automatic replay or rollback: %v", failure.Directory, failure.Unresolved, failure.Cause)
}
func (failure *APKTransitionExecutionError) Unwrap() error { return failure.Cause }

type apkExecutionServices struct {
	run   func(context.Context, *verifiedPreparedAPKTransition, *os.File, []string, io.Writer) error
	write func(*pinnedServiceDirectory, string, []byte) error
}

func apkExecutionJSON(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	return append(data, '\n'), err
}

func apkExecutionOriginalLaunchers(snapshot []apkTransitionHostEntry) ([]apkTransitionHostEntry, error) {
	var selected []apkTransitionHostEntry
	for _, entry := range snapshot {
		if entry.Path == "." || entry.Path == "usr" || entry.Path == "usr/local" || entry.Path == "usr/local/bin" || entry.Path == "usr/local/bin/syswarden" || entry.Path == "usr/local/bin/syswarden-tui" {
			selected = append(selected, entry)
		}
	}
	if len(selected) != 6 {
		return nil, errors.New("APK execution requires the complete original launcher and parent snapshot")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	return selected, nil
}

func buildAPKExecutionPlan(ctx context.Context, prepared *verifiedPreparedAPKTransition, boundary apkExecutionBoundary) (apkExecutionPlan, []apkTransitionHostEntry, error) {
	var empty apkExecutionPlan
	if !apkExecutionValuePresent(boundary) || prepared == nil || prepared.activation == nil || !validSHA256(boundary.EffectPlanSHA256()) || boundary.EffectPlanSHA256() != prepared.plan.EffectPlanSHA256 {
		return empty, nil, errors.New("APK execution lacks qualified candidate-specific hook and lifecycle authority")
	}
	if err := prepared.Revalidate(ctx); err != nil {
		return empty, nil, err
	}
	if err := boundary.Revalidate(ctx); err != nil {
		return empty, nil, err
	}
	capability, err := attestNativeActivationCandidate(ctx, prepared.candidate.target, prepared.candidate.file)
	if err != nil || capability.SHA256() != prepared.plan.CandidateCapabilitySHA256 {
		return empty, nil, errors.Join(errors.New("APK execution candidate capability changed"), err)
	}
	launchers, err := apkExecutionOriginalLaunchers(prepared.snapshot)
	if err != nil {
		return empty, nil, err
	}
	original, err := apkExecutionJSON(launchers)
	if err != nil {
		return empty, nil, err
	}
	inventory, err := apkExecutionJSON(prepared.plan.Inventory)
	if err != nil {
		return empty, nil, err
	}
	args, err := apkExecutionArguments(prepared.candidate.path, prepared.plan.RetainedDependencyNames)
	if err != nil {
		return empty, nil, err
	}
	targets, err := captureAPKLauncherTargetProposalAt(ctx, prepared.services.hostRoot, launchers, prepared.plan.Inventory)
	if err != nil {
		return empty, nil, err
	}
	targetsDigest := ""
	if targets != nil {
		targetBytes, err := apkExecutionJSON(targets)
		if err != nil {
			return empty, nil, err
		}
		targetsDigest = apkTransitionDigest(targetBytes)
	}
	return apkExecutionPlan{CandidateAPKChecksum: prepared.plan.CandidateAPKChecksum, LauncherTargets: targets, LauncherTargetsSHA256: targetsDigest, Schema: apkExecutionSchema, PreparationSHA256: prepared.digest, CandidateSHA256: prepared.candidate.artifact.SHA256,
		CandidateCLISHA256: prepared.candidate.cliSHA256, CandidateCapabilitySHA256: capability.SHA256(), InventorySHA256: apkTransitionDigest(inventory), EffectPlanSHA256: prepared.plan.EffectPlanSHA256,
		OriginalLaunchersSHA256: apkTransitionDigest(original), OverlaySHA256: apkTransitionDigest([]byte(apkExecutionOverlay)), Installer: prepared.candidate.target.installer, Arguments: args}, launchers, ctx.Err()
}

func apkExecutionArguments(candidatePath string, dependencies []string) ([]string, error) {
	if !filepath.IsAbs(candidatePath) || filepath.Clean(candidatePath) != candidatePath || !strings.HasSuffix(candidatePath, ".apk") {
		return nil, errors.New("APK execution candidate path is not canonical")
	}
	previous := -1
	for _, name := range dependencies {
		index := -1
		for i, allowed := range apkOptionalDependencyNames {
			if name == allowed {
				index = i
			}
		}
		if index <= previous || index < 0 {
			return nil, errors.New("APK execution retention arguments are not the exact bounded ordered names")
		}
		previous = index
	}
	args := []string{"--no-network", "--no-cache", "--repositories-file", "/dev/null", "--overlay-from-stdin", "add", candidatePath}
	return append(args, dependencies...), nil
}

// A regular sealed memfd provides complete overlay bytes before APK starts.
// Neither this descriptor nor the custody flock is an APK database lock lease.
func openAPKExecutionOverlay() (*os.File, error) {
	fd, err := unix.MemfdCreate("syswarden-apk-overlay", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "syswarden-apk-overlay")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("APK overlay descriptor unavailable")
	}
	fail := func(err error) (*os.File, error) { return nil, errors.Join(err, file.Close()) }
	if _, err := file.WriteString(apkExecutionOverlay); err != nil {
		return fail(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return fail(err)
	}
	return file, nil
}

func runAPKOverlayTransaction(ctx context.Context, prepared *verifiedPreparedAPKTransition, overlay *os.File, args []string, output io.Writer) error {
	if prepared == nil || overlay == nil || output == nil {
		return errors.New("APK native dispatch lacks retained execution descriptors")
	}
	if err := prepared.Revalidate(ctx); err != nil {
		return err
	}
	want, err := apkExecutionArguments(prepared.candidate.path, prepared.plan.RetainedDependencyNames)
	if err != nil || !reflect.DeepEqual(args, want) {
		return errors.Join(errors.New("APK native arguments differ from the fixed transaction"), err)
	}
	manager := prepared.candidate.target.installer
	if manager != "/sbin/apk" && manager != "/usr/sbin/apk" {
		return errors.New("APK execution manager is not fixed")
	}
	if err := validateAPKExecutionOverlay(overlay); err != nil {
		return err
	}
	if err := validateOfflineQualificationDependency(manager, prepared.candidate.uid); err != nil {
		return err
	}
	command := exec.Command(manager, args...) // #nosec G204 -- compiled manager and closed authenticated argument contract
	command.Dir = "/"
	command.Env = nativeRetentionEnvironment()
	command.Stdin = overlay
	command.Stdout, command.Stderr = output, output
	return dispatchAPKExecution(ctx, command, runQualificationProcessGroup)
}

// The native subprocess has the same compiled maximum as ordinary updater
// installation. A shorter caller deadline still wins; cancellation cannot be
// hidden by a dispatch callback that reports a successful process exit.
func dispatchAPKExecution(ctx context.Context, command *exec.Cmd, dispatch func(context.Context, *exec.Cmd) error) error {
	if ctx == nil || command == nil || dispatch == nil {
		return errors.New("APK bounded dispatch dependencies are unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, packageInstallationTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	err := dispatch(bounded, command)
	return errors.Join(err, bounded.Err())
}

func validateAPKExecutionOverlay(overlay *os.File) error {
	if overlay == nil {
		return errors.New("APK overlay descriptor is unavailable")
	}
	seals, err := unix.FcntlInt(overlay.Fd(), unix.F_GET_SEALS, 0)
	position, seekErr := overlay.Seek(0, io.SeekCurrent)
	info, statErr := overlay.Stat()
	wantSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seekErr != nil || statErr != nil || seals != wantSeals || position != 0 || info.Size() != int64(len(apkExecutionOverlay)) {
		return errors.New("APK overlay is not a complete sealed descriptor at offset zero")
	}
	data := make([]byte, len(apkExecutionOverlay))
	if _, err := overlay.ReadAt(data, 0); err != nil || string(data) != apkExecutionOverlay {
		return errors.New("APK overlay bytes changed")
	}
	return nil
}

func retainAPKExecutionHelper(ctx context.Context, prepared *verifiedPreparedAPKTransition, directory *pinnedServiceDirectory) error {
	var helper bytes.Buffer
	_, err := readAuthenticatedAPKObserved(ctx, prepared.candidate.file, func(stream, name string, header *tar.Header) (io.Writer, error) {
		if stream == "apk-data" && name == "opt/syswarden/bin/syswarden-cli" {
			if header.Size <= 0 || header.Size > maximumAPKExecutionHelperBytes {
				return nil, errors.New("APK candidate helper exceeds its retained bound")
			}
			return &helper, nil
		}
		return io.Discard, nil
	})
	if err != nil {
		return err
	}
	if apkTransitionDigest(helper.Bytes()) != prepared.candidate.cliSHA256 {
		return errors.New("APK retained helper differs from authenticated CLI bytes")
	}
	file, err := directory.root.OpenFile(apkExecutionHelper, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0700)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(helper.Bytes())
	return errors.Join(writeErr, file.Sync(), file.Close(), directory.sync())
}

func openAPKExecutionHelper(directory *pinnedServiceDirectory, digest string) (file *os.File, returnErr error) {
	file, err := directory.root.OpenFile(apkExecutionHelper, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	opened := file
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, opened.Close())
			file = nil
		}
	}()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	status, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Mode() != 0700 || int64(status.Uid) != int64(os.Geteuid()) || int64(status.Gid) != int64(os.Getegid()) || status.Nlink != 1 || before.Size() <= 0 || before.Size() > maximumAPKExecutionHelperBytes {
		return nil, errors.New("APK retained helper custody is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumAPKExecutionHelperBytes+1))
	if err != nil || apkTransitionDigest(data) != digest {
		return nil, errors.Join(errors.New("APK retained helper bytes changed"), err)
	}
	after, err := directory.root.Lstat(apkExecutionHelper)
	if err != nil || apkTransitionStat(after.Sys().(*syscall.Stat_t)) != apkTransitionStat(status) {
		return nil, errors.New("APK retained helper identity changed")
	}
	return file, nil
}

func openAPKExecutionDirectory(ctx context.Context, prepared *verifiedPreparedAPKTransition, plan apkExecutionPlan) (directory *pinnedServiceDirectory, review *APKTransitionExecutionReview, returnErr error) {
	data, err := apkExecutionJSON(plan)
	if err != nil {
		return nil, nil, err
	}
	digest := apkTransitionDigest(data)
	path := filepath.Join(prepared.services.root, "execution-"+digest)
	review = &APKTransitionExecutionReview{digest, prepared.digest, path}
	created := false
	if err := prepared.parent.root.Mkdir("execution-"+digest, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, review, err
		}
	} else {
		created = true
	}
	directory, err = openExistingPinnedServiceDirectory(path)
	if err != nil {
		return nil, review, err
	}
	opened := directory
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, closeAPKExecutionDirectory(opened))
			directory = nil
		}
	}()
	info, err := directory.file.Stat()
	if err != nil || info.Mode() != os.ModeDir|0700 {
		return nil, review, errors.New("APK execution custody is not private")
	}
	if created {
		if err := prepared.parent.sync(); err != nil {
			return nil, review, err
		}
		if err := writeAPKTransitionBytes(directory, "execution-plan.json", data); err != nil {
			return nil, review, err
		}
		if err := retainAPKExecutionHelper(ctx, prepared, directory); err != nil {
			return nil, review, err
		}
	}
	entries, err := directory.root.Open(".")
	if err != nil {
		return nil, review, err
	}
	names, readErr := entries.Readdirnames(4)
	closeErr := entries.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, review, readErr
	}
	sort.Strings(names)
	if closeErr != nil || !reflect.DeepEqual(names, []string{apkExecutionHelper, "execution-plan.json"}) {
		return nil, review, errors.Join(errors.New("APK execution attempt already exists or custody is incomplete; replay is forbidden"), closeErr)
	}
	existing, err := readAPKTransitionBytes(directory, "execution-plan.json", 1<<20)
	if err != nil || !bytes.Equal(existing, data) {
		return nil, review, errors.New("APK immutable execution plan differs")
	}
	helper, err := openAPKExecutionHelper(directory, plan.CandidateCLISHA256)
	if err != nil {
		return nil, review, err
	}
	if err := helper.Close(); err != nil {
		return nil, review, err
	}
	return directory, review, nil
}

func revalidateAPKExecutionHelper(directory *pinnedServiceDirectory, helper *os.File, digest string) error {
	checked, err := openAPKExecutionHelper(directory, digest)
	if err != nil {
		return err
	}
	saved, savedErr := helper.Stat()
	current, currentErr := checked.Stat()
	closeErr := checked.Close()
	if savedErr != nil || currentErr != nil || closeErr != nil || apkTransitionStat(saved.Sys().(*syscall.Stat_t)) != apkTransitionStat(current.Sys().(*syscall.Stat_t)) {
		return errors.Join(errors.New("APK retained helper descriptor changed"), savedErr, currentErr, closeErr)
	}
	return nil
}

func closeAPKExecutionDirectory(directory *pinnedServiceDirectory) error {
	if directory == nil {
		return nil
	}
	return errors.Join(directory.file.Close(), directory.root.Close())
}

func planAPKTransitionExecution(ctx context.Context, digest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, boundary apkExecutionBoundary) (review *APKTransitionExecutionReview, returnErr error) {
	if ctx == nil || !apkExecutionValuePresent(boundary) {
		return nil, errors.New("APK native execution requires a context and qualified hooks and lifecycle authority")
	}
	defer func() { returnErr = errors.Join(returnErr, boundary.Close()) }()
	prepared, err := openVerifiedPreparedAPKTransition(ctx, digest, keys, attest, services)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, prepared.Close()) }()
	plan, _, err := buildAPKExecutionPlan(ctx, prepared, boundary)
	if err != nil {
		return nil, err
	}
	directory, review, err := openAPKExecutionDirectory(ctx, prepared, plan)
	if err != nil {
		return review, err
	}
	defer func() { returnErr = errors.Join(returnErr, closeAPKExecutionDirectory(directory)) }()
	return review, ctx.Err()
}

func executeAPKTransition(ctx context.Context, digest, approvedExecutionDigest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, boundary apkExecutionBoundary) error {
	return executeAPKTransitionWith(ctx, digest, approvedExecutionDigest, keys, attest, services, boundary, apkExecutionServices{})
}

func executeAPKTransitionWith(ctx context.Context, digest, approvedExecutionDigest string, keys map[string]ed25519.PublicKey, attest installedVersionAttestor, services apkTransitionServices, boundary apkExecutionBoundary, execution apkExecutionServices) (returnErr error) {
	if ctx == nil || !apkExecutionValuePresent(boundary) || !validSHA256(approvedExecutionDigest) {
		return errors.New("APK execution requires separate exact execution approval and qualified lifecycle authority")
	}
	var prepared *verifiedPreparedAPKTransition
	var directory *pinnedServiceDirectory
	var launchers apkExecutionLaunchers
	var overlay, helper *os.File
	path := ""
	started := false
	approvalDigest := ""
	boundaryClosed := false
	write := execution.write
	if write == nil {
		write = writeAPKTransitionBytes
	}
	// All close errors are outcome failures. If closure fails after a completion
	// record, an unresolved sibling supersedes it when publication succeeds.
	// If that publication also fails, completed alone remains insufficient for
	// acceptance. Any future lifecycle consumer must independently inspect the
	// bounded native state and custody; no such reader is enabled here.
	defer func() {
		if overlay != nil {
			returnErr = errors.Join(returnErr, overlay.Close())
		}
		if helper != nil {
			returnErr = errors.Join(returnErr, helper.Close())
		}
		if apkExecutionValuePresent(launchers) {
			returnErr = errors.Join(returnErr, launchers.Close())
		}
		if !boundaryClosed {
			returnErr = errors.Join(returnErr, boundary.Close())
		}
		if prepared != nil {
			returnErr = errors.Join(returnErr, prepared.Close())
		}
		if ctx != nil {
			returnErr = errors.Join(returnErr, ctx.Err())
		}
		if returnErr != nil && directory != nil {
			state := "pre-dispatch-refused"
			if started {
				state = "unresolved"
			}
			data, _ := apkExecutionJSON(apkExecutionEvent{Schema: apkExecutionSchema, State: state, PlanSHA256: approvedExecutionDigest, ApprovalSHA256: approvalDigest, Failure: returnErr.Error()})
			returnErr = errors.Join(returnErr, write(directory, state+".json", data))
		}
		closeErr := closeAPKExecutionDirectory(directory)
		returnErr = errors.Join(returnErr, closeErr)
		if closeErr != nil && started && path != "" {
			reopened, err := openExistingPinnedServiceDirectory(path)
			if err == nil {
				data, _ := apkExecutionJSON(apkExecutionEvent{Schema: apkExecutionSchema, State: "unresolved", PlanSHA256: approvedExecutionDigest, ApprovalSHA256: approvalDigest, Failure: returnErr.Error()})
				err = errors.Join(writeAPKTransitionBytes(reopened, "unresolved.json", data), closeAPKExecutionDirectory(reopened))
			}
			returnErr = errors.Join(returnErr, err)
		}
		if returnErr != nil && path != "" {
			returnErr = &APKTransitionExecutionError{path, started, returnErr}
		}
	}()
	var err error
	prepared, err = openVerifiedPreparedAPKTransition(ctx, digest, keys, attest, services)
	if err != nil {
		return err
	}
	plan, original, err := buildAPKExecutionPlan(ctx, prepared, boundary)
	if err != nil {
		return err
	}
	data, err := apkExecutionJSON(plan)
	if err != nil {
		return err
	}
	if apkTransitionDigest(data) != approvedExecutionDigest {
		return errors.New("APK explicit execution approval differs from the exact current proposal")
	}
	// Execution consumes an existing proposal. It never creates an unseen plan.
	path = filepath.Join(services.root, "execution-"+approvedExecutionDigest)
	if _, err := prepared.parent.root.Lstat("execution-" + approvedExecutionDigest); err != nil {
		return errors.New("APK execution proposal must be retained and reviewed before execution")
	}
	directory, _, err = openAPKExecutionDirectory(ctx, prepared, plan)
	if err != nil {
		return err
	}
	approval, err := apkExecutionJSON(apkExecutionApproval{apkExecutionSchema, "explicit-native-execution", approvedExecutionDigest, plan.EffectPlanSHA256})
	if err != nil {
		return err
	}
	approvalDigest = apkTransitionDigest(approval)
	if err := write(directory, "execution-approval.json", approval); err != nil {
		return err
	}
	binding := apkLauncherCustodyBinding{PlanSHA256: approvedExecutionDigest, ApprovalSHA256: approvalDigest, CandidateSHA256: plan.CandidateSHA256, CandidateCLISHA256: plan.CandidateCLISHA256, CandidateCapabilitySHA256: plan.CandidateCapabilitySHA256, InventorySHA256: plan.InventorySHA256, OriginalSnapshotSHA256: plan.OriginalLaunchersSHA256}
	launchers, err = boundary.PrepareLaunchers(ctx, path, binding, original)
	if err != nil {
		return err
	}
	if !apkExecutionValuePresent(launchers) {
		return errors.New("APK launcher custody is unavailable")
	}
	overlay, err = openAPKExecutionOverlay()
	if err != nil {
		return err
	}
	helper, err = openAPKExecutionHelper(directory, plan.CandidateCLISHA256)
	if err != nil {
		return err
	}
	revalidate := func() error {
		if err := prepared.Revalidate(ctx); err != nil {
			return err
		}
		capability, err := attestNativeActivationCandidate(ctx, prepared.candidate.target, prepared.candidate.file)
		if err != nil || capability.SHA256() != plan.CandidateCapabilitySHA256 {
			return errors.Join(errors.New("APK capability changed before native handoff"), err)
		}
		if err := boundary.Revalidate(ctx); err != nil {
			return err
		}
		if err := revalidateAPKExecutionHelper(directory, helper, plan.CandidateCLISHA256); err != nil {
			return err
		}
		if err := launchers.Revalidate(); err != nil {
			return err
		}
		if err := launchers.RefuseProductTargetDependencies(); err != nil {
			return err
		}
		return errors.Join(ctx.Err(), attestRetainedDirectoryParent(path, directory, false))
	}
	event := func(state, receipt, observation string) error {
		data, err := apkExecutionJSON(apkExecutionEvent{Schema: apkExecutionSchema, State: state, PlanSHA256: approvedExecutionDigest, ApprovalSHA256: approvalDigest, LauncherReceiptSHA256: receipt, ObservationSHA256: observation})
		if err != nil {
			return err
		}
		return write(directory, state+".json", data)
	}
	if err := revalidate(); err != nil {
		return err
	}
	if err := event("armed", "", ""); err != nil {
		return err
	}
	if err := revalidate(); err != nil {
		return err
	}
	// Set before writing: a failed fsync may still leave a durable start intent.
	// Conservatively classify all subsequent outcomes as potentially native.
	started = true
	if err := event("native-started", "", ""); err != nil {
		return err
	}
	if err := revalidate(); err != nil {
		return err
	}
	output := qualificationBoundedBuffer{limit: 1 << 20}
	run := execution.run
	if run == nil {
		run = runAPKOverlayTransaction
	}
	runErr := run(ctx, prepared, overlay, plan.Arguments, &output)
	diagnosticErr := write(directory, "native-output.txt", output.Bytes())
	snapshot, snapshotErr := captureAPKTransitionHost(ctx, prepared.services.hostRoot)
	snapshotDigest := ""
	if snapshotErr == nil {
		snapshotBytes, marshalErr := apkExecutionJSON(snapshot)
		snapshotErr = errors.Join(marshalErr, write(directory, "observed-host-snapshot.json", snapshotBytes))
		snapshotDigest = apkTransitionDigest(snapshotBytes)
	}
	observationErr := errors.Join(snapshotErr, event("observed", "", snapshotDigest))
	if output.overflow {
		runErr = errors.Join(runErr, errors.New("APK native diagnostics exceeded the retained bound"))
	}
	if err := errors.Join(runErr, diagnosticErr, observationErr, ctx.Err()); err != nil {
		return err
	}
	observed, err := attestAPKExecutionResult(ctx, prepared, launchers, boundary)
	if err != nil {
		return err
	}
	observedBytes, err := apkExecutionJSON(observed)
	if err != nil {
		return err
	}
	if err := write(directory, "post-attestation.json", observedBytes); err != nil {
		return err
	}
	receipt, err := launchers.Commit()
	if err != nil {
		return err
	}
	if !validSHA256(receipt) {
		return errors.New("APK launcher completion receipt is absent or malformed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := launchers.Revalidate(); err != nil {
		return err
	}
	if err := revalidateAPKExecutionHelper(directory, helper, plan.CandidateCLISHA256); err != nil {
		return err
	}
	// Close resources before terminal publication; any failure remains unresolved.
	if err := launchers.Close(); err != nil {
		launchers = nil
		return err
	}
	launchers = nil
	if err := helper.Close(); err != nil {
		helper = nil
		return err
	}
	helper = nil
	if err := overlay.Close(); err != nil {
		overlay = nil
		return err
	}
	overlay = nil
	boundaryClosed = true
	if err := boundary.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return event("completed", receipt, apkTransitionDigest(observedBytes))
}

func attestAPKExecutionResult(ctx context.Context, prepared *verifiedPreparedAPKTransition, launchers apkExecutionLaunchers, boundary apkExecutionBoundary) (apkExecutionObservation, error) {
	var empty apkExecutionObservation
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := launchers.AttestUpgradeTargets(); err != nil {
		return empty, err
	}
	if err := boundary.AttestResult(ctx); err != nil {
		return empty, err
	}
	candidate := prepared.candidate
	installed, err := candidate.attestInstalled(ctx, candidate.target, candidate.uid)
	if err != nil || installed.version != candidate.version || installed.cliSHA256 != candidate.cliSHA256 {
		return empty, errors.Join(errors.New("APK installed candidate identity, version or CLI bytes differ"), err)
	}
	if err := prepared.activation.VerifyInstalledCandidate(ctx); err != nil {
		return empty, err
	}
	current, err := captureAPKTransitionHost(ctx, prepared.services.hostRoot)
	if err != nil {
		return empty, err
	}
	if err := attestAPKExecutionHost(prepared.snapshot, current, prepared.plan); err != nil {
		return empty, err
	}
	if err := launchers.Revalidate(); err != nil {
		return empty, err
	}
	if err := launchers.RefuseProductTargetDependencies(); err != nil {
		return empty, err
	}
	data, err := apkExecutionJSON(current)
	if err != nil {
		return empty, err
	}
	if err := verifySecurePackageForInstallation(candidate.file, candidate.path, candidate.artifact, candidate.uid); err != nil {
		return empty, err
	}
	return apkExecutionObservation{apkExecutionSchema, installed.version, installed.cliSHA256, prepared.capability.SHA256(), apkTransitionDigest(data)}, ctx.Err()
}

func attestAPKExecutionHost(original, current []apkTransitionHostEntry, plan apkTransitionPlan) error {
	before, after := map[string]apkTransitionHostEntry{}, map[string]apkTransitionHostEntry{}
	for _, entry := range original {
		before[entry.Path] = entry
	}
	for _, entry := range current {
		after[entry.Path] = entry
	}
	for path, entry := range before {
		if path == "." || path == "usr" || strings.HasPrefix(path, "usr/local") || path == "etc/syswarden" || strings.HasPrefix(path, "etc/syswarden/") {
			if !reflect.DeepEqual(entry, after[path]) {
				return fmt.Errorf("APK retained original identity or bytes changed: %s", path)
			}
		}
	}
	for path := range after {
		if strings.HasPrefix(path, "etc/syswarden/") {
			if _, exists := before[path]; !exists {
				return errors.New("APK candidate introduced unapproved configuration")
			}
		}
	}
	return attestAPKExecutionNativeState(before["etc/apk/world"].Content, before["lib/apk/db/installed"].Content, after["etc/apk/world"].Content, after["lib/apk/db/installed"].Content, plan)
}

// Direct F/R records establish alias registration. `apk info --who-owns` can
// report a symlink target's owner, which is not ownership of the alias itself.
func apkExecutionDatabase(data []byte) (map[string]string, map[string]string, error) {
	if len(data) == 0 || len(data) > maximumAPKInstalledDatabaseSize || bytes.ContainsAny(data, "\x00\r") {
		return nil, nil, errors.New("APK observed native database is malformed")
	}
	records, fields := map[string]string{}, map[string]string{}
	for _, block := range strings.Split(strings.TrimRight(string(data), "\n"), "\n\n") {
		if block == "" {
			return nil, nil, errors.New("APK observed database has an empty record")
		}
		name, directory := "", ""
		seen := map[string]bool{}
		values := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if len(line) < 2 || line[1] != ':' || len(line) > 64<<10 {
				return nil, nil, errors.New("APK observed database record is malformed")
			}
			key, value := line[:1], line[2:]
			switch key {
			case "P", "V", "A", "C", "f":
				if seen[key] {
					return nil, nil, errors.New("APK observed database repeats identity fields")
				}
				seen[key] = true
				values[key] = value
				if key == "P" {
					name = value
				}
			case "F":
				if value == "" || strings.HasPrefix(value, "/") || filepath.Clean(value) != value || value == ".." || strings.HasPrefix(value, "../") {
					return nil, nil, errors.New("APK observed database has a noncanonical directory")
				}
				directory = value
			case "R":
				if directory == "" || value == "" || filepath.Base(value) != value || value == "." || value == ".." {
					return nil, nil, errors.New("APK observed database has a noncanonical file")
				}
				path := directory + "/" + value
				if path == "usr/local/bin/syswarden" || path == "usr/local/bin/syswarden-tui" {
					return nil, nil, errors.New("APK retained administrator alias is still directly package-owned")
				}
			}
		}
		if name == "" || records[name] != "" || values["V"] == "" {
			return nil, nil, errors.New("APK observed database identity is missing or duplicated")
		}
		records[name] = block
		if name == compatibilityNativePackageName {
			fields = values
		}
	}
	return records, fields, nil
}

func attestAPKExecutionNativeState(oldWorld, oldDatabase, newWorld, newDatabase []byte, plan apkTransitionPlan) error {
	// Original aliases may be registered before overlay. Only the new database
	// is subjected to the direct alias-ownership check.
	oldRecords := map[string]string{}
	for _, block := range strings.Split(strings.TrimRight(string(oldDatabase), "\n"), "\n\n") {
		for _, line := range strings.Split(block, "\n") {
			if strings.HasPrefix(line, "P:") {
				name := line[2:]
				if name == "" || oldRecords[name] != "" {
					return errors.New("APK original native identity is ambiguous")
				}
				oldRecords[name] = block
			}
		}
	}
	current, fields, err := apkExecutionDatabase(newDatabase)
	if err != nil {
		return err
	}
	version, err := canonicalInstalledAPKVersionForName(fields["V"], plan.PackageName)
	if err != nil || version != plan.CandidateVersion || fields["A"] != "x86_64" || !validAPKRetentionChecksum(fields["C"]) || fields["C"] != plan.CandidateAPKChecksum || strings.Trim(fields["f"], "S") != "" {
		return errors.New("APK observed product registration is not the healthy selected candidate")
	}
	if _, exists := current[baseNativePackageName]; exists {
		return errors.New("APK execution introduced a second product identity")
	}
	for name, record := range oldRecords {
		if name != plan.PackageName && current[name] != record {
			return fmt.Errorf("APK changed an unrelated installed package or dependency: %s", name)
		}
	}
	for name := range current {
		if name != plan.PackageName {
			if _, exists := oldRecords[name]; !exists {
				return errors.New("APK introduced an unapproved dependency or unrelated package")
			}
		}
	}
	if len(newWorld) == 0 || len(newWorld) > 1<<20 || bytes.ContainsAny(newWorld, "\x00\r\t") {
		return errors.New("APK observed world is malformed")
	}
	expected := map[string]int{}
	for _, line := range strings.Split(string(oldWorld), "\n") {
		if line == "" {
			continue
		}
		if apkRetentionName(line) == plan.PackageName {
			continue
		}
		expected[line]++
	}
	for _, name := range plan.RetainedDependencyNames {
		expected[name]++
	}
	product := 0
	for _, line := range strings.Split(string(newWorld), "\n") {
		if line == "" {
			continue
		}
		if apkRetentionName(line) == plan.PackageName {
			product++
			if line != plan.PackageName+"><"+fields["C"] {
				return errors.New("APK observed world is not pinned to the exact selected registration")
			}
			continue
		}
		if expected[line] == 0 {
			return errors.New("APK changed unrelated dependency reasons or world constraints")
		}
		expected[line]--
	}
	if product != 1 {
		return errors.New("APK observed product root is missing or duplicated")
	}
	for _, count := range expected {
		if count != 0 {
			return errors.New("APK removed original world entries or retained dependency roots")
		}
	}
	return nil
}
