//go:build linux

package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ActivationApprovalRequest carries the exact independently reviewed command
// plan. The caller must bind policy, local source scope, operation, predecessor
// approval and live host observations into PlanSHA256 before asking approval.
type ActivationApprovalRequest struct {
	PlanSHA256             string
	ApprovedPlanSHA256     string
	PreviousApprovalSHA256 string
	Operation              string
}

// ActivationApprovalReview distinguishes explicit authority from successful
// application. Applied reports only a matching application record, not runtime
// health, release acceptance or completion of a different operation.
type ActivationApprovalReview struct {
	SHA256                 string
	PolicySHA256           string
	HostSHA256             string
	PlanSHA256             string
	PreviousApprovalSHA256 string
	Operation              string
	Applied                bool
}

type activationApprovalStore struct {
	path string
	uid  uint32
}

type activationStoredState struct {
	directory       activationDirectoryIdentity
	record          *activationApprovalRecord
	raw             []byte
	identity        activationFileIdentity
	appliedRaw      []byte
	appliedIdentity activationFileIdentity
}

// ActivationApproval is an immutable reference to explicit durable authority.
// It does not hold a process-spanning lock or imply successful application.
type ActivationApproval struct {
	store     activationApprovalStore
	record    *activationApprovalRecord
	digest    string
	directory activationDirectoryIdentity
	identity  activationFileIdentity
	applied   bool
}

func productionActivationStore() (activationApprovalStore, error) {
	if os.Geteuid() != 0 {
		return activationApprovalStore{}, errors.New("durable activation approval requires root")
	}
	return activationApprovalStore{path: activationStateDirectory, uid: 0}, nil
}

// HostSHA256 binds the canonical configuration root and its captured directory
// identities. This is a local source-scope binding, not a global machine ID.
func (policy *ActivationPolicy) HostSHA256() (string, error) {
	if policy == nil || policy.snapshot == nil {
		return "", errors.New("activation policy capture is unavailable")
	}
	uid, err := activationOwnerUID(int64(os.Geteuid()))
	if err != nil {
		return "", err
	}
	root, err := activationDirectoryFrom(policy.snapshot.configRootInfo, uid)
	if err != nil {
		return "", err
	}
	modules, err := activationDirectoryFrom(policy.snapshot.modulesRootInfo, uid)
	if err != nil {
		return "", err
	}
	return activationHostDigest(policy.root, root, modules)
}

// CurrentApproval reads existing authority without installing configuration or
// checking that older policy is still selected. Nil,nil means no approval.
// This permits a new explicit plan to bind and replace an older approval by CAS.
func (policy *ActivationPolicy) CurrentApproval(ctx context.Context) (*ActivationApproval, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	return policy.currentApprovalAt(ctx, store)
}

func (policy *ActivationPolicy) currentApprovalAt(ctx context.Context, store activationApprovalStore) (*ActivationApproval, error) {
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	state, err := readActivationState(store)
	if err != nil {
		return nil, err
	}
	if state == nil || state.record == nil {
		return nil, nil
	}
	host, err := policy.HostSHA256()
	if err != nil || state.record.Root != policy.root || state.record.HostSHA256 != host {
		return nil, errors.New("activation approval belongs to another local source scope")
	}
	return approvalFromState(store, state), nil
}

// Approve persists the exact caller-approved plan only after both policy and
// caller-provided live host observations are revalidated. A digest alone is not
// consent: the command ingress must obtain ApprovedPlanSHA256 from the operator.
func (policy *ActivationPolicy) Approve(ctx context.Context, request ActivationApprovalRequest, revalidateHost func() error) (*ActivationApproval, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	if policy == nil || policy.root != "/etc/syswarden/config" {
		return nil, errors.New("production activation requires the fixed configuration root")
	}
	return policy.approveAt(ctx, store, request, revalidateHost)
}

func (policy *ActivationPolicy) approveAt(ctx context.Context, store activationApprovalStore, request ActivationApprovalRequest, revalidateHost func() error) (*ActivationApproval, error) {
	if !activationHex(request.PlanSHA256) || request.ApprovedPlanSHA256 != request.PlanSHA256 ||
		(request.PreviousApprovalSHA256 != "" && !activationHex(request.PreviousApprovalSHA256)) ||
		(request.Operation != "install" && request.Operation != "reload") || revalidateHost == nil {
		return nil, errors.New("activation requires exact reviewed plan approval and live host revalidation")
	}
	guard := func() error {
		if err := policy.Revalidate(ctx); err != nil {
			return err
		}
		if err := revalidateHost(); err != nil {
			return fmt.Errorf("activation live host observations changed: %w", err)
		}
		return policy.Revalidate(ctx)
	}
	if err := guard(); err != nil {
		return nil, err
	}
	before, err := readActivationState(store)
	if err != nil {
		return nil, err
	}
	if approvalStateDigest(before) != request.PreviousApprovalSHA256 {
		return nil, errors.New("activation predecessor approval changed before publication")
	}
	if err := createActivationStore(store); err != nil {
		return nil, err
	}
	unlock, err := lockActivationStore(store)
	if err != nil {
		return nil, err
	}
	defer unlock()
	current, err := readActivationState(store)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, errors.New("activation state directory disappeared while acquiring custody")
	}
	if approvalStateDigest(current) != request.PreviousApprovalSHA256 {
		return nil, errors.New("activation predecessor approval changed while acquiring publication custody")
	}
	record, err := policy.approvalRecord(request, store.uid)
	if err != nil {
		return nil, err
	}
	if current != nil && len(current.appliedRaw) != 0 {
		record.RetainedAppliedSHA256 = activationDigest(current.appliedRaw)
	}
	if err := validateActivationRecord(record, store.uid); err != nil {
		return nil, err
	}
	raw, err := activationCanonical(record)
	if err != nil {
		return nil, err
	}
	if len(raw) > maximumActivationRecordBytes {
		return nil, errors.New("activation approval exceeds its record bound")
	}
	if err := guard(); err != nil {
		return nil, err
	}
	expected, err := activationReplacementIdentity(store, activationApprovedName, current)
	if err != nil {
		return nil, err
	}
	directory := current.directory
	prePublish := func() error {
		if err := guard(); err != nil {
			return err
		}
		state, err := readActivationStateForPublication(store, directory)
		if err != nil {
			return err
		}
		if approvalStateDigest(state) != request.PreviousApprovalSHA256 {
			return errors.New("activation predecessor changed at publication")
		}
		return nil
	}
	if err := replaceSecureConfigFile(store.path, activationApprovedName, raw, expected, prePublish, nil, nil); err != nil {
		return nil, fmt.Errorf("activation approval publication did not complete: %w", err)
	}
	state, err := readActivationState(store)
	if err != nil {
		return nil, err
	}
	if state == nil || !bytes.Equal(state.raw, raw) {
		return nil, errors.New("activation approval changed after publication")
	}
	approval := approvalFromState(store, state)
	if err := approval.Revalidate(ctx); err != nil {
		return nil, err
	}
	// Publication itself can overlap an independent host change. Retain any
	// published pending record on failure, but return no consumable handle and
	// never report successful application from publication alone.
	if err := guard(); err != nil {
		return nil, fmt.Errorf("activation observations changed after approval publication; pending authority is retained without application: %w", err)
	}
	return approval, nil
}

func (policy *ActivationPolicy) approvalRecord(request ActivationApprovalRequest, uid uint32) (*activationApprovalRecord, error) {
	root, err := activationDirectoryFrom(policy.snapshot.configRootInfo, uid)
	if err != nil {
		return nil, err
	}
	modules, err := activationDirectoryFrom(policy.snapshot.modulesRootInfo, uid)
	if err != nil {
		return nil, err
	}
	host, err := activationHostDigest(policy.root, root, modules)
	if err != nil {
		return nil, err
	}
	record := &activationApprovalRecord{
		Schema: activationApprovalSchema, SourceContract: activationSourceContract, Environment: activationEnvironmentContract,
		Root: policy.root, RootIdentity: root, ModulesIdentity: modules, PolicySHA256: policy.review.Digest, HostSHA256: host,
		PlanSHA256: request.PlanSHA256, PreviousApprovalSHA256: request.PreviousApprovalSHA256, Operation: request.Operation,
	}
	appendInput := func(path string, identity *secureFileIdentity) error {
		if identity == nil {
			return errors.New("activation input identity is absent")
		}
		file, err := activationFileFrom(identity.info, nil, uid, maximumActivationInputBytes)
		if err != nil {
			return err
		}
		file.SHA256 = fmt.Sprintf("%x", identity.digest)
		record.Inputs = append(record.Inputs, activationInput{Path: path, File: file})
		return nil
	}
	if err := appendInput("config.toml", policy.snapshot.master); err != nil {
		return nil, err
	}
	for _, name := range policy.snapshot.moduleNames {
		identity := policy.snapshot.modules[name]
		if name == userModuleName {
			identity = policy.snapshot.user
		}
		if err := appendInput("modules/"+name, identity); err != nil {
			return nil, err
		}
	}
	return record, nil
}

// VerifyApproved independently verifies exact current source and approval
// lineage without writing files or changing the process-global configuration.
func (policy *ActivationPolicy) VerifyApproved(ctx context.Context) (*ActivationApproval, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	return policy.verifyApprovedAt(ctx, store)
}

func (policy *ActivationPolicy) verifyApprovedAt(ctx context.Context, store activationApprovalStore) (*ActivationApproval, error) {
	approval, err := policy.currentApprovalAt(ctx, store)
	if err != nil {
		return nil, err
	}
	if approval == nil {
		return nil, errors.New("explicit activation approval is absent; legacy state cannot be adopted implicitly")
	}
	if approval.record.PolicySHA256 != policy.review.Digest {
		return nil, errors.New("current TOML policy has no matching activation approval")
	}
	if err := approval.Revalidate(ctx); err != nil {
		return nil, err
	}
	if err := policy.Revalidate(ctx); err != nil {
		return nil, err
	}
	return approval, nil
}

// UseApproved installs only the captured, currently approved configuration.
// It is a single-threaded command-startup operation, not a runtime reload API.
func (policy *ActivationPolicy) UseApproved(ctx context.Context) (*ActivationApproval, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	return policy.useApprovedAt(ctx, store)
}

func (policy *ActivationPolicy) useApprovedAt(ctx context.Context, store activationApprovalStore) (*ActivationApproval, error) {
	approval, err := policy.verifyApprovedAt(ctx, store)
	if err != nil {
		return nil, err
	}
	candidate, err := policy.Configuration(ctx)
	if err != nil {
		return nil, err
	}
	if err := approval.Revalidate(ctx); err != nil {
		return nil, err
	}
	configLoadMu.Lock()
	defer configLoadMu.Unlock()
	commitGlobalConfig(candidate, policy.root)
	return approval, nil
}

func (approval *ActivationApproval) Review() ActivationApprovalReview {
	if approval == nil || approval.record == nil {
		return ActivationApprovalReview{}
	}
	record := approval.record
	return ActivationApprovalReview{
		SHA256: approval.digest, PolicySHA256: record.PolicySHA256, HostSHA256: record.HostSHA256, PlanSHA256: record.PlanSHA256,
		PreviousApprovalSHA256: record.PreviousApprovalSHA256, Operation: record.Operation, Applied: approval.applied,
	}
}

// Revalidate does not acquire a write lock and is safe in nested service reload.
// Exact source or approval replacement is refused even when bytes are equivalent.
func (approval *ActivationApproval) Revalidate(ctx context.Context) error {
	if err := activationPolicyContext(ctx); err != nil {
		return err
	}
	if approval == nil || approval.record == nil {
		return errors.New("activation approval is unavailable")
	}
	state, err := readActivationState(approval.store)
	if err != nil {
		return err
	}
	if state == nil || state.record == nil || state.directory != approval.directory || state.identity != approval.identity || activationDigest(state.raw) != approval.digest {
		return errors.New("activation approval changed after verification")
	}
	if _, err := readActivationInputs(approval.record, approval.store.uid); err != nil {
		return err
	}
	return activationPolicyContext(ctx)
}

// MarkApplied records completion of the approved operation only. The command
// must not call this for a nested reload of an install approval; only the parent
// installation can report that all of its stages completed.
func (approval *ActivationApproval) MarkApplied(ctx context.Context) error {
	return approval.markAppliedUsing(ctx, defaultConfigReplacementOps())
}

func (approval *ActivationApproval) markAppliedUsing(ctx context.Context, ops configReplacementOps) error {
	if err := approval.Revalidate(ctx); err != nil {
		return err
	}
	unlock, err := lockActivationStore(approval.store)
	if err != nil {
		return err
	}
	defer unlock()
	if err := approval.Revalidate(ctx); err != nil {
		return err
	}
	state, err := readActivationState(approval.store)
	if err != nil {
		return err
	}
	if state == nil || state.record == nil || state.directory != approval.directory || state.identity != approval.identity || approvalStateDigest(state) != approval.digest {
		return errors.New("activation approval changed before application recording")
	}
	raw, err := activationCanonical(activationAppliedRecord{Schema: activationAppliedSchema, ApprovalSHA256: approval.digest})
	if err != nil {
		return err
	}
	if bytes.Equal(raw, state.appliedRaw) {
		return approval.Revalidate(ctx)
	}
	expected, err := activationReplacementIdentity(approval.store, activationAppliedName, state)
	if err != nil {
		return err
	}
	guard := func() error {
		if err := activationPolicyContext(ctx); err != nil {
			return err
		}
		current, err := readActivationStateForPublication(approval.store, approval.directory)
		if err != nil {
			return err
		}
		if approvalStateDigest(current) != approval.digest {
			return errors.New("activation approval changed before application recording")
		}
		_, err = readActivationInputs(approval.record, approval.store.uid)
		return err
	}
	if err := replaceSecureConfigFileUsing(approval.store.path, activationAppliedName, raw, expected, guard, nil, nil, ops); err != nil {
		return err
	}
	// Publication and final directory synchronization can outlive the last
	// source check. Retain the record on uncertainty, but do not report
	// successful completion using a changed source or approval.
	return approval.Revalidate(ctx)
}

func approvalFromState(store activationApprovalStore, state *activationStoredState) *ActivationApproval {
	digest := activationDigest(state.raw)
	applied := false
	if len(state.appliedRaw) != 0 {
		record, err := decodeActivationApplied(state.appliedRaw)
		applied = err == nil && record.ApprovalSHA256 == digest
	}
	return &ActivationApproval{store: store, record: state.record, digest: digest, directory: state.directory, identity: state.identity, applied: applied}
}

func approvalStateDigest(state *activationStoredState) string {
	if state == nil || state.record == nil {
		return ""
	}
	return activationDigest(state.raw)
}

func readActivationState(store activationApprovalStore) (*activationStoredState, error) {
	if err := refuseActivationRetirement(store.path, store.uid); err != nil {
		return nil, err
	}
	return readActivationStateUsing(store, nil)
}

// Atomic replacement has one private stage present. Publication guards ignore
// only that exact validated replacement mechanism's temporary name family;
// public readers refuse any unexplained entry.
func readActivationStateForPublication(store activationApprovalStore, expected activationDirectoryIdentity) (*activationStoredState, error) {
	state, err := readActivationStateUsing(store, &expected)
	if err != nil {
		return nil, err
	}
	if state == nil || state.directory != expected {
		return nil, errors.New("activation state directory changed during publication")
	}
	return state, nil
}

func readActivationStateUsing(store activationApprovalStore, publication *activationDirectoryIdentity) (*activationStoredState, error) {
	root, identity, err := openActivationDirectory(store.path, store.uid)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if identity.Mode != 0700 {
		return nil, errors.New("activation state directory is not private")
	}
	if publication != nil && *publication != identity {
		return nil, errors.New("activation state directory changed")
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(9)
	_ = directory.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, readErr
	}
	if len(entries) > 8 {
		return nil, errors.New("activation state inventory exceeds its bound")
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == activationApprovedName || name == activationAppliedName || name == activationLockName {
			continue
		}
		if publication != nil && (validActivationStageName(name, activationApprovedName) || validActivationStageName(name, activationAppliedName)) {
			continue
		}
		return nil, errors.New("activation state contains an unrecognized retained artifact")
	}
	state := &activationStoredState{directory: identity}
	raw, file, err := readActivationFile(root, activationApprovedName, store.uid, maximumActivationRecordBytes)
	if err == nil {
		if file.Mode != 0600 {
			return nil, errors.New("activation approval is not private")
		}
		record, err := decodeActivationApproval(raw, store.uid)
		if err != nil {
			return nil, err
		}
		state.raw, state.identity, state.record = raw, file, record
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	raw, file, err = readActivationFile(root, activationAppliedName, store.uid, maximumActivationRecordBytes)
	if err == nil {
		if state.record == nil || file.Mode != 0600 {
			return nil, errors.New("activation application record has no valid approval")
		}
		applied, err := decodeActivationApplied(raw)
		if err != nil {
			return nil, err
		}
		if applied.ApprovalSHA256 != activationDigest(state.raw) && activationDigest(raw) != state.record.RetainedAppliedSHA256 {
			return nil, errors.New("activation application record has no exact approval lineage")
		}
		state.appliedRaw, state.appliedIdentity = raw, file
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if _, witness, err := readActivationFile(root, activationLockName, store.uid, 0); err == nil {
		if witness.Mode != 0600 {
			return nil, errors.New("activation publication lock is not private")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	reopened, after, err := openActivationDirectory(store.path, store.uid)
	if err != nil {
		return nil, err
	}
	_ = reopened.Close()
	if after != identity {
		return nil, errors.New("activation state directory changed while reading")
	}
	return state, nil
}

func validActivationStageName(name, target string) bool {
	prefix := "." + target + ".tmp-"
	if len(name) != len(prefix)+32 || name[:len(prefix)] != prefix {
		return false
	}
	for _, digit := range name[len(prefix):] {
		if !((digit >= 'a' && digit <= 'f') || (digit >= '0' && digit <= '9')) {
			return false
		}
	}
	return true
}

func activationReplacementIdentity(store activationApprovalStore, name string, state *activationStoredState) (*secureFileIdentity, error) {
	if state == nil {
		return nil, errors.New("activation state directory is unavailable")
	}
	expected := state.identity
	if name == activationAppliedName {
		expected = state.appliedIdentity
	}
	root, identity, err := openActivationDirectory(store.path, store.uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if identity != state.directory {
		return nil, errors.New("activation state directory changed")
	}
	if expected.Inode == 0 {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return nil, errors.New("activation record appeared unexpectedly")
		}
		return nil, nil
	}
	raw, info, err := readSecureRegularFileSnapshotBounded(root, name, name, maximumActivationRecordBytes)
	if err != nil {
		return nil, err
	}
	actual, err := activationFileFrom(info, raw, store.uid, maximumActivationRecordBytes)
	if err != nil || actual != expected {
		return nil, errors.New("activation record changed before replacement")
	}
	return newSecureFileIdentity(raw, info), nil
}

func createActivationStore(store activationApprovalStore) error {
	if err := refuseActivationRetirement(store.path, store.uid); err != nil {
		return err
	}
	parentPath := filepath.Dir(store.path)
	parent, err := openDirectoryNoSymlinks(parentPath, true, 0700)
	if err != nil {
		return err
	}
	_ = parent.Close()
	parent, _, err = openActivationDirectory(parentPath, store.uid)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	name := filepath.Base(store.path)
	if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := syncRootDirectory(parent); err != nil {
		return err
	}
	root, identity, err := openActivationDirectory(store.path, store.uid)
	if err != nil {
		return err
	}
	_ = root.Close()
	if identity.Mode != 0700 {
		return errors.New("activation state directory is not private")
	}
	return nil
}

func lockActivationStore(store activationApprovalStore) (func(), error) {
	root, identity, err := openActivationDirectory(store.path, store.uid)
	if err != nil {
		return nil, err
	}
	if identity.Mode != 0700 {
		_ = root.Close()
		return nil, errors.New("activation state directory is not private")
	}
	file, err := root.OpenFile(activationLockName, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	cleanup := func() { _ = file.Close(); _ = root.Close() }
	info, err := file.Stat()
	if err != nil {
		cleanup()
		return nil, err
	}
	witness, err := activationFileFrom(info, nil, store.uid, 0)
	if err != nil || witness.Mode != 0600 {
		cleanup()
		return nil, errors.New("activation lock metadata is unsafe")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		cleanup()
		return nil, errors.New("activation approval publication is already in progress")
	}
	raw, current, err := readActivationFile(root, activationLockName, store.uid, 0)
	if err != nil || len(raw) != 0 || current != witness {
		cleanup()
		return nil, errors.New("activation publication lock changed")
	}
	if err := syncRootDirectory(root); err != nil {
		cleanup()
		return nil, err
	}
	return cleanup, nil
}
