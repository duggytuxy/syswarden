package config

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"syswarden-cli/pkg/sshselection"
)

// User-specific aliases preserve callers of the initial bounded publication API.
type UserModuleEdit = ModuleEdit
type UserModuleProposal = ModuleProposal
type UserModuleReview = ModuleReview

const userModuleReviewLifetime = 10 * time.Minute

// ModuleEdit pins configuration before editing one allowed ordinary TOML file.
// Copies share state; callers receive no mutable snapshot or authoritative bytes.
type ModuleEdit struct{ state *moduleEditState }

type moduleEditState struct {
	mu       sync.Mutex
	root     string
	target   tomlEditTarget
	original []byte
	snapshot *mergedConfigSnapshot
	prepared bool
}

// ModuleProposal is an in-process, single-use approval. Publication records
// durable file-exchange intent, but never authorizes host-policy activation.
type ModuleProposal struct{ state *moduleProposalState }

type moduleProposalState struct {
	mu       sync.Mutex
	root     string
	target   tomlEditTarget
	content  []byte
	snapshot *mergedConfigSnapshot
	review   ModuleReview
	used     bool
}

// ModuleReview contains no configuration values except the fixed, validated
// module-selection summary. Unknown/deprecated keys are represented by counts.
type ModuleReview struct {
	Target             string
	ApprovalID         string
	ExpiresAt          time.Time
	ModulePlan         []string
	Effects            []ConfigurationEffect
	UnknownKeyCount    int
	DeprecatedKeyCount int
}

// BeginUserModuleEdit selects the user override file through the common editor.
func BeginUserModuleEdit(ctx context.Context, configDir string) (*ModuleEdit, error) {
	return BeginModuleEdit(ctx, configDir, "modules/"+userModuleName)
}

// BeginModuleEdit reads identities without parsing the target, so invalid TOML
// can be repaired without writing unvalidated bytes into live configuration.
func BeginModuleEdit(ctx context.Context, configDir, relative string) (*ModuleEdit, error) {
	target, err := ordinaryTOMLTarget(relative)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("configuration edit requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(configDir) || filepath.Clean(configDir) != configDir {
		return nil, errors.New("configuration edit root must be absolute and canonical")
	}
	if err := sshselection.RejectEnvironment(); err != nil {
		return nil, err
	}
	if err := rejectOperatorPolicyEnvironment(); err != nil {
		return nil, err
	}
	snapshot, content, err := captureModuleEdit(configDir, target)
	if err != nil {
		return nil, err
	}
	if err := snapshot.requireEditOwnership(os.Geteuid()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &ModuleEdit{state: &moduleEditState{root: configDir, target: target, original: content, snapshot: snapshot}}, nil
}

// Content returns a disposable copy for the private editor, never the live path.
func (edit *ModuleEdit) Content() []byte {
	if edit == nil || edit.state == nil {
		return nil
	}
	edit.state.mu.Lock()
	defer edit.state.mu.Unlock()
	return bytes.Clone(edit.state.original)
}

// Prepare validates the candidate against the originally captured configuration.
// It never recaptures a newer baseline to replace the operator's original view.
func (edit *ModuleEdit) Prepare(ctx context.Context, content []byte) (*ModuleProposal, error) {
	if edit == nil || edit.state == nil || ctx == nil {
		return nil, errors.New("configuration edit is unavailable")
	}
	state := edit.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.prepared {
		return nil, errors.New("configuration edit already prepared; open a new edit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(content)) > maximumUserModuleSize {
		return nil, fmt.Errorf("configuration candidate exceeds the %d-byte limit", maximumUserModuleSize)
	}
	if err := state.snapshot.requireEditRecoveryMetadata(); err != nil {
		return nil, err
	}
	candidate := bytes.Clone(content)
	if err := state.snapshot.revalidate(state.root, false, nil); err != nil {
		return nil, fmt.Errorf("configuration changed since editing began: %w", err)
	}
	validated, err := validateModuleCandidate(state.root, state.target, candidate, state.snapshot.identity(state.target))
	if err != nil {
		return nil, fmt.Errorf("validate proposed configuration: %w", err)
	}
	if !sameUserModuleBaseline(state.snapshot, validated) {
		return nil, errors.New("proposal validation observed a different configuration baseline")
	}
	if err := state.snapshot.revalidate(state.root, false, nil); err != nil {
		return nil, fmt.Errorf("configuration changed during proposal validation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("create configuration approval identity: %w", err)
	}
	// The random identity selects this exact opaque proposal and its captured
	// inode snapshot, rather than serving as a reusable content-hash authority.
	hash := sha256.New()
	_, _ = hash.Write([]byte("syswarden-toml-module-review-v2\x00"))
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write([]byte(state.root))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(state.target.relative))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(candidate)
	review := ModuleReview{
		Target: state.target.relative, ApprovalID: hex.EncodeToString(hash.Sum(nil)),
		ExpiresAt:       time.Now().Add(userModuleReviewLifetime),
		ModulePlan:      append([]string(nil), validated.report.ModulePlan...),
		Effects:         append([]ConfigurationEffect(nil), validated.effects...),
		UnknownKeyCount: len(validated.report.UnknownKeys), DeprecatedKeyCount: len(validated.report.DeprecatedKeys),
	}
	state.prepared = true
	return &ModuleProposal{state: &moduleProposalState{
		root: state.root, target: state.target, content: candidate, snapshot: state.snapshot, review: review,
	}}, nil
}

func (proposal *ModuleProposal) Review() ModuleReview {
	if proposal == nil || proposal.state == nil {
		return ModuleReview{}
	}
	proposal.state.mu.Lock()
	defer proposal.state.mu.Unlock()
	review := proposal.state.review
	review.ModulePlan = append([]string(nil), review.ModulePlan...)
	review.Effects = append([]ConfigurationEffect(nil), review.Effects...)
	return review
}

// Publish requires exact approval and a caller-supplied read-only lifecycle
// barrier. It rechecks that barrier and the original snapshot around publication.
// Every attempt is single-use, including refused, interrupted or ambiguous ones.
func (proposal *ModuleProposal) Publish(ctx context.Context, approvalID string, preflight func() error) error {
	if proposal == nil || proposal.state == nil {
		return errors.New("configuration publication requires a proposal, context and lifecycle preflight")
	}
	state := proposal.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.used {
		return errors.New("configuration proposal already consumed; prepare and review a new proposal")
	}
	state.used = true
	if ctx == nil || preflight == nil {
		return errors.New("configuration publication requires a context and lifecycle preflight")
	}
	if approvalID == "" || approvalID != state.review.ApprovalID {
		return errors.New("configuration approval does not match the reviewed proposal")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(state.review.ExpiresAt) {
			return errors.New("configuration proposal expired; prepare and review a new proposal")
		}
		if err := sshselection.RejectEnvironment(); err != nil {
			return err
		}
		return rejectOperatorPolicyEnvironment()
	}
	guard := func() error {
		if err := check(); err != nil {
			return err
		}
		if err := preflight(); err != nil {
			return err
		}
		return check()
	}
	userModuleWriteMu.Lock()
	defer userModuleWriteMu.Unlock()
	preCommit := func() error {
		if err := guard(); err != nil {
			return err
		}
		return state.snapshot.revalidate(state.root, false, nil)
	}
	if err := preCommit(); err != nil {
		return err
	}
	postCommit := func() error {
		if err := guard(); err != nil {
			return err
		}
		return state.snapshot.revalidateTarget(state.root, state.target, state.content)
	}
	return publishReviewedModule(state, preCommit, guard, postCommit)
}

func captureModuleEdit(configDir string, target tomlEditTarget) (*mergedConfigSnapshot, []byte, error) {
	return captureModuleInputs(configDir, target, nil)
}

// Only an internally captured, unchanged intent permits read-only recovery
// inspection through the ordinary edit barrier. It grants no write authority.
func captureModuleInputs(configDir string, target tomlEditTarget, intent *secureFileIdentity) (*mergedConfigSnapshot, []byte, error) {
	checkIntent := func() error {
		if intent == nil {
			return RefusePendingModuleEdit(configDir)
		}
		opened, err := openConfigDirectory(configDir, false, 0)
		if err != nil {
			return err
		}
		defer func() { _ = opened.Close() }()
		raw, info, err := readSecureRegularFileSnapshotBounded(opened, moduleEditIntentName, moduleEditIntentName, maximumModuleEditIntentSize)
		if err != nil {
			return err
		}
		if !intent.matches(raw, info) || !sameSecureFileMetadata(intent.info, info) {
			return errors.New("configuration edit intent changed during recovery input capture")
		}
		return nil
	}
	if err := checkIntent(); err != nil {
		return nil, nil, err
	}
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, nil, err
	}
	if _, err := root.Lstat(migrationMarkerName); err == nil {
		return nil, nil, errors.New("configuration migration must be resolved before editing")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}
	var master *secureFileIdentity
	var masterContent []byte
	if _, err := root.Lstat("config.toml"); err == nil {
		masterContent, master, err = readEditFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
		if err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, err
	}

	modulesDir := filepath.Join(configDir, "modules")
	modules, err := openConfigDirectory(modulesDir, false, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = modules.Close() }()
	modulesInfo, err := rootDirectoryInfo(modules)
	if err != nil {
		return nil, nil, err
	}
	file, err := modules.Open(".")
	if err != nil {
		return nil, nil, err
	}
	entries, err := readBoundedEditEntries(file)
	_ = file.Close()
	if err != nil {
		return nil, nil, err
	}
	snapshot := &mergedConfigSnapshot{configRootInfo: rootInfo, modulesRootInfo: modulesInfo,
		master: master, modules: make(map[string]*secureFileIdentity)}
	var original []byte
	if target.master {
		original = masterContent
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		inputCount := len(snapshot.moduleNames)
		if snapshot.master != nil {
			inputCount++
		}
		if inputCount >= maximumModuleEditInputs {
			return nil, nil, errors.New("configuration exceeds the edit/preview TOML input limit")
		}
		snapshot.moduleNames = append(snapshot.moduleNames, entry.Name())
		content, identity, err := readEditFileIdentity(modules, entry.Name(), filepath.Join(modulesDir, entry.Name()))
		if err != nil {
			return nil, nil, err
		}
		if entry.Name() == userModuleName {
			snapshot.user = identity
		} else {
			snapshot.modules[entry.Name()] = identity
		}
		if !target.master && entry.Name() == target.name {
			original = content
		}
	}
	sort.Strings(snapshot.moduleNames)
	if snapshot.user == nil {
		if _, err := modules.Lstat(userModuleName); !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, errors.New("operator user module appeared during capture")
		}
	}
	if err := snapshot.revalidate(configDir, false, nil); err != nil {
		return nil, nil, err
	}
	if err := checkIntent(); err != nil {
		return nil, nil, err
	}
	return snapshot, original, nil
}

// Comparing both captures prevents validation against a transient replacement
// from being authorized after the original files have been put back.
func sameUserModuleBaseline(left, right *mergedConfigSnapshot) bool {
	if left == nil || right == nil || !sameFileAndMode(left.configRootInfo, right.configRootInfo) ||
		!sameFileAndMode(left.modulesRootInfo, right.modulesRootInfo) ||
		!sameUserModuleIdentity(left.master, right.master) || !sameUserModuleIdentity(left.marker, right.marker) ||
		!sameUserModuleIdentity(left.user, right.user) || len(left.moduleNames) != len(right.moduleNames) {
		return false
	}
	for i, name := range left.moduleNames {
		if name != right.moduleNames[i] || !sameUserModuleIdentity(left.modules[name], right.modules[name]) {
			return false
		}
	}
	return true
}

func sameUserModuleIdentity(left, right *secureFileIdentity) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.digest == right.digest && sameSecureFileMetadata(left.info, right.info)
}
