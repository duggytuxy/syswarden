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
	"path/filepath"
	"sort"
	"sync"
	"time"

	"syswarden-cli/pkg/sshselection"
)

const userModuleReviewLifetime = 10 * time.Minute

// UserModuleEdit pins the configuration observed before an external edit. Copies
// share state; callers receive no mutable snapshot or authoritative file bytes.
type UserModuleEdit struct{ state *userModuleEditState }

type userModuleEditState struct {
	mu       sync.Mutex
	root     string
	original []byte
	snapshot *mergedConfigSnapshot
	prepared bool
}

// UserModuleProposal is an in-process, single-use publication proposal. It is
// neither durable recovery evidence nor permission to activate host policy.
type UserModuleProposal struct{ state *userModuleProposalState }

type userModuleProposalState struct {
	mu       sync.Mutex
	root     string
	content  []byte
	snapshot *mergedConfigSnapshot
	review   UserModuleReview
	used     bool
}

// UserModuleReview contains no configuration values except the fixed, validated
// module-selection summary. Unknown/deprecated keys are represented by counts.
type UserModuleReview struct {
	Target             string
	ApprovalID         string
	ExpiresAt          time.Time
	ModulePlan         []string
	UnknownKeyCount    int
	DeprecatedKeyCount int
}

// BeginUserModuleEdit reads identities without parsing the existing user file,
// so invalid operator TOML can be repaired without writing it first.
func BeginUserModuleEdit(ctx context.Context, configDir string) (*UserModuleEdit, error) {
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
	snapshot, content, err := captureUserModuleEdit(configDir)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &UserModuleEdit{state: &userModuleEditState{root: configDir, original: content, snapshot: snapshot}}, nil
}

// Content returns a disposable copy for the private editor, never the live path.
func (edit *UserModuleEdit) Content() []byte {
	if edit == nil || edit.state == nil {
		return nil
	}
	edit.state.mu.Lock()
	defer edit.state.mu.Unlock()
	return bytes.Clone(edit.state.original)
}

// Prepare validates the candidate against the originally captured configuration.
// It never recaptures a newer baseline to replace the operator's original view.
func (edit *UserModuleEdit) Prepare(ctx context.Context, content []byte) (*UserModuleProposal, error) {
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
		return nil, fmt.Errorf("operator user module exceeds the %d-byte limit", maximumUserModuleSize)
	}
	candidate := bytes.Clone(content)
	if err := state.snapshot.revalidate(state.root, false, nil); err != nil {
		return nil, fmt.Errorf("configuration changed since editing began: %w", err)
	}
	validated, err := validateModularUserCandidate(state.root, candidate, state.snapshot.user)
	if err != nil {
		return nil, fmt.Errorf("validate proposed user configuration: %w", err)
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
	_, _ = hash.Write([]byte("syswarden-user-module-review-v1\x00"))
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write([]byte(state.root))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(candidate)
	review := UserModuleReview{
		Target: "modules/" + userModuleName, ApprovalID: hex.EncodeToString(hash.Sum(nil)),
		ExpiresAt:       time.Now().Add(userModuleReviewLifetime),
		ModulePlan:      append([]string(nil), validated.report.ModulePlan...),
		UnknownKeyCount: len(validated.report.UnknownKeys), DeprecatedKeyCount: len(validated.report.DeprecatedKeys),
	}
	state.prepared = true
	return &UserModuleProposal{state: &userModuleProposalState{
		root: state.root, content: candidate, snapshot: state.snapshot, review: review,
	}}, nil
}

func (proposal *UserModuleProposal) Review() UserModuleReview {
	if proposal == nil || proposal.state == nil {
		return UserModuleReview{}
	}
	proposal.state.mu.Lock()
	defer proposal.state.mu.Unlock()
	review := proposal.state.review
	review.ModulePlan = append([]string(nil), review.ModulePlan...)
	return review
}

// Publish requires exact approval and a caller-supplied read-only lifecycle
// barrier. It rechecks that barrier and the original snapshot around publication.
// Every attempt is single-use, including refused, interrupted or ambiguous ones.
func (proposal *UserModuleProposal) Publish(ctx context.Context, approvalID string, preflight func() error) error {
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
		return state.snapshot.revalidate(state.root, true, state.content)
	}
	return publishValidatedUserModule(filepath.Join(state.root, "modules"), userModuleName,
		state.content, state.snapshot.user, preCommit, guard, postCommit)
}

func captureUserModuleEdit(configDir string) (*mergedConfigSnapshot, []byte, error) {
	root, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	rootInfo, err := rootDirectoryInfo(root)
	if err != nil {
		return nil, nil, err
	}
	marker, err := readOptionalSecureFileIdentity(root, migrationMarkerName, filepath.Join(configDir, migrationMarkerName))
	if err != nil {
		return nil, nil, err
	}
	if marker != nil {
		return nil, nil, errors.New("configuration migration must be resolved before editing")
	}
	master, err := readOptionalSecureFileIdentity(root, "config.toml", filepath.Join(configDir, "config.toml"))
	if err != nil {
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
	entries, err := file.ReadDir(-1)
	_ = file.Close()
	if err != nil {
		return nil, nil, err
	}
	snapshot := &mergedConfigSnapshot{configRootInfo: rootInfo, modulesRootInfo: modulesInfo,
		master: master, modules: make(map[string]*secureFileIdentity)}
	var original []byte
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".toml" {
			continue
		}
		snapshot.moduleNames = append(snapshot.moduleNames, entry.Name())
		content, identity, err := readSecureRegularFileIdentity(modules, entry.Name(), filepath.Join(modulesDir, entry.Name()))
		if err != nil {
			return nil, nil, err
		}
		if entry.Name() == userModuleName {
			original, snapshot.user = content, identity
		} else {
			snapshot.modules[entry.Name()] = identity
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
