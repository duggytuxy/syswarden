package config

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"time"

	"syswarden-cli/pkg/sshselection"
)

// ModuleEditRecovery keeps recovery authority opaque and single-use. The
// public review contains no TOML values, private file paths or original bytes.
type ModuleEditRecovery struct{ state *moduleEditRecoveryState }
type moduleEditRecoveryState struct {
	mu       sync.Mutex
	root     string
	target   tomlEditTarget
	observed *observedModuleEdit
	snapshot *mergedConfigSnapshot
	review   ModuleEditRecoveryReview
	used     bool
}

type ModuleEditRecoveryReview struct {
	Target             string
	State              string
	Action             string
	InputsChanged      bool
	ModulePlan         []string
	UnknownKeyCount    int
	DeprecatedKeyCount int
	ApprovalID         string
	ExpiresAt          time.Time
}

// PrepareModuleEditRecovery captures a fresh observation and all current
// inputs. It never treats an older publication approval as recovery consent.
func PrepareModuleEditRecovery(ctx context.Context, configDir string) (*ModuleEditRecovery, error) {
	observed, err := observeModuleEdit(ctx, configDir)
	if err != nil {
		return nil, err
	}
	action := ""
	switch observed.observation.State {
	case "prepared":
		action = "discard_unpublished_candidate"
	case "published_pending":
		action = "restore_original_file"
	case "committed_cleanup":
		action = "finish_committed_cleanup"
	case "rolled_back_cleanup":
		action = "finish_rollback_cleanup"
	default:
		return nil, errors.New("configuration edit has no unambiguous supported recovery action; preserve all evidence")
	}
	target, err := ordinaryTOMLTarget(observed.intent.Target)
	if err != nil {
		return nil, err
	}
	snapshot, content, err := captureModuleInputs(configDir, target, observed.identity)
	if err != nil {
		return nil, err
	}
	if err := snapshot.requireEditOwnership(os.Geteuid()); err != nil {
		return nil, err
	}
	var report ValidationReport
	if observed.observation.State == "committed_cleanup" {
		validated, err := validateModuleCandidateWithIntent(configDir, target, content, snapshot.identity(target), observed.identity)
		if err != nil {
			return nil, err
		}
		if !sameUserModuleBaseline(snapshot, validated) {
			return nil, errors.New("configuration changed during committed recovery validation")
		}
		report = validated.report
	}
	latest, err := observeModuleEdit(ctx, configDir)
	if err != nil {
		return nil, err
	}
	if latest.observation != observed.observation || !sameUserModuleIdentity(latest.identity, observed.identity) {
		return nil, errors.New("configuration edit changed while recovery was prepared")
	}
	if err := snapshot.revalidate(configDir, false, nil); err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("syswarden-module-edit-recovery-v1\x00"))
	_, _ = hash.Write(nonce[:])
	_, _ = hash.Write([]byte(configDir))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(observed.observation.RecordSHA256))
	review := ModuleEditRecoveryReview{Target: target.relative, State: observed.observation.State, Action: action,
		ModulePlan: append([]string(nil), report.ModulePlan...), UnknownKeyCount: len(report.UnknownKeys), DeprecatedKeyCount: len(report.DeprecatedKeys),
		InputsChanged: observed.observation.InputsChanged, ApprovalID: hex.EncodeToString(hash.Sum(nil)), ExpiresAt: time.Now().Add(userModuleReviewLifetime)}
	return &ModuleEditRecovery{state: &moduleEditRecoveryState{root: configDir, target: target, observed: observed, snapshot: snapshot, review: review}}, nil
}

func (plan *ModuleEditRecovery) Review() ModuleEditRecoveryReview {
	if plan == nil || plan.state == nil {
		return ModuleEditRecoveryReview{}
	}
	plan.state.mu.Lock()
	defer plan.state.mu.Unlock()
	review := plan.state.review
	review.ModulePlan = append([]string(nil), review.ModulePlan...)
	return review
}

// Apply requires exact fresh consent and a read-only lifecycle barrier. It
// performs only the supported file action; it never activates host policy.
func (plan *ModuleEditRecovery) Apply(ctx context.Context, approvalID string, preflight func() error) error {
	if plan == nil || plan.state == nil {
		return errors.New("configuration edit recovery plan is unavailable")
	}
	state := plan.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.used {
		return errors.New("configuration recovery approval was already consumed")
	}
	state.used = true
	if ctx == nil || preflight == nil || approvalID == "" || approvalID != state.review.ApprovalID {
		return errors.New("configuration recovery requires its exact approval, context and read-only lifecycle preflight")
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !time.Now().Before(state.review.ExpiresAt) {
			return errors.New("configuration recovery approval expired")
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
	if err := guard(); err != nil {
		return err
	}
	actual, _, err := captureModuleInputs(state.root, state.target, state.observed.identity)
	if err != nil {
		return err
	}
	if !sameUserModuleBaseline(state.snapshot, actual) {
		return errors.New("configuration changed after recovery review")
	}
	observed, err := observeModuleEdit(ctx, state.root)
	if err != nil {
		return err
	}
	if observed.observation != state.observed.observation || !sameUserModuleIdentity(observed.identity, state.observed.identity) {
		return errors.New("configuration edit pair changed after recovery review")
	}
	return applyModuleEditRecovery(state, guard)
}
