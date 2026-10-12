package v5

import (
	"errors"
	"fmt"
	"time"
)

const ControlSnapshotSchema = "syswarden.control-snapshot.v1"

var (
	ErrInvalidControlDocument   = errors.New("invalid control snapshot contract document")
	ErrUnsupportedControlSchema = errors.New("unsupported control snapshot contract schema")
	ErrInvalidControlScope      = errors.New("invalid control scope")
	ErrInvalidControlContext    = errors.New("invalid control snapshot read context")
	ErrControlScopeMismatch     = errors.New("control snapshot does not match the expected scope")
	ErrControlNotCurrent        = errors.New("control snapshot lacks complete current verification metadata")
)

// ControlScope names one owner's exact control and immutable target definition.
// These opaque references neither resolve a target nor prove ownership. A match
// does not grant authority over another owner's claims or a whole shared table.
type ControlScope struct {
	ControlID    string `json:"control_id"`
	TargetRef    string `json:"target_ref"`
	TargetSHA256 string `json:"target_sha256"`
	OwnerID      string `json:"owner_id"`
}

func (s ControlScope) Validate() error {
	if !identifier(s.ControlID) || !identifier(s.TargetRef) ||
		!digest(s.TargetSHA256) || !identifier(s.OwnerID) {
		return ErrInvalidControlScope
	}
	return nil
}

// ControlSnapshot is a scoped verifier report, independent of action history.
// Effective and absent describe only the exact resolved control definition.
// Neither means that all traffic is blocked, allowed or harmless.
type ControlSnapshot struct {
	Schema          string       `json:"schema"`
	SnapshotID      string       `json:"snapshot_id"`
	Identity        NodeIdentity `json:"identity"`
	Scope           ControlScope `json:"scope"`
	ObserverID      string       `json:"observer_id"`
	CollectedAt     string       `json:"collected_at"`
	ValidUntil      string       `json:"valid_until"`
	ObservedAt      Field        `json:"observed_at"`
	ClockQuality    string       `json:"clock_quality"`
	Basis           string       `json:"basis"`
	State           Field        `json:"state"`
	EffectExpiresAt Field        `json:"effect_expires_at"`
	EvidenceRef     Field        `json:"evidence_ref"`
	ActionRef       Field        `json:"action_ref"`
}

func invalidControl(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidControlDocument, field)
}

// Validate checks bounded shape and claims for coherence, not their truth.
// Clock-skewed or expired reports may remain decodable as historical evidence.
func (s ControlSnapshot) Validate() error {
	if s.Schema != ControlSnapshotSchema {
		return ErrUnsupportedControlSchema
	}
	if s.Identity.Validate() != nil || s.Scope.Validate() != nil {
		return invalidControl("identity or scope")
	}
	if !identifier(s.SnapshotID) || !identifier(s.ObserverID) {
		return invalidControl("snapshot or observer identifier")
	}
	if !timestamp(s.CollectedAt) || !timestamp(s.ValidUntil) {
		return invalidControl("collection timestamps")
	}
	collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if !until.After(collected) || until.Sub(collected) > MaxSnapshotLifetime {
		return invalidControl("snapshot lifetime")
	}
	if !s.ObservedAt.validate(timestamp) || !member("unknown", "synchronized", "unsynchronized")(s.ClockQuality) {
		return invalidControl("observation time or clock quality")
	}
	if !member("live_verification", "cached", "unavailable")(s.Basis) {
		return invalidControl("verification basis")
	}
	if !s.State.validate(member("effective", "absent")) || !s.EffectExpiresAt.validate(timestamp) ||
		!s.EvidenceRef.validate(identifier) || !s.ActionRef.validate(identifier) {
		return invalidControl("state or evidence references")
	}
	if s.State.hasValue() && (!s.ObservedAt.hasValue() || !s.EvidenceRef.hasValue()) {
		return invalidControl("state without observation and evidence")
	}
	if s.State.State == Present && (s.Basis != "live_verification" ||
		s.ObservedAt.State != Present || s.EvidenceRef.State != Present) {
		return invalidControl("present state without live verification metadata")
	}
	if s.State.State == Present && s.State.Value == "absent" && s.EffectExpiresAt.State != NotApplicable {
		return invalidControl("absent control with effect expiry")
	}
	for _, field := range []Field{s.State, s.ObservedAt, s.EffectExpiresAt, s.EvidenceRef} {
		if s.Basis == "cached" && field.hasValue() && field.State != Stale {
			return invalidControl("cached verification must remain stale")
		}
		if s.Basis == "unavailable" && field.hasValue() {
			return invalidControl("unavailable verification with a retained value")
		}
	}
	return nil
}

// ControlReadContext comes from authorized scope resolution, current membership
// and local freshness policy. Do not copy it from an untrusted report.
type ControlReadContext struct {
	ExpectedIdentity NodeIdentity
	ExpectedScope    ControlScope
	Now              time.Time
	MaxAge           time.Duration
}

// CheckCurrentControlSnapshot checks exact scope and complete, fresh declared
// verification metadata. It does not authenticate the observer or verify the
// referenced evidence. Those are separate obligations before trusted display.
// Success may describe absence: callers must inspect State.Value. No action
// result or transport health can substitute for an actual verifier report.
func CheckCurrentControlSnapshot(s ControlSnapshot, context ControlReadContext) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if context.ExpectedIdentity.Validate() != nil || context.ExpectedScope.Validate() != nil ||
		context.MaxAge <= 0 || context.MaxAge > MaxSnapshotLifetime ||
		!timestamp(context.Now.UTC().Format(time.RFC3339Nano)) {
		return ErrInvalidControlContext
	}
	if s.Identity != context.ExpectedIdentity || s.Scope != context.ExpectedScope {
		return ErrControlScopeMismatch
	}
	if s.Basis != "live_verification" || s.State.State != Present ||
		s.ObservedAt.State != Present || s.EvidenceRef.State != Present || s.ClockQuality != "synchronized" {
		return ErrControlNotCurrent
	}
	collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	observed, _ := time.Parse(time.RFC3339Nano, s.ObservedAt.Value)
	if observed.After(collected) || context.Now.Before(collected) ||
		!context.Now.Before(until) || context.Now.Sub(observed) >= context.MaxAge {
		return ErrControlNotCurrent
	}
	// A fresh report cannot outlive the independently observed control TTL.
	// NotApplicable is a positive verifier statement that this control has no
	// expiry, not a fallback for missing or unresolvable lifetime metadata.
	if s.State.Value == "effective" {
		switch s.EffectExpiresAt.State {
		case Present:
			expires, _ := time.Parse(time.RFC3339Nano, s.EffectExpiresAt.Value)
			if !expires.After(observed) || !context.Now.Before(expires) {
				return ErrControlNotCurrent
			}
		case NotApplicable:
		default:
			return ErrControlNotCurrent
		}
	}
	return nil
}
