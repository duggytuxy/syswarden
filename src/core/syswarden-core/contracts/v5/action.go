package v5

import (
	"errors"
	"fmt"
)

const ActionOutcomeSchema = "syswarden.action-outcome.v1"

var (
	ErrInvalidActionDocument   = errors.New("invalid action outcome contract document")
	ErrUnsupportedActionSchema = errors.New("unsupported action outcome contract schema")
	ErrInvalidActionContext    = errors.New("invalid action outcome read context")
	ErrActionBindingMismatch   = errors.New("action outcome does not match the expected attempt and plan")
)

// ActionOutcome is one immutable report about one action attempt, not an
// executable request or a transaction state machine. Retries need explicit
// attempt identity; timestamps alone cannot order concurrent attempts.
type ActionOutcome struct {
	Schema          string       `json:"schema"`
	OutcomeID       string       `json:"outcome_id"`
	ActionID        string       `json:"action_id"`
	AttemptID       string       `json:"attempt_id"`
	Identity        NodeIdentity `json:"identity"`
	Scope           ControlScope `json:"scope"`
	ReporterID      string       `json:"reporter_id"`
	RecordedAt      string       `json:"recorded_at"`
	ClockQuality    string       `json:"clock_quality"`
	PlanRef         string       `json:"plan_ref"`
	PlanSHA256      string       `json:"plan_sha256"`
	State           string       `json:"state"`
	AuthorityRef    Field        `json:"authority_ref"`
	ReasonCode      Field        `json:"reason_code"`
	EvidenceRef     Field        `json:"evidence_ref"`
	VerificationRef Field        `json:"verification_ref"`
}

func invalidAction(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidActionDocument, field)
}

// Validate checks bounded historical claims. A reference being present does not
// prove its content, authority, durable commit, successful rollback or effect.
func (a ActionOutcome) Validate() error {
	if a.Schema != ActionOutcomeSchema {
		return ErrUnsupportedActionSchema
	}
	if a.Identity.Validate() != nil || a.Scope.Validate() != nil {
		return invalidAction("identity or scope")
	}
	for _, id := range []string{a.OutcomeID, a.ActionID, a.AttemptID, a.ReporterID, a.PlanRef} {
		if !identifier(id) {
			return invalidAction("record, attempt, reporter or plan identifier")
		}
	}
	if !digest(a.PlanSHA256) || !timestamp(a.RecordedAt) ||
		!member("unknown", "synchronized", "unsynchronized")(a.ClockQuality) {
		return invalidAction("plan digest, time or clock quality")
	}
	if !member("pending", "applied", "verified", "expired", "rolled_back", "failed", "partial", "unknown")(a.State) {
		return invalidAction("outcome state")
	}
	for _, field := range []Field{a.AuthorityRef, a.ReasonCode, a.EvidenceRef, a.VerificationRef} {
		if !field.validate(identifier) {
			return invalidAction("outcome evidence reference")
		}
	}
	if a.State != "unknown" && (a.ReasonCode.State != Present || a.EvidenceRef.State != Present) {
		return invalidAction("outcome without identified explanation")
	}
	if member("applied", "verified", "rolled_back", "partial")(a.State) && a.AuthorityRef.State != Present {
		return invalidAction("reported effect without identified authority")
	}
	if member("verified", "rolled_back")(a.State) && a.VerificationRef.State != Present {
		return invalidAction("verified outcome without verification reference")
	}
	return nil
}

// ActionReadContext must come from separately authenticated and authorized
// immutable attempt/plan records. The plan digest covers their exact plan bytes;
// this contract neither defines that executable plan nor approves its use.
type ActionReadContext struct {
	ExpectedIdentity NodeIdentity
	ExpectedScope    ControlScope
	ActionID         string
	AttemptID        string
	PlanRef          string
	PlanSHA256       string
}

// CheckActionOutcomeBinding compares one historical report with an exact
// resolved attempt and plan. Success does not mean the action succeeded and
// never establishes current control, permission to retry or a safe rollback.
func CheckActionOutcomeBinding(a ActionOutcome, context ActionReadContext) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if context.ExpectedIdentity.Validate() != nil || context.ExpectedScope.Validate() != nil ||
		!identifier(context.ActionID) || !identifier(context.AttemptID) ||
		!identifier(context.PlanRef) || !digest(context.PlanSHA256) {
		return ErrInvalidActionContext
	}
	if a.Identity != context.ExpectedIdentity || a.Scope != context.ExpectedScope ||
		a.ActionID != context.ActionID || a.AttemptID != context.AttemptID ||
		a.PlanRef != context.PlanRef || a.PlanSHA256 != context.PlanSHA256 {
		return ErrActionBindingMismatch
	}
	return nil
}
