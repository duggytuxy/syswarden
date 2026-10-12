package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const PolicyDecisionSchema = "syswarden.policy-decision.v1"

var (
	ErrInvalidDecisionDocument   = errors.New("invalid policy decision contract document")
	ErrUnsupportedDecisionSchema = errors.New("unsupported policy decision contract schema")
	ErrInvalidDecisionInput      = errors.New("invalid policy decision input context")
	ErrDecisionInputMismatch     = errors.New("policy decision does not match the expected inputs")
)

// DecisionInput pins an immutable event representation, not just a reusable
// event identifier. EventSHA256 covers EncodeEvent bytes, not raw input JSON.
type DecisionInput struct {
	EventID     string `json:"event_id"`
	EventSHA256 string `json:"event_sha256"`
}

// PolicyDecision records a core evaluation. A block verdict is an intended
// disposition, never proof of execution or current enforcement. An allow
// verdict does not grant trust, operator permission or exemption from another
// policy. No field in this record authorizes an action.
type PolicyDecision struct {
	Schema       string        `json:"schema"`
	DecisionID   string        `json:"decision_id"`
	Identity     NodeIdentity  `json:"identity"`
	EvaluatorID  string        `json:"evaluator_id"`
	EvaluatedAt  string        `json:"evaluated_at"`
	ClockQuality string        `json:"clock_quality"`
	Input        DecisionInput `json:"input"`
	PolicyRef    Field         `json:"policy_ref"`
	PolicySHA256 Field         `json:"policy_sha256"`
	Verdict      Field         `json:"verdict"`
	Severity     Field         `json:"severity"`
	ReasonCode   Field         `json:"reason_code"`
	EvidenceRef  Field         `json:"evidence_ref"`
}

func invalidDecision(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDecisionDocument, field)
}

// Validate checks bounded syntax and internal coherence. It cannot verify the
// evaluator, referenced policy, evidence quality or the truth of a verdict.
func (d PolicyDecision) Validate() error {
	if d.Schema != PolicyDecisionSchema {
		return ErrUnsupportedDecisionSchema
	}
	if err := d.Identity.Validate(); err != nil {
		return invalidDecision("identity")
	}
	if !identifier(d.DecisionID) || !identifier(d.EvaluatorID) || !identifier(d.Input.EventID) {
		return invalidDecision("decision, evaluator or event identifier")
	}
	if !digest(d.Input.EventSHA256) {
		return invalidDecision("event digest")
	}
	if !timestamp(d.EvaluatedAt) || !member("unknown", "synchronized", "unsynchronized")(d.ClockQuality) {
		return invalidDecision("evaluation time or clock quality")
	}
	for _, item := range []struct {
		name  string
		field Field
	}{
		{"policy_ref", d.PolicyRef}, {"reason_code", d.ReasonCode}, {"evidence_ref", d.EvidenceRef},
	} {
		if !item.field.validate(identifier) {
			return invalidDecision(item.name)
		}
	}
	if !d.PolicySHA256.validate(digest) || d.PolicyRef.State != d.PolicySHA256.State {
		return invalidDecision("policy reference and digest")
	}
	if !d.Verdict.validate(member("allow", "block", "observe")) {
		return invalidDecision("verdict")
	}
	if !d.Severity.validate(member("informational", "low", "medium", "high", "critical")) {
		return invalidDecision("severity")
	}
	// Even a retained stale or partial classification needs identified inputs
	// and an explanation reference. Present references identify immutable
	// records; they do not attest current policy, accessibility or completeness.
	if d.Verdict.hasValue() || d.Severity.hasValue() {
		for _, field := range []Field{d.PolicyRef, d.PolicySHA256, d.ReasonCode, d.EvidenceRef} {
			if field.State != Present {
				return invalidDecision("classification without identified policy and explanation")
			}
		}
	}
	return nil
}

// DecisionEventSHA256 hashes the entire validated EncodeEvent representation.
// Availability must identify the exact event and node. The digest is neither
// an authentication proof nor the hash of the original sensor input bytes.
func DecisionEventSHA256(event Event) (string, error) {
	data, err := EncodeEvent(event)
	if err != nil || event.EventID.State != Present || event.NodeID.State != Present {
		return "", ErrInvalidDecisionInput
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// DecisionReadContext comes from separately authenticated, scope-authorized
// immutable journal and policy records, never from the decision itself.
// EventIdentity binds the event's ingestion generation: Event.NodeID alone
// cannot establish cluster or epoch. Historical review may use an old epoch.
type DecisionReadContext struct {
	EventIdentity NodeIdentity
	Event         Event
	PolicyRef     string
	PolicySHA256  string
}

// CheckPolicyDecisionBinding compares exact inputs without interpreting the
// verdict. It does not authenticate, authorize, track replay, check freshness,
// recompute classification or permit enforcement. Success can describe a stale,
// partial or absent verdict, which consumers must continue to display as such.
func CheckPolicyDecisionBinding(d PolicyDecision, context DecisionReadContext) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if err := context.EventIdentity.Validate(); err != nil {
		return ErrInvalidDecisionInput
	}
	if !identifier(context.PolicyRef) || !digest(context.PolicySHA256) {
		return ErrInvalidDecisionInput
	}
	hash, err := DecisionEventSHA256(context.Event)
	if err != nil || context.Event.NodeID.Value != context.EventIdentity.NodeID {
		return ErrInvalidDecisionInput
	}
	if d.Identity != context.EventIdentity || d.Input.EventID != context.Event.EventID.Value ||
		d.Input.EventSHA256 != hash || d.PolicyRef.State != Present || d.PolicySHA256.State != Present ||
		d.PolicyRef.Value != context.PolicyRef || d.PolicySHA256.Value != context.PolicySHA256 {
		return ErrDecisionInputMismatch
	}
	return nil
}
