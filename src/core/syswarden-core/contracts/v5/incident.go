package v5

import (
	"errors"
	"fmt"
)

const IncidentRelationSchema = "syswarden.incident-relation.v1"

var (
	ErrInvalidIncidentDocument   = errors.New("invalid incident relation contract document")
	ErrUnsupportedIncidentSchema = errors.New("unsupported incident relation contract schema")
	ErrInvalidIncidentInput      = errors.New("invalid incident input context")
	ErrIncidentInputMismatch     = errors.New("incident relation does not match the expected inputs")
	ErrIncidentInputsUnavailable = errors.New("incident relation evidence is not fully identified")
)

// IncidentRecordReference pins a typed immutable endpoint. SHA256 covers its
// schema's Encode output, not arbitrary incoming JSON or an evidence payload.
type IncidentRecordReference struct {
	Schema   string `json:"schema"`
	RecordID string `json:"record_id"`
	SHA256   string `json:"sha256"`
}

func (r IncidentRecordReference) validate() bool {
	return member(EventSchema, NodeSnapshotSchema, PolicyDecisionSchema, ActionOutcomeSchema,
		ControlSnapshotSchema, EvidenceDescriptorSchema)(r.Schema) && identifier(r.RecordID) && digest(r.SHA256)
}

// IncidentRelation is one immutable, directed claim in a node-local incident.
// Association does not imply causality; a causal hypothesis remains a claim
// even when its producer reports supporting evidence. No severity, verdict,
// successful action or current protection is computed from this record.
type IncidentRelation struct {
	Schema       string                  `json:"schema"`
	RelationID   string                  `json:"relation_id"`
	IncidentID   string                  `json:"incident_id"`
	Identity     NodeIdentity            `json:"identity"`
	CorrelatorID string                  `json:"correlator_id"`
	RecordedAt   string                  `json:"recorded_at"`
	ClockQuality string                  `json:"clock_quality"`
	RuleRef      string                  `json:"rule_ref"`
	RuleSHA256   string                  `json:"rule_sha256"`
	From         IncidentRecordReference `json:"from"`
	To           IncidentRecordReference `json:"to"`
	Kind         string                  `json:"kind"`
	Support      Field                   `json:"support"`
	ReasonCode   Field                   `json:"reason_code"`
	Evidence     EvidenceReference       `json:"evidence"`
}

func invalidIncident(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidIncidentDocument, field)
}

// Validate checks declared structure, not correlation correctness. Evidence
// references identify descriptor metadata; they do not prove payload quality.
func (r IncidentRelation) Validate() error {
	if r.Schema != IncidentRelationSchema {
		return ErrUnsupportedIncidentSchema
	}
	if r.Identity.Validate() != nil {
		return invalidIncident("identity")
	}
	for _, id := range []string{r.RelationID, r.IncidentID, r.CorrelatorID, r.RuleRef} {
		if !identifier(id) {
			return invalidIncident("relation, incident, correlator or rule identifier")
		}
	}
	if !digest(r.RuleSHA256) || !timestamp(r.RecordedAt) ||
		!member("unknown", "synchronized", "unsynchronized")(r.ClockQuality) {
		return invalidIncident("rule digest, time or clock quality")
	}
	if !r.From.validate() || !r.To.validate() ||
		(r.From.Schema == r.To.Schema && r.From.RecordID == r.To.RecordID) {
		return invalidIncident("distinct typed endpoints")
	}
	if !member("association", "causal_hypothesis")(r.Kind) ||
		!r.Support.validate(member("supporting", "contradicting", "inconclusive")) ||
		!r.ReasonCode.validate(identifier) || !r.Evidence.validate() {
		return invalidIncident("relationship kind, support or explanation")
	}
	if r.Support.hasValue() && (r.ReasonCode.State != Present || r.Evidence.Ref.State != Present) {
		return invalidIncident("assessment without identified explanation")
	}
	return nil
}

// ResolvedIncidentRecord comes from an independently authenticated and
// scope-authorized immutable journal. Identity must describe its actual
// ingestion generation; copying the relation's identity defeats isolation.
type ResolvedIncidentRecord struct {
	Identity NodeIdentity
	Schema   string
	Data     []byte
}

// IncidentReadContext supplies independently resolved incident membership,
// a resolved rule digest and endpoint/evidence records. It does not
// assert that the correlator or the evidence's semantic claims are truthful.
type IncidentReadContext struct {
	ExpectedIdentity NodeIdentity
	RelationID       string
	IncidentID       string
	RuleRef          string
	RuleSHA256       string
	From             ResolvedIncidentRecord
	To               ResolvedIncidentRecord
	Evidence         EvidenceDescriptor
}

// CheckIncidentRelationBinding checks exact ordered inputs. Nil may describe
// contradictory, stale or missing support and unavailable evidence payloads.
// It never approves the relationship, establishes causal order or authorizes
// an action. Readers must preserve all explicit assessments and availability.
func CheckIncidentRelationBinding(r IncidentRelation, context IncidentReadContext) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if context.ExpectedIdentity.Validate() != nil || !identifier(context.RelationID) ||
		!identifier(context.IncidentID) || !identifier(context.RuleRef) || !digest(context.RuleSHA256) {
		return ErrInvalidIncidentInput
	}
	from, err := IncidentRecordReferenceFromJSON(context.From)
	if err != nil {
		return err
	}
	to, err := IncidentRecordReferenceFromJSON(context.To)
	if err != nil {
		return err
	}
	if r.Identity != context.ExpectedIdentity || context.From.Identity != r.Identity || context.To.Identity != r.Identity ||
		r.RelationID != context.RelationID || r.IncidentID != context.IncidentID ||
		r.RuleRef != context.RuleRef || r.RuleSHA256 != context.RuleSHA256 || r.From != from || r.To != to {
		return ErrIncidentInputMismatch
	}
	if r.Evidence.Ref.State != Present {
		return ErrIncidentInputsUnavailable
	}
	hash, err := EvidenceDescriptorSHA256(context.Evidence)
	if err != nil {
		return ErrInvalidIncidentInput
	}
	if context.Evidence.Identity != r.Identity || context.Evidence.EvidenceID != r.Evidence.Ref.Value || hash != r.Evidence.SHA256.Value {
		return ErrIncidentInputMismatch
	}
	return nil
}
