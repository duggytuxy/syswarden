package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

const EvidenceDescriptorSchema = "syswarden.evidence-descriptor.v1"

var (
	ErrInvalidEvidenceDocument   = errors.New("invalid evidence descriptor contract document")
	ErrUnsupportedEvidenceSchema = errors.New("unsupported evidence descriptor contract schema")
	ErrInvalidEvidenceContext    = errors.New("invalid evidence read context")
	ErrEvidenceBindingMismatch   = errors.New("evidence does not match the expected record")
	ErrEvidencePayloadMismatch   = errors.New("evidence payload is unavailable, exceeds budget or does not match")
	ErrEvidenceParentMismatch    = errors.New("evidence parent does not match the declared lineage")
)

// EvidenceContent describes exact stored bytes. Partial and stale descriptors
// retain their labels even when those bytes can be hashed. References are
// opaque identifiers, never paths, URLs or permission to load content.
type EvidenceContent struct {
	Ref       Field `json:"ref"`
	SHA256    Field `json:"sha256"`
	SizeBytes Field `json:"size_bytes"`
}

// EvidenceReference pins one immutable record. For Parent, Ref is an evidence
// ID and SHA256 covers EncodeEvidenceDescriptor bytes. For Transformation,
// SHA256 covers the exact transformation-definition bytes, not its name.
type EvidenceReference struct {
	Ref    Field `json:"ref"`
	SHA256 Field `json:"sha256"`
}

// EvidenceDescriptor is a collector's historical statement about an object.
// It is not a signed capsule, an authenticity verdict, a completeness claim
// about a capture or an incident, or an authorization to disclose its content.
type EvidenceDescriptor struct {
	Schema         string            `json:"schema"`
	EvidenceID     string            `json:"evidence_id"`
	Identity       NodeIdentity      `json:"identity"`
	CollectorID    string            `json:"collector_id"`
	SourceID       string            `json:"source_id"`
	CollectedAt    string            `json:"collected_at"`
	ClockQuality   string            `json:"clock_quality"`
	Representation string            `json:"representation"`
	Content        EvidenceContent   `json:"content"`
	Parent         EvidenceReference `json:"parent"`
	Transformation EvidenceReference `json:"transformation"`
}

func invalidEvidence(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidEvidenceDocument, field)
}

// Decimal strings avoid lossy JSON numeric conversions. This is a wire range,
// not an allocation budget. Payload readers must impose their own byte limit.
func evidenceSize(value string) bool {
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n >= 0 && strconv.FormatInt(n, 10) == value
}

func (r EvidenceReference) validate() bool {
	return r.Ref.validate(identifier) && r.SHA256.validate(digest) && r.Ref.State == r.SHA256.State
}

// Validate checks declared coherence only. Presence identifies exact bytes,
// not their accessibility, confidentiality, authenticity or evidentiary value.
func (e EvidenceDescriptor) Validate() error {
	if e.Schema != EvidenceDescriptorSchema {
		return ErrUnsupportedEvidenceSchema
	}
	if e.Identity.Validate() != nil {
		return invalidEvidence("identity")
	}
	for _, id := range []string{e.EvidenceID, e.CollectorID, e.SourceID} {
		if !identifier(id) {
			return invalidEvidence("evidence, collector or source identifier")
		}
	}
	if !timestamp(e.CollectedAt) || !member("unknown", "synchronized", "unsynchronized")(e.ClockQuality) {
		return invalidEvidence("collection time or clock quality")
	}
	c := e.Content
	if !c.Ref.validate(identifier) || !c.SHA256.validate(digest) || !c.SizeBytes.validate(evidenceSize) ||
		c.Ref.State != c.SHA256.State || c.Ref.State != c.SizeBytes.State {
		return invalidEvidence("content reference, digest or size")
	}
	if !e.Parent.validate() || !e.Transformation.validate() {
		return invalidEvidence("lineage reference or digest")
	}
	switch e.Representation {
	case "original":
		if e.Parent.Ref.State != NotApplicable || e.Transformation.Ref.State != NotApplicable {
			return invalidEvidence("original with transformation lineage")
		}
	case "redacted", "derived":
		if e.Parent.Ref.State != Present || e.Transformation.Ref.State != Present || e.Parent.Ref.Value == e.EvidenceID {
			return invalidEvidence("transformed object without distinct identified parent and transformation")
		}
	case "unknown":
		for _, field := range []Field{c.Ref, e.Parent.Ref, e.Transformation.Ref} {
			if !member(Missing, Unavailable, Rejected)(field.State) {
				return invalidEvidence("unknown representation with asserted content or lineage")
			}
		}
	default:
		return invalidEvidence("representation")
	}
	return nil
}

// EvidenceDescriptorSHA256 hashes the validated, deterministic descriptor
// encoding. It is distinct from Content.SHA256, which covers the raw object.
func EvidenceDescriptorSHA256(e EvidenceDescriptor) (string, error) {
	data, err := EncodeEvidenceDescriptor(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// EvidenceReadContext must come from separately authenticated, authorized,
// immutable journal context. MaxBytes is an explicit caller budget, not a
// size received from the descriptor. Apply it before loading the payload too.
type EvidenceReadContext struct {
	ExpectedIdentity NodeIdentity
	EvidenceID       string
	DescriptorSHA256 string
	MaxBytes         int64
}

// CheckEvidencePayloadBinding hashes only caller-supplied bytes within the
// explicit budget. Success means exact byte binding, including for redacted
// or derived objects. It never means original, complete, authentic, safe to
// render/export, current, causally relevant or sufficient to act on.
func CheckEvidencePayloadBinding(e EvidenceDescriptor, context EvidenceReadContext, payload []byte) error {
	hash, err := EvidenceDescriptorSHA256(e)
	if err != nil {
		return err
	}
	if context.ExpectedIdentity.Validate() != nil || !identifier(context.EvidenceID) ||
		!digest(context.DescriptorSHA256) || context.MaxBytes <= 0 {
		return ErrInvalidEvidenceContext
	}
	if e.Identity != context.ExpectedIdentity || e.EvidenceID != context.EvidenceID || hash != context.DescriptorSHA256 {
		return ErrEvidenceBindingMismatch
	}
	if e.Content.Ref.State != Present || int64(len(payload)) > context.MaxBytes ||
		e.Content.SizeBytes.Value != strconv.FormatInt(int64(len(payload)), 10) {
		return ErrEvidencePayloadMismatch
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != e.Content.SHA256.Value {
		return ErrEvidencePayloadMismatch
	}
	return nil
}

// CheckEvidenceParentBinding checks one local lineage edge, not a graph,
// transformation execution or custody chain. Both records still require
// independent authentication and scope authorization before trusted use.
func CheckEvidenceParentBinding(child, parent EvidenceDescriptor) error {
	if err := child.Validate(); err != nil {
		return err
	}
	hash, err := EvidenceDescriptorSHA256(parent)
	if err != nil {
		return err
	}
	if !member("redacted", "derived")(child.Representation) || child.Identity != parent.Identity ||
		child.Parent.Ref.Value != parent.EvidenceID || child.Parent.SHA256.Value != hash {
		return ErrEvidenceParentMismatch
	}
	return nil
}
