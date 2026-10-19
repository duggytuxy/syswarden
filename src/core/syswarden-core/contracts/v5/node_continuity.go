package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	NodeRegistryGenerationSchema = "syswarden.node-registry-generation.v1"
	NodeRegistryCheckpointSchema = "syswarden.node-registry-checkpoint.v1"
	MaxNodeContinuityBytes       = 4096
)

var (
	ErrInvalidNodeContinuity = errors.New("invalid node registry continuity record")
	ErrNodeContinuityBinding = errors.New("node registry differs from independently expected continuity")
	ErrNodeContinuityChange  = errors.New("node registry change requires separate recovery or retention approval")
)

// NodeRegistryGeneration is an independent administration generation, not the
// hash of a snapshot containing its own grants. Trust and Administration name
// separately provisioned policies; neither a reference nor this record signs,
// loads or authenticates them. No browser or node may choose these inputs.
type NodeRegistryGeneration struct {
	Schema         string        `json:"schema"`
	GenerationID   string        `json:"generation_id"`
	AuthorityID    string        `json:"authority_id"`
	LineageID      string        `json:"lineage_id"`
	Policy         RateReference `json:"policy"`
	ClientTrust    RateReference `json:"client_trust"`
	Administration RateReference `json:"administration"`
}

func (g NodeRegistryGeneration) Validate() error {
	if g.Schema != NodeRegistryGenerationSchema || !identifier(g.GenerationID) || !identifier(g.AuthorityID) ||
		!identifier(g.LineageID) || !g.Policy.validate() || !g.ClientTrust.validate() || !g.Administration.validate() {
		return ErrInvalidNodeContinuity
	}
	return nil
}

func (g NodeRegistryGeneration) Reference() (RateReference, error) {
	data, err := EncodeNodeRegistryGeneration(g)
	if err != nil {
		return RateReference{}, err
	}
	return RateReference{Ref: g.GenerationID, SHA256: nodeBytesSHA256(data)}, nil
}

// NodeRegistryCheckpoint is public metadata for a future protected writer. Its
// digest is not an approval, signature, witness or durable acknowledgement.
// Sequence is canonical unsigned decimal to avoid JSON number precision loss.
type NodeRegistryCheckpoint struct {
	Schema         string        `json:"schema"`
	CheckpointID   string        `json:"checkpoint_id"`
	AuthorityID    string        `json:"authority_id"`
	LineageID      string        `json:"lineage_id"`
	Sequence       string        `json:"sequence"`
	PreviousSHA256 string        `json:"previous_sha256"`
	Generation     RateReference `json:"generation"`
	Snapshot       RateReference `json:"snapshot"`
	State          string        `json:"state"`
}

func (c NodeRegistryCheckpoint) Validate() error {
	n, err := strconv.ParseUint(c.Sequence, 10, 64)
	if c.Schema != NodeRegistryCheckpointSchema || !identifier(c.CheckpointID) || !identifier(c.AuthorityID) ||
		!identifier(c.LineageID) || err != nil || n == 0 || strconv.FormatUint(n, 10) != c.Sequence ||
		!digest(c.PreviousSHA256) || !c.Generation.validate() || !c.Snapshot.validate() || !member("active", "disabled")(c.State) {
		return ErrInvalidNodeContinuity
	}
	// The genesis sentinel is not a substitute for independent initial approval.
	if (n == 1) != (c.PreviousSHA256 == nodeContinuityGenesis) {
		return ErrInvalidNodeContinuity
	}
	return nil
}

const nodeContinuityGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

func (c NodeRegistryCheckpoint) Reference() (RateReference, error) {
	data, err := EncodeNodeRegistryCheckpoint(c)
	if err != nil {
		return RateReference{}, err
	}
	return RateReference{Ref: c.CheckpointID, SHA256: nodeBytesSHA256(data)}, nil
}

func encodeNodeContinuity[T interface{ Validate() error }](v T) ([]byte, error) {
	if v.Validate() != nil {
		return nil, ErrInvalidNodeContinuity
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxNodeContinuityBytes {
		return nil, ErrInvalidNodeContinuity
	}
	return b, nil
}

func decodeNodeContinuity[T interface{ Validate() error }](b []byte) (T, error) {
	var v, zero T
	if len(b) == 0 || len(b) > MaxNodeContinuityBytes || json.Unmarshal(b, &v) != nil {
		return zero, ErrInvalidNodeContinuity
	}
	canonical, err := encodeNodeContinuity(v)
	// Exact re-encoding rejects duplicates, missing/unknown fields, null aliases,
	// case folding, lossy Unicode and whitespace/order variants before use.
	if err != nil || !bytes.Equal(b, canonical) {
		return zero, ErrInvalidNodeContinuity
	}
	return v, nil
}

func EncodeNodeRegistryGeneration(g NodeRegistryGeneration) ([]byte, error) {
	return encodeNodeContinuity(g)
}
func DecodeNodeRegistryGeneration(b []byte) (NodeRegistryGeneration, error) {
	return decodeNodeContinuity[NodeRegistryGeneration](b)
}
func EncodeNodeRegistryCheckpoint(c NodeRegistryCheckpoint) ([]byte, error) {
	return encodeNodeContinuity(c)
}
func DecodeNodeRegistryCheckpoint(b []byte) (NodeRegistryCheckpoint, error) {
	return decodeNodeContinuity[NodeRegistryCheckpoint](b)
}

// NodeRegistryContinuityContext comes from independent current custody, not from
// the candidate, adjacent files, an uploaded backup or a cached prior read.
// There is deliberately no fallback that adopts the highest presented sequence.
type NodeRegistryContinuityContext struct {
	AuthorityID string
	LineageID   string
	Generation  RateReference
	Checkpoint  RateReference
}

func checkNodeContinuity(g NodeRegistryGeneration, c NodeRegistryCheckpoint, r NodeAdmissionRegistry, expected NodeRegistryContinuityContext) error {
	gr, ge := g.Reference()
	cr, ce := c.Reference()
	if ge != nil || ce != nil || !identifier(expected.AuthorityID) || !identifier(expected.LineageID) ||
		!expected.Generation.validate() || !expected.Checkpoint.validate() {
		return ErrInvalidNodeContinuity
	}
	if g.AuthorityID != expected.AuthorityID || g.LineageID != expected.LineageID || gr != expected.Generation ||
		c.AuthorityID != g.AuthorityID || c.LineageID != g.LineageID || c.Generation != gr || cr != expected.Checkpoint ||
		len(r.manifest) == 0 || c.Snapshot != r.reference || r.binding != (NodeAdmissionRegistryBinding{Registry: gr, Policy: g.Policy}) {
		return ErrNodeContinuityBinding
	}
	return nil
}

// NodeRegistryReadContext derives a snapshot-bound context only after exact
// independent continuity checks. It is not a reusable lease. The future writer
// must serialize this check with durable admission and revocation at each use.
func NodeRegistryReadContext(g NodeRegistryGeneration, c NodeRegistryCheckpoint, r NodeAdmissionRegistry, expected NodeRegistryContinuityContext, now time.Time) (NodeAdmissionRegistryReadContext, error) {
	if err := checkNodeContinuity(g, c, r, expected); err != nil {
		return NodeAdmissionRegistryReadContext{}, err
	}
	if c.State != "active" {
		return NodeAdmissionRegistryReadContext{}, ErrNodeRegistryNotAdmitted
	}
	ctx := NodeAdmissionRegistryReadContext{Snapshot: c.Snapshot, Binding: r.binding, Now: now}
	if err := r.checkContext(ctx); err != nil {
		return NodeAdmissionRegistryReadContext{}, err
	}
	return ctx, nil
}

// CheckNodeRegistryAdvance validates a separately approved ordinary transition.
// ApprovedNext must be authenticated independently of next. It authorizes exact
// bytes only, and does not itself prove who approved them. This pure component
// neither stores/consumes approval nor excludes racing writers or replay.
// Generation, lineage, reactivation, retention and epoch recovery are excluded.
func CheckNodeRegistryAdvance(g NodeRegistryGeneration, before NodeRegistryCheckpoint, current NodeAdmissionRegistry,
	next NodeRegistryCheckpoint, candidate NodeAdmissionRegistry, expected NodeRegistryContinuityContext, approvedNext RateReference) error {
	if err := checkNodeContinuity(g, before, current, expected); err != nil {
		return err
	}
	proposal := expected
	proposal.Checkpoint = approvedNext
	if err := checkNodeContinuity(g, next, candidate, proposal); err != nil {
		return err
	}
	n, _ := strconv.ParseUint(before.Sequence, 10, 64)
	m, _ := strconv.ParseUint(next.Sequence, 10, 64)
	if n == math.MaxUint64 || m != n+1 || next.PreviousSHA256 != expected.Checkpoint.SHA256 ||
		next.CheckpointID == before.CheckpointID || (before.State == "disabled" && next.State != "disabled") ||
		(current.reference.Ref == candidate.reference.Ref && current.reference != candidate.reference) {
		return ErrNodeContinuityChange
	}
	return retainNodeRegistryHistory(current, candidate)
}
