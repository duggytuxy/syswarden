package v5

import (
	"errors"
	"fmt"
	"time"
)

const NodeSnapshotSchema = "syswarden.node-snapshot.v1"

// MaxSnapshotLifetime is a wire bound, not an operational freshness default.
// Each reader must supply its own stricter maximum age where required.
const MaxSnapshotLifetime = 24 * time.Hour

var (
	ErrInvalidNodeDocument    = errors.New("invalid node snapshot contract document")
	ErrUnsupportedNodeSchema  = errors.New("unsupported node snapshot contract schema")
	ErrNodeIdentityMismatch   = errors.New("node snapshot does not match the expected identity")
	ErrNodeSnapshotNotCurrent = errors.New("node snapshot is outside the accepted freshness window")
	ErrInvalidNodeReadContext = errors.New("invalid node snapshot read context")
)

// NodeIdentity is assigned by a separately authenticated membership registry.
// Epoch is opaque: only exact equality is accepted, never lexical/numeric order.
// These strings do not enroll a node, prove identity or grant an HA writer role.
type NodeIdentity struct {
	ClusterID string `json:"cluster_id"`
	NodeID    string `json:"node_id"`
	Epoch     string `json:"epoch"`
}

func (i NodeIdentity) Validate() error {
	if !identifier(i.ClusterID) || !identifier(i.NodeID) || !identifier(i.Epoch) {
		return invalidNode("identity")
	}
	return nil
}

// NodeSnapshot is a bounded collector statement, not a self-enrollment request.
// Reachability describes transport. Policy, protection and integrations remain
// independent referenced evidence; an unreachable node is not an unprotected one.
type NodeSnapshot struct {
	Schema                string       `json:"schema"`
	SnapshotID            string       `json:"snapshot_id"`
	Identity              NodeIdentity `json:"identity"`
	CollectorID           string       `json:"collector_id"`
	CollectedAt           string       `json:"collected_at"`
	ValidUntil            string       `json:"valid_until"`
	Reachability          string       `json:"reachability"`
	LastSuccessfulContact Field        `json:"last_successful_contact"`
	ObservedAt            Field        `json:"observed_at"`
	ClockQuality          Field        `json:"clock_quality"`
	AgentVersion          Field        `json:"agent_version"`
	PolicyRef             Field        `json:"policy_ref"`
	ControlRef            Field        `json:"control_ref"`
	IntegrationRef        Field        `json:"integration_ref"`
}

func invalidNode(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeDocument, field)
}

// Validate checks shape and internal coherence only. A syntactically valid
// statement is not authenticated, authorized or necessarily current.
func (s NodeSnapshot) Validate() error {
	if s.Schema != NodeSnapshotSchema {
		return ErrUnsupportedNodeSchema
	}
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	if !identifier(s.SnapshotID) || !identifier(s.CollectorID) {
		return invalidNode("snapshot or collector identifier")
	}
	if !timestamp(s.CollectedAt) || !timestamp(s.ValidUntil) {
		return invalidNode("collector timestamps")
	}
	collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if !until.After(collected) || until.Sub(collected) > MaxSnapshotLifetime {
		return invalidNode("snapshot lifetime")
	}
	if !member("reachable", "unreachable", "unknown")(s.Reachability) {
		return invalidNode("reachability")
	}
	if !s.LastSuccessfulContact.validate(timestamp) {
		return invalidNode("last_successful_contact")
	}
	if s.LastSuccessfulContact.hasValue() {
		contact, _ := time.Parse(time.RFC3339Nano, s.LastSuccessfulContact.Value)
		if contact.After(collected) {
			return invalidNode("contact after collection")
		}
	}
	if s.Reachability == "reachable" && (s.LastSuccessfulContact.State != Present ||
		s.LastSuccessfulContact.Value != s.CollectedAt) {
		return invalidNode("reachable without established contact")
	}
	if !s.ObservedAt.validate(timestamp) {
		return invalidNode("observed_at")
	}
	if !s.ClockQuality.validate(member("unknown", "synchronized", "unsynchronized")) {
		return invalidNode("clock_quality")
	}
	for _, item := range []struct {
		name  string
		field Field
	}{
		{"agent_version", s.AgentVersion}, {"policy_ref", s.PolicyRef},
		{"control_ref", s.ControlRef}, {"integration_ref", s.IntegrationRef},
	} {
		if !item.field.validate(identifier) {
			return invalidNode(item.name)
		}
	}
	// Cached agent data cannot become fresh just because an outage report is new.
	if s.Reachability != "reachable" {
		for _, field := range []Field{s.ObservedAt, s.ClockQuality, s.AgentVersion,
			s.PolicyRef, s.ControlRef, s.IntegrationRef} {
			if field.hasValue() && field.State != Stale {
				return invalidNode("cached agent data must be stale")
			}
		}
	}
	return nil
}

// NodeReadContext must come from trusted local policy and authenticated
// membership, never from the document being checked. MaxAge has no default.
type NodeReadContext struct {
	ExpectedIdentity NodeIdentity
	Now              time.Time
	MaxAge           time.Duration
}

// CheckCurrentNodeSnapshot checks exact membership generation and freshness.
// It does not authenticate the collector, authorize a read, track replay or
// verify the referenced evidence. Those are separate ingestion obligations.
// A current report of an outage is allowed, with its agent facts still stale.
func CheckCurrentNodeSnapshot(s NodeSnapshot, context NodeReadContext) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := context.ExpectedIdentity.Validate(); err != nil {
		return ErrInvalidNodeReadContext
	}
	if context.MaxAge <= 0 || context.MaxAge > MaxSnapshotLifetime ||
		!timestamp(context.Now.UTC().Format(time.RFC3339Nano)) {
		return ErrInvalidNodeReadContext
	}
	if s.Identity != context.ExpectedIdentity {
		return ErrNodeIdentityMismatch
	}
	collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if context.Now.Before(collected) || !context.Now.Before(until) || context.Now.Sub(collected) >= context.MaxAge {
		return ErrNodeSnapshotNotCurrent
	}
	return nil
}
