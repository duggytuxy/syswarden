// Package v5 defines read-only, versioned contracts under development for v5.
// It does not authorize actions, authenticate producers or change the v4 API.
package v5

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	EventSchema        = "syswarden.event-envelope.v1"
	MaxDocumentBytes   = 16 * 1024
	MaxIdentifierBytes = 128
)

var (
	ErrInvalidDocument   = errors.New("invalid event contract document")
	ErrUnsupportedSchema = errors.New("unsupported event contract schema")
)

// Field separates availability from content. Present does not mean authentic,
// trusted, fresh enough for an action or cryptographically verified.
type Field struct {
	State string `json:"state"`
	Value string `json:"value"`
}

const (
	Present       = "present"
	Missing       = "missing"
	Unavailable   = "unavailable"
	Stale         = "stale"
	Partial       = "partial"
	Rejected      = "rejected"
	NotApplicable = "not_applicable"
)

// Provenance identifies the representation, not the authenticated principal.
// OriginalSHA256 binds exact input bytes but is not a signature or an identity.
type Provenance struct {
	Format         string `json:"format"`
	SourceID       Field  `json:"source_id"`
	OriginalSHA256 Field  `json:"original_sha256"`
}

// Subject supports non-IP observations without manufacturing an IP address.
type Subject struct {
	Kind    string `json:"kind"`
	Address Field  `json:"address"`
}

// ContextReferences keep source assessments independent. Their referenced
// contracts and scope authorization must be implemented before resolution.
type ContextReferences struct {
	Reputation  Field `json:"reputation"`
	Trust       Field `json:"trust"`
	History     Field `json:"history"`
	Attribution Field `json:"attribution"`
}

// Event is an observation envelope, not a decision or an executable action.
// Separate references prevent interpreting an observation label as evidence of
// a policy decision, a successful past action or a current enforcement state.
// References never authorize lookup by themselves and are not URLs or paths.
type Event struct {
	Schema          string            `json:"schema"`
	EventID         Field             `json:"event_id"`
	NodeID          Field             `json:"node_id"`
	ObservedAt      Field             `json:"observed_at"`
	ReceivedAt      string            `json:"received_at"`
	ClockQuality    string            `json:"clock_quality"`
	Provenance      Provenance        `json:"provenance"`
	Subject         Subject           `json:"subject"`
	ObservationCode Field             `json:"observation_code"`
	Layer           Field             `json:"layer"`
	Severity        Field             `json:"severity"`
	PolicyRef       Field             `json:"policy_ref"`
	ActionRef       Field             `json:"action_ref"`
	ControlRef      Field             `json:"control_ref"`
	EvidenceRef     Field             `json:"evidence_ref"`
	Context         ContextReferences `json:"context"`
}

func invalid(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDocument, field)
}

func (f Field) hasValue() bool {
	return f.State == Present || f.State == Stale || f.State == Partial
}

func (f Field) validate(check func(string) bool) bool {
	if f.hasValue() {
		return f.Value != "" && check(f.Value)
	}
	switch f.State {
	case Missing, Unavailable, Rejected, NotApplicable:
		return f.Value == ""
	default:
		return false
	}
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > MaxIdentifierBytes {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("._:-", c) {
			continue
		}
		return false
	}
	return true
}

func timestamp(s string) bool {
	t, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && !t.IsZero() && t.Year() >= 1970 &&
		t.UTC().Format(time.RFC3339Nano) == s
}

func member(values ...string) func(string) bool {
	return func(s string) bool {
		for _, value := range values {
			if s == value {
				return true
			}
		}
		return false
	}
}

func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Validate checks bounded syntax and local invariants only. Authentication,
// reference resolution, freshness windows and authority belong to ingestion.
func (e Event) Validate() error {
	if e.Schema != EventSchema {
		return ErrUnsupportedSchema
	}
	for _, item := range []struct {
		name  string
		value Field
	}{
		{"event_id", e.EventID}, {"node_id", e.NodeID},
		{"provenance.source_id", e.Provenance.SourceID},
		{"observation_code", e.ObservationCode}, {"policy_ref", e.PolicyRef},
		{"action_ref", e.ActionRef}, {"control_ref", e.ControlRef},
		{"evidence_ref", e.EvidenceRef}, {"context.reputation", e.Context.Reputation},
		{"context.trust", e.Context.Trust}, {"context.history", e.Context.History},
		{"context.attribution", e.Context.Attribution},
	} {
		if !item.value.validate(identifier) {
			return invalid(item.name)
		}
	}
	if !e.ObservedAt.validate(timestamp) {
		return invalid("observed_at")
	}
	if !timestamp(e.ReceivedAt) {
		return invalid("received_at")
	}
	if !member("unknown", "synchronized", "unsynchronized")(e.ClockQuality) {
		return invalid("clock_quality")
	}
	if !e.Layer.validate(member("L2", "L3", "L4", "L5", "L6", "L7")) {
		return invalid("layer")
	}
	if !e.Severity.validate(member("informational", "low", "medium", "high", "critical")) {
		return invalid("severity")
	}
	if !e.Provenance.OriginalSHA256.validate(digest) {
		return invalid("provenance.original_sha256")
	}
	if !member("native", "legacy_v4")(e.Provenance.Format) {
		return invalid("provenance.format")
	}
	if err := e.Subject.validate(); err != nil {
		return err
	}
	if e.Provenance.Format == "legacy_v4" {
		return e.validateLegacy()
	}
	return nil
}

func (s Subject) validate() error {
	var check func(string) bool
	switch s.Kind {
	case "ip":
		check = func(v string) bool {
			ip, err := netip.ParseAddr(v)
			return err == nil && ip.Zone() == "" && !ip.Is4In6() && ip.String() == v
		}
	case "mac":
		check = func(v string) bool {
			mac, err := net.ParseMAC(v)
			return err == nil && len(mac) == 6 && mac.String() == v
		}
	case "unknown":
		check = func(string) bool { return false }
	default:
		return invalid("subject.kind")
	}
	if !s.Address.validate(check) {
		return invalid("subject.address")
	}
	return nil
}

func (e Event) validateLegacy() error {
	if e.Provenance.OriginalSHA256.State != Present || e.ClockQuality != "unknown" ||
		e.ObservationCode.State != Present || !legacyAction(e.ObservationCode.Value) {
		return invalid("legacy provenance")
	}
	// This projection cannot attest information absent from the frozen input
	// contract. A later evidence-enriching adapter requires a separate review.
	for _, f := range []Field{e.Layer, e.Severity, e.PolicyRef, e.ActionRef,
		e.ControlRef, e.EvidenceRef, e.Context.Reputation, e.Context.Trust,
		e.Context.History, e.Context.Attribution} {
		if f.State != Unavailable || f.Value != "" {
			return invalid("legacy evidence promotion")
		}
	}
	return nil
}
