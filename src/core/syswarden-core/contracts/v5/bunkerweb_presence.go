package v5

import (
	"errors"
	"fmt"
	"time"
)

const BunkerWebPresenceSnapshotSchema = "syswarden.bunkerweb-presence-snapshot.v1"

var (
	ErrInvalidBunkerWebPresenceDocument   = errors.New("invalid BunkerWeb presence snapshot")
	ErrUnsupportedBunkerWebPresenceSchema = errors.New("unsupported BunkerWeb presence schema")
	ErrInvalidBunkerWebPresenceContext    = errors.New("invalid BunkerWeb presence read context")
	ErrBunkerWebPresenceBindingMismatch   = errors.New("BunkerWeb presence snapshot does not match the expected inputs")
	ErrBunkerWebPresenceFutureReport      = errors.New("BunkerWeb presence report is in the future")
)

// BunkerWebPresenceSnapshot separates retained integration registration from
// configuration mode. Neither claim establishes reachability, health or ban
// enforcement. Paths, event labels and API credentials are deliberately absent.
// The authenticated producer must retain established history while authorized;
// this stateless schema cannot infer it from missing observations.
type BunkerWebPresenceSnapshot struct {
	Schema       string                  `json:"schema"`
	SnapshotID   string                  `json:"snapshot_id"`
	Identity     NodeIdentity            `json:"identity"`
	CollectorID  string                  `json:"collector_id"`
	Scope        RateReference           `json:"scope"`
	Policy       RateReference           `json:"policy"`
	GeneratedAt  string                  `json:"generated_at"`
	ValidUntil   string                  `json:"valid_until"`
	ClockQuality string                  `json:"clock_quality"`
	Registration InventoryClassification `json:"registration"`
	Mode         InventoryClassification `json:"mode"`
}

func invalidBunkerWebPresence(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidBunkerWebPresenceDocument, field)
}

// Validate checks internal coherence only. Supporting configuration/capability
// and retained registration records need independent authenticated verification.
func (s BunkerWebPresenceSnapshot) Validate() error {
	if s.Schema != BunkerWebPresenceSnapshotSchema {
		return ErrUnsupportedBunkerWebPresenceSchema
	}
	if s.Identity.Validate() != nil || !identifier(s.SnapshotID) || !identifier(s.CollectorID) ||
		!s.Scope.validate() || !s.Policy.validate() {
		return invalidBunkerWebPresence("identity or inputs")
	}
	if !timestamp(s.GeneratedAt) || !timestamp(s.ValidUntil) ||
		!member("synchronized", "unsynchronized", "unknown")(s.ClockQuality) {
		return invalidBunkerWebPresence("report time or clock")
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if !until.After(generated) || until.Sub(generated) > MaxSnapshotLifetime {
		return invalidBunkerWebPresence("report lifetime")
	}
	if !s.Registration.validate("established", "absent", "unknown") ||
		!s.Mode.validate("log_only", "sync_only", "combined", "disabled", "unknown") {
		return invalidBunkerWebPresence("classification")
	}
	if member(Present, Stale)(s.Mode.State) && s.Mode.Value != "unknown" &&
		s.Registration.Value != "established" {
		return invalidBunkerWebPresence("mode without established registration")
	}
	for _, c := range []InventoryClassification{s.Registration, s.Mode} {
		if c.AssessedAt != "" {
			assessed, _ := time.Parse(time.RFC3339Nano, c.AssessedAt)
			if assessed.After(generated) {
				return invalidBunkerWebPresence("assessment after report")
			}
		}
	}
	return nil
}

// BunkerWebPresenceReadContext comes from an authenticated, scope-authorized read
// plane, never from the received report. Every age budget is explicit policy.
type BunkerWebPresenceReadContext struct {
	SnapshotID         string
	SnapshotSHA256     string
	ExpectedIdentity   NodeIdentity
	CollectorID        string
	Scope              RateReference
	Policy             RateReference
	Now                time.Time
	MaxReportAge       time.Duration
	MaxRegistrationAge time.Duration
	MaxModeAge         time.Duration
}

func (c BunkerWebPresenceReadContext) validate() bool {
	return identifier(c.SnapshotID) && digest(c.SnapshotSHA256) && c.ExpectedIdentity.Validate() == nil &&
		identifier(c.CollectorID) && c.Scope.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano)) &&
		c.MaxReportAge > 0 && c.MaxReportAge <= MaxSnapshotLifetime &&
		c.MaxRegistrationAge > 0 && c.MaxRegistrationAge <= MaxSnapshotLifetime &&
		c.MaxModeAge > 0 && c.MaxModeAge <= MaxSnapshotLifetime
}

// BunkerWebPresenceView grants no permission. Relevance is known, absent or
// unknown. Known registrations remain relevant when stale or disabled. Only a
// current authoritative absence assessment produces absent. CurrentMode never
// infers operational health or protection, even for a current enabled mode.
type BunkerWebPresenceView struct {
	Identity     NodeIdentity
	SnapshotID   string
	ReportState  string
	Relevance    string
	CurrentMode  string
	Reason       string
	Registration InventoryClassification
	Mode         InventoryClassification
}

// ProjectBunkerWebPresenceSnapshot verifies all bindings before returning data.
// Rejected or missing reports must not hide an independently known integration
// in the caller's authorized inventory. This helper has no discovery, enrollment,
// persistence, wall-clock access, network access or mutation authority.
func ProjectBunkerWebPresenceSnapshot(s BunkerWebPresenceSnapshot, context BunkerWebPresenceReadContext) (BunkerWebPresenceView, error) {
	hash, err := BunkerWebPresenceSnapshotSHA256(s)
	if err != nil {
		return BunkerWebPresenceView{}, err
	}
	if !context.validate() {
		return BunkerWebPresenceView{}, ErrInvalidBunkerWebPresenceContext
	}
	if s.SnapshotID != context.SnapshotID || hash != context.SnapshotSHA256 || s.Identity != context.ExpectedIdentity ||
		s.CollectorID != context.CollectorID || s.Scope != context.Scope || s.Policy != context.Policy {
		return BunkerWebPresenceView{}, ErrBunkerWebPresenceBindingMismatch
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if context.Now.Before(generated) {
		return BunkerWebPresenceView{}, ErrBunkerWebPresenceFutureReport
	}
	view := BunkerWebPresenceView{Identity: s.Identity, SnapshotID: s.SnapshotID,
		ReportState: Present, Relevance: "unknown", CurrentMode: "unknown"}
	switch {
	case s.ClockQuality != "synchronized":
		view.ReportState, view.Reason = Unavailable, "report_clock_unverified"
	case !context.Now.Before(until) || context.Now.Sub(generated) >= context.MaxReportAge:
		view.ReportState, view.Reason = Stale, "report_expired"
	}
	view.Registration = projectBunkerWebClaim(s.Registration, view.ReportState, context.Now, context.MaxRegistrationAge)
	view.Mode = projectBunkerWebClaim(s.Mode, view.ReportState, context.Now, context.MaxModeAge)
	if view.Registration.Value == "established" {
		view.Relevance = "known"
	}
	if view.ReportState != Present {
		return view, nil
	}
	switch {
	case view.Registration.State == Stale:
		view.Reason = "registration_stale"
	case view.Registration.State != Present:
		view.Reason = "registration_unavailable"
	case view.Registration.Value == "absent":
		view.Relevance, view.Reason = "absent", "current_absence"
	case view.Registration.Value == "unknown":
		view.Reason = "registration_unknown"
	case view.Mode.State == Stale:
		view.Reason = "mode_stale"
	case view.Mode.State != Present:
		view.Reason = "mode_unavailable"
	case view.Mode.Value == "unknown":
		view.Reason = "mode_unknown"
	default:
		view.CurrentMode, view.Reason = view.Mode.Value, "current_configuration"
	}
	return view, nil
}

func projectBunkerWebClaim(c InventoryClassification, reportState string, now time.Time, maxAge time.Duration) InventoryClassification {
	if c.State == Present {
		assessed, _ := time.Parse(time.RFC3339Nano, c.AssessedAt)
		if reportState != Present || now.Sub(assessed) >= maxAge {
			c.State = Stale
		}
	}
	return c
}
