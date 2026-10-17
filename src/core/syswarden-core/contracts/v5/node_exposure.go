package v5

import (
	"errors"
	"fmt"
	"time"
)

const NodeExposureSnapshotSchema = "syswarden.node-exposure-snapshot.v1"

var (
	ErrInvalidNodeExposureDocument   = errors.New("invalid node exposure snapshot")
	ErrUnsupportedNodeExposureSchema = errors.New("unsupported node exposure schema")
	ErrInvalidNodeExposureContext    = errors.New("invalid node exposure read context")
	ErrNodeExposureBindingMismatch   = errors.New("node exposure snapshot does not match the expected inputs")
	ErrNodeExposureFutureReport      = errors.New("node exposure report is in the future")
)

// InventoryClassification is a separately evaluated inventory claim. Source
// references the exact supporting record; the digest is not authentication.
// Unavailable classifications have no value, source or assessment timestamp.
type InventoryClassification struct {
	State      string        `json:"state"`
	Value      string        `json:"value"`
	Source     RateReference `json:"source"`
	AssessedAt string        `json:"assessed_at"`
}

func (c InventoryClassification) validate(values ...string) bool {
	if member(Present, Stale)(c.State) {
		return member(values...)(c.Value) && c.Source.validate() && timestamp(c.AssessedAt)
	}
	return member(Missing, Unavailable, Rejected)(c.State) && c.Value == "" &&
		c.Source == (RateReference{}) && c.AssessedAt == ""
}

// NodeExposureSnapshot separates Internet exposure from hosting, reachability
// and protection. It declares no addresses, coordinates, endpoint permissions or
// response authority. A private address or on-premises label cannot select a tab.
type NodeExposureSnapshot struct {
	Schema       string                  `json:"schema"`
	SnapshotID   string                  `json:"snapshot_id"`
	Identity     NodeIdentity            `json:"identity"`
	CollectorID  string                  `json:"collector_id"`
	Scope        RateReference           `json:"scope"`
	Policy       RateReference           `json:"policy"`
	GeneratedAt  string                  `json:"generated_at"`
	ValidUntil   string                  `json:"valid_until"`
	ClockQuality string                  `json:"clock_quality"`
	Exposure     InventoryClassification `json:"exposure"`
	HostingModel InventoryClassification `json:"hosting_model"`
}

func invalidNodeExposure(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeExposureDocument, field)
}

// Validate checks shape and coherence, not the producer's authority or source
// content. Exposure is a node-level reviewed classification: any established
// Internet-facing path requires internet_exposed, including NAT or reverse proxy.
func (s NodeExposureSnapshot) Validate() error {
	if s.Schema != NodeExposureSnapshotSchema {
		return ErrUnsupportedNodeExposureSchema
	}
	if s.Identity.Validate() != nil || !identifier(s.SnapshotID) || !identifier(s.CollectorID) ||
		!s.Scope.validate() || !s.Policy.validate() {
		return invalidNodeExposure("identity or inputs")
	}
	if !timestamp(s.GeneratedAt) || !timestamp(s.ValidUntil) ||
		!member("synchronized", "unsynchronized", "unknown")(s.ClockQuality) {
		return invalidNodeExposure("report time or clock")
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if !until.After(generated) || until.Sub(generated) > MaxSnapshotLifetime {
		return invalidNodeExposure("report lifetime")
	}
	if !s.Exposure.validate("internet_exposed", "internal_only", "unknown") ||
		!s.HostingModel.validate("on_premises", "cloud", "colocation", "unknown") {
		return invalidNodeExposure("classification")
	}
	for _, c := range []InventoryClassification{s.Exposure, s.HostingModel} {
		if c.AssessedAt != "" {
			assessed, _ := time.Parse(time.RFC3339Nano, c.AssessedAt)
			if assessed.After(generated) {
				return invalidNodeExposure("assessment after report")
			}
		}
	}
	return nil
}

// NodeExposureReadContext is supplied independently by an authenticated,
// scope-authorized read plane. Never populate it from the received document.
// Age budgets are explicit reviewed policy, with no freshness defaults.
type NodeExposureReadContext struct {
	SnapshotID           string
	SnapshotSHA256       string
	ExpectedIdentity     NodeIdentity
	CollectorID          string
	Scope                RateReference
	Policy               RateReference
	Now                  time.Time
	MaxReportAge         time.Duration
	MaxClassificationAge time.Duration
}

func (c NodeExposureReadContext) validate() bool {
	return identifier(c.SnapshotID) && digest(c.SnapshotSHA256) && c.ExpectedIdentity.Validate() == nil &&
		identifier(c.CollectorID) && c.Scope.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano)) &&
		c.MaxReportAge > 0 && c.MaxReportAge <= MaxSnapshotLifetime &&
		c.MaxClassificationAge > 0 && c.MaxClassificationAge <= MaxSnapshotLifetime
}

// NodeExposureView preserves one stable identity and last-known classification.
// Group is external, internal or needs_classification; it grants no permission.
// Only an independently authorized external population may supply a world map.
// ReportState describes report freshness, never current protection or health.
type NodeExposureView struct {
	Identity     NodeIdentity
	SnapshotID   string
	Group        string
	ReportState  string
	Reason       string
	Exposure     InventoryClassification
	HostingModel InventoryClassification
}

// ProjectNodeExposureSnapshot checks exact binding before returning any data.
// Expired reports and unverified clocks retain known values as stale in the
// needs_classification group. They never silently become internal or disappear.
// Future, malformed or substituted reports return zero and an error. The caller
// must keep the independently authorized inventory node visible without those
// rejected fields. No host is scanned and no source is fetched by this function.
func ProjectNodeExposureSnapshot(s NodeExposureSnapshot, context NodeExposureReadContext) (NodeExposureView, error) {
	hash, err := NodeExposureSnapshotSHA256(s)
	if err != nil {
		return NodeExposureView{}, err
	}
	if !context.validate() {
		return NodeExposureView{}, ErrInvalidNodeExposureContext
	}
	if s.SnapshotID != context.SnapshotID || hash != context.SnapshotSHA256 || s.Identity != context.ExpectedIdentity ||
		s.CollectorID != context.CollectorID || s.Scope != context.Scope || s.Policy != context.Policy {
		return NodeExposureView{}, ErrNodeExposureBindingMismatch
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if context.Now.Before(generated) {
		return NodeExposureView{}, ErrNodeExposureFutureReport
	}
	view := NodeExposureView{Identity: s.Identity, SnapshotID: s.SnapshotID,
		Group: "needs_classification", ReportState: Present}
	switch {
	case s.ClockQuality != "synchronized":
		view.ReportState, view.Reason = Unavailable, "report_clock_unverified"
	case !context.Now.Before(until) || context.Now.Sub(generated) >= context.MaxReportAge:
		view.ReportState, view.Reason = Stale, "report_expired"
	}
	view.Exposure = projectInventoryClassification(s.Exposure, view.ReportState, context)
	view.HostingModel = projectInventoryClassification(s.HostingModel, view.ReportState, context)
	if view.ReportState == Present {
		view.Group, view.Reason = nodeExposureGroup(view.Exposure)
	}
	return view, nil
}

func projectInventoryClassification(c InventoryClassification, reportState string, context NodeExposureReadContext) InventoryClassification {
	if c.State == Present {
		assessed, _ := time.Parse(time.RFC3339Nano, c.AssessedAt)
		if reportState != Present || context.Now.Sub(assessed) >= context.MaxClassificationAge {
			c.State = Stale
		}
	}
	return c
}

func nodeExposureGroup(c InventoryClassification) (string, string) {
	if c.State == Present {
		switch c.Value {
		case "internet_exposed":
			return "external", "current_classification"
		case "internal_only":
			return "internal", "current_classification"
		default:
			return "needs_classification", "exposure_unknown"
		}
	}
	if c.State == Stale {
		return "needs_classification", "exposure_stale"
	}
	return "needs_classification", "exposure_unavailable"
}
