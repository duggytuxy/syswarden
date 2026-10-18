package v5

import (
	"errors"
	"time"
)

var (
	ErrInvalidNodeViewContext  = errors.New("invalid node snapshot view context")
	ErrNodeViewBindingMismatch = errors.New("node snapshot does not match the selected report")
	ErrNodeViewFutureReport    = errors.New("node snapshot collector time is in the future")
)

// NodeSnapshotViewContext comes from independently authenticated, authorized
// report selection and membership. Copying these values from submitted data
// defeats the binding. The digest is byte identity, not proof of authority.
type NodeSnapshotViewContext struct {
	SnapshotID     string
	SnapshotSHA256 string
	CollectorID    string
	ReadContext    NodeReadContext
}

func (c NodeSnapshotViewContext) validate() bool {
	return identifier(c.SnapshotID) && digest(c.SnapshotSHA256) &&
		identifier(c.CollectorID) && c.ReadContext.validate()
}

// NodeSnapshotFieldView retains the exact reported field separately from its
// effective State at the caller's assessment time. Expiry can downgrade that
// state, but never upgrades source quality or erases a partial/stale qualifier.
// Consumers must display State alongside any Reported.Value. Present does not
// authenticate or resolve the value, nor attest the referenced protection.
type NodeSnapshotFieldView struct {
	Reported Field  `json:"reported"`
	State    string `json:"state"`
}

// NodeSnapshotView distinguishes current transport from historical observations.
// It has no health/protection verdict, authorization, action or discovery role.
// Its fields contain no shared mutable storage. Reproject at each new read time;
// retaining this value does not renew its freshness or implement revocation.
type NodeSnapshotView struct {
	Identity              NodeIdentity
	SnapshotID            string
	CollectorID           string
	CollectedAt           string
	ValidUntil            string
	ReportState           string
	Reason                string
	CurrentReachability   string
	Reachability          Field
	LastSuccessfulContact NodeSnapshotFieldView
	ObservedAt            NodeSnapshotFieldView
	ClockQuality          NodeSnapshotFieldView
	AgentVersion          NodeSnapshotFieldView
	PolicyRef             NodeSnapshotFieldView
	ControlRef            NodeSnapshotFieldView
	IntegrationRef        NodeSnapshotFieldView
}

// ProjectNodeSnapshot checks the entire selected report before disclosing data.
// Future, malformed or substituted input returns zero and a fixed diagnostic.
// Expired reports retain historical observations but no current reachability.
// Callers must retain authorized inventory identities even when a report fails.
// Source clock quality is an agent observation, not the collector clock: it
// cannot refresh old data or invalidate independently established contact time.
func ProjectNodeSnapshot(s NodeSnapshot, context NodeSnapshotViewContext) (NodeSnapshotView, error) {
	hash, err := NodeSnapshotSHA256(s)
	if err != nil {
		return NodeSnapshotView{}, err
	}
	if !context.validate() {
		return NodeSnapshotView{}, ErrInvalidNodeViewContext
	}
	if s.SnapshotID != context.SnapshotID || hash != context.SnapshotSHA256 ||
		s.CollectorID != context.CollectorID || s.Identity != context.ReadContext.ExpectedIdentity {
		return NodeSnapshotView{}, ErrNodeViewBindingMismatch
	}
	collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
	if context.ReadContext.Now.Before(collected) {
		return NodeSnapshotView{}, ErrNodeViewFutureReport
	}
	view := NodeSnapshotView{
		Identity: s.Identity, SnapshotID: s.SnapshotID, CollectorID: s.CollectorID,
		CollectedAt: s.CollectedAt, ValidUntil: s.ValidUntil, ReportState: Present,
		CurrentReachability: s.Reachability,
	}
	if err := CheckCurrentNodeSnapshot(s, context.ReadContext); err != nil {
		if !errors.Is(err, ErrNodeSnapshotNotCurrent) {
			return NodeSnapshotView{}, err
		}
		view.ReportState, view.Reason = Stale, "report_expired"
		view.CurrentReachability = "unknown"
	}
	view.Reachability = Field{State: view.ReportState, Value: s.Reachability}
	view.LastSuccessfulContact = projectNodeSnapshotField(s.LastSuccessfulContact, view.ReportState)
	view.ObservedAt = projectNodeSnapshotField(s.ObservedAt, view.ReportState)
	view.ClockQuality = projectNodeSnapshotField(s.ClockQuality, view.ReportState)
	view.AgentVersion = projectNodeSnapshotField(s.AgentVersion, view.ReportState)
	view.PolicyRef = projectNodeSnapshotField(s.PolicyRef, view.ReportState)
	view.ControlRef = projectNodeSnapshotField(s.ControlRef, view.ReportState)
	view.IntegrationRef = projectNodeSnapshotField(s.IntegrationRef, view.ReportState)
	return view, nil
}

func projectNodeSnapshotField(field Field, reportState string) NodeSnapshotFieldView {
	view := NodeSnapshotFieldView{Reported: field, State: field.State}
	if reportState == Stale && field.hasValue() {
		view.State = Stale
	}
	return view
}
