package v5

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Synthetic test selection only. Production selection is independent of input.
func nodeViewContext(t testing.TB, s NodeSnapshot) NodeSnapshotViewContext {
	t.Helper()
	hash, err := NodeSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	return NodeSnapshotViewContext{SnapshotID: s.SnapshotID, SnapshotSHA256: hash,
		CollectorID: s.CollectorID, ReadContext: readContext()}
}

func TestNodeViewCanonicalBinding(t *testing.T) {
	// Independently calculated from the existing compact JSON golden vectors.
	for name, want := range map[string]string{
		"node-reachable.json":   "407259a2346da3b21d7b169169167260d9a982edc23b19807017f1f9f2b4d1fa",
		"node-unreachable.json": "3dd54d6f87b98320e4350d36d167bf8664799405f362dbfd04b6b58b8cb274cb",
		"node-unknown.json":     "02c9b33eaa011f8b7047d3031f98e125e9b8da74505eb009b4095b8b9e8415be",
	} {
		t.Run(name, func(t *testing.T) {
			s := nodeFixture(t, name)
			hash, err := NodeSnapshotSHA256(s)
			if err != nil || hash != want {
				t.Fatal("canonical digest changed", err)
			}
			formatted, err := DecodeNodeSnapshot(append([]byte("\n  "), fixture(t, name)...))
			if err != nil {
				t.Fatal(err)
			}
			if other, err := NodeSnapshotSHA256(formatted); err != nil || other != hash {
				t.Fatal("whitespace changed report binding", err)
			}
			context := nodeViewContext(t, s)
			view, err := ProjectNodeSnapshot(s, context)
			if err != nil || view.Identity != s.Identity || view.SnapshotID != s.SnapshotID ||
				view.CollectorID != s.CollectorID || view.CollectedAt != s.CollectedAt || view.ValidUntil != s.ValidUntil ||
				view.ReportState != Present || view.Reason != "" || view.CurrentReachability != s.Reachability ||
				view.Reachability != (Field{State: Present, Value: s.Reachability}) {
				t.Fatal("current report changed identity or transport meaning", err)
			}
			checkNodeViewFields(t, s, view, false)
			// A view is a value copy, not a mutable alias of the selected report.
			view.Identity.NodeID = "changed"
			view.ControlRef.Reported.Value = "changed"
			again, err := ProjectNodeSnapshot(s, context)
			if err != nil || again.Identity != s.Identity || again.ControlRef.Reported != s.ControlRef {
				t.Fatal("caller mutation changed source", err)
			}
		})
	}
}

func checkNodeViewFields(t testing.TB, s NodeSnapshot, view NodeSnapshotView, expired bool) {
	t.Helper()
	for _, item := range []struct {
		source Field
		actual NodeSnapshotFieldView
	}{
		{s.LastSuccessfulContact, view.LastSuccessfulContact}, {s.ObservedAt, view.ObservedAt},
		{s.ClockQuality, view.ClockQuality}, {s.AgentVersion, view.AgentVersion},
		{s.PolicyRef, view.PolicyRef}, {s.ControlRef, view.ControlRef}, {s.IntegrationRef, view.IntegrationRef},
	} {
		want := item.source.State
		if expired && item.source.Value != "" {
			want = Stale
		}
		if item.actual.Reported != item.source || item.actual.State != want {
			t.Fatal("reported quality/value lost or effective state promoted", item.actual)
		}
	}
}

func TestNodeViewFreshnessBoundaries(t *testing.T) {
	for _, name := range []string{"node-reachable.json", "node-unreachable.json", "node-unknown.json"} {
		for _, test := range []struct {
			name    string
			delta   time.Duration
			maxAge  time.Duration
			expired bool
		}{
			{"collection instant", 0, time.Minute, false},
			{"before validity limit", time.Minute - time.Nanosecond, time.Hour, false},
			{"validity limit", time.Minute, time.Hour, true},
			{"after validity limit", 2 * time.Minute, time.Hour, true},
			{"before age limit", 10*time.Second - time.Nanosecond, 10 * time.Second, false},
			{"age limit", 10 * time.Second, 10 * time.Second, true},
			{"after age limit", 11 * time.Second, 10 * time.Second, true},
		} {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				s := nodeFixture(t, name)
				context := nodeViewContext(t, s)
				collected, _ := time.Parse(time.RFC3339Nano, s.CollectedAt)
				context.ReadContext.Now = collected.Add(test.delta)
				context.ReadContext.MaxAge = test.maxAge
				view, err := ProjectNodeSnapshot(s, context)
				if err != nil {
					t.Fatal(err)
				}
				state, current, reason := Present, s.Reachability, ""
				if test.expired {
					state, current, reason = Stale, "unknown", "report_expired"
				}
				if view.Identity != s.Identity || view.ReportState != state || view.Reason != reason ||
					view.CurrentReachability != current || view.Reachability != (Field{State: state, Value: s.Reachability}) {
					t.Fatal("expiry hid node or misrepresented current transport", view)
				}
				checkNodeViewFields(t, s, view, test.expired)
				// Same instant in another location must not change the projection.
				context.ReadContext.Now = context.ReadContext.Now.In(time.FixedZone("fixture", 3600))
				other, err := ProjectNodeSnapshot(s, context)
				if err != nil || other != view {
					t.Fatal("location changed assessment", err)
				}
			})
		}
	}
}

func TestNodeViewRejectsSubstitutionWithoutPartialData(t *testing.T) {
	s := nodeFixture(t, "node-reachable.json")
	for name, change := range map[string]func(*NodeSnapshot){
		"snapshot":        func(s *NodeSnapshot) { s.SnapshotID = "other" },
		"collector":       func(s *NodeSnapshot) { s.CollectorID = "other" },
		"cluster":         func(s *NodeSnapshot) { s.Identity.ClusterID = "other" },
		"node":            func(s *NodeSnapshot) { s.Identity.NodeID = "other" },
		"epoch":           func(s *NodeSnapshot) { s.Identity.Epoch = "other" },
		"longer lifetime": func(s *NodeSnapshot) { s.ValidUntil = "2026-01-01T01:00:00Z" },
		"agent version":   func(s *NodeSnapshot) { s.AgentVersion.Value = "other" },
		"control":         func(s *NodeSnapshot) { s.ControlRef.Value = "other" },
		"policy":          func(s *NodeSnapshot) { s.PolicyRef.Value = "other" },
		"integration":     func(s *NodeSnapshot) { s.IntegrationRef.Value = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			context := nodeViewContext(t, s)
			changed := s
			change(&changed)
			view, err := ProjectNodeSnapshot(changed, context)
			if !errors.Is(err, ErrNodeViewBindingMismatch) || view != (NodeSnapshotView{}) {
				t.Fatal("substituted report leaked fields", err)
			}
		})
	}
	for name, change := range map[string]func(*NodeSnapshotViewContext){
		"snapshot":  func(c *NodeSnapshotViewContext) { c.SnapshotID = "other" },
		"collector": func(c *NodeSnapshotViewContext) { c.CollectorID = "other" },
		"digest":    func(c *NodeSnapshotViewContext) { c.SnapshotSHA256 = strings.Repeat("0", 64) },
		"cluster":   func(c *NodeSnapshotViewContext) { c.ReadContext.ExpectedIdentity.ClusterID = "other" },
		"node":      func(c *NodeSnapshotViewContext) { c.ReadContext.ExpectedIdentity.NodeID = "other" },
		"epoch":     func(c *NodeSnapshotViewContext) { c.ReadContext.ExpectedIdentity.Epoch = "other" },
	} {
		t.Run("selected "+name, func(t *testing.T) {
			context := nodeViewContext(t, s)
			change(&context)
			view, err := ProjectNodeSnapshot(s, context)
			if !errors.Is(err, ErrNodeViewBindingMismatch) || view != (NodeSnapshotView{}) {
				t.Fatal("selection binding ignored", err)
			}
		})
	}
}

func TestNodeViewRejectsInvalidContextAndFutureReport(t *testing.T) {
	s := nodeFixture(t, "node-reachable.json")
	for name, change := range map[string]func(*NodeSnapshotViewContext){
		"zero":             func(c *NodeSnapshotViewContext) { *c = NodeSnapshotViewContext{} },
		"no snapshot":      func(c *NodeSnapshotViewContext) { c.SnapshotID = "" },
		"no collector":     func(c *NodeSnapshotViewContext) { c.CollectorID = "" },
		"no digest":        func(c *NodeSnapshotViewContext) { c.SnapshotSHA256 = "" },
		"upper digest":     func(c *NodeSnapshotViewContext) { c.SnapshotSHA256 = strings.ToUpper(c.SnapshotSHA256) },
		"invalid identity": func(c *NodeSnapshotViewContext) { c.ReadContext.ExpectedIdentity.Epoch = "" },
		"zero time":        func(c *NodeSnapshotViewContext) { c.ReadContext.Now = time.Time{} },
		"no age":           func(c *NodeSnapshotViewContext) { c.ReadContext.MaxAge = 0 },
		"negative age":     func(c *NodeSnapshotViewContext) { c.ReadContext.MaxAge = -time.Second },
		"excess age":       func(c *NodeSnapshotViewContext) { c.ReadContext.MaxAge = MaxSnapshotLifetime + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			context := nodeViewContext(t, s)
			change(&context)
			view, err := ProjectNodeSnapshot(s, context)
			if !errors.Is(err, ErrInvalidNodeViewContext) || view != (NodeSnapshotView{}) {
				t.Fatal("invalid context returned fields", err)
			}
		})
	}
	context := nodeViewContext(t, s)
	context.ReadContext.Now, _ = time.Parse(time.RFC3339Nano, s.CollectedAt)
	context.ReadContext.Now = context.ReadContext.Now.Add(-time.Nanosecond)
	if view, err := ProjectNodeSnapshot(s, context); !errors.Is(err, ErrNodeViewFutureReport) || view != (NodeSnapshotView{}) {
		t.Fatal("future collector report accepted as historical", err)
	}
	s.ControlRef.Value = "private-invalid-value\n"
	if hash, err := NodeSnapshotSHA256(s); err == nil || hash != "" || strings.Contains(err.Error(), "private-invalid-value") {
		t.Fatal("invalid report hashed or error disclosed payload", err)
	}
	if view, err := ProjectNodeSnapshot(s, context); err == nil || view != (NodeSnapshotView{}) || strings.Contains(err.Error(), "private-invalid-value") {
		t.Fatal("malformed input disclosed data", err)
	}
}

func TestNodeViewSourceQualitySurvivesExpiry(t *testing.T) {
	for _, state := range []string{Present, Partial, Stale, Missing, Unavailable, Rejected, NotApplicable} {
		t.Run(state, func(t *testing.T) {
			s := nodeFixture(t, "node-reachable.json")
			for _, field := range []*Field{&s.ObservedAt, &s.ClockQuality, &s.AgentVersion, &s.PolicyRef, &s.ControlRef, &s.IntegrationRef} {
				field.State = state
				if state == Missing || state == Unavailable || state == Rejected || state == NotApplicable {
					field.Value = ""
				}
			}
			context := nodeViewContext(t, s)
			view, err := ProjectNodeSnapshot(s, context)
			if err != nil || view.ReportState != Present || view.CurrentReachability != "reachable" {
				t.Fatal("unavailable protection invalidated transport observation", err)
			}
			checkNodeViewFields(t, s, view, false)
			context.ReadContext.Now = context.ReadContext.Now.Add(time.Minute)
			view, err = ProjectNodeSnapshot(s, context)
			if err != nil || view.ReportState != Stale {
				t.Fatal(err)
			}
			checkNodeViewFields(t, s, view, true)
		})
	}
}

func TestNodeViewAgentClockDoesNotReplaceCollectorTime(t *testing.T) {
	for _, clock := range []string{"synchronized", "unsynchronized", "unknown"} {
		for _, observed := range []string{"2025-01-01T00:00:00Z", "2027-01-01T00:00:00Z"} {
			t.Run(clock+"/"+observed, func(t *testing.T) {
				s := nodeFixture(t, "node-reachable.json")
				s.ClockQuality.Value, s.ObservedAt.Value = clock, observed
				context := nodeViewContext(t, s)
				view, err := ProjectNodeSnapshot(s, context)
				if err != nil || view.ReportState != Present || view.CurrentReachability != "reachable" {
					t.Fatal("agent clock invalidated independent collector report", err)
				}
				checkNodeViewFields(t, s, view, false)
				context.ReadContext.Now = context.ReadContext.Now.Add(time.Minute)
				view, err = ProjectNodeSnapshot(s, context)
				if err != nil || view.ReportState != Stale || view.CurrentReachability != "unknown" {
					t.Fatal("agent clock extended collector freshness", err)
				}
				checkNodeViewFields(t, s, view, true)
			})
		}
	}
}
