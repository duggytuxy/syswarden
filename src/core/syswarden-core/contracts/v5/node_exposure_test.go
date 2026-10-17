package v5

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func exposureFixture(t testing.TB) NodeExposureSnapshot {
	t.Helper()
	s, err := DecodeNodeExposureSnapshot(fixture(t, "node-exposure.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func exposureContext(t testing.TB, s NodeExposureSnapshot) NodeExposureReadContext {
	t.Helper()
	hash, err := NodeExposureSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	return NodeExposureReadContext{SnapshotID: s.SnapshotID, SnapshotSHA256: hash,
		ExpectedIdentity: s.Identity, CollectorID: s.CollectorID, Scope: s.Scope, Policy: s.Policy,
		Now: time.Date(2026, time.January, 1, 0, 0, 30, 0, time.UTC), MaxReportAge: time.Minute, MaxClassificationAge: 2 * time.Minute}
}

func TestNodeExposureGolden(t *testing.T) {
	data := fixture(t, "node-exposure.json")
	s := exposureFixture(t)
	encoded, err := EncodeNodeExposureSnapshot(s)
	if err != nil || !bytes.Equal(data, encoded) {
		t.Fatal("canonical exposure bytes changed", err)
	}
	hash, err := NodeExposureSnapshotSHA256(s)
	if err != nil || hash != strings.TrimSpace(string(fixture(t, "node-exposure-digest.txt"))) {
		t.Fatal("canonical exposure digest changed", err)
	}
}

func TestNodeExposureDoesNotInferExposureFromHosting(t *testing.T) {
	for _, hosting := range []string{"on_premises", "cloud", "colocation", "unknown"} {
		for exposure, group := range map[string]string{"internet_exposed": "external", "internal_only": "internal", "unknown": "needs_classification"} {
			t.Run(hosting+"/"+exposure, func(t *testing.T) {
				s := exposureFixture(t)
				s.HostingModel.Value = hosting
				s.Exposure.Value = exposure
				before := s
				view, err := ProjectNodeExposureSnapshot(s, exposureContext(t, s))
				if err != nil || view.Group != group || view.ReportState != Present || view.Identity != s.Identity || view.Exposure != s.Exposure || view.HostingModel != s.HostingModel {
					t.Fatal("classification was inferred or lost", view, err)
				}
				view.Exposure.Value = "changed"
				if s != before {
					t.Fatal("projection modified source")
				}
			})
		}
	}
}

func TestNodeExposureReclassificationPreservesIdentity(t *testing.T) {
	s := exposureFixture(t)
	first, err := ProjectNodeExposureSnapshot(s, exposureContext(t, s))
	if err != nil {
		t.Fatal(err)
	}
	s.SnapshotID = "exposure.fixture.2"
	s.Exposure.Value = "internal_only"
	s.Exposure.Source.Ref = "assessment.fixture.2"
	s.Exposure.Source.SHA256 = strings.Repeat("d", 64)
	second, err := ProjectNodeExposureSnapshot(s, exposureContext(t, s))
	if err != nil || first.Group != "external" || second.Group != "internal" || first.Identity != second.Identity {
		t.Fatal("reclassification replaced membership or retained old group", err)
	}
	// Identity alone cannot authorize an old classification after a new assessment.
	if view, err := ProjectNodeExposureSnapshot(exposureFixture(t), exposureContext(t, s)); !errors.Is(err, ErrNodeExposureBindingMismatch) || view != (NodeExposureView{}) {
		t.Fatal("old classification replayed into new selection", err)
	}
}

func TestNodeExposureRetainsUncertainty(t *testing.T) {
	for _, state := range []string{Stale, Missing, Unavailable, Rejected} {
		for _, field := range []string{"exposure", "hosting"} {
			t.Run(field+"/"+state, func(t *testing.T) {
				s := exposureFixture(t)
				c := &s.Exposure
				if field == "hosting" {
					c = &s.HostingModel
				}
				c.State = state
				if state != Stale {
					*c = InventoryClassification{State: state}
				}
				view, err := ProjectNodeExposureSnapshot(s, exposureContext(t, s))
				if err != nil {
					t.Fatal(err)
				}
				want := "needs_classification"
				if field == "hosting" {
					want = "external"
				}
				if view.Group != want || view.ReportState != Present || view.Exposure != s.Exposure || view.HostingModel != s.HostingModel {
					t.Fatal("unavailable field hidden, inferred or renewed", view)
				}
			})
		}
	}
}

func TestNodeExposureFreshnessBoundaries(t *testing.T) {
	cases := []struct {
		name                             string
		offset, reportAge, classAge      time.Duration
		wantState, wantGroup, wantReason string
		future                           bool
	}{
		{"before report", -time.Nanosecond, time.Minute, 2 * time.Minute, "", "", "", true},
		{"exact report", 0, time.Minute, 2 * time.Minute, Present, "external", "current_classification", false},
		{"before report expiry", time.Minute - time.Nanosecond, time.Minute, 2 * time.Minute, Present, "external", "current_classification", false},
		{"exact report expiry", time.Minute, 2 * time.Minute, 3 * time.Minute, Stale, "needs_classification", "report_expired", false},
		{"shorter report policy", 30 * time.Second, 30 * time.Second, 2 * time.Minute, Stale, "needs_classification", "report_expired", false},
		{"old assessment", 30 * time.Second, time.Minute, time.Minute, Present, "needs_classification", "exposure_stale", false},
		{"exact assessment expiry", 30 * time.Second, time.Minute, 90 * time.Second, Present, "needs_classification", "exposure_stale", false},
		{"before assessment expiry", 30*time.Second - time.Nanosecond, time.Minute, 90 * time.Second, Present, "external", "current_classification", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := exposureFixture(t)
			c := exposureContext(t, s)
			generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
			c.Now = generated.Add(tc.offset)
			c.MaxReportAge, c.MaxClassificationAge = tc.reportAge, tc.classAge
			view, err := ProjectNodeExposureSnapshot(s, c)
			if tc.future {
				if !errors.Is(err, ErrNodeExposureFutureReport) || view != (NodeExposureView{}) {
					t.Fatal("future report disclosed", err)
				}
				return
			}
			if err != nil || view.ReportState != tc.wantState || view.Group != tc.wantGroup || view.Reason != tc.wantReason {
				t.Fatal("wrong freshness outcome", view, err)
			}
			if view.Exposure.Value != s.Exposure.Value || view.Exposure.Source != s.Exposure.Source || view.Exposure.AssessedAt != s.Exposure.AssessedAt {
				t.Fatal("last-known lineage lost")
			}
		})
	}
}

func TestNodeExposureReportCannotRenewSourceOrEstablishProtection(t *testing.T) {
	s := exposureFixture(t)
	s.HostingModel.AssessedAt = "2025-12-30T00:00:00Z"
	view, err := ProjectNodeExposureSnapshot(s, exposureContext(t, s))
	if err != nil || view.Group != "external" || view.HostingModel.State != Stale || view.Exposure.State != Present {
		t.Fatal("hosting age changed exposure", view, err)
	}
	for _, clock := range []string{"unknown", "unsynchronized"} {
		s.ClockQuality = clock
		view, err = ProjectNodeExposureSnapshot(s, exposureContext(t, s))
		if err != nil || view.ReportState != Unavailable || view.Group != "needs_classification" || view.Reason != "report_clock_unverified" || view.Exposure.State != Stale {
			t.Fatal("unverified clock established current exposure", view, err)
		}
	}
	s = exposureFixture(t)
	// A fresh report retaining an old assessment must not renew that assessment.
	s.GeneratedAt = "2026-01-01T00:10:00Z"
	s.ValidUntil = "2026-01-01T00:11:00Z"
	c := exposureContext(t, s)
	c.Now = time.Date(2026, time.January, 1, 0, 10, 30, 0, time.UTC)
	view, err = ProjectNodeExposureSnapshot(s, c)
	if err != nil || view.ReportState != Present || view.Group != "needs_classification" || view.Exposure.State != Stale {
		t.Fatal("new report renewed old source", view, err)
	}
}

func TestNodeExposureExactBinding(t *testing.T) {
	changes := map[string]func(*NodeExposureSnapshot){
		"snapshot":        func(s *NodeExposureSnapshot) { s.SnapshotID = "other" },
		"cluster":         func(s *NodeExposureSnapshot) { s.Identity.ClusterID = "other" },
		"node":            func(s *NodeExposureSnapshot) { s.Identity.NodeID = "other" },
		"epoch":           func(s *NodeExposureSnapshot) { s.Identity.Epoch = "other" },
		"collector":       func(s *NodeExposureSnapshot) { s.CollectorID = "other" },
		"scope ref":       func(s *NodeExposureSnapshot) { s.Scope.Ref = "other" },
		"scope hash":      func(s *NodeExposureSnapshot) { s.Scope.SHA256 = strings.Repeat("0", 64) },
		"policy ref":      func(s *NodeExposureSnapshot) { s.Policy.Ref = "other" },
		"policy hash":     func(s *NodeExposureSnapshot) { s.Policy.SHA256 = strings.Repeat("0", 64) },
		"classification":  func(s *NodeExposureSnapshot) { s.Exposure.Value = "internal_only" },
		"hosting":         func(s *NodeExposureSnapshot) { s.HostingModel.Value = "cloud" },
		"assessment ref":  func(s *NodeExposureSnapshot) { s.Exposure.Source.Ref = "other" },
		"assessment hash": func(s *NodeExposureSnapshot) { s.Exposure.Source.SHA256 = strings.Repeat("0", 64) },
		"assessment time": func(s *NodeExposureSnapshot) { s.Exposure.AssessedAt = "2026-01-01T00:00:00Z" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := exposureFixture(t)
			c := exposureContext(t, s)
			change(&s)
			if err := s.Validate(); err != nil {
				t.Fatal(err)
			}
			if view, err := ProjectNodeExposureSnapshot(s, c); !errors.Is(err, ErrNodeExposureBindingMismatch) || view != (NodeExposureView{}) {
				t.Fatal("substituted report disclosed", err)
			}
		})
	}
	// Also bind each independent context field even when the selected hash matches.
	contexts := map[string]func(*NodeExposureReadContext){
		"snapshot":      func(c *NodeExposureReadContext) { c.SnapshotID = "other" },
		"cluster":       func(c *NodeExposureReadContext) { c.ExpectedIdentity.ClusterID = "other" },
		"node":          func(c *NodeExposureReadContext) { c.ExpectedIdentity.NodeID = "other" },
		"epoch":         func(c *NodeExposureReadContext) { c.ExpectedIdentity.Epoch = "other" },
		"collector":     func(c *NodeExposureReadContext) { c.CollectorID = "other" },
		"scope ref":     func(c *NodeExposureReadContext) { c.Scope.Ref = "other" },
		"scope digest":  func(c *NodeExposureReadContext) { c.Scope.SHA256 = strings.Repeat("0", 64) },
		"policy ref":    func(c *NodeExposureReadContext) { c.Policy.Ref = "other" },
		"policy digest": func(c *NodeExposureReadContext) { c.Policy.SHA256 = strings.Repeat("0", 64) },
		"digest":        func(c *NodeExposureReadContext) { c.SnapshotSHA256 = strings.Repeat("0", 64) },
	}
	for name, change := range contexts {
		t.Run("context/"+name, func(t *testing.T) {
			s := exposureFixture(t)
			c := exposureContext(t, s)
			change(&c)
			if view, err := ProjectNodeExposureSnapshot(s, c); !errors.Is(err, ErrNodeExposureBindingMismatch) || view != (NodeExposureView{}) {
				t.Fatal("unbound context disclosed report", err)
			}
		})
	}
}

func TestNodeExposureRejectsInvalidContexts(t *testing.T) {
	changes := map[string]func(*NodeExposureReadContext){
		"missing identity":            func(c *NodeExposureReadContext) { c.ExpectedIdentity = NodeIdentity{} },
		"missing snapshot":            func(c *NodeExposureReadContext) { c.SnapshotID = "" },
		"missing hash":                func(c *NodeExposureReadContext) { c.SnapshotSHA256 = "" },
		"missing collector":           func(c *NodeExposureReadContext) { c.CollectorID = "" },
		"missing scope":               func(c *NodeExposureReadContext) { c.Scope = RateReference{} },
		"missing policy":              func(c *NodeExposureReadContext) { c.Policy = RateReference{} },
		"missing time":                func(c *NodeExposureReadContext) { c.Now = time.Time{} },
		"zero report budget":          func(c *NodeExposureReadContext) { c.MaxReportAge = 0 },
		"negative report budget":      func(c *NodeExposureReadContext) { c.MaxReportAge = -time.Second },
		"unbounded report budget":     func(c *NodeExposureReadContext) { c.MaxReportAge = MaxSnapshotLifetime + 1 },
		"zero assessment budget":      func(c *NodeExposureReadContext) { c.MaxClassificationAge = 0 },
		"negative assessment budget":  func(c *NodeExposureReadContext) { c.MaxClassificationAge = -time.Second },
		"unbounded assessment budget": func(c *NodeExposureReadContext) { c.MaxClassificationAge = MaxSnapshotLifetime + 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := exposureFixture(t)
			c := exposureContext(t, s)
			change(&c)
			if view, err := ProjectNodeExposureSnapshot(s, c); !errors.Is(err, ErrInvalidNodeExposureContext) || view != (NodeExposureView{}) {
				t.Fatal("invalid context accepted", err)
			}
		})
	}
}

func TestNodeExposureRejectsIncoherentClaims(t *testing.T) {
	changes := map[string]func(*NodeExposureSnapshot){
		"missing identity":           func(s *NodeExposureSnapshot) { s.Identity = NodeIdentity{} },
		"missing collector":          func(s *NodeExposureSnapshot) { s.CollectorID = "" },
		"malformed policy":           func(s *NodeExposureSnapshot) { s.Policy.SHA256 = "hash" },
		"empty lifetime":             func(s *NodeExposureSnapshot) { s.ValidUntil = s.GeneratedAt },
		"unbounded lifetime":         func(s *NodeExposureSnapshot) { s.ValidUntil = "2026-01-02T00:00:01Z" },
		"clock":                      func(s *NodeExposureSnapshot) { s.ClockQuality = "trusted" },
		"local time":                 func(s *NodeExposureSnapshot) { s.GeneratedAt = "2026-01-01T01:00:00+01:00" },
		"exposure future assessment": func(s *NodeExposureSnapshot) { s.Exposure.AssessedAt = s.ValidUntil },
		"hosting future assessment":  func(s *NodeExposureSnapshot) { s.HostingModel.AssessedAt = s.ValidUntil },
		"invented exposure":          func(s *NodeExposureSnapshot) { s.Exposure.Value = "protected" },
		"mixed exposure":             func(s *NodeExposureSnapshot) { s.Exposure.Value = "external,internal" },
		"hosting as exposure":        func(s *NodeExposureSnapshot) { s.Exposure.Value = "on_premises" },
		"missing lineage":            func(s *NodeExposureSnapshot) { s.Exposure.Source = RateReference{} },
		"partial lineage":            func(s *NodeExposureSnapshot) { s.HostingModel.Source.SHA256 = "" },
		"missing assessment time":    func(s *NodeExposureSnapshot) { s.Exposure.AssessedAt = "" },
		"partial claim":              func(s *NodeExposureSnapshot) { s.Exposure.State = Partial },
		"absent with value":          func(s *NodeExposureSnapshot) { s.Exposure.State = Missing },
		"stale without value":        func(s *NodeExposureSnapshot) { s.Exposure = InventoryClassification{State: Stale} },
		"absent with lineage":        func(s *NodeExposureSnapshot) { s.Exposure = InventoryClassification{State: Missing, Source: s.Scope} },
		"absent with time": func(s *NodeExposureSnapshot) {
			s.HostingModel = InventoryClassification{State: Rejected, AssessedAt: s.GeneratedAt}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := exposureFixture(t)
			c := exposureContext(t, s)
			change(&s)
			if err := s.Validate(); !errors.Is(err, ErrInvalidNodeExposureDocument) {
				t.Fatal("incoherent claim accepted", err)
			}
			if b, err := EncodeNodeExposureSnapshot(s); err == nil || b != nil {
				t.Fatal("incoherent claim encoded")
			}
			if h, err := NodeExposureSnapshotSHA256(s); err == nil || h != "" {
				t.Fatal("incoherent claim hashed")
			}
			if view, err := ProjectNodeExposureSnapshot(s, c); err == nil || view != (NodeExposureView{}) {
				t.Fatal("incoherent claim projected")
			}
		})
	}
}
