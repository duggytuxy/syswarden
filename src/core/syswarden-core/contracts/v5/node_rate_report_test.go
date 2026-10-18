package v5

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func nodeRateReportMetadata() NodeRateSnapshotMetadata {
	return NodeRateSnapshotMetadata{SnapshotID: "node-rate.fixture.1", CollectorID: "collector.fixture.1",
		GeneratedAt: "2026-10-17T10:00:01Z", ValidUntil: "2026-10-17T10:05:00Z",
		ClockQuality: "synchronized", MinimumEligible: "1"}
}

func nodeRateReportFixture(t testing.TB) (NodeRateBasis, NodeRatePopulation, RateReference, RateSnapshot) {
	t.Helper()
	b := nodeRateBasisFixture()
	m := []NodeRateMember{nodeRateMemberFixture(1), nodeRateMemberFixture(2), nodeRateMemberFixture(3)}
	m[2].Exclusion = RateReference{"approved-eligibility-decision", strings.Repeat("5", 64)}
	p := resolveNodeRateFixture(t, b, m, []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")})
	if !bytes.Equal(p.Manifest(), fixture(t, "node-rate-population.json")) {
		t.Fatal("existing independent population fixture changed")
	}
	ref, err := p.Reference("population.fixture.1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ComposeNodeRateSnapshot(b, p, ref, nodeRateReportMetadata())
	if err != nil {
		t.Fatal(err)
	}
	return b, p, ref, s
}

// Synthetic trusted selection for tests, not admission of a submitted report.
func nodeRateReportReadContext(t testing.TB, s RateSnapshot) RateReadContext {
	t.Helper()
	h, err := RateSnapshotSHA256(s)
	if err != nil {
		t.Fatal(err)
	}
	return RateReadContext{SnapshotID: s.SnapshotID, SnapshotSHA256: h, CollectorID: s.CollectorID,
		DefinitionID: s.DefinitionID, Category: s.Category, Inputs: s.Inputs, Window: s.Window,
		MinimumEligible: s.MinimumEligible, Now: time.Date(2026, 10, 17, 10, 0, 2, 0, time.UTC), MaxAge: time.Minute}
}

func requireRejectedNodeRateReport(t testing.TB, s RateSnapshot, b NodeRateBasis, p NodeRatePopulation, c RateReadContext) {
	t.Helper()
	r, err := ProjectNodeRatePercentages(s, b, p, c)
	if !errors.Is(err, ErrInvalidNodeRateReport) || r != (RatePercentages{}) {
		t.Fatal("rejected population report returned a partial result", err, r)
	}
}

func TestNodeRateReportGoldenAndCopyIsolation(t *testing.T) {
	b, p, ref, s := nodeRateReportFixture(t)
	data, err := EncodeRateSnapshot(s)
	if err != nil || !bytes.Equal(data, fixture(t, "node-rate-report.json")) {
		t.Fatal("independent report bytes differ", err)
	}
	h, err := RateSnapshotSHA256(s)
	if err != nil || h != strings.TrimSpace(string(fixture(t, "node-rate-report-digest.txt"))) {
		t.Fatal("independent report digest differs", err)
	}
	parsed, err := DecodeRateSnapshot(data)
	if err != nil || parsed != s {
		t.Fatal("existing wire codec changed report", err)
	}
	c := nodeRateReportReadContext(t, s)
	c.SnapshotSHA256 = strings.TrimSpace(string(fixture(t, "node-rate-report-digest.txt")))
	r, err := ProjectNodeRatePercentages(parsed, b, p, c)
	if err != nil || r.Matched != (Field{Partial, "50.00"}) || r.Unknown != (Field{Partial, "50.00"}) {
		t.Fatal("unknown members hidden after report composition", err, r)
	}
	parsed.Counts.Matched, parsed.Counts.Unknown = "2", "0"
	data[0] = 'X'
	manifest := p.Manifest()
	manifest[0] = 'X'
	again, err := ComposeNodeRateSnapshot(b, p, ref, nodeRateReportMetadata())
	if err != nil || again != s {
		t.Fatal("caller changed immutable population or report", err)
	}
}

func TestNodeRateReportRejectsWrongBasisAndMetadata(t *testing.T) {
	for _, field := range []string{"zero population", "empty reference", "wrong digest", "bad ref", "scope", "membership", "policy", "instant", "basis state", "formula", "nonnode formula", "unknown formula", "snapshot id", "collector id", "generated before window", "expired lifetime", "overlong lifetime", "bad clock", "zero minimum", "large minimum", "noncanonical time"} {
		t.Run(field, func(t *testing.T) {
			b, p, ref, _ := nodeRateReportFixture(t)
			m := nodeRateReportMetadata()
			switch field {
			case "zero population":
				p = NodeRatePopulation{}
			case "empty reference":
				ref = RateReference{}
			case "wrong digest":
				ref.SHA256 = strings.Repeat("f", 64)
			case "bad ref":
				ref.Ref = "private\ninput"
			case "scope":
				b.Scope.Ref = "other"
			case "membership":
				b.Membership.SHA256 = strings.Repeat("f", 64)
			case "policy":
				b.Policy.Ref = "other"
			case "instant":
				b.Window.Start, b.Window.End = "2026-10-17T09:59:59Z", "2026-10-17T09:59:59Z"
			case "basis state":
				b.State = Partial
			case "formula":
				b.DefinitionID = "policy_conformity.v1"
			case "nonnode formula":
				b.DefinitionID = "alert_severity_share.v1"
			case "unknown formula":
				b.DefinitionID = "unknown.v1"
			case "snapshot id":
				m.SnapshotID = ""
			case "collector id":
				m.CollectorID = strings.Repeat("x", MaxIdentifierBytes+1)
			case "generated before window":
				m.GeneratedAt = "2026-10-17T09:59:59Z"
			case "expired lifetime":
				m.ValidUntil = m.GeneratedAt
			case "overlong lifetime":
				m.ValidUntil = "2026-10-18T10:00:02Z"
			case "bad clock":
				m.ClockQuality = "trusted"
			case "zero minimum":
				m.MinimumEligible = "0"
			case "large minimum":
				m.MinimumEligible = "9223372036854775808"
			case "noncanonical time":
				m.GeneratedAt = "2026-10-17T10:00:01.000Z"
			}
			s, err := ComposeNodeRateSnapshot(b, p, ref, m)
			if !errors.Is(err, ErrInvalidNodeRateReport) || s != (RateSnapshot{}) || strings.Contains(err.Error(), "private\ninput") {
				t.Fatal("bad composition returned report or private input", err)
			}
		})
	}
}

func TestNodeRateReportRejectsCoherentButSubstitutedClaims(t *testing.T) {
	for _, field := range []string{"counts", "denominator", "excluded", "count quality", "formula", "scope", "policy", "instant", "population digest", "same counts other members", "same counts other evidence", "wrong expected basis"} {
		t.Run(field, func(t *testing.T) {
			b, p, _, s := nodeRateReportFixture(t)
			switch field {
			case "counts":
				s.Counts.Matched, s.Counts.Unknown = "2", "0"
			case "denominator":
				s.Counts.Matched, s.Counts.Eligible = "2", "3"
			case "excluded":
				s.Counts.Excluded = "0"
			case "count quality":
				s.Counts.State = Present
			case "formula":
				s.DefinitionID = "reporting_coverage.v1"
				s.DefinitionSHA256, _ = RateDefinitionSHA256(s.DefinitionID)
			case "scope":
				s.Inputs.Scope.Ref = "other"
			case "policy":
				s.Inputs.Policy.SHA256 = strings.Repeat("f", 64)
			case "instant":
				s.Window.Start, s.Window.End = "2026-10-17T09:59:59Z", "2026-10-17T09:59:59Z"
			case "population digest":
				s.Inputs.Population.SHA256 = strings.Repeat("f", 64)
			case "same counts other members", "same counts other evidence":
				members := []NodeRateMember{nodeRateMemberFixture(1), nodeRateMemberFixture(2), nodeRateMemberFixture(3)}
				members[2].Exclusion = RateReference{"approved-eligibility-decision", strings.Repeat("5", 64)}
				if field == "same counts other members" {
					members[0].Identity.NodeID = "different"
				}
				a := nodeRateAssessmentFixture(t, b, members[0], "matched")
				if field == "same counts other evidence" {
					a.Evidence.SHA256 = strings.Repeat("f", 64)
				}
				p = resolveNodeRateFixture(t, b, members, []NodeRateAssessment{a})
				if p.Counts() != s.Counts {
					t.Fatal("fixture must preserve scalar counts")
				}
			case "wrong expected basis":
				b.Membership.Ref = "different.selection"
			}
			// Even independently selected, fresh and well-formed scalar reports
			// must agree with the separately resolved actual population.
			c := nodeRateReportReadContext(t, s)
			if err := CheckCurrentRateSnapshot(s, c); err != nil {
				t.Fatal(err)
			}
			requireRejectedNodeRateReport(t, s, b, p, c)
		})
	}
}

func TestNodeRateReportReadBindingAndFreshness(t *testing.T) {
	b, p, _, s := nodeRateReportFixture(t)
	for _, field := range []string{"snapshot", "digest", "collector", "formula", "scope", "policy", "population", "window", "minimum", "zero age", "future", "expiry", "age boundary"} {
		t.Run(field, func(t *testing.T) {
			c := nodeRateReportReadContext(t, s)
			switch field {
			case "snapshot":
				c.SnapshotID = "other"
			case "digest":
				c.SnapshotSHA256 = strings.Repeat("f", 64)
			case "collector":
				c.CollectorID = "other"
			case "formula":
				c.DefinitionID = "policy_conformity.v1"
			case "scope":
				c.Inputs.Scope.Ref = "other"
			case "policy":
				c.Inputs.Policy.Ref = "other"
			case "population":
				c.Inputs.Population.Ref = "other"
			case "window":
				c.Window.Start, c.Window.End = "2026-10-17T09:00:00Z", "2026-10-17T09:00:00Z"
			case "minimum":
				c.MinimumEligible = "2"
			case "zero age":
				c.MaxAge = 0
			case "future":
				c.Now = time.Date(2026, 10, 17, 10, 0, 0, 999999999, time.UTC)
			case "expiry":
				c.Now = time.Date(2026, 10, 17, 10, 5, 0, 0, time.UTC)
			case "age boundary":
				c.MaxAge = time.Second
			}
			requireRejectedNodeRateReport(t, s, b, p, c)
		})
	}
	for _, clock := range []string{"unknown", "unsynchronized"} {
		s.ClockQuality = clock
		requireRejectedNodeRateReport(t, s, b, p, nodeRateReportReadContext(t, s))
	}
}

func TestNodeRateReportKeepsQualityAndUnavailablePercentages(t *testing.T) {
	for _, definition := range []string{"reporting_coverage.v1", "verified_protection_coverage.v1", "policy_conformity.v1"} {
		for _, state := range []string{Present, Partial, Stale} {
			for _, caseName := range []string{"matched", "missing", "stale", "empty", "excluded", "below minimum"} {
				t.Run(definition+"/"+state+"/"+caseName, func(t *testing.T) {
					b := nodeRateBasisFixture()
					b.DefinitionID, b.State = definition, state
					m := []NodeRateMember{nodeRateMemberFixture(1)}
					var a []NodeRateAssessment
					metadata := nodeRateReportMetadata()
					switch caseName {
					case "matched", "below minimum":
						a = []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")}
					case "stale":
						a = []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "stale")}
					case "empty":
						m = nil
					case "excluded":
						m[0].Exclusion = RateReference{"reviewed", strings.Repeat("a", 64)}
					}
					if caseName == "below minimum" {
						metadata.MinimumEligible = "2"
					}
					p := resolveNodeRateFixture(t, b, m, a)
					ref, _ := p.Reference("population")
					s, err := ComposeNodeRateSnapshot(b, p, ref, metadata)
					if err != nil {
						t.Fatal(err)
					}
					r, err := ProjectNodeRatePercentages(s, b, p, nodeRateReportReadContext(t, s))
					if err != nil {
						t.Fatal(err)
					}
					if caseName == "empty" || caseName == "excluded" || caseName == "below minimum" {
						if r.Matched != (Field{State: Unavailable}) {
							t.Fatal("unavailable percentage became numeric", r)
						}
					} else {
						want := state
						if state == Present && caseName != "matched" {
							want = Partial
						}
						if r.Matched.State != want {
							t.Fatal("fresh report upgraded source quality", r)
						}
						if caseName == "matched" && r.Matched.Value != "100.00" || caseName == "missing" && r.Unknown.Value != "100.00" || caseName == "stale" && r.Stale.Value != "100.00" {
							t.Fatal("partition changed", r)
						}
					}
				})
			}
		}
	}
}

func TestNodeRateReportEndToEndSelectedFleet(t *testing.T) {
	f := syntheticRateFleet(t, 500)
	for _, group := range []string{"all", "external", "internal", "needs_classification"} {
		t.Run(group, func(t *testing.T) {
			v, err := f.Select(group)
			if err != nil {
				t.Fatal(err)
			}
			selected, b := fleetRateBasis(t, v, "reporting_coverage.v1")
			var members []NodeRateMember
			var assessments []NodeRateAssessment
			rows := v.Entries()
			for i, row := range rows {
				m := NodeRateMember{Identity: row.NodeState.Identity}
				members = append(members, m)
				if i < len(rows)*4/5 {
					assessments = append(assessments, nodeRateAssessmentFixture(t, b, m, "matched"))
				}
			}
			p, err := ResolveFleetNodeRatePopulation(v, selected, b, members, assessments)
			if err != nil {
				t.Fatal(err)
			}
			ref, _ := p.Reference("selected.population")
			s, err := ComposeNodeRateSnapshot(b, p, ref, nodeRateReportMetadata())
			if err != nil {
				t.Fatal(err)
			}
			data, err := EncodeRateSnapshot(s)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeRateSnapshot(data)
			if err != nil {
				t.Fatal(err)
			}
			r, err := ProjectNodeRatePercentages(decoded, b, p, nodeRateReportReadContext(t, s))
			if err != nil {
				t.Fatal(err)
			}
			if group == "needs_classification" {
				if r.Matched.State != Unavailable || r.Matched.Value != "" {
					t.Fatal("empty group became numeric", r)
				}
			} else if r.Matched != (Field{Partial, "80.00"}) || r.Unknown != (Field{Partial, "20.00"}) {
				t.Fatal("selected fleet denominator lost in codec or projection", r)
			}
		})
	}
}
