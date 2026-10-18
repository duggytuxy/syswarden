package v5

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fleetProjectionInput(t testing.TB, basis NodeRateBasis, members []NodeRateMember, assessments []NodeRateAssessment) FleetNodeRateReport {
	t.Helper()
	p := resolveNodeRateFixture(t, basis, members, assessments)
	ref, err := p.Reference("population." + basis.DefinitionID)
	if err != nil {
		t.Fatal(err)
	}
	instant, err := time.Parse(time.RFC3339Nano, basis.Window.Start)
	if err != nil {
		t.Fatal(err)
	}
	m := nodeRateReportMetadata()
	m.SnapshotID = "report." + basis.DefinitionID
	m.GeneratedAt, m.ValidUntil = instant.Add(time.Second).Format(time.RFC3339Nano), instant.Add(5*time.Minute).Format(time.RFC3339Nano)
	s, err := ComposeNodeRateSnapshot(basis, p, ref, m)
	if err != nil {
		t.Fatal(err)
	}
	c := nodeRateReportReadContext(t, s)
	c.Now = instant.Add(2 * time.Second)
	return FleetNodeRateReport{Basis: basis, Population: p, Snapshot: s, ReadContext: c}
}

func fleetProjectionInputs(t testing.TB, v FleetStateView) (RateReference, time.Time, []FleetNodeRateReport, []NodeRateMember) {
	t.Helper()
	var members []NodeRateMember
	for _, entry := range v.Entries() {
		members = append(members, NodeRateMember{Identity: entry.NodeState.Identity})
	}
	var reports []FleetNodeRateReport
	var ref RateReference
	for _, id := range []string{"reporting_coverage.v1", "verified_protection_coverage.v1", "policy_conformity.v1"} {
		selected, b := fleetRateBasis(t, v, id)
		ref = selected
		reports = append(reports, fleetProjectionInput(t, b, members, nil))
	}
	return ref, reports[0].ReadContext.Now, reports, members
}

func requireRejectedFleetProjection(t testing.TB, v FleetStateView, ref RateReference, now time.Time, inputs []FleetNodeRateReport) {
	t.Helper()
	result, err := ProjectFleetNodeRates(v, ref, now, inputs)
	if !errors.Is(err, ErrInvalidFleetRateProjection) || result != (FleetNodeRateProjection{}) {
		t.Fatal("rejected bundle disclosed a partial projection", err)
	}
	if strings.Contains(err.Error(), "private-input") {
		t.Fatal("input value disclosed by error")
	}
}

func TestFleetRateProjectionPreservesUnknownAndInputOrder(t *testing.T) {
	f, v, _, _, _ := fleetRateFixture(t)
	ref, now, inputs, _ := fleetProjectionInputs(t, v)
	want, err := ProjectFleetNodeRates(v, ref, now, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if want.Scope != inputs[0].Basis.Scope || want.Policy != inputs[0].Basis.Policy || want.Selection != ref ||
		want.Window != inputs[0].Basis.Window || want.ReadAt != now.Format(time.RFC3339Nano) {
		t.Fatal("shared context lost")
	}
	for i, got := range []NodeRateProjection{want.ReportingCoverage, want.VerifiedProtectionCoverage, want.PolicyConformity} {
		if got.DefinitionID != inputs[i].Basis.DefinitionID || got.Counts != inputs[i].Population.Counts() ||
			got.Report != (RateReference{inputs[i].Snapshot.SnapshotID, inputs[i].ReadContext.SnapshotSHA256}) ||
			got.Population != inputs[i].Snapshot.Inputs.Population || got.MinimumEligible != "1" ||
			got.DefinitionSHA256 != inputs[i].Snapshot.DefinitionSHA256 ||
			got.Percentages.Matched != (Field{Partial, "0.00"}) || got.Percentages.Unknown != (Field{Partial, "100.00"}) {
			t.Fatal("transport state or unassessed evidence became protection", got)
		}
	}
	for _, order := range [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		shuffled := []FleetNodeRateReport{inputs[order[0]], inputs[order[1]], inputs[order[2]]}
		got, err := ProjectFleetNodeRates(v, ref, now.In(time.FixedZone("display", 3600)), shuffled)
		if err != nil || got != want {
			t.Fatal("arrival order or equivalent read instant changed the result", err)
		}
	}
	other, _ := f.Select("all")
	requireRejectedFleetProjection(t, other, ref, now, inputs)
	copy := want
	copy.ReportingCoverage.Percentages.Matched.Value = "100.00"
	inputs[0].Snapshot.Counts.Matched = "1"
	if want.ReportingCoverage.Percentages.Matched.Value != "0.00" || want.ReportingCoverage.Counts.Matched != "0" {
		t.Fatal("result aliased caller state")
	}
}

func TestFleetRateProjectionRejectsIncompleteAndUnboundBundles(t *testing.T) {
	for _, field := range []string{"missing", "extra", "duplicate", "unknown formula", "nonnode formula", "zero view", "zero selection", "selection ref", "selection digest", "zero time", "invalid time"} {
		t.Run(field, func(t *testing.T) {
			_, v, _, _, _ := fleetRateFixture(t)
			ref, now, inputs, _ := fleetProjectionInputs(t, v)
			switch field {
			case "missing":
				inputs = inputs[:2]
			case "extra":
				inputs = append(inputs, inputs[0])
			case "duplicate":
				inputs[2] = inputs[0]
			case "unknown formula":
				inputs[2].Basis.DefinitionID = "private-input"
			case "nonnode formula":
				inputs[2].Basis.DefinitionID = "alert_severity_share.v1"
			case "zero view":
				v = FleetStateView{}
			case "zero selection":
				ref = RateReference{}
			case "selection ref":
				ref.Ref = "other"
			case "selection digest":
				ref.SHA256 = strings.Repeat("f", 64)
			case "zero time":
				now = time.Time{}
			case "invalid time":
				now = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			}
			requireRejectedFleetProjection(t, v, ref, now, inputs)
		})
	}
}

func TestFleetRateProjectionRejectsCoherentPopulationSubstitution(t *testing.T) {
	for position := 0; position < 3; position++ {
		for _, change := range []string{"scope", "policy", "membership", "measurement", "omitted", "added", "epoch", "cluster", "identity", "excluded identity"} {
			t.Run(strconv.Itoa(position)+"/"+change, func(t *testing.T) {
				_, v, _, _, _ := fleetRateFixture(t)
				ref, now, inputs, members := fleetProjectionInputs(t, v)
				basis := inputs[position].Basis
				switch change {
				case "scope":
					basis.Scope.Ref = "other"
				case "policy":
					basis.Policy.SHA256 = strings.Repeat("f", 64)
				case "membership":
					basis.Membership.Ref = "other"
				case "measurement":
					b, _ := time.Parse(time.RFC3339Nano, basis.Window.Start)
					basis.Window.Start, basis.Window.End = b.Add(-time.Second).Format(time.RFC3339Nano), b.Add(-time.Second).Format(time.RFC3339Nano)
				case "omitted":
					members = nil
				case "added":
					m := members[0]
					m.Identity.NodeID = "extra"
					members = append(members, m)
				case "epoch":
					members[0].Identity.Epoch = "old"
				case "cluster":
					members[0].Identity.ClusterID = "other"
				case "identity":
					members[0].Identity.NodeID = "other"
				case "excluded identity":
					members[0].Identity.NodeID = "other"
					members[0].Exclusion = RateReference{"reviewed", strings.Repeat("f", 64)}
				}
				inputs[position] = fleetProjectionInput(t, basis, members, nil)
				inputs[position].ReadContext.Now = now
				in := inputs[position]
				if _, err := ProjectNodeRatePercentages(in.Snapshot, in.Basis, in.Population, in.ReadContext); err != nil {
					t.Fatal("fixture must be a valid individually selected report", err)
				}
				requireRejectedFleetProjection(t, v, ref, now, inputs)
			})
		}
	}
}

func TestFleetRateProjectionRejectsEachReportBindingAndFreshness(t *testing.T) {
	for position := 0; position < 3; position++ {
		for _, change := range []string{"zero population", "read instant", "old report", "new report", "collector", "population", "minimum", "digest", "coherent counts", "exact expiry", "exact max age", "bad clock", "wrong formula"} {
			t.Run(strconv.Itoa(position)+"/"+change, func(t *testing.T) {
				_, v, _, _, _ := fleetRateFixture(t)
				ref, now, inputs, _ := fleetProjectionInputs(t, v)
				in := &inputs[position]
				switch change {
				case "zero population":
					in.Population = NodeRatePopulation{}
				case "read instant":
					in.ReadContext.Now = now.Add(time.Nanosecond)
				case "old report":
					in.ReadContext.SnapshotID = "other"
				case "new report":
					in.Snapshot.GeneratedAt = now.Add(time.Second).Format(time.RFC3339Nano)
				case "collector":
					in.ReadContext.CollectorID = "other"
				case "population":
					in.ReadContext.Inputs.Population.SHA256 = strings.Repeat("f", 64)
				case "minimum":
					in.ReadContext.MinimumEligible = "2"
				case "digest":
					in.ReadContext.SnapshotSHA256 = strings.Repeat("f", 64)
				case "coherent counts":
					in.Snapshot.Counts.Matched, in.Snapshot.Counts.Unknown = "1", "0"
				case "exact expiry":
					in.Snapshot.ValidUntil = now.Format(time.RFC3339Nano)
				case "exact max age":
					in.ReadContext.MaxAge = time.Second
				case "bad clock":
					in.Snapshot.ClockQuality = "unknown"
				case "wrong formula":
					in.Snapshot.DefinitionID = "policy_conformity.v1"
					if in.Basis.DefinitionID == in.Snapshot.DefinitionID {
						in.Snapshot.DefinitionID = "reporting_coverage.v1"
					}
					in.Snapshot.DefinitionSHA256, _ = RateDefinitionSHA256(in.Snapshot.DefinitionID)
				}
				if change == "coherent counts" || change == "exact expiry" || change == "bad clock" || change == "new report" || change == "wrong formula" {
					in.ReadContext = nodeRateReportReadContext(t, in.Snapshot)
					in.ReadContext.Now = now
				}
				requireRejectedFleetProjection(t, v, ref, now, inputs)
			})
		}
	}
}

func TestFleetRateProjectionKeepsIndependentEligibilityAndQuality(t *testing.T) {
	f := syntheticRateFleet(t, 8)
	v, _ := f.Select("all")
	ref, now, inputs, members := fleetProjectionInputs(t, v)
	for i := range inputs {
		m := slices.Clone(members)
		var assessments []NodeRateAssessment
		for j := range m {
			part := "matched"
			if i == 1 && j < 2 || i == 2 && j < 5 {
				m[j].Exclusion = RateReference{"reviewed.eligibility", strings.Repeat("f", 64)}
				continue
			}
			if i == 1 {
				if j == 5 {
					part = "other"
				}
				if j == 6 {
					part = "stale"
				}
				if j == 7 {
					continue
				}
			}
			if i == 2 && j == 7 {
				part = "other"
			}
			assessments = append(assessments, nodeRateAssessmentFixture(t, inputs[i].Basis, m[j], part))
		}
		inputs[i] = fleetProjectionInput(t, inputs[i].Basis, m, assessments)
	}
	result, err := ProjectFleetNodeRates(v, ref, now, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if result.ReportingCoverage.Percentages.Matched != (Field{Present, "100.00"}) ||
		result.VerifiedProtectionCoverage.Percentages != (RatePercentages{Field{Partial, "50.00"}, Field{Partial, "16.67"}, Field{Partial, "16.67"}, Field{Partial, "16.67"}}) ||
		result.PolicyConformity.Percentages.Matched != (Field{Present, "66.67"}) ||
		result.VerifiedProtectionCoverage.Counts.Excluded != "2" || result.PolicyConformity.Counts.Excluded != "5" {
		t.Fatal("independent denominators, exclusions or uncertainty changed", result)
	}
	inputs[2].Snapshot.MinimumEligible = "4"
	inputs[2].ReadContext = nodeRateReportReadContext(t, inputs[2].Snapshot)
	inputs[2].ReadContext.Now = now
	result, err = ProjectFleetNodeRates(v, ref, now, inputs)
	if err != nil || result.PolicyConformity.Percentages.Matched != (Field{State: Unavailable}) || result.ReportingCoverage.Percentages.Matched.Value != "100.00" {
		t.Fatal("formula threshold affected another indicator", err)
	}
}

func TestFleetRateProjectionSelectionAndScale(t *testing.T) {
	for _, size := range []int{0, 500} {
		f := syntheticRateFleet(t, size)
		for _, group := range []string{"all", "external", "internal", "needs_classification"} {
			t.Run(strconv.Itoa(size)+"/"+group, func(t *testing.T) {
				v, err := f.Select(group)
				if err != nil {
					t.Fatal(err)
				}
				ref, now, inputs, members := fleetProjectionInputs(t, v)
				for i := range inputs {
					data, err := EncodeRateSnapshot(inputs[i].Snapshot)
					if err != nil {
						t.Fatal(err)
					}
					inputs[i].Snapshot, err = DecodeRateSnapshot(data)
					if err != nil {
						t.Fatal(err)
					}
				}
				result, err := ProjectFleetNodeRates(v, ref, now, inputs)
				if err != nil {
					t.Fatal(err)
				}
				for _, rate := range []NodeRateProjection{result.ReportingCoverage, result.VerifiedProtectionCoverage, result.PolicyConformity} {
					if rate.Counts.Eligible != strconv.Itoa(len(members)) {
						t.Fatal("selected denominator changed")
					}
					if len(members) == 0 {
						if rate.Percentages.Matched != (Field{State: Unavailable}) {
							t.Fatal("empty population became numeric")
						}
					} else if rate.Percentages.Unknown != (Field{Partial, "100.00"}) || rate.Percentages.Matched.Value != "0.00" {
						t.Fatal("outage disappeared from complete selected population")
					}
				}
			})
		}
	}
}

func TestFleetRateProjectionKeepsSourceQualityAndEmptyEligibility(t *testing.T) {
	for _, quality := range []string{Present, Partial, Stale} {
		for _, excluded := range []bool{false, true} {
			t.Run(quality+"/"+strconv.FormatBool(excluded), func(t *testing.T) {
				_, v, _, _, _ := fleetRateFixture(t)
				ref, now, inputs, members := fleetProjectionInputs(t, v)
				for i := range inputs {
					b := inputs[i].Basis
					b.State = quality
					m := slices.Clone(members)
					var a []NodeRateAssessment
					if excluded {
						m[0].Exclusion = RateReference{"reviewed.exclusion", strings.Repeat("f", 64)}
					} else {
						a = []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")}
					}
					inputs[i] = fleetProjectionInput(t, b, m, a)
					m[0].Identity.NodeID = "caller.changed"
				}
				got, err := ProjectFleetNodeRates(v, ref, now, inputs)
				if err != nil {
					t.Fatal(err)
				}
				want := Field{quality, "100.00"}
				if excluded {
					want = Field{State: Unavailable}
				}
				for _, kpi := range []NodeRateProjection{got.ReportingCoverage, got.VerifiedProtectionCoverage, got.PolicyConformity} {
					if kpi.Percentages.Matched != want {
						t.Fatal("source quality or eligibility lost", kpi)
					}
				}
			})
		}
	}
}

func TestFleetRateProjectionNanosecondReadBoundary(t *testing.T) {
	_, v, _, _, _ := fleetRateFixture(t)
	ref, _, inputs, _ := fleetProjectionInputs(t, v)
	generated, _ := time.Parse(time.RFC3339Nano, inputs[0].Snapshot.GeneratedAt)
	boundary := generated.Add(time.Minute)
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		now := boundary.Add(delta)
		for i := range inputs {
			inputs[i].ReadContext.Now = now
		}
		if delta >= 0 {
			requireRejectedFleetProjection(t, v, ref, now, inputs)
		} else if _, err := ProjectFleetNodeRates(v, ref, now, inputs); err != nil {
			t.Fatal("valid instant before exact age boundary rejected", err)
		}
	}
}
