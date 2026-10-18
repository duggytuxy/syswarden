package v5

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func fleetRateBasis(t testing.TB, view FleetStateView, definition string) (RateReference, NodeRateBasis) {
	t.Helper()
	ref, err := view.Reference("selection.fixture.1")
	if err != nil {
		t.Fatal(err)
	}
	c := view.binding.Context.Exposure
	instant := c.Now.Format(time.RFC3339Nano)
	return ref, NodeRateBasis{DefinitionID: definition, Scope: c.Scope, Membership: ref,
		Policy: c.Policy, Window: RateWindow{Kind: "snapshot", Start: instant, End: instant}, State: Present}
}

func fleetRateFixture(t testing.TB) (FleetState, FleetStateView, RateReference, NodeRateBasis, []NodeRateMember) {
	t.Helper()
	c, f, n := fleetStateFixture(t)
	s, err := ComposeFleetState(c, f, n)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Select("external")
	if err != nil {
		t.Fatal(err)
	}
	ref, basis := fleetRateBasis(t, v, "reporting_coverage.v1")
	return s, v, ref, basis, []NodeRateMember{{Identity: v.Entries()[0].NodeState.Identity}}
}

func requireInvalidFleetRate(t testing.TB, view FleetStateView, ref RateReference, basis NodeRateBasis, m []NodeRateMember, a []NodeRateAssessment) {
	t.Helper()
	p, err := ResolveFleetNodeRatePopulation(view, ref, basis, m, a)
	if !errors.Is(err, ErrInvalidFleetNodeRatePopulation) || p.Manifest() != nil || p.Counts() != (RateCounts{}) {
		t.Fatal("rejected binding disclosed a partial population", err)
	}
	if ref, err := p.Reference("rejected"); err == nil || ref != (RateReference{}) {
		t.Fatal("rejected population referenced")
	}
}

func TestFleetNodeRatesGoldenAndNoInferredVerdict(t *testing.T) {
	_, v, ref, b, m := fleetRateFixture(t)
	p, err := ResolveFleetNodeRatePopulation(v, ref, b, m, nil)
	if err != nil || !bytes.Equal(p.Manifest(), fixture(t, "fleet-node-rate-population.json")) {
		t.Fatal("independent golden bytes differ", err)
	}
	got, err := p.Reference("population")
	if err != nil || got.SHA256 != strings.TrimSpace(string(fixture(t, "fleet-node-rate-population-digest.txt"))) {
		t.Fatal("independent golden digest differs", err)
	}
	for _, definition := range []string{"reporting_coverage.v1", "verified_protection_coverage.v1", "policy_conformity.v1"} {
		_, basis := fleetRateBasis(t, v, definition)
		p, err := ResolveFleetNodeRatePopulation(v, ref, basis, m, nil)
		if err != nil || p.Counts() != (RateCounts{Partial, "1", "0", "0", "1", "0", "0"}) {
			t.Fatal("reachable node or opaque references became an assessed verdict", definition, err)
		}
		if got := nodeRatePercentages(t, basis, p); got.Matched.Value != "0.00" || got.Unknown.Value != "100.00" || got.Matched.State != Partial {
			t.Fatal("unknown assessment hidden in percentage", got)
		}
	}
	data := p.Manifest()
	data[0] = 'X'
	if !bytes.Equal(p.Manifest(), fixture(t, "fleet-node-rate-population.json")) {
		t.Fatal("caller mutated retained population")
	}
}

func TestFleetNodeRatesRejectDifferentBindingsAndMembership(t *testing.T) {
	for _, field := range []string{"zero view", "other group", "empty selection", "selection digest", "selection ref", "scope ref", "scope digest", "membership ref", "membership digest", "policy ref", "policy digest", "time", "interval", "unknown denominator", "unknown formula", "nonnode formula", "missing node", "extra node", "old epoch", "other cluster", "other node", "invalid identity", "eligibility conflict", "partial exclusion", "member limit", "assessment limit", "assessment basis", "foreign assessment", "excluded assessment", "missing evidence"} {
		t.Run(field, func(t *testing.T) {
			s, v, ref, b, m := fleetRateFixture(t)
			a := []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")}
			switch field {
			case "zero view":
				v = FleetStateView{}
			case "other group":
				var err error
				v, err = s.Select("all")
				if err != nil {
					t.Fatal(err)
				}
			case "empty selection":
				ref = RateReference{}
			case "selection digest":
				ref.SHA256 = strings.Repeat("a", 64)
				b.Membership = ref
			case "selection ref":
				ref.Ref = "different"
			case "scope ref":
				b.Scope.Ref = "other"
			case "scope digest":
				b.Scope.SHA256 = strings.Repeat("f", 64)
			case "membership ref":
				b.Membership.Ref = "other"
			case "membership digest":
				b.Membership.SHA256 = strings.Repeat("a", 64)
			case "policy ref":
				b.Policy.Ref = "other"
			case "policy digest":
				b.Policy.SHA256 = strings.Repeat("f", 64)
			case "time":
				b.Window.Start, b.Window.End = "2026-01-01T00:00:30.000000001Z", "2026-01-01T00:00:30.000000001Z"
			case "interval":
				b.Window.Kind = "interval"
			case "unknown denominator":
				b.State = Unavailable
			case "unknown formula":
				b.DefinitionID = "unknown.v1"
			case "nonnode formula":
				b.DefinitionID = "alert_severity_share.v1"
			case "missing node":
				m = nil
			case "extra node":
				other := m[0]
				other.Identity.NodeID = "extra"
				m = append(m, other)
			case "old epoch":
				m[0].Identity.Epoch = "replaced"
			case "other cluster":
				m[0].Identity.ClusterID = "other"
			case "other node":
				m[0].Identity.NodeID = "other"
			case "invalid identity":
				m[0].Identity.NodeID = "bad\nidentity"
			case "eligibility conflict":
				m = append(m, m[0])
				m[1].Exclusion = RateReference{"exclude", strings.Repeat("a", 64)}
			case "partial exclusion":
				m[0].Exclusion.Ref = "missing.digest"
			case "member limit":
				m = make([]NodeRateMember, MaxNodeRateInputs+1)
			case "assessment limit":
				a = make([]NodeRateAssessment, MaxNodeRateInputs+1)
			case "assessment basis":
				a[0].BasisSHA256 = strings.Repeat("f", 64)
			case "foreign assessment":
				a[0].Identity.NodeID = "foreign"
			case "excluded assessment":
				m[0].Exclusion = RateReference{"exclude", strings.Repeat("a", 64)}
			case "missing evidence":
				a[0].Evidence = RateReference{}
			}
			requireInvalidFleetRate(t, v, ref, b, m, a)
		})
	}
}

func syntheticRateFleet(t testing.TB, size int) FleetState {
	t.Helper()
	ec, em, _ := exposureInventoryFixture(t)
	bc, bm, _ := inventoryFixture(t)
	nc, nm, _ := stateInventoryFixture(t)
	var ems []NodeExposureInventoryMember
	var bms []BunkerWebInventoryMember
	var nms []NodeStateInventoryMember
	var ers []NodeExposureInventoryReport
	for i := 0; i < size; i++ {
		e, b, n := em, bm, nm
		e.Identity.NodeID = fmt.Sprintf("node.simulated.%03d", i)
		b.Identity, n.Identity = e.Identity, e.Identity
		s := exposureFixture(t)
		s.Identity = e.Identity
		if i >= size/2 {
			s.Exposure.Value = "internal_only"
		}
		r := selectExposureInventoryReport(t, &e, s)
		ems, bms, nms, ers = append(ems, e), append(bms, b), append(nms, n), append(ers, r)
	}
	e, err := ResolveNodeExposureInventory(ec, ems, ers)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveBunkerWebInventory(bc, bms, nil)
	if err != nil {
		t.Fatal(err)
	}
	n, err := ResolveNodeStateInventory(nc, nms, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := FleetStateBinding{Context: FleetContextBinding{Exposure: ec, BunkerWeb: bc}, NodeState: nc}
	f, err := ComposeFleetContext(c.Context, e, b)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ComposeFleetState(c, f, n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFleetNodeRatesPreserveSelectedDenominatorsAndAssessmentUncertainty(t *testing.T) {
	f := syntheticRateFleet(t, 500)
	for _, group := range []string{"all", "external", "internal"} {
		t.Run(group, func(t *testing.T) {
			v, err := f.Select(group)
			if err != nil {
				t.Fatal(err)
			}
			ref, b := fleetRateBasis(t, v, "verified_protection_coverage.v1")
			var m []NodeRateMember
			var a []NodeRateAssessment
			for i, row := range v.Entries() {
				member := NodeRateMember{Identity: row.NodeState.Identity}
				m = append(m, member, member)
				if i < len(v.Entries())*4/5 {
					a = append(a, nodeRateAssessmentFixture(t, b, member, "matched"))
				}
			}
			p, err := ResolveFleetNodeRatePopulation(v, ref, b, m, a)
			if err != nil {
				t.Fatal(err)
			}
			// These are independent synthetic assessments. The empty node report
			// alone does not produce them or establish enforcement state.
			percent := nodeRatePercentages(t, b, p)
			if percent.Matched != (Field{Partial, "80.00"}) || percent.Unknown != (Field{Partial, "20.00"}) {
				t.Fatal("missing assessments dropped or counted twice", percent)
			}
			slices.Reverse(m)
			slices.Reverse(a)
			q, err := ResolveFleetNodeRatePopulation(v, ref, b, m, a)
			if err != nil || !bytes.Equal(p.Manifest(), q.Manifest()) {
				t.Fatal("order changed selected rate", err)
			}
			// A source report outage alone never authorizes a protection claim.
			outage, err := ResolveFleetNodeRatePopulation(v, ref, b, m, nil)
			if err != nil || nodeRatePercentages(t, b, outage).Unknown.Value != "100.00" {
				t.Fatal("outage concealed unknown members", err)
			}
			if group != "all" {
				all, err := f.Select("all")
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range all.Entries() {
					if row.Context.Exposure.Group != group {
						foreign := append(slices.Clone(m), NodeRateMember{Identity: row.NodeState.Identity})
						requireInvalidFleetRate(t, v, ref, b, foreign, a)
						break
					}
				}
			}
		})
	}
}

func TestFleetNodeRatesEligibilityConflictAndEmptySelections(t *testing.T) {
	f, v, ref, b, m := fleetRateFixture(t)
	for _, state := range []string{Present, Partial, Stale} {
		b.State = state
		a := nodeRateAssessmentFixture(t, b, m[0], "matched")
		conflict := a
		conflict.Part = "other"
		p, err := ResolveFleetNodeRatePopulation(v, ref, b, m, []NodeRateAssessment{a, conflict, a})
		wantState := Partial
		if state == Stale {
			wantState = Stale
		}
		if err != nil || p.Counts().State != wantState || p.Counts().Unknown != "1" || inspectNodeRateManifest(t, p).Members[0].Reason != "conflicting_assessments" {
			t.Fatal("conflicting assessment selected a winner", err)
		}
	}
	m[0].Exclusion = RateReference{"reviewed.eligibility", strings.Repeat("a", 64)}
	p, err := ResolveFleetNodeRatePopulation(v, ref, b, m, nil)
	if err != nil || p.Counts().Excluded != "1" || p.Counts().Eligible != "0" || nodeRatePercentages(t, b, p).Matched.State != Unavailable {
		t.Fatal("policy exclusion became a success percentage", err)
	}
	empty, err := f.Select("internal")
	if err != nil {
		t.Fatal(err)
	}
	eref, eb := fleetRateBasis(t, empty, "reporting_coverage.v1")
	p, err = ResolveFleetNodeRatePopulation(empty, eref, eb, nil, nil)
	if err != nil || p.Counts().Eligible != "0" || nodeRatePercentages(t, eb, p).Matched != (Field{State: Unavailable}) {
		t.Fatal("empty selection invented a numeric percentage", err)
	}
	// Existing rate contracts require canonical UTC spelling; redundant
	// fractional precision must not create an alternate basis for an instant.
	b.Window.Start, b.Window.End = "2026-01-01T00:00:30.000Z", "2026-01-01T00:00:30.000Z"
	requireInvalidFleetRate(t, v, ref, b, m, nil)
}

func TestFleetNodeRatesNewSourceRequiresNewAssessmentBasis(t *testing.T) {
	_, _, oldRef, oldBasis, members := fleetRateFixture(t)
	oldAssessment := nodeRateAssessmentFixture(t, oldBasis, members[0], "matched")
	c, f, _ := fleetStateFixture(t)
	_, m, r := stateInventoryFixture(t)
	c.NodeState.MaxReportAge += time.Second
	n, err := ResolveNodeStateInventory(c.NodeState, []NodeStateInventoryMember{m}, []NodeStateInventoryReport{r})
	if err != nil {
		t.Fatal(err)
	}
	s, err := ComposeFleetState(c, f, n)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Select("external")
	if err != nil {
		t.Fatal(err)
	}
	// Same identity, policy, instant and visible observations; the selected
	// source budget changed. Previously assessed inputs must not be replayed.
	requireInvalidFleetRate(t, v, oldRef, oldBasis, members, []NodeRateAssessment{oldAssessment})
	ref, basis := fleetRateBasis(t, v, oldBasis.DefinitionID)
	requireInvalidFleetRate(t, v, ref, basis, members, []NodeRateAssessment{oldAssessment})
	a := nodeRateAssessmentFixture(t, basis, members[0], "matched")
	p, err := ResolveFleetNodeRatePopulation(v, ref, basis, members, []NodeRateAssessment{a})
	if err != nil || p.Counts().Matched != "1" {
		t.Fatal("new independently bound assessment rejected", err)
	}
}
