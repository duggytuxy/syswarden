package v5

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func nodeRateBasisFixture() NodeRateBasis {
	return NodeRateBasis{DefinitionID: "verified_protection_coverage.v1",
		Scope:      RateReference{"authorized-scope", strings.Repeat("1", 64)},
		Membership: RateReference{"enrolled-population", strings.Repeat("2", 64)},
		Policy:     RateReference{"evidence-policy", strings.Repeat("3", 64)},
		Window:     RateWindow{Kind: "snapshot", Start: "2026-10-17T10:00:00Z", End: "2026-10-17T10:00:00Z"}, State: Present}
}

func nodeRateMemberFixture(id int) NodeRateMember {
	return NodeRateMember{Identity: NodeIdentity{"synthetic-cluster", fmt.Sprintf("node-%04d", id), "epoch-1"}}
}

func nodeRateAssessmentFixture(t testing.TB, basis NodeRateBasis, m NodeRateMember, part string) NodeRateAssessment {
	t.Helper()
	hash, err := NodeRateBasisSHA256(basis)
	if err != nil {
		t.Fatal(err)
	}
	return NodeRateAssessment{Identity: m.Identity, BasisSHA256: hash, Part: part,
		Evidence: RateReference{"assessment-" + m.Identity.NodeID, strings.Repeat("4", 64)}}
}

func resolveNodeRateFixture(t testing.TB, b NodeRateBasis, m []NodeRateMember, a []NodeRateAssessment) NodeRatePopulation {
	t.Helper()
	p, err := ResolveNodeRatePopulation(b, m, a)
	if err != nil || len(p.Manifest()) == 0 || !p.Counts().validate() {
		t.Fatal("valid population rejected", err)
	}
	return p
}

func inspectNodeRateManifest(t testing.TB, p NodeRatePopulation) nodeRateManifest {
	t.Helper()
	var m nodeRateManifest
	if err := json.Unmarshal(p.Manifest(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func nodeRatePercentages(t testing.TB, basis NodeRateBasis, population NodeRatePopulation) RatePercentages {
	t.Helper()
	s := rateFixture(t, "mixed")
	s.DefinitionID = basis.DefinitionID
	s.DefinitionSHA256, _ = RateDefinitionSHA256(basis.DefinitionID)
	s.Inputs.Scope, s.Inputs.Policy = basis.Scope, basis.Policy
	s.Inputs.Population, _ = population.Reference("resolved-population")
	s.Window, s.Counts = basis.Window, population.Counts()
	s.GeneratedAt, s.ValidUntil = "2026-10-17T10:00:01Z", "2026-10-17T10:05:00Z"
	result, err := ComputeRatePercentages(s)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNodeRatePopulationPreservesDenominator(t *testing.T) {
	b := nodeRateBasisFixture()
	m := []NodeRateMember{nodeRateMemberFixture(1), nodeRateMemberFixture(2), nodeRateMemberFixture(3), nodeRateMemberFixture(4), nodeRateMemberFixture(5)}
	m[4].Exclusion = RateReference{"approved-eligibility-decision", strings.Repeat("5", 64)}
	a := []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched"), nodeRateAssessmentFixture(t, b, m[1], "other"), nodeRateAssessmentFixture(t, b, m[2], "stale")}
	p := resolveNodeRateFixture(t, b, m, a)
	if p.Counts() != (RateCounts{Partial, "4", "1", "1", "1", "1", "1"}) {
		t.Fatal("missing or stale node removed from the population", p.Counts())
	}
	if got := nodeRatePercentages(t, b, p); got.Matched != (Field{State: Partial, Value: "25.00"}) || got.Unknown.Value != "25.00" || got.Stale.Value != "25.00" {
		t.Fatal("existing percentage codec disagrees", got)
	}
	manifest := inspectNodeRateManifest(t, p)
	if manifest.Members[3].Reason != "missing_assessment" || manifest.Members[4].Exclusion != m[4].Exclusion || manifest.Members[4].Reason != "policy_exclusion" {
		t.Fatal("missing or excluded provenance lost")
	}
}

func TestNodeRatePopulationDeduplicatesOverlappingGroups(t *testing.T) {
	b := nodeRateBasisFixture()
	m := make([]NodeRateMember, 0, 10)
	a := make([]NodeRateAssessment, 0, 10)
	for i := 0; i < 10; i++ {
		member := nodeRateMemberFixture(i)
		part := "other"
		if i == 0 {
			part = "matched"
		}
		m = append(m, member)
		a = append(a, nodeRateAssessmentFixture(t, b, member, part))
	}
	expected := resolveNodeRateFixture(t, b, m, a)
	m = append(m, m[0], m[1], m[0])
	a = append(a, a[0], a[1], a[0])
	slices.Reverse(m)
	slices.Reverse(a)
	got := resolveNodeRateFixture(t, b, m, a)
	if !bytes.Equal(got.Manifest(), expected.Manifest()) || nodeRatePercentages(t, b, got).Matched.Value != "10.00" {
		t.Fatal("overlapping groups or unequal sizes changed the rate")
	}
}

func TestNodeRatePopulationConflictsRemainUnknown(t *testing.T) {
	for _, kind := range []string{"different_part", "different_digest", "different_reference"} {
		t.Run(kind, func(t *testing.T) {
			b, m := nodeRateBasisFixture(), []NodeRateMember{nodeRateMemberFixture(1)}
			a := nodeRateAssessmentFixture(t, b, m[0], "matched")
			conflict := a
			switch kind {
			case "different_part":
				conflict.Part = "stale"
			case "different_digest":
				conflict.Evidence.SHA256 = strings.Repeat("a", 64)
			case "different_reference":
				conflict.Evidence.Ref = "different-assessment"
			}
			p := resolveNodeRateFixture(t, b, m, []NodeRateAssessment{a, conflict, a})
			q := resolveNodeRateFixture(t, b, m, []NodeRateAssessment{conflict, a})
			entry := inspectNodeRateManifest(t, p).Members[0]
			if p.Counts() != (RateCounts{Partial, "1", "0", "0", "1", "0", "0"}) || len(entry.Assessments) != 2 || entry.Reason != "conflicting_assessments" || !bytes.Equal(p.Manifest(), q.Manifest()) {
				t.Fatal("conflict selected a winner or lost evidence")
			}
		})
	}
}

func TestNodeRatePopulationRejectsAmbiguousInputs(t *testing.T) {
	for _, name := range []string{"foreign_node", "old_epoch", "excluded_assessment", "eligibility_conflict", "exclusion_conflict", "multiple_epochs", "bad_identity", "partial_exclusion", "bad_part", "missing_evidence", "bad_evidence_digest", "basis_hash", "policy", "scope", "membership", "window", "formula", "unknown_denominator", "missing_membership", "interval", "unknown_formula", "input_members_budget", "input_assessments_budget"} {
		t.Run(name, func(t *testing.T) {
			b := nodeRateBasisFixture()
			m := []NodeRateMember{nodeRateMemberFixture(1)}
			a := []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")}
			switch name {
			case "foreign_node":
				a[0].Identity.NodeID = "unauthorized-node"
			case "old_epoch":
				a[0].Identity.Epoch = "epoch-0"
			case "excluded_assessment":
				m[0].Exclusion = RateReference{"approved-exclusion", strings.Repeat("a", 64)}
			case "eligibility_conflict", "exclusion_conflict":
				if name == "exclusion_conflict" {
					m[0].Exclusion = RateReference{"approved-exclusion", strings.Repeat("b", 64)}
				}
				m = append(m, m[0])
				m[1].Exclusion = RateReference{"approved-exclusion", strings.Repeat("a", 64)}
			case "multiple_epochs":
				m = append(m, m[0])
				m[1].Identity.Epoch = "epoch-2"
			case "bad_identity":
				m[0].Identity.NodeID = "unsafe\nidentity"
			case "partial_exclusion":
				m[0].Exclusion.Ref = "missing-digest"
			case "bad_part":
				a[0].Part = "protected"
			case "missing_evidence":
				a[0].Evidence = RateReference{}
			case "bad_evidence_digest":
				a[0].Evidence.SHA256 = strings.Repeat("A", 64)
			case "basis_hash":
				a[0].BasisSHA256 = strings.Repeat("f", 64)
			case "policy":
				b.Policy.SHA256 = strings.Repeat("b", 64)
			case "scope":
				b.Scope.Ref = "other-scope"
			case "membership":
				b.Membership.SHA256 = strings.Repeat("c", 64)
			case "window":
				b.Window.Start, b.Window.End = "2026-10-17T10:00:02Z", "2026-10-17T10:00:02Z"
			case "formula":
				b.DefinitionID = "reporting_coverage.v1"
			case "unknown_denominator":
				b.State = Unavailable
			case "missing_membership":
				b.Membership = RateReference{}
			case "interval":
				b.DefinitionID = "alert_severity_share.v1"
			case "unknown_formula":
				b.DefinitionID = "security_score.v1"
			case "input_members_budget":
				m = make([]NodeRateMember, MaxNodeRateInputs+1)
			case "input_assessments_budget":
				a = make([]NodeRateAssessment, MaxNodeRateInputs+1)
			}
			p, err := ResolveNodeRatePopulation(b, m, a)
			if !errors.Is(err, ErrInvalidNodeRatePopulation) || p.Manifest() != nil || p.Counts() != (RateCounts{}) {
				t.Fatal("invalid input returned a partial result", err)
			}
			if strings.Contains(err.Error(), "unauthorized-node") || strings.Contains(err.Error(), "unsafe") {
				t.Fatal("diagnostic disclosed input")
			}
		})
	}
}

func TestNodeRatePopulationAvailabilityAndEmptyPopulation(t *testing.T) {
	for _, state := range []string{Present, Partial, Stale} {
		for _, formula := range []string{"reporting_coverage.v1", "verified_protection_coverage.v1", "policy_conformity.v1"} {
			t.Run(state+"/"+formula, func(t *testing.T) {
				b := nodeRateBasisFixture()
				b.State, b.DefinitionID = state, formula
				p := resolveNodeRateFixture(t, b, nil, nil)
				if p.Counts() != (RateCounts{state, "0", "0", "0", "0", "0", "0"}) || nodeRatePercentages(t, b, p).Matched != (Field{State: Unavailable}) {
					t.Fatal("empty denominator invented a percentage")
				}
				m := []NodeRateMember{nodeRateMemberFixture(1)}
				p = resolveNodeRateFixture(t, b, m, []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")})
				if p.Counts().State != state || nodeRatePercentages(t, b, p).Matched.State != state {
					t.Fatal("upstream availability promoted")
				}
			})
		}
	}
}

func TestNodeRatePopulationImmutableResult(t *testing.T) {
	b := nodeRateBasisFixture()
	m := []NodeRateMember{nodeRateMemberFixture(1)}
	a := []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "unknown")}
	p := resolveNodeRateFixture(t, b, m, a)
	before := p.Manifest()
	ref, err := p.Reference("population-1")
	if err != nil || ref.SHA256 != nodeRateDigest(before) {
		t.Fatal("manifest reference mismatch", err)
	}
	m[0].Identity.NodeID, a[0].Part = "changed-input", "matched"
	data := p.Manifest()
	data[0] = '!'
	counts := p.Counts()
	counts.Matched = "42"
	if !bytes.Equal(before, p.Manifest()) || p.Counts().Matched != "0" || p.Counts().Unknown != "1" {
		t.Fatal("caller mutated resolved state")
	}
	for _, bad := range []string{"", "../path", "https://example.test", strings.Repeat("a", MaxIdentifierBytes+1)} {
		if ref, err := p.Reference(bad); err == nil || ref != (RateReference{}) {
			t.Fatal("invalid reference admitted")
		}
	}
	if ref, err := (NodeRatePopulation{}).Reference("population-1"); err == nil || ref != (RateReference{}) {
		t.Fatal("uninitialized result referenced")
	}
}

func TestNodeRatePopulationSimulationAndBounds(t *testing.T) {
	for _, size := range []int{500, MaxNodeRateMembers, MaxNodeRateMembers + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			b := nodeRateBasisFixture()
			m := make([]NodeRateMember, 0, size)
			a := make([]NodeRateAssessment, 0, size)
			for i := 0; i < size; i++ {
				node := nodeRateMemberFixture(i)
				m = append(m, node)
				if i%5 != 0 {
					a = append(a, nodeRateAssessmentFixture(t, b, node, "matched"))
				}
			}
			if size > MaxNodeRateMembers {
				if p, err := ResolveNodeRatePopulation(b, m, nil); err == nil || p.Manifest() != nil {
					t.Fatal("unique member limit exceeded")
				}
				return
			}
			p := resolveNodeRateFixture(t, b, append(slices.Clone(m), m...), append(slices.Clone(a), a...))
			if size == 500 && (p.Counts().Eligible != "500" || p.Counts().Unknown != "100" || nodeRatePercentages(t, b, p).Matched.Value != "80.00") {
				t.Fatal("simulated 500-node population changed")
			}
			if !bytes.Equal(p.Manifest(), resolveNodeRateFixture(t, b, m, a).Manifest()) {
				t.Fatal("maximum overlapping input changed the population")
			}
		})
	}
}

func TestNodeRatePopulationIndependentGolden(t *testing.T) {
	b := nodeRateBasisFixture()
	m := []NodeRateMember{nodeRateMemberFixture(1), nodeRateMemberFixture(2), nodeRateMemberFixture(3)}
	m[2].Exclusion = RateReference{"approved-eligibility-decision", strings.Repeat("5", 64)}
	p := resolveNodeRateFixture(t, b, m, []NodeRateAssessment{nodeRateAssessmentFixture(t, b, m[0], "matched")})
	// This vector was independently assembled with Python's compact JSON and
	// hashlib, using the unchanged catalog fixture rather than Go output.
	if !bytes.Equal(p.Manifest(), fixture(t, "node-rate-population.json")) {
		t.Fatal("canonical population differs from the independent vector")
	}
}

func TestNodeRatePopulationAssessmentBudget(t *testing.T) {
	b := nodeRateBasisFixture()
	m := []NodeRateMember{nodeRateMemberFixture(1)}
	a := make([]NodeRateAssessment, MaxNodeRateInputs)
	base := nodeRateAssessmentFixture(t, b, m[0], "matched")
	for i := range a {
		a[i] = base
		a[i].Evidence.Ref = fmt.Sprintf("assessment-%04d", i)
	}
	p := resolveNodeRateFixture(t, b, m, a)
	if p.Counts().Unknown != "1" || len(inspectNodeRateManifest(t, p).Members[0].Assessments) != MaxNodeRateInputs {
		t.Fatal("bounded conflicting evidence was dropped")
	}
	if p, err := ResolveNodeRatePopulation(b, m, append(a, base)); err == nil || p.Manifest() != nil {
		t.Fatal("excess assessment admitted")
	}
}

func FuzzNodeRatePopulationPermutation(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 128 {
			t.Skip()
		}
		b := nodeRateBasisFixture()
		m, a := []NodeRateMember{}, []NodeRateAssessment{}
		for _, value := range data {
			node := nodeRateMemberFixture(int(value % 16))
			m = append(m, node)
			if value%5 != 0 {
				a = append(a, nodeRateAssessmentFixture(t, b, node, []string{"matched", "other", "unknown", "stale"}[value%4]))
			}
		}
		p := resolveNodeRateFixture(t, b, m, a)
		slices.Reverse(m)
		slices.Reverse(a)
		q := resolveNodeRateFixture(t, b, append(slices.Clone(m), m...), append(slices.Clone(a), a...))
		if !bytes.Equal(p.Manifest(), q.Manifest()) {
			t.Fatal("ordering or duplicate reception changed the result")
		}
	})
}
