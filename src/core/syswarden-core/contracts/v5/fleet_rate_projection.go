package v5

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidFleetRateProjection = errors.New("invalid fleet rate projection")

// FleetNodeRateReport keeps one independently selected report together with its
// actual constructed population and expected basis. ReadContext must come from
// trusted resolution, not from copying the received report's declarations.
type FleetNodeRateReport struct {
	Basis       NodeRateBasis
	Population  NodeRatePopulation
	Snapshot    RateSnapshot
	ReadContext RateReadContext
}

// NodeRateProjection retains one KPI's percentages and calculation provenance.
// Counts are not headline indicators. Different eligibility policies may produce
// different denominators; neither an average nor an overall score is implied.
type NodeRateProjection struct {
	Report           RateReference
	Population       RateReference
	DefinitionID     string
	DefinitionSHA256 string
	Counts           RateCounts
	MinimumEligible  string
	Percentages      RatePercentages
}

// FleetNodeRateProjection is an immutable-by-copy result for one selected fleet
// and measurement instant, checked at one read instant. No browser/export
// authorization or live enforcement claim follows from constructing this value.
type FleetNodeRateProjection struct {
	Scope                      RateReference
	Policy                     RateReference
	Selection                  RateReference
	Window                     RateWindow
	ReadAt                     string
	ReportingCoverage          NodeRateProjection
	VerifiedProtectionCoverage NodeRateProjection
	PolicyConformity           NodeRateProjection
}

func invalidFleetRateProjection(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidFleetRateProjection, field)
}

// ProjectFleetNodeRates binds exactly one report for each existing node formula
// to the actual identities in one already authorized selected view. References
// alone do not prove population identity. All read contexts use the independent
// trusted now; report freshness does not renew the measurement or source evidence.
// A missing, duplicate or invalid report rejects the complete projection, never
// producing a partial KPI bundle or replacing a missing rate with a healthy zero.
// Eligibility, verdict truth, producer authentication and disclosure permission
// must be established independently. No node or partner state is mutated.
func ProjectFleetNodeRates(view FleetStateView, selection RateReference, now time.Time, reports []FleetNodeRateReport) (FleetNodeRateProjection, error) {
	if len(reports) != 3 || !timestamp(now.UTC().Format(time.RFC3339Nano)) {
		return FleetNodeRateProjection{}, invalidFleetRateProjection("report count or read instant")
	}
	expected, err := view.Reference(selection.Ref)
	if err != nil || expected != selection {
		return FleetNodeRateProjection{}, invalidFleetRateProjection("selection binding")
	}
	context := view.binding.Context.Exposure
	instant := context.Now.Format(time.RFC3339Nano)
	result := FleetNodeRateProjection{Scope: context.Scope, Policy: context.Policy, Selection: selection,
		Window: RateWindow{Kind: "snapshot", Start: instant, End: instant}, ReadAt: now.UTC().Format(time.RFC3339Nano)}
	seen := make(map[string]bool, 3)
	for _, input := range reports {
		var target *NodeRateProjection
		switch input.Basis.DefinitionID {
		case "reporting_coverage.v1":
			target = &result.ReportingCoverage
		case "verified_protection_coverage.v1":
			target = &result.VerifiedProtectionCoverage
		case "policy_conformity.v1":
			target = &result.PolicyConformity
		default:
			return FleetNodeRateProjection{}, invalidFleetRateProjection("unsupported formula")
		}
		if seen[input.Basis.DefinitionID] {
			return FleetNodeRateProjection{}, invalidFleetRateProjection("duplicate formula")
		}
		seen[input.Basis.DefinitionID] = true
		projected, err := projectFleetNodeRate(view, selection, now, input)
		if err != nil {
			return FleetNodeRateProjection{}, err
		}
		*target = projected
	}
	return result, nil
}

func projectFleetNodeRate(view FleetStateView, selection RateReference, now time.Time, input FleetNodeRateReport) (NodeRateProjection, error) {
	if !fleetNodeRateBasisMatches(view, selection, input.Basis) || !input.ReadContext.Now.Equal(now) {
		return NodeRateProjection{}, invalidFleetRateProjection("basis or read instant")
	}
	if len(input.Population.identities) != len(view.entries) {
		return NodeRateProjection{}, invalidFleetRateProjection("membership population")
	}
	// Both constructed sources sort by cluster/node/epoch. Excluded nodes remain
	// in the comparison; a generic population cannot substitute other identities
	// while claiming the selected fleet's membership reference.
	for i, identity := range input.Population.identities {
		if identity != view.entries[i].NodeState.Identity {
			return NodeRateProjection{}, invalidFleetRateProjection("membership identity")
		}
	}
	rates, err := ProjectNodeRatePercentages(input.Snapshot, input.Basis, input.Population, input.ReadContext)
	if err != nil {
		return NodeRateProjection{}, fmt.Errorf("%w: %w", ErrInvalidFleetRateProjection, err)
	}
	s := input.Snapshot
	return NodeRateProjection{Report: RateReference{Ref: s.SnapshotID, SHA256: input.ReadContext.SnapshotSHA256},
		Population: s.Inputs.Population, DefinitionID: s.DefinitionID, DefinitionSHA256: s.DefinitionSHA256,
		Counts: s.Counts, MinimumEligible: s.MinimumEligible, Percentages: rates}, nil
}
