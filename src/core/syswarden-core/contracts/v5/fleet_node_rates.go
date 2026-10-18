package v5

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidFleetNodeRatePopulation = errors.New("invalid fleet node rate population")

func invalidFleetNodeRatePopulation(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidFleetNodeRatePopulation, field)
}

// ResolveFleetNodeRatePopulation binds an existing node formula to one exact
// already authorized fleet selection. Membership names that selected view's
// manifest, not the larger unselected inventory. The producer must independently
// verify eligibility and assessments; neither reachability nor an opaque control
// reference establishes protection, policy conformity or a valid assessment.
// Missing reports and transport failures never imply eligibility exclusions.
func ResolveFleetNodeRatePopulation(view FleetStateView, selection RateReference, basis NodeRateBasis, members []NodeRateMember, assessments []NodeRateAssessment) (NodeRatePopulation, error) {
	if len(members) > MaxNodeRateInputs || len(assessments) > MaxNodeRateInputs {
		return NodeRatePopulation{}, invalidFleetNodeRatePopulation("input count")
	}
	expected, err := view.Reference(selection.Ref)
	if err != nil || selection != expected || !basis.validate() || basis.Membership != selection {
		return NodeRatePopulation{}, invalidFleetNodeRatePopulation("selection binding")
	}
	context := view.binding.Context.Exposure
	instant, _ := time.Parse(time.RFC3339Nano, basis.Window.Start)
	if basis.Scope != context.Scope || basis.Policy != context.Policy || !instant.Equal(context.Now) {
		return NodeRatePopulation{}, invalidFleetNodeRatePopulation("scope, policy or instant")
	}
	population, err := indexNodeRateMembers(members)
	if err != nil {
		return NodeRatePopulation{}, invalidFleetNodeRatePopulation("eligibility")
	}
	if len(population) != len(view.entries) {
		return NodeRatePopulation{}, invalidFleetNodeRatePopulation("membership population")
	}
	// Exact coverage includes excluded nodes and nodes without a report. There
	// is no intersection, implicit eligible subset or responder-only fallback.
	for _, entry := range view.entries {
		if _, found := population[entry.NodeState.Identity]; !found {
			return NodeRatePopulation{}, invalidFleetNodeRatePopulation("membership identity")
		}
	}
	result, err := ResolveNodeRatePopulation(basis, members, assessments)
	if err != nil {
		return NodeRatePopulation{}, fmt.Errorf("%w: %w", ErrInvalidFleetNodeRatePopulation, err)
	}
	return result, nil
}
