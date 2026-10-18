package v5

import (
	"errors"
	"fmt"
)

var ErrInvalidNodeRateReport = errors.New("invalid population-bound node rate report")

// NodeRateSnapshotMetadata comes from the authorized producer and exact policy.
// It contains no population counts, formula or source authority overrides.
// Report generation and expiry never renew the underlying measurement instant.
type NodeRateSnapshotMetadata struct {
	SnapshotID      string
	CollectorID     string
	GeneratedAt     string
	ValidUntil      string
	ClockQuality    string
	MinimumEligible string
}

func invalidNodeRateReport(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeRateReport, field)
}

func nodeRateSnapshotInputs(basis NodeRateBasis, population NodeRatePopulation, expected RateReference) (RateInputs, error) {
	actual, err := population.Reference(expected.Ref)
	if err != nil || actual != expected || !basis.validate() || population.basis != basis {
		return RateInputs{}, invalidNodeRateReport("population basis or reference")
	}
	return RateInputs{Scope: basis.Scope, Population: actual, Policy: basis.Policy}, nil
}

// ComposeNodeRateSnapshot binds an existing constructed population to an
// independently expected basis and reference. Counts and formula come only from
// that population. Producer identity, eligibility, evidence and metadata must
// already be independently authenticated and authorized; this is not attestation.
func ComposeNodeRateSnapshot(basis NodeRateBasis, population NodeRatePopulation, expected RateReference, metadata NodeRateSnapshotMetadata) (RateSnapshot, error) {
	inputs, err := nodeRateSnapshotInputs(basis, population, expected)
	if err != nil {
		return RateSnapshot{}, err
	}
	definition, err := RateDefinitionSHA256(basis.DefinitionID)
	if err != nil {
		return RateSnapshot{}, fmt.Errorf("%w: %w", ErrInvalidNodeRateReport, err)
	}
	s := RateSnapshot{Schema: RateSnapshotSchema, SnapshotID: metadata.SnapshotID,
		CollectorID: metadata.CollectorID, DefinitionID: basis.DefinitionID, DefinitionSHA256: definition,
		Category: NotApplicable, Inputs: inputs, Window: basis.Window,
		GeneratedAt: metadata.GeneratedAt, ValidUntil: metadata.ValidUntil, ClockQuality: metadata.ClockQuality,
		MinimumEligible: metadata.MinimumEligible, Counts: population.counts}
	if err := s.Validate(); err != nil {
		return RateSnapshot{}, fmt.Errorf("%w: %w", ErrInvalidNodeRateReport, err)
	}
	return s, nil
}

// ProjectNodeRatePercentages checks the exact selected report, current read
// context and actual constructed population before calculating any percentages.
// A valid scalar partition or even an independently selected report digest does
// not excuse a mismatch with that population. No partial result is returned.
// Callers must reauthorize each read, independently resolve all inputs and keep
// measurement/source freshness separate from report freshness. This function
// supplies no authentication, enrollment, export permission or protection verdict.
func ProjectNodeRatePercentages(s RateSnapshot, basis NodeRateBasis, population NodeRatePopulation, context RateReadContext) (RatePercentages, error) {
	if err := CheckCurrentRateSnapshot(s, context); err != nil {
		return RatePercentages{}, fmt.Errorf("%w: %w", ErrInvalidNodeRateReport, err)
	}
	inputs, err := nodeRateSnapshotInputs(basis, population, context.Inputs.Population)
	if err != nil {
		return RatePercentages{}, err
	}
	if s.Inputs != inputs || s.DefinitionID != basis.DefinitionID || s.Category != NotApplicable ||
		s.Window != basis.Window || s.Counts != population.counts {
		return RatePercentages{}, invalidNodeRateReport("report population mismatch")
	}
	result, err := ComputeRatePercentages(s)
	if err != nil {
		return RatePercentages{}, fmt.Errorf("%w: %w", ErrInvalidNodeRateReport, err)
	}
	return result, nil
}
