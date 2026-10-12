package v5

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"time"
)

const RateSnapshotSchema = "syswarden.rate-snapshot.v1"

var (
	ErrInvalidRateDocument       = errors.New("invalid rate snapshot contract document")
	ErrUnsupportedRateSchema     = errors.New("unsupported rate snapshot contract schema")
	ErrUnsupportedRateDefinition = errors.New("unsupported rate definition")
	ErrInvalidRateReadContext    = errors.New("invalid rate snapshot read context")
	ErrRateBindingMismatch       = errors.New("rate snapshot does not match the expected inputs")
	ErrRateSnapshotNotCurrent    = errors.New("rate report is outside the accepted freshness window")
)

// RateReference pins exact externally resolved bytes. References are opaque,
// not URLs or paths. Resolving, authenticating and authorizing them is separate.
type RateReference struct {
	Ref    string `json:"ref"`
	SHA256 string `json:"sha256"`
}

func (r RateReference) validate() bool { return identifier(r.Ref) && digest(r.SHA256) }

// RateInputs binds the authorized scope, deduplicated population manifest and
// eligibility/evidence policy. The manifest must retain exclusions and gaps.
// Matching digests alone cannot establish completeness or correct selection.
type RateInputs struct {
	Scope      RateReference `json:"scope"`
	Population RateReference `json:"population"`
	Policy     RateReference `json:"policy"`
}

func (i RateInputs) validate() bool {
	return i.Scope.validate() && i.Population.validate() && i.Policy.validate()
}

// RateWindow is a UTC instant (equal bounds) or a half-open [start, end)
// interval. Display time zones must not change these measurement boundaries.
type RateWindow struct {
	Kind  string `json:"kind"`
	Start string `json:"start"`
	End   string `json:"end"`
}

func (w RateWindow) validate() bool {
	if !timestamp(w.Start) || !timestamp(w.End) {
		return false
	}
	start, _ := time.Parse(time.RFC3339Nano, w.Start)
	end, _ := time.Parse(time.RFC3339Nano, w.End)
	return (w.Kind == "snapshot" && start.Equal(end)) || (w.Kind == "interval" && start.Before(end))
}

// RateCounts is calculation provenance, not headline KPIs. The four included
// parts must partition Eligible exactly. Excluded is separate and must have
// policy-backed reasons in the population manifest. Numeric strings avoid
// JSON precision loss. The integer wire bound is not a capacity claim.
type RateCounts struct {
	State    string `json:"state"`
	Eligible string `json:"eligible"`
	Matched  string `json:"matched"`
	Other    string `json:"other"`
	Unknown  string `json:"unknown"`
	Stale    string `json:"stale"`
	Excluded string `json:"excluded"`
}

func rateCount(value string) (uint64, bool) {
	n, err := strconv.ParseUint(value, 10, 63)
	return n, err == nil && strconv.FormatUint(n, 10) == value
}

func (c RateCounts) validate() bool {
	values := []string{c.Eligible, c.Matched, c.Other, c.Unknown, c.Stale, c.Excluded}
	if !member(Present, Partial, Stale)(c.State) {
		if !member(Missing, Unavailable, Rejected, NotApplicable)(c.State) {
			return false
		}
		for _, value := range values {
			if value != "" {
				return false
			}
		}
		return true
	}
	for _, value := range values {
		if _, ok := rateCount(value); !ok {
			return false
		}
	}
	remaining, _ := rateCount(c.Eligible)
	for _, value := range []string{c.Matched, c.Other, c.Unknown, c.Stale} {
		n, _ := rateCount(value)
		if n > remaining {
			return false
		}
		remaining -= n
	}
	return remaining == 0
}

// RateSnapshot is one bounded collector report. Counts and input references
// are claims, not authenticated evidence, current protection or permission to
// disclose a population. There is no implicit node enrollment or aggregation.
type RateSnapshot struct {
	Schema           string     `json:"schema"`
	SnapshotID       string     `json:"snapshot_id"`
	CollectorID      string     `json:"collector_id"`
	DefinitionID     string     `json:"definition_id"`
	DefinitionSHA256 string     `json:"definition_sha256"`
	Category         string     `json:"category"`
	Inputs           RateInputs `json:"inputs"`
	Window           RateWindow `json:"window"`
	GeneratedAt      string     `json:"generated_at"`
	ValidUntil       string     `json:"valid_until"`
	ClockQuality     string     `json:"clock_quality"`
	MinimumEligible  string     `json:"minimum_eligible"`
	Counts           RateCounts `json:"counts"`
}

func invalidRate(field string) error { return fmt.Errorf("%w: %s", ErrInvalidRateDocument, field) }

// Validate checks declaration coherence. It does not deduplicate a population,
// verify evidence, execute an eligibility policy or authenticate a collector.
func (s RateSnapshot) Validate() error {
	if s.Schema != RateSnapshotSchema {
		return ErrUnsupportedRateSchema
	}
	d, err := LookupRateDefinition(s.DefinitionID)
	if err != nil {
		return err
	}
	hash, err := RateDefinitionSHA256(s.DefinitionID)
	if err != nil || s.DefinitionSHA256 != hash {
		return invalidRate("definition digest")
	}
	if !identifier(s.SnapshotID) || !identifier(s.CollectorID) || !s.Inputs.validate() || !s.Counts.validate() {
		return invalidRate("identity, inputs or population partition")
	}
	if s.DefinitionID == "alert_severity_share.v1" {
		if !member("informational", "low", "medium", "high", "critical")(s.Category) {
			return invalidRate("severity category")
		}
	} else if s.Category != NotApplicable {
		return invalidRate("inapplicable category")
	}
	minimum, ok := rateCount(s.MinimumEligible)
	if !ok || minimum == 0 {
		return invalidRate("minimum eligible population")
	}
	if !s.Window.validate() || s.Window.Kind != d.WindowKind || !timestamp(s.GeneratedAt) || !timestamp(s.ValidUntil) ||
		!member("unknown", "synchronized", "unsynchronized")(s.ClockQuality) {
		return invalidRate("measurement window, report timestamps or clock quality")
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	end, _ := time.Parse(time.RFC3339Nano, s.Window.End)
	if end.After(generated) || !until.After(generated) || until.Sub(generated) > MaxSnapshotLifetime {
		return invalidRate("measurement time or report lifetime")
	}
	return nil
}

// RatePercentages keeps every partition and its availability. Values have
// exactly two decimals without a percent sign. They must be rendered as rates,
// never as counts, verdicts or security scores. Rounded parts can total 99.99
// or 100.01; consumers must not silently rewrite them to force a total of 100.
type RatePercentages struct {
	Matched Field
	Other   Field
	Unknown Field
	Stale   Field
}

// ComputeRatePercentages performs only deterministic arithmetic on a validated
// declaration. Callers must separately authenticate, authorize, bind and check
// report freshness. Missing denominators and insufficient samples have no
// percentage value. Stale/partial inputs retain that status in every result.
func ComputeRatePercentages(s RateSnapshot) (RatePercentages, error) {
	if err := s.Validate(); err != nil {
		return RatePercentages{}, err
	}
	state := s.Counts.State
	d, _ := rateCount(s.Counts.Eligible)
	minimum, _ := rateCount(s.MinimumEligible)
	if member(Present, Partial, Stale)(state) && d < minimum {
		state = Unavailable
	}
	result := func(value string) Field {
		if !member(Present, Partial, Stale)(state) {
			return Field{State: state}
		}
		n, _ := rateCount(value)
		hi, lo := bits.Mul64(n, 10000)
		q, r := bits.Div64(hi, lo, d)
		if r >= d-r {
			q++
		}
		return Field{State: state, Value: fmt.Sprintf("%d.%02d", q/100, q%100)}
	}
	return RatePercentages{Matched: result(s.Counts.Matched), Other: result(s.Counts.Other),
		Unknown: result(s.Counts.Unknown), Stale: result(s.Counts.Stale)}, nil
}

// RateReadContext comes from independently authenticated, scope-authorized
// immutable input resolution. Copying the received report into this context
// defeats binding. MinimumEligible must come from the exact reviewed policy.
type RateReadContext struct {
	SnapshotID      string
	SnapshotSHA256  string
	CollectorID     string
	DefinitionID    string
	Category        string
	Inputs          RateInputs
	Window          RateWindow
	MinimumEligible string
	Now             time.Time
	MaxAge          time.Duration
}

// CheckCurrentRateSnapshot checks the exact report, scope, population, policy,
// measurement and caller age bound. Nil may describe zero eligible subjects,
// partial acquisition or stale source data. It does not prove the manifest is
// complete, select a newer snapshot, authorize export or infer protection.
func CheckCurrentRateSnapshot(s RateSnapshot, context RateReadContext) error {
	hash, err := RateSnapshotSHA256(s)
	if err != nil {
		return err
	}
	d, err := LookupRateDefinition(context.DefinitionID)
	minimum, ok := rateCount(context.MinimumEligible)
	if err != nil || !identifier(context.SnapshotID) || !digest(context.SnapshotSHA256) || !identifier(context.CollectorID) ||
		!context.Inputs.validate() || !context.Window.validate() || context.Window.Kind != d.WindowKind ||
		!ok || minimum == 0 || context.MaxAge <= 0 || context.MaxAge > MaxSnapshotLifetime ||
		!timestamp(context.Now.UTC().Format(time.RFC3339Nano)) {
		return ErrInvalidRateReadContext
	}
	if s.SnapshotID != context.SnapshotID || hash != context.SnapshotSHA256 || s.CollectorID != context.CollectorID ||
		s.DefinitionID != context.DefinitionID || s.Category != context.Category || s.Inputs != context.Inputs ||
		s.Window != context.Window || s.MinimumEligible != context.MinimumEligible {
		return ErrRateBindingMismatch
	}
	generated, _ := time.Parse(time.RFC3339Nano, s.GeneratedAt)
	until, _ := time.Parse(time.RFC3339Nano, s.ValidUntil)
	if s.ClockQuality != "synchronized" || context.Now.Before(generated) || !context.Now.Before(until) || context.Now.Sub(generated) >= context.MaxAge {
		return ErrRateSnapshotNotCurrent
	}
	return nil
}
