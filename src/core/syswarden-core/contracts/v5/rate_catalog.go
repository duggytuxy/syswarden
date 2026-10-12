package v5

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

const RateCatalogSchema = "syswarden.rate-catalog.v1"

// RateDefinition is a code-owned formula, returned by value. Its digest pins
// these exact semantics. Changing a definition requires a new versioned ID.
// Eligibility and evidence still require independently reviewed producers.
type RateDefinition struct {
	Catalog       string `json:"catalog"`
	ID            string `json:"id"`
	Population    string `json:"population"`
	WindowKind    string `json:"window_kind"`
	Numerator     string `json:"numerator"`
	Denominator   string `json:"denominator"`
	Deduplication string `json:"deduplication"`
	Unit          string `json:"unit"`
	Precision     string `json:"precision"`
	Rounding      string `json:"rounding"`
}

// LookupRateDefinition recognizes only the reviewed built-in formula IDs.
// No remote formula, script, mutable registry or consumer-specific override is
// loaded. This initial catalog defines severity shares, not outcome shares.
func LookupRateDefinition(id string) (RateDefinition, error) {
	d := RateDefinition{Catalog: RateCatalogSchema, ID: id, Unit: "percent", Precision: "2", Rounding: "half_up"}
	switch id {
	case "reporting_coverage.v1":
		d.Population, d.WindowKind = "nodes", "snapshot"
		d.Numerator = "Eligible enrolled nodes with a timely valid report at the declared instant."
		d.Denominator = "All eligible enrolled nodes in the authorized scope, including unreachable nodes."
	case "verified_protection_coverage.v1":
		d.Population, d.WindowKind = "nodes", "snapshot"
		d.Numerator = "Intended protected nodes with current evidence of the required enforcement state."
		d.Denominator = "All nodes intended to be protected in the authorized scope, including unknown and stale states."
	case "policy_conformity.v1":
		d.Population, d.WindowKind = "nodes", "snapshot"
		d.Numerator = "Eligible managed nodes with current attestation of conformity to the exact policy."
		d.Denominator = "All eligible managed nodes in the authorized scope, including unknown and stale states."
	case "telemetry_freshness_compliance.v1":
		d.Population, d.WindowKind = "expected_observations", "interval"
		d.Numerator = "Expected eligible source observations meeting the exact freshness policy."
		d.Denominator = "All expected eligible source observations in the half-open interval, including missing observations."
	case "verified_response_success.v1":
		d.Population, d.WindowKind = "transactions", "interval"
		d.Numerator = "Unique eligible transactions with a verified successful result by their verification deadline."
		d.Denominator = "All eligible transactions whose verification deadline falls in the half-open interval."
	case "alert_severity_share.v1":
		d.Population, d.WindowKind = "observations", "interval"
		d.Numerator = "Eligible retained observations with the selected authoritative severity category."
		d.Denominator = "All eligible retained observations in the same authorized snapshot and half-open interval."
	default:
		return RateDefinition{}, ErrUnsupportedRateDefinition
	}
	switch d.Population {
	case "nodes":
		d.Deduplication = "Exact cluster, node and membership epoch in the independently resolved scope."
	case "transactions":
		d.Deduplication = "Exact cluster, node, membership epoch and transaction ID; retries are not new transactions."
	case "expected_observations":
		d.Deduplication = "Exact cluster, node, membership epoch, source and expected slot; receipt retries are not new slots."
	case "observations":
		d.Deduplication = "Exact cluster, node, membership epoch and event ID; overlapping groups are not new observations."
	}
	return d, nil
}

// RateDefinitionSHA256 hashes compact struct-order JSON for a built-in entry.
// It is not a signature, a policy digest or proof that a producer used it.
func RateDefinitionSHA256(id string) (string, error) {
	d, err := LookupRateDefinition(id)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(d)
	if err != nil {
		return "", ErrInvalidRateDocument
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
