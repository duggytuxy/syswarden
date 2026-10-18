# Checked fleet KPI projection

Status: inactive v5 component for #224, #233 and #315. Stable remains v4.10.4.
This connects [fleet selection](FLEET_STATE.md), its
[complete node populations](FLEET_NODE_RATES.md) and
[population-bound reports](NODE_RATE_REPORTS.md). It does not implement a browser
endpoint, authenticate ingestion or establish final v5.00.0 IVVQ acceptance.

## One selection and three independent indicators

`ProjectFleetNodeRates` accepts one constructed `FleetStateView`, its independently
selected exact reference, a trusted read instant and exactly three
`FleetNodeRateReport` inputs. Each holds a constructed population, expected basis,
report and independently resolved `RateReadContext`. The formulas must be exactly
`reporting_coverage.v1`, `verified_protection_coverage.v1` and
`policy_conformity.v1`, once each. Input order does not affect named output slots.
Missing, duplicate, additional or unsupported reports reject the complete result.

Every basis must bind the same selected view, authorized scope, policy and
measurement instant. Every report is checked at the supplied read instant, with
its own independently selected age bound, sampling minimum, collector and digest.
An input cannot use a different time to keep an expired report usable. Display
time zones may change presentation, not measurement or read boundaries.

The complete actual identity population is compared against the selected view,
including excluded nodes and nodes without reports. A generic population that
claims the correct membership reference but contains different nodes is rejected,
even when its report, manifest digest and scalar partition are individually valid.
Old epochs, omitted nodes and added nodes are also rejected. The resolver retains
only an additional bounded private sorted identity slice, copied from its already
constructed entries; existing manifest bytes and public wire schemas are unchanged.
No parsing or fetching of a submitted population manifest is introduced.

## Preserve provenance and uncertainty

Each named indicator carries its percentages, exact report and population
references, definition and digest, sampling minimum and calculation counts. Counts
are provenance, not headline KPIs. There is no average of percentages, inferred
overall security score or assumed common denominator. Reviewed exclusions may
differ by formula, so all three retain their own complete partition.

Unknown and stale parts remain visible. Partial or stale acquisition quality is
not upgraded by a current report. Empty, fully excluded or undersized eligible
populations have no numeric percentage. A missing required report returns no
bundle; the caller must show explicit unavailability and may continue displaying
the independently authorized fleet table. It must not reuse an old successful
bundle or turn the missing indicator into a healthy zero.

The result is copied by value and does not reference caller-owned mutable state.
Its shared context names the selection, scope, policy, measurement window and
read instant. No successful prefix is returned when a later report fails.

## Authority remains separate

All contexts and eligibility decisions must come from independently authenticated
and scope-authorized resolution. The producer still has to establish each
assessment's truth. A recent collector report, reachable node or opaque control
reference cannot by itself prove valid agent reporting, effective protection or
policy conformity. A hash is a binding, not an attestation.

This projection can describe a historical measurement using a currently valid
report. It does not renew source evidence or implement a measurement-age policy.
Consumers must display the window, apply the reviewed measurement and source
freshness rules, reauthorize fields for every read/export and invalidate results
after selection or authority changes. UI/export parity and revocation behavior
remain separate integration work; this in-memory function grants no permission.

## Component verification

Tests cover every named slot, input permutations, all-or-nothing rejection,
coherent foreign populations, different scopes/policies/epochs/instants, explicit
read-time mismatch, report selection and expiry, independent eligibility and
sampling minima, and unknown/stale quality. Existing canonical population and
report vectors remain required and unchanged. Local simulations use zero and
500 nodes with All, External, Internal and Needs Classification selections,
including codec round trips and complete outages. They use existing resources
and do not claim deployed capacity or native acceptance.

The component adds no network listener, dependency, background task or new
wire format. BunkerWeb API authentication, TTL, source ownership, retries, HA
and withdrawal/cache behavior remain independent of the dashboard. Producer
admission, verified assessments, field RBAC, enrollment, UI/export wiring,
native lifecycle and final major-version IVVQ remain open.
