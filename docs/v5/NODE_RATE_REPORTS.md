# Population-bound node rate reports

Status: inactive v5 component for #224, #233 and #315. Stable remains v4.10.4.
This connects the [node population resolver](NODE_RATE_POPULATION.md) and
[fleet selection adapter](FLEET_NODE_RATES.md) to the existing
[percentage snapshot codec](RATE_SNAPSHOT.md). It does not establish producer
authentication, an operational dashboard or final v5.00.0 IVVQ acceptance.

## Construct from the actual population

`ComposeNodeRateSnapshot` takes a constructed `NodeRatePopulation`, an
independently expected `NodeRateBasis`, the exact expected population reference
and explicit producer metadata. A zero population, mismatched reference or
changed basis rejects the operation without returning a partial report.
The comparison includes formula, scope, selected membership generation, policy,
measurement instant and acquisition state. Equal scalar counts are insufficient.

The existing resolver retains its basis privately without changing manifest
bytes. The constructor copies its complete partition and derives formula,
scope, policy and window from that verified binding. The caller cannot override
counts or substitute a different formula through the metadata. Only the three
existing node formulas are accepted; event, observation and transaction
populations require their own implementation.

Metadata supplies the exact report and collector identifiers, generation and
expiry, clock quality and policy-defined minimum eligible population. Existing
canonical timestamp, lifetime and identifier limits remain unchanged. There is
no implicit minimum, current clock read or guessed lifetime. An unknown or
unsynchronized collector clock remains representable, but cannot pass the
current-report read check.

## Verify before calculating

`ProjectNodeRatePercentages` first checks the complete selected report through
`CheckCurrentRateSnapshot`, including its independently expected canonical
digest, collector, formula, scope, population, policy, window, sampling threshold,
trusted current time and maximum report age. It then verifies the actual
constructed population against the independently expected basis and requires
exact agreement with the report's partition and formula inputs.

A well-formed report with an internally consistent total is rejected if its
counts, exclusions or quality differ from the population. Selecting a new report
digest does not excuse that discrepancy. Replacing a population by another with
the same totals but different members or evidence is also rejected when its
expected reference does not match. Errors return no percentages or private
input values. Existing deterministic arithmetic runs only after these checks.

All partitions and their availability remain visible. A missing assessment stays
unknown, conflicting assessments remain unknown and stale evidence stays stale.
An empty or fully excluded population, or one below the reviewed minimum, has no
numeric percentage. Exclusions retain their separate provenance and are not
silently converted to failures or successes.

## Keep authority and time boundaries explicit

These functions bind already resolved inputs. They neither authenticate a
producer nor verify an assessment's truth, execute an eligibility policy or
authorize an export. Producers must independently establish those properties;
copying context fields from an untrusted report defeats selection checks.
Existing formulas cannot be promoted into protection verdicts by a matching hash.

A newly generated report may describe a historical measurement. Generation and
expiry do not update that measurement or renew its source evidence. Consumers
must display the window and availability, apply the reviewed measurement and
source-freshness policy, and reauthorize current scope before disclosure. A
current report is not necessarily current enforcement evidence. The pure
projection provides no live revocation or cross-request caching policy.

## Verification and boundaries

Independent golden report bytes and digest are derived from the existing
population fixture. Tests cover every basis binding, inconsistent but valid
scalar reports, substitutions with unchanged totals, changed source evidence,
read-context and exact expiry boundaries, immutable copies, all three formulas,
unknown/stale partitions and policy thresholds. A local 500-node selected-fleet
simulation runs through population resolution, report composition, wire encoding,
decoding and projection for All, External, Internal and an empty classification
view. This uses existing resources and is not deployed capacity evidence.

The existing formula catalog, population manifest and report schema remain
unchanged. No new parser, dependency, network call or background task is added.
Authentication, field RBAC, verified assessment producers, UI/export parity,
enrollment, native lifecycle and final major IVVQ remain open. BunkerWeb's API,
authentication, TTL, source ownership, retries, HA and withdrawal/cache checks
remain independent of these read models and the dashboard.
