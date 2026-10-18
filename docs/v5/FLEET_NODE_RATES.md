# Percentage populations bound to a fleet selection

Status: inactive v5 read-model integration for #224, #233 and #315. Stable
remains v4.10.4. This component connects [selected fleet state](FLEET_STATE.md)
to the existing [node percentage population](NODE_RATE_POPULATION.md). It does
not authenticate enrollment, render a dashboard or establish final v5.00.0 IVVQ.

## Bind the selection before calculating

`ResolveFleetNodeRatePopulation` accepts an already constructed `FleetStateView`,
an independent exact selection reference, a `NodeRateBasis`, complete eligibility
decisions and independent producer assessments. The selection reference must
match the view's canonical manifest. `basis.Membership` must equal that reference;
the basis scope, policy and snapshot instant must match the view's retained
authorization context.

The selected-view digest binds the explicit group, parent fleet state, all three
source inventories, selected observations and freshness budgets. Two selections
containing the same identities are still different inputs. A basis for All must
not silently be reused for External, Internal or Needs classification. A source
change requires a new basis and separately evaluated assessments, even when
the identities or visible values happen to remain equal.

Only the existing node formulas are accepted: reporting coverage, verified
protection coverage and policy conformity. Event, transaction and telemetry-slot
formulas require different populations. The existing canonical UTC timestamp
rules and snapshot measurement window remain unchanged.

## Keep complete eligibility and independent evidence

Every selected cluster/node/epoch must have an explicit member decision. The
deduplicated decision population must exactly equal the selected population,
including excluded nodes and nodes with missing reports. Extra, missing, foreign
or replaced identities reject the complete calculation. There is no default
eligible subset, intersection with responders or fallback to the larger fleet.

An exclusion requires a separately reviewed decision reference under the exact
policy. Its justification remains the producer's responsibility. An unavailable
node, failed connection or missing report does not authorize exclusion. Duplicate
identical decisions count once; conflicting eligibility decisions reject the
operation. Exclusions remain in the private manifest with their provenance.

Assessments are independent producer decisions bound to the exact basis. The
adapter does not derive them from a reachable node, a version string, an opaque
control reference, integration presence or a BunkerWeb reload request. Producers
must verify source authenticity, currentness and formula-specific evidence before
supplying `matched`, `other`, `unknown` or `stale`. A typed input or matching hash
does not authenticate that decision.

No assessment leaves an eligible node unknown. Conflicting assessments remain
unknown with their evidence retained. Stale evidence stays stale, and partial or
stale acquisition cannot become present. The adapter delegates these existing
rules to `ResolveNodeRatePopulation`; it does not introduce another verdict or
percentage algorithm.

## Display percentages with their uncertainty

The result is the existing `NodeRatePopulation`. Its unchanged manifest binds
the selected-view reference through the basis and retains full calculation
provenance. Use its counts and reference with the same formula, scope, policy
and instant in the existing `RateSnapshot` and percentage codec. Counts are
calculation evidence, not headline KPIs.

For example, 400 independently verified matches and 100 missing assessments in
a selected population of 500 yield 80.00% matched and 20.00% unknown, with partial
availability. Dropping the missing members would incorrectly produce 100.00%.
An explicitly empty selection or one with no eligible nodes yields no numeric
percentage. Unknown membership is not an empty selection and must remain
unavailable. Rounded percentages are not security scores or action permissions.

Membership completeness here is relative to the supplied authorized view.
The producer must still establish the correct enrollment registry, scope and
field permissions before constructing that view. Selection is not RBAC. After
scope, policy, membership or time changes, reauthorize and rebuild both the view
and the rate inputs. Immutable snapshots are historical, not live revocation.

## Bounds and verification

The adapter retains the existing limits: 8,192 input member decisions and 8,192
assessments, 4,096 unique nodes and an 8 MiB result manifest. It validates input
counts before indexing. No I/O, reference fetching, background process, new
dependency or network API is introduced. Error outputs contain fixed diagnostic
fields, not private input identities or evidence values.

Tests cover an independent canonical vector and digest, all binding mismatches,
different groups with identical members, wrong epochs and scope, omitted and
foreign members, invalid exclusions, conflicts, replay after source changes,
empty selections and unchanged percentage arithmetic. Local 500-node scenarios
retain missing members, deduplicate decisions, verify independent group rates
and preserve unknown states during a complete assessment outage. They use
existing resources and establish neither deployed capacity nor native IVVQ.

Existing catalog definitions, population schema, rate codec and source golden
bytes remain unchanged. Producer attestation, field RBAC, UI and exports,
enrollment, authenticated ingestion and native acceptance remain open.
BunkerWeb's authentication, API, TTL, source ownership, retries and HA continue
independently of the dashboard and these read models.
