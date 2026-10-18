# Complete authorized node-state inventory

The [shared fleet state](FLEET_STATE.md) composes this inventory with exposure
and BunkerWeb context under one complete identity population and one assessment
instant. Node-state uncertainty cannot erase independent integration history.

Status: inactive v5 read-model component for #224, #233 and #315. It composes
the [bound node projection](NODE_VIEW.md) over complete authorized membership.
Stable remains v4.10.4. This helper does not enroll nodes, discover servers,
open a listener, compute protection verdicts or accept v5.00.0 IVVQ.

## Preserve the complete population

`ResolveNodeStateInventory` starts from independently authorized identities,
not just responders. Every cluster/node/epoch appears once, including during a
total reporting outage. Identical repeated members are deduplicated; conflicting
epochs or selections reject the operation without a partial result.

Each entry keeps the current transport observation separate from last-known
agent fields. A current unreachable node may still have retained policy,
control and integration references. Reachable does not mean protected, and
unreachable does not prove protection stopped. Missing reports leave current
reachability unknown. A selected report reference alone is not an observation.

A valid expired report retains its historical reachability, times, version and
references, with explicit stale state. Its current reachability is unknown.
Field availability retains both the reported qualifier and its effective state;
expiry cannot turn partial source evidence into trusted complete evidence.
Missing or rejected reports expose only trusted membership/selection and fixed
unavailable fields, never payload timestamps, identifiers or references.

## Authorization and report binding

The caller supplies independently approved scope, complete membership reference,
policy, measurement time and a positive report age budget. It must verify the
membership contents, source admission and field permissions before resolution.
Identifiers and hashes are bindings, not authentication or RBAC.

Every member has an independently selected snapshot ID, canonical SHA-256 and
collector ID, or an entirely empty selection. Partial selection is invalid.
Transport routing identity is independently authenticated. Foreign nodes, old
epochs, unselected reports and invalid bounds reject the whole operation before
any payload is exposed. Trusted membership cannot be inferred from a report.

The existing strict decoder and projector validate report schema, selected
canonical content, collector, identity and freshness. Future collector time or
substitution rejects that member's report. Differing projected observations for
one member remain `conflicting_reports` regardless of order or repetition.
Identical document bytes are decoded once after total input limits are checked;
equivalent valid JSON formatting also resolves to the same observation.

Unlike exposure reports, the underlying node snapshot carries no scope or
policy authorization claim. The inventory manifest binds the caller's approved
context. A changed authorization context must be independently rechecked by the
caller; this resolver cannot infer that old selected bytes are authorized for a
new scope. Opaque `policy_ref` is an agent observation, not that permission.

On a whole-operation failure, the UI must not show an empty healthy fleet. It
must retain independently known authorized membership with unavailable state,
without displaying rejected payload fields. Rebuild after selection, membership,
policy or time changes. A retained result does not implement live revocation.

## Deterministic representation and boundaries

Entries are sorted by cluster, node and epoch. The compact struct-order manifest
uses `syswarden.node-state-inventory.v1` and binds scope, membership, policy,
canonical UTC assessment time, age budget and every entry. It is not JCS, a
public input decoder, a signature or an authenticated export. A valid empty
population contains an empty entries array. `Entries` and `Manifest` return
independent copies. A digest reference cannot be obtained from a zero result.

Limits are 8,192 member inputs, 8,192 reports, 4,096 unique nodes, 16 KiB per
report and 8 MiB each for total input bytes and manifest output. Duplicate
bytes still consume the input budget. Maximum report age is bounded by the
existing 24-hour schema ceiling, not an operational freshness recommendation.
There is no I/O, background worker or shared mutable store.

This component does not authorize External map coordinates or address display,
calculate KPI percentages, render UI or join inventories automatically. Shared
selection is provided separately by the [fleet state composition](FLEET_STATE.md).
BunkerWeb integration presence and applied state require their own evidence.
An integration reference does not prove a ban was withdrawn from every worker;
see the [withdrawal contract](BUNKERWEB_WITHDRAWAL.md). The authenticated partner
API, source ownership, TTL, retry and HA behavior remain independent.

## Verification and remaining acceptance

Tests cover independently generated golden bytes and digest, current and stale
source qualifiers, complete missing-node retention, canonical deduplication,
conflict ordering, source substitution without disclosure, revoked or old-epoch
routing, new report selection, defensive copies, context binding and resource
limits. A 500-identity synthetic population preserves 400 reporting and 100
missing nodes, and all 500 during a total outage. This simulation uses existing
local resources and does not imply a deployed fleet or new infrastructure cost.
A bounded permutation fuzzer is part of the existing CI fuzz gate.

Authenticated ingestion and enrollment, membership lifecycle, field RBAC,
persistent history, consumer integration, native lifecycle and final v5.00.0
IVVQ acceptance remain open. These are component regression results only.
