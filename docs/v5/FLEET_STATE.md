# Shared fleet state and independent observations

Status: inactive read-model composition for #224, #233 and #315. Stable remains
v4.10.4. This joins the [fleet context](FLEET_CONTEXT.md) with the
[complete node-state inventory](NODE_STATE_INVENTORY.md). It does not activate
a dashboard, remote ingestion, enrollment or final v5.00.0 IVVQ acceptance.

## Bind the complete population before disclosure

`ComposeFleetState` accepts two constructed immutable sources and an independent
`FleetStateBinding`. The binding contains all three source contexts: exposure,
BunkerWeb and node state. Each complete context must match the one used to
evaluate its source, including its freshness budgets. All three must share the
exact scope, membership reference, policy and assessment instant. Equivalent
UTC instants are accepted. Changing the expected policy or time cannot reuse
old results as newly authorized observations.

Actual cluster/node/epoch identities must also agree across every source row.
A shared membership digest cannot hide different populations or a replacement
epoch. Extra, missing or substituted identities reject the complete join before
any partial result is returned. There is no intersection, union or selection of
responders only. An authorized member with a missing report remains a member.

The caller must independently authenticate sources, verify membership and apply
node and field authorization before constructing and disclosing these objects.
References and matching digests are not authority. The typed sources cannot be
created by decoding an arbitrary submitted fleet manifest. This component
does not replace transport authentication, RBAC or current revocation checks.

## Preserve independent evidence

Each row retains its exact exposure, BunkerWeb and node-state assessments.
Joining does not refresh an observation or infer protection from reachability.
For example:

- A missing node report leaves current reachability unknown while preserving
  independently current exposure and integration observations.
- An unreachable node remains in its independently assessed group. Its stale
  agent facts retain their original quality and cannot become current facts.
- Missing or expired exposure places the node in Needs classification, even
  when a current node snapshot reports reachability.
- Established BunkerWeb history remains relevant during an outage or disabled
  integration; it does not establish that the partner applied a change.
- An opaque control, policy or integration reference remains a reference.
  It is not a healthy state, a protection verdict or an applied acknowledgement.

The node snapshot's reported policy reference and the producer's authorization
policy are different concepts. This join preserves both without interpreting
an opaque reported reference as proof of policy compliance.

## Select once for all components

`Select` requires `all`, `external`, `internal` or `needs_classification`.
No default or invalid-selection fallback exists. Exposure determines the group;
IP syntax, hosting model and node reachability do not determine it. Reclassification
moves the entire row, including its independent node and integration evidence.

BunkerWeb relevance is calculated only from the selected population. Established
history on Internal nodes cannot make an External-only view report known
integration. A valid empty selection remains distinct from rejected context,
denied access or unavailable evidence. Empty-view `absent` describes only that
empty population, not a fleet-wide absence claim.

Returned entries and bytes are defensive copies. These immutable results are
not live caches: reauthorize and rebuild after membership, scope, policy or time
changes. A previously created snapshot retains its historical assessment; a
caller must not advertise it as current after its admission context changes.

## Deterministic private records and bounded work

`syswarden.fleet-state.v1` binds the shared authority context, assessment time,
both complete source-manifest digests and every joined row. Its selected form,
`syswarden.fleet-state-view.v1`, binds the parent digest, explicit group,
selection-local relevance and selected rows. The digests also bind the separate
source budgets and selected reports through the source manifests.

These compact struct-order JSON records are private deterministic records, not
JCS, signatures, authenticated exports or public browser responses. Existing
fleet-context and node-inventory golden bytes remain unchanged.

The existing resolvers cap the population at 4,096 unique identities. The join
and each selected manifest are limited to 24 MiB and perform bounded in-memory
work without I/O, a clock read, goroutines or network calls. A synthetic 500-node
fleet uses local resources and does not imply a purchased fleet or native
capacity acceptance. It covers independent partial outages and total outage
without dropping authorized members.

Validation includes independent canonical vectors and digests, every expected
context field, different actual membership despite equal references, equivalent
instants, zero and empty objects, copy isolation, source freshness independence,
reclassification, component-local relevance, source-budget changes, reordered
and duplicate inputs, and the maximum population. Existing resolver fuzz and
contract regressions remain required.

This is a shared library read model. Consumer wiring, enrollment, authenticated
ingestion, field RBAC, operational UI, percentage KPIs, exports, native lifecycle
and final v5.00.0 IVVQ remain open. BunkerWeb's API, authentication, TTL, source
ownership, retries, HA and withdrawal checks remain independent of this model.
