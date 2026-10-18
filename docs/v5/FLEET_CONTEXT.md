# Shared exposure and BunkerWeb fleet context

Status: inactive shared read-model composition for #224 and #315. Stable remains
v4.10.4. This component joins the [exposure inventory](NODE_EXPOSURE_INVENTORY.md)
and [BunkerWeb inventory](BUNKERWEB_INVENTORY.md). It does not implement a console,
enrollment, authenticated ingestion or final v5.00.0 IVVQ acceptance.

## Bind before joining

`ComposeFleetContext` accepts the two already constructed immutable inventories
and independently supplied expected contexts. Every field of each expected
context must match its corresponding inventory, including that component's
explicit freshness budgets. Both contexts must share the exact scope, membership
reference, policy and measurement instant. Equivalent UTC instants are accepted;
even a one-nanosecond difference is a different assessment. Freshness budgets
may differ between components but cannot change after their evaluation.

The actual sorted cluster/node/epoch populations must also match, entry by entry.
A shared membership reference alone cannot hide different contents. Extra,
missing, foreign or replaced identities reject the entire composition before
returning entries. There is no union, intersection or responder-only fallback.
The caller must verify the independent membership contents and authority before
constructing either source. Matching digests are not authentication.

Inventories retain their validated context internally without changing their
existing manifest bytes. The join consumes those typed results only; no decoder
accepts arbitrary submitted inventory manifests. Each joined row preserves both
component assessments exactly. A current exposure does not refresh an old
integration report, and an enabled integration does not establish exposure,
reachability, protection or permission to perform an action.

## One explicit selection across both components

`Select` requires one of `all`, `external`, `internal` or
`needs_classification`. There is no default or unknown-group fallback. Each
result retains the source ordering and provides defensive copies of its rows
and manifest. A valid empty selection contains an empty entries array; invalid
or uninitialized results return an error and no fields or reference.

BunkerWeb relevance is recomputed from the selected rows using the existing
relevance rules. For example, established integration history only on Internal
nodes cannot make an External-only selection report `known`. Missing evidence
inside a selection produces `unknown` unless another selected node establishes
`known`. History remains relevant during outages and disabled configuration.
An empty selected population reports `absent` only for that empty selection,
not for the fleet or a denied scope. The UI must distinguish these conditions.

Reclassification moves the same stable identity and its independent BunkerWeb
context between views. A reporting outage retains authorized nodes in Needs
classification rather than reusing their former External/Internal group. No
percentage, denominator, alert, health verdict, address or map location is
invented by the join. KPI and alert contracts remain separate.

Selections are filters within an already authorized population, not permission
boundaries. Node and field authorization must precede construction and disclosure.
Callers must reauthorize and rebuild when scope, policy, membership or time
changes. This immutable snapshot is not a live revocation service. On rejection,
the caller must present unavailable context without using rejected fields or
inventing an empty healthy fleet.

## Private references and bounded work

The context manifest uses compact struct-order JSON under
`syswarden.fleet-context.v1`. It binds the shared context, both complete source
manifest digests and the exact joined entries. The selected-view manifest under
`syswarden.fleet-context-view.v1` binds its parent digest, explicit selection,
selected relevance and selected entries. Even empty views retain their selection
identity. These are private deterministic records, not JCS, signatures, public
wire formats, browser responses or authenticated exports.

The source resolvers enforce their existing input and population ceilings. The
join and each selection process at most 4,096 nodes and cap their manifest at
16 MiB. There is no I/O, network call, database, internal clock or background
worker. Synthetic 500-node tests use existing local resources, not a purchased
fleet or a native capacity guarantee.

Validation covers independent canonical vectors and digests, complete context
binding, actual membership mismatch despite equal references, zero/empty states,
defensive copies, freshness independence, reclassification, source-budget changes,
selection-local relevance, population ceilings and deterministic permutations.
Partial and complete reporting outages preserve the same authorized population.
Existing source schema golden vectors remain byte-identical.

The independent BunkerWeb API, authentication, temporary source ownership, TTL,
retries and HA are unchanged. Production admission, registry persistence, field
RBAC, UI, exports, native lifecycle and final v5.00.0 IVVQ remain open.
