# Authorized External and Internal inventory

Status: inactive v5 read-model component for #224 and #315. It composes the
[exposure snapshot](NODE_EXPOSURE.md) over a complete authorized population.
The [fleet context](FLEET_CONTEXT.md) binds this inventory to the BunkerWeb
inventory before exposing a consistent selection from both components.
Stable remains v4.10.4. No dashboard, enrollment service, network scan, address
geolocation or final v5.00.0 IVVQ acceptance is implemented by this helper.

## One population and three explicit groups

`ResolveNodeExposureInventory` starts from independently authorized membership,
including servers without reports. It returns one sorted entry per enrolled
cluster/node/epoch identity. Identical overlapping memberships are deduplicated;
conflicting epochs or selected-report bindings reject the whole operation.

| Group | Required evidence | Consequence |
| --- | --- | --- |
| `external` | A current, exactly bound `internet_exposed` assessment. | The node may be considered by the separately authorized External view. |
| `internal` | A current, exactly bound `internal_only` assessment. | The node may be considered by the separately authorized Internal view. |
| `needs_classification` | Missing, malformed, rejected, contradictory, unknown or stale exposure evidence, or an unverified report clock. | The node remains in global inventory without an invented exposure verdict. |

Hosting is independent: an on-premises node may be External, and a cloud node
may be Internal. Missing information never defaults to Internal. A fresh hosting
claim cannot rescue stale exposure; stale hosting does not invalidate a current
exposure assessment. Mixed exposure paths must already be assessed upstream:
this helper does not discover NAT, proxies, published ports or Internet reachability.

`Entries` returns the complete authorized population. `SelectGroup` returns an
independent sorted subset from the same snapshot. The three groups form a
complete disjoint partition, including during a total reporting outage. There
is no implicit `all` alias or fallback for an invalid group. A valid empty group
returns an empty slice; invalid selection or an uninitialized result returns an
error and no entries. A previously returned slice cannot modify the inventory.

## Bind reports before using classification

The caller supplies scope, complete membership reference, policy, trusted time
and explicit positive report/classification age budgets. It must authenticate
these inputs, verify the actual membership contents and apply field permissions
before resolution. A digest or a familiar identifier alone is not authority.

Each member's independently selected snapshot ID, canonical SHA-256 and collector
are mandatory together, or entirely empty when nothing has been selected. A
submitted document cannot supply its own expected binding. Routing identity
comes from independently authenticated transport and is validated before indexing.
Foreign nodes, old epochs, unselected reports and excessive input reject the
whole result before any entries are returned. Filtering an unauthorized record
only after aggregation is not an acceptable recovery.

Within that population, the existing strict exposure decoder and projector check
schema, selected bytes, collector, identity, scope, policy and freshness. A bad
report preserves only the trusted member identity and selection, with empty
rejected classification fields. It cannot disclose submitted metadata or replace
another node. Different projected observations for one member remain rejected as
`conflicting_reports`; repetition cannot erase that conflict or select a winner.
Identical bytes are decoded once after the total input budget is checked.
Equivalent JSON formatting with the same valid canonical report also deduplicates.

A whole-operation error does not authorize an empty healthy UI. The caller must
retain its independently known authorized inventory with an unavailable state,
without rendering fields from rejected payloads. Report admission, source
verification, membership storage and retirement remain separate implementation.

## Freshness, reclassification and scope changes

This is an assessment at the explicit context instant, with no internal clock.
The existing report and classification expiry boundaries are preserved. Valid
stale reports retain their last-known provenance, but cannot enter a current
External or Internal group. A new report does not renew an old assessment.

Reclassification uses a newly selected report while retaining the stable node
identity. A previous report cannot satisfy the new binding. Revoking membership
removes authority for its old reports; a new epoch does not inherit them. An
already built inventory is not a live revocation or freshness service. Callers
must reauthorize and rebuild at the applicable time and policy before presenting
current results. `SelectGroup` does not renew that authority or advance time.

The private manifest binds scope, membership, policy, canonical UTC assessment
instant, both age budgets and the complete sorted entries. Its reference hashes
compact struct-order JSON under `syswarden.node-exposure-inventory.v1`; this is
not JCS, a signature, a public decoder or an authenticated export. Equivalent
representations of the same time instant produce the same manifest. The valid
empty population is explicit through an empty entries array.

## Map, KPI and integration boundaries

External selection alone grants no right to disclose addresses or locations.
Those fields need their own authorization and evidence before any world map is
built. Internal and uncertain nodes cannot silently enter the External map. No
address, coordinate, geography lookup or external mapping service is used here.

KPI eligibility, uncertainty and rate calculations remain under the shared rate
contract. This component emits no headline counts or success percentages. UI,
exports, map filters and BunkerWeb context must reconcile to the same authorized
population and measurement instant; none may reuse a revoked or stale cache as
current evidence. The existing BunkerWeb API, authentication, temporary source
ownership, TTL, retries and HA remain independent of dashboard availability.

## Bounds and verification

Ceilings are 8,192 member inputs, 8,192 reports, 4,096 unique nodes, 16 KiB per
report and 8 MiB each for total report bytes and the output manifest. Duplicate
bytes still count against the input budget. Report and classification age budgets
are bounded by the existing 24-hour schema limit; these are not operational
freshness recommendations or a benchmarked capacity guarantee.

Tests cover an independent golden manifest and digest, exact context binding,
malformed/substituted input, stable reclassification, revoked/foreign identity,
epoch conflicts, stale provenance, unknown clocks, group isolation, defensive
copies, input limits and deterministic deduplication. A synthetic 500-identity
fixture partitions 400 responders into 200 External and 200 Internal members,
while retaining 100 nonresponders in Needs classification. A complete outage
retains all 500 members without current map candidates. A bounded permutation
fuzzer complements the fixed cases. These are synthetic identities and existing
local resources, not a deployed fleet or authenticated transport capacity test.

The component performs no I/O or service changes. Authenticated ingestion,
persistent history, field RBAC, live views, maps, exports, native lifecycle and
final v5.00.0 IVVQ acceptance remain open.
