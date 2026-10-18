# Authorized BunkerWeb inventory

Status: inactive v5 read-model component for #224 and #315, dependent on the
[presence snapshot](BUNKERWEB_PRESENCE.md). Stable remains v4.10.4. This helper
implements no enrollment service, authenticated endpoint, persistent registration
store, visual dashboard or final v5.00.0 IVVQ acceptance.

## Start from authorized membership, not responding nodes

`ResolveBunkerWebInventory` assembles one deterministic private inventory from a
complete, independently authorized membership. Nonresponding nodes remain in the
result. Identical overlapping memberships contribute one row. Different epochs,
retained-registration references or selected-report bindings for the same member
reject the whole inventory. No arrival order chooses a current generation.

The context pins the scope, complete membership manifest, policy, measurement
instant and three positive freshness budgets. The caller must authenticate these
inputs, verify the membership manifest's actual contents and apply current node
and field permissions before calling this helper. A reference and digest alone
do not establish authority, completeness or membership. These are typed producer
inputs, not a network admission protocol or self-enrollment request.

Each member supplies the exact expected snapshot ID, canonical SHA-256 and
collector from trusted report admission. An empty selection means no selected
report exists; partially specified selection is rejected. A received document
cannot fill in its own expected binding. Scope/policy and measurement time are
shared across the inventory. Each report still passes the presence projection's
independent node/epoch, collector, hash, scope, policy and freshness checks.

The routing identity must come from authenticated transport. Invalid, foreign or
obsolete routing identities and reports with no independent selection reject the
whole operation before any inventory is returned. Silently filtering a foreign
record after it influenced relevance or aggregation is not allowed. Payload fields
cannot override that transport identity.

## Retain history without asserting current operation

A member's optional `KnownRegistration` pins independently retained registration
history. It is not a current health assertion or renewed freshness evidence.
A missing or invalid report cannot remove this trusted history. A fresh absence
report that conflicts with retained registration is rejected with
`registration_conflict`; deliberate retirement requires a newly authorized
membership/history decision outside this component.

| Observation | Inventory behavior |
| --- | --- |
| Selected report is missing | Keep the authorized member with `missing_report`; known history keeps relevance `known`. |
| No report has been selected | Keep the authorized member as missing, without inventing source evidence. |
| Valid current report | Reuse its exact configuration mode and presence projection. |
| Expired report or unverified clock | Retain last-known provenance and freshness states; do not assert a current mode. |
| Malformed, substituted or future report | Keep only trusted member fields and a fixed rejection reason, with current mode unknown. |
| Identical reports, including equivalent JSON formatting | Collapse to one observation. |
| Conflicting projected outcomes | Reject the member's report with `conflicting_reports`; later repetition cannot erase the conflict. |

Rejected reports disclose no submitted registration, mode or source values.
Unavailable fields have explicit states and empty evidence. The independent
known-registration reference is retained separately. Different invalid payloads
that produce the same empty rejection remain rejected; their raw bytes are not
retained in this inventory.

Successful observations do not automatically persist new registrations. The
trusted producer must retain independently established history for later cycles.
This helper does not implement a database, retirement ledger, replay-admission
store or signature verification. A rebuilt inventory needs fresh authorization
when membership, policy or permissions change.

## Relevance is not a health verdict

Fleet relevance is `known` when any authorized member has established integration
history or a successfully projected established registration. Otherwise it is
`unknown` while any member lacks current absence evidence. It is `absent` only
when every authorized member has a current absence assessment, or when the
independently established authorized population is empty. Empty membership is
represented by an empty entries array and must remain distinguishable in the UI.

This is not an instruction to hide unknown servers or erase historical data.
On a whole-operation rejection, the caller must retain its independently known
authorized inventory with an unavailable state rather than render an empty
healthy result. Rejected fields must not be used for fallback rendering.

No percentages, health counters, protection judgments or response permissions
are derived here. KPI populations still use their separate reviewed eligibility
and evidence contract. The UI, exports and charts must apply the same authorized
scope before disclosure. A denied node cannot influence any tab or denominator.

## Deterministic private manifest and bounds

The result exposes defensive copies of entries and manifest bytes. Its reference
binds compact struct-order JSON under `syswarden.bunkerweb-inventory.v1`, containing
scope, membership, policy, canonical UTC measurement time, explicit age budgets,
fleet relevance and lexically sorted cluster/node/epoch entries. It is not JCS,
a signature, a public wire decoder or an authenticated export. An uninitialized
result cannot produce a reference. Canonical bytes never include raw report data.

Input ceilings are 8,192 members including duplicates, 8,192 reports and 4,096
unique nodes. Routing identifiers are validated before indexing. Every document
must fit the existing 16-KiB codec limit; total document bytes and the generated
manifest are each capped at 8 MiB. Report and source age budgets stay within the
presence schema's 24-hour ceiling. These are safety ceilings, not benchmarked
fleet capacity or recommended operational freshness defaults.

Tests include an independent golden digest, exact scope/epoch/selection binding,
missing/unknown/stale and disabled states, history/absence conflicts, rejected
payload isolation, deduplication, permutation stability, defensive copies and
input boundaries. A synthetic 500-node fixture retains 100 nonresponding members
alongside 400 current reports, including duplicate memberships and responses.
It uses existing local resources and makes no 500-server deployment or capacity
claim. A bounded permutation fuzz campaign complements these cases.

## Compatibility and remaining integration

This component performs no network access, file mutation or wall-clock read.
Authenticated ingestion, membership/history persistence, per-field RBAC, fleet
presentation and exports remain separate implementation work. It introduces no
Redis/Valkey or other external storage/runtime dependency. Future storage changes
need their own architecture review under the lightweight console contract.

BunkerWeb authentication, synchronization, per-source temporary ownership, TTL,
retry behavior and HA fencing remain independent of the dashboard. No existing
API, log collector, firewall or installed service is changed. Native lifecycle
and final v5.00.0 IVVQ acceptance remain open.
