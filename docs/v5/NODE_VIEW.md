# Bound node state projection

Status: inactive shared read model for #224, #233 and #315. The stable release
remains v4.10.4. This component prepares consistent node rows without enabling
enrollment, transport, a dashboard or final v5.00.0 IVVQ acceptance.

## Select the report independently

`ProjectNodeSnapshot` consumes a validated [node snapshot](NODE_SNAPSHOT.md) and
an independent `NodeSnapshotViewContext`. The context pins the snapshot ID, the
canonical SHA-256, collector ID and exact cluster/node/membership epoch. Its
`NodeReadContext` supplies the assessment time and explicit maximum report age.
There are no implicit clock reads or freshness defaults.

`NodeSnapshotSHA256` hashes the existing compact struct-order JSON encoding,
with no final newline. Formatting differences in accepted input do not change
this digest; any changed reported field does. The existing schema and golden
bytes are unchanged. The digest establishes byte identity, not authenticity.

The caller must authenticate collection, authorize node and field disclosure,
select the exact permitted report and establish current membership before
calling this function. Deriving the expected values from received input defeats
selection. Neither this helper nor the older `CheckCurrentNodeSnapshot` provides
enrollment, replay storage, registry revocation, RBAC or credential verification.

Invalid contexts, malformed reports, changed identities, mismatched selection
and future collector timestamps return an all-zero view and an error without
payload values. The inventory consumer must keep the independently authorized
node visible as having unavailable/rejected evidence, not remove it or invent
an empty healthy population. This helper does not construct that inventory.

## Separate current transport from historical data

Report freshness uses the existing exclusive interval:

```text
[collected_at, min(valid_until, collected_at + caller_max_age))
```

Expiry retains the stable identity, report identifiers, original timestamps and
historical values. `ReportState` becomes `stale`, `Reason` is `report_expired`,
and `CurrentReachability` becomes `unknown`. The separate `Reachability` field
keeps the original value with `state=stale`. It must not be displayed as a
current reachable or unreachable verdict. No cached report receives a new
collection timestamp when rendered again.

| Selected report | Report state | Current reachability | Retained source fields |
| --- | --- | --- | --- |
| Current successful contact | `present` | `reachable` | Exact reported quality |
| Current failed contact | `present` | `unreachable` | Available agent facts are already `stale` |
| Current unknown contact | `present` | `unknown` | Explicit absence or stale history |
| Expired report | `stale` | `unknown` | Nonempty values become effectively stale; original quality is retained |
| Future or rejected report | No view | No usable value | No fields returned |

Every projected source field contains `Reported`, the exact original `Field`,
and `State`, the effective availability at the supplied assessment time. On
expiry, any value-bearing state becomes effectively stale. Empty `missing`,
`unavailable`, `rejected` and `not_applicable` fields retain their meaning and
never receive an invented value. An originally `partial` field therefore keeps
that source qualifier even when its effective state becomes stale. Consumers
must display the effective state alongside any reported value and preserve
the source qualifier in detail views and exports.

A current outage report can retain a present historical last-successful-contact
time. That fact is not current connectivity. Its agent facts stay stale even
though the collector report is recent. Conversely, a reachable node can have
missing or rejected protection evidence. Neither condition authorizes a green
protection status, a response action or a percentage numerator.

## Keep the two clocks and evidence references distinct

`ClockQuality` and `ObservedAt` describe the agent's reported observation, not
the collector's trusted time. Unknown, unsynchronized or skewed agent time does
not refresh the collector report or erase its independent contact observation.
The reported clock value and availability remain visible without silently
substituting collector time for source time.

The projection only downgrades field availability when the enclosing report
expires. It does not independently authenticate source quality, infer that an
agent observation is fresh from its timestamp, or evaluate referenced evidence.
Even a source claiming a synchronized clock can be wrong. A future source time
is preserved as reported data, never used for validity or trusted ordering.
Ingestion and each referenced evidence contract must verify their own trust,
clock and age requirements before presenting authoritative results.

Policy, control and integration references remain opaque references. Their
presence is not proof of applied policy, active protection or BunkerWeb
participation. BunkerWeb presence and selected fleet relevance continue to use
their [dedicated inventory](BUNKERWEB_INVENTORY.md) and
[shared fleet context](FLEET_CONTEXT.md). An outage cannot turn a retained
integration reference into an authorization or silently discard known history.

## Bounds and validation

The existing node decoder and canonical encoder enforce the 16-KiB source
document bound. The projection has fixed fields, no I/O, no background worker
and no shared mutable storage. Consumers must reauthorize and reproject when
membership, policy or time changes; a retained value is not a live view.

Tests pin independent digests of the existing golden vectors, exact report and
membership binding, zero-data refusals, nanosecond freshness boundaries, caller
age precedence, current outages, unknown connectivity, all availability states,
partial-quality retention, agent clock skew and value-copy isolation. The
existing node snapshot fuzz target also checks current and expired projection.

Authenticated ingestion, membership lifecycle, inventory integration, field
RBAC, visual rendering, exports, fleet simulation and native acceptance remain
separate work. The independent BunkerWeb API, temporary-ban source ownership,
TTL, retry and HA contracts are unchanged. Component validation is intermediate
evidence under the major v5.00.0 IVVQ contract, not final acceptance.

The [complete authorized node-state inventory](NODE_STATE_INVENTORY.md) now
retains missing and stale members without inventing current reachability or
protection. Its bound manifest, source quality, resource limits and synthetic
500-node outage cases are component evidence; consumer integration, enrollment
and native v5.00.0 IVVQ acceptance remain open.
