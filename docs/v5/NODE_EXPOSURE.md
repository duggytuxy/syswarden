# Fleet exposure classification

Status: inactive shared v5 development contract. Refs #224 and #315. The published
stable baseline remains v4.10.4. This component neither enables the dashboard nor
establishes v5.00.0 IVVQ acceptance.

## Separate exposure, hosting and operational state

The [exposure snapshot](../../src/core/syswarden-core/contracts/v5/node_exposure.go)
adds an independent schema without changing the existing node, event or KPI wire
formats. It represents one reviewed classification for one exact enrolled
cluster/node/epoch tuple. It carries no addresses, coordinates or arbitrary labels.

| Exposure value | Current group | Interpretation |
| --- | --- | --- |
| `internet_exposed` | `external` | The trusted inventory assessment establishes at least one Internet-facing path. |
| `internal_only` | `internal` | The trusted inventory assessment establishes internal-only access. |
| `unknown` | `needs_classification` | A current assessment cannot establish either classification. |
| Missing, unavailable, rejected or stale exposure | `needs_classification` | The node remains visible without a current exposure verdict. |

Hosting is a separate claim: `on_premises`, `cloud`, `colocation` or `unknown`.
A cloud server can be Internal. A server on premises can be External. A public
address alone does not establish an open service; a private address does not
exclude exposure through NAT, a load balancer or a reverse proxy. Neither field
is inferred from the other. This component performs no scans or network access.

The upstream inventory producer must account for every established exposure path
and select `internet_exposed` for mixed-use nodes. A node belongs to one current
group; reclassification retains its stable identity and historical records. This
helper does not enumerate or verify those paths, implement a membership registry
or deduplicate a fleet. Those responsibilities remain with authenticated ingestion
and the authorized inventory assembly.

Exposure does not establish connectivity, deployed protection, enforcement,
compliance or a successful incident response. The independent
[node report](NODE_SNAPSHOT.md) and control evidence keep their own semantics.

## Provenance and exact binding

`syswarden.node-exposure-snapshot.v1` contains mandatory snapshot and collector
identifiers, node identity, scope and policy references with SHA-256 digests,
report generation/expiry times, clock quality, exposure and hosting claims.
Each classification includes its availability state, value, exact source reference
and digest, and assessment time. `present` and `stale` require all this provenance.
`missing`, `unavailable` and `rejected` require empty value, source and time.
Partial or not-applicable exposure is deliberately not a classification.

`ProjectNodeExposureSnapshot` takes an independently prepared read context with
expected snapshot ID and canonical digest, collector, membership generation,
current scope and policy, trusted caller time and explicit age budgets. It compares
all bindings before returning any data. A changed claim, source, generation, scope
or policy cannot be substituted into a previously selected report, including a
stale report. A newly selected assessment needs a new independently authorized
binding. A historical digest does not authorize replay under current scope.

The caller must authenticate the producer, verify supporting assessment content,
resolve current membership and scope authorization, and select the exact record
before constructing this context. Copying its fields from an untrusted report
would defeat the boundary. A hash establishes byte identity, not authenticity or
permission. No string identifier proves enrollment or a valid policy decision.

Malformed documents, future reports and context mismatches return a zero view
and an error. The caller must retain the independently authorized inventory node
in the global view with rejected or unavailable classification. It must not
render rejected payload fields, hide the node or default it to Internal.

## Freshness without silently renewing assessments

The report is current only in this interval, with a synchronized report clock:

```text
[generated_at, min(valid_until, generated_at + max_report_age))
```

Each present classification additionally requires:

```text
now < assessed_at + max_classification_age
```

Assessment time cannot be later than report generation. Equality at either expiry
is stale. A fresh report carrying an old assessment does not refresh that
assessment. An already stale claim never becomes present through projection.
Each policy age must be explicit, positive and at most 24 hours; report lifetime
has the same hard ceiling. These are schema bounds, not deployment freshness
recommendations. Operational windows still require the reviewed policy.

An expired report keeps its bound last-known values and provenance as stale in
`needs_classification`. Unknown or unsynchronized report clocks produce an
unavailable report and stale retained values. There is no call to the wall clock
inside the helper. The caller must provide a trustworthy current time.

Hosting freshness is evaluated separately. Stale hosting does not invalidate a
current exposure assessment, and current hosting cannot rescue stale exposure.
The output reason explains report expiry, unverified clock, stale exposure,
unknown exposure or unavailable exposure. `current_classification` means that the
provided claims passed contextual checks, not that the helper verified a network
path. The output is a value copy and grants no additional authority.

The [authorized exposure inventory](NODE_EXPOSURE_INVENTORY.md) now assembles
these projections over complete membership, retaining nonresponders and providing
consistent External, Internal and Needs classification subsets. It does not
implement authenticated admission, registry storage or field permissions.

## Consumer and map obligations

Scope and field permissions must be applied before tab selection, aggregation,
search, export or map construction. Tabs cannot broaden RBAC. Only independently
authorized External nodes may enter the world map, and location/IP fields need
their own permission checks. Internal nodes and uncertain classifications do not
silently appear on the map. No geography or IP disclosure is implemented here.

Global inventory must include authorized unknown and stale nodes. Filtered KPI
populations must use the same authorized selection, carry uncertainty explicitly
and avoid duplicate identities. This component computes no KPI or percentage;
the shared rate contract remains independent. Presentation, map geometry, exports,
registry synchronization and audited classification changes remain future work.

## Decoder, tests and compatibility

Strict JSON uses the existing 16-KiB limit and bounded nesting/member/value counts.
All fields are mandatory. Unknown members, aliases, duplicate keys, nulls, malformed
Unicode, trailing values and unsupported schemas fail without partial output or
untrusted values in diagnostics. Canonical encoding is compact JSON in declared
field order, not JCS or a signature. Synthetic golden bytes and an independently
computed SHA-256 vector pin that encoding.

Tests cover hosting/exposure independence, all supported uncertainty states,
exact generation/scope/policy/source binding, reassessment without identity change,
report and assessment expiry boundaries, untrusted clocks, stale provenance,
strict decoding, schema isolation, legacy rejection and bounded fuzz round trips.
No v4 event or address is promoted into an enrolled exposure claim.

The [BunkerWeb contract](BUNKERWEB_COMPATIBILITY.md) is unchanged: its API,
authentication, temporary ban ownership, TTL, retries and HA remain independent
of this schema and of dashboard availability. No production caller, firewall,
package hook, service or server is changed. The remaining native integration
work and complete v5.00.0 IVVQ are separate acceptance requirements.
