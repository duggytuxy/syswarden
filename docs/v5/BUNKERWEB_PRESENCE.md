# BunkerWeb integration presence

Status: inactive shared v5 development contract. Refs #224 and #315. Stable
remains v4.10.4. This component does not enable a dashboard or establish native
integration acceptance or final v5.00.0 IVVQ acceptance.

## Registration is separate from current configuration

The [presence snapshot](../../src/core/syswarden-core/contracts/v5/bunkerweb_presence.go)
represents one exact enrolled cluster/node/epoch tuple. It separates retained
integration registration from the configuration mode observed by an authorized
producer. It contains no log paths, IP addresses, credentials or arbitrary labels.
Neither a path named BunkerWeb nor an event label establishes a registration.

| Registration claim | Mode claim | Projection while both claims and report are current |
| --- | --- | --- |
| `established` | `log_only` | Known integration, log collection configured. |
| `established` | `sync_only` | Known integration, scheduler synchronization configured. |
| `established` | `combined` | Known integration, both paths configured. |
| `established` | `disabled` | Known integration with an explicit disabled configuration. |
| `established` | `unknown`, missing, unavailable or rejected | Known integration, current mode unknown. |
| `absent` | Unknown or unavailable mode | Explicit current absence assessment. |
| `unknown`, missing, unavailable or rejected | Unknown or unavailable mode | Presence remains unknown. |

A concrete mode, including disabled or a stale retained mode, requires established
registration. Current registration does not turn an unavailable mode into enabled.
Enabled configuration does not establish service reachability, successful delivery,
protection, plugin version, HA writer authority or verified enforcement. These need
independent evidence. A log-only integration does not enable synchronization.

The producer must verify supporting configuration/capability records and retain
established history while it remains authorized. Failed discovery, an unreachable
service or an empty event stream is not an absence assessment. Disabling a known
integration retains its registration. An intentional retirement needs independently
verified inventory policy and history handling; this stateless helper does not
implement retirement, tombstones or a persistent registration ledger.

## Exact scope and provenance before disclosure

`syswarden.bunkerweb-presence-snapshot.v1` requires snapshot ID, collector ID,
node identity, scope and policy references with SHA-256 digests, generation/expiry
timestamps, clock quality, registration and mode. Each claim has its own state,
value, source reference/digest and assessment time. `present` and `stale` require
complete provenance. `missing`, `unavailable` and `rejected` require empty value,
source and time. Unknown is an explicit sourced value, not an empty success.

`ProjectBunkerWebPresenceSnapshot` requires independently prepared expected
snapshot ID and canonical digest, enrolled identity including epoch, collector,
current scope/policy, trusted caller time and three explicit age budgets. It
compares every binding before returning any field, including stale history.
A changed source, claim, identity, scope or policy needs a new authorized binding.
Digest equality establishes byte identity, not authenticity or permission.

The caller must authenticate the producer, verify its supporting records, resolve
current membership, select the exact report and apply scope and field permissions
before constructing the read context. Copying context from an untrusted report
would defeat this boundary. A denied node must not influence tab visibility,
aggregation, search, export or KPI denominators. No enrollment or RBAC service is
implemented by this schema.

Malformed input, a future report or a context mismatch returns zero data and an
error with no document values. The caller must keep an independently known,
authorized integration visible as rejected or unavailable, using its own trusted
inventory rather than the rejected payload. Missing reports obey the same rule.
A fleet cannot conclude global absence merely from the reports that arrived.

## Independent freshness and retained history

The report is current only with a synchronized clock and within:

```text
[generated_at, min(valid_until, generated_at + max_report_age))
```

Each present claim additionally requires its own unexpired assessment:

```text
registration: now < assessed_at + max_registration_age
mode:         now < assessed_at + max_mode_age
```

Assessment cannot be later than report generation. Exact expiry is stale. Each
age budget is positive and at most 24 hours, as is report lifetime. These are
wire bounds, not recommended operational windows. The caller supplies reviewed
policy values and trustworthy time; the helper does not read the wall clock.

A new report cannot renew an old assessment. Already stale claims stay stale.
Expired reports or unverified clocks retain last-known values and provenance as
stale. Established registration still projects `known`, preserving tab relevance,
but current mode becomes `unknown` until all required evidence is current.
Stale absence becomes `unknown`, never a current absence assertion.

`ReportState` describes report freshness only. `Relevance` is `known`, `absent`
or `unknown`; it is not a Boolean hide/show instruction. `CurrentMode` is either
a current configuration mode or `unknown`. The retained registration/mode fields
carry their own states and provenance. `Reason` distinguishes report expiry,
unverified clock, stale/unavailable/unknown registration, current absence,
stale/unavailable/unknown mode and current configuration. Disabled registrations
remain visible as known, and unavailable history does not silently disappear.

## Wire bounds and executable checks

Strict JSON reuses the 16-KiB document limit and bounded nesting, member and value
counts. All fields are mandatory. Unknown fields, aliases, duplicate keys, nulls,
invalid Unicode, trailing values and unsupported schemas fail without partial
output. Canonical encoding is compact struct-order JSON, not JCS or a signature.
Synthetic golden bytes and an independently computed SHA-256 pin the format.
Existing node, exposure, event, control and KPI wire formats are unchanged.

Tests cover every mode and availability state, absence and disabled distinctions,
independent report/registration/mode expiry boundaries, unverified clocks, retained
provenance, exact binding, rejected nodes, schema isolation and hostile decoding.
A bounded fuzz target runs in the security workflow. A 500-identity synthetic
exercise checks scope isolation using existing resources; it is not a deployed
fleet, load benchmark, capacity certification or new infrastructure expense.

## Remaining integration and compatibility work

This is an isolated shared contract with no production caller. Authenticated
registration ingestion, persistent history and retirement, fleet assembly, RBAC,
visual tab rendering, source health, plugin versions, temporary claim views, KPI
populations and exports remain separate work. Known-but-unreachable presentation
will join this report with independently authorized node reachability; this schema
cannot infer it from configuration.

The [BunkerWeb compatibility boundary](BUNKERWEB_COMPATIBILITY.md) remains mandatory.
No API, authentication, TTL, per-source ownership, retry, HA fence, firewall,
package or service is changed. Dashboard availability never controls the existing
integration. Native lifecycle and final v5.00.0 IVVQ acceptance remain open.
