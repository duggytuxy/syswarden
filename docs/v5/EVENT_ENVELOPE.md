# v5 shared event envelope

Status: first executable WP02 slice for review. This is a development contract,
not an enabled v5 feature or a published API. Refs #224, #234, #255 and #315.
The stable version remains v4.10.4. The contract must be reviewed with its
consumers before its first production use.

## Implementation boundary

The standard-library-only [contracts/v5 package](../../src/core/syswarden-core/contracts/v5/event.go)
implements `syswarden.event-envelope.v1`, explicit field availability, strict
JSON decoding, deterministic encoding and a conservative v4 projection. It is
inside the existing Core module so the established test, race, vet, lint and
security checks include it. There is no new service, dependency or module.

No production handler, logger, CLI, TUI or dashboard imports this package yet.
Cross-consumer adoption is subsequent work, not demonstrated by package tests.
The envelope contains references to future policy, action, current-control and
evidence records. It does not implement those contracts or resolve references.

The [BunkerWeb compatibility boundary](BUNKERWEB_COMPATIBILITY.md) is unchanged.
In particular, the envelope is not accepted by `/ha/sync` and cannot request a
ban, replace source ownership, change TTL or bypass an HA fence. Existing
automatic integration requests do not acquire a dashboard/session dependency.

## Fields and authority

| Field | Meaning and constraints |
| --- | --- |
| `schema` | Exact representation identifier. Unknown versions are unsupported, never interpreted as a known event. |
| `event_id`, `node_id` | Explicit references supplied by an identified ingestion boundary. An IP, timestamp or name is not a substitute for stable identity. |
| `observed_at`, `received_at`, `clock_quality` | Source time, caller-supplied receipt time and declared clock quality. Do not infer global order or fix source clocks. |
| `provenance` | Native or legacy representation, source reference and optional original-byte SHA-256. A hash does not authenticate an origin. |
| `subject` | Canonical IP, six-byte MAC address or explicit unknown subject. A MAC address is an observed value, not authenticated device identity. |
| `observation_code` | Producer label. It is neither a policy verdict nor evidence of current enforcement. |
| `layer` | Explicit L2-L7 when supplied by a supported producer. Never infer a layer from a jail name, address or port. |
| `severity` | Authoritative producer classification when available. The codec does not compute or calibrate severity. |
| `policy_ref`, `action_ref`, `control_ref` | Separate records for the decision, action history and current control evidence. None substitutes for either of the others. |
| `evidence_ref` | Reference to evidence whose integrity, completeness and access still need checking. |
| `context` | Separate reputation, trust, history and attribution references. Trust does not suppress an observation or imply an allowed action. |

Every JSON member is required. A `Field` is always an object with `state` and
`value`. The states are:

| State | Value | Consumer obligation |
| --- | --- | --- |
| `present` | Required | Validate source authority, access and applicability separately. Present does not mean authenticated or fresh enough for an action. |
| `stale` | Required | Retain the old value with an explicit stale label. Do not treat it as current. |
| `partial` | Required | Identify incomplete data. Do not manufacture complete population coverage. |
| `missing` | Empty | The expected value was absent from the supplied observation. |
| `unavailable` | Empty | The producer or adapter cannot establish this information. |
| `rejected` | Empty | Discard the unusable value; retain the fact that it was rejected. |
| `not_applicable` | Empty | A producer explicitly states that this dimension does not apply. |

These are declared states, not cryptographic attestations. Ingestion must bind
producer identity and scope before accepting facts. Reference resolution must
apply authorization before lookup or aggregation. The package does not perform
network requests, filesystem lookups or implicit reference resolution. Do not
expose raw identifiers to an unauthorized reader.

## Wire bounds and deterministic encoding

Use `DecodeEvent` and `EncodeEvent` at the contract boundary. Calling the Go JSON
decoder directly bypasses the strict checks. In-memory values also require
`Validate` before consumption. Mutating a validated struct invalidates that
validation.

- Maximum input/output: 16 KiB. Network adapters must limit reads before
  allocation; this byte-slice API cannot bound an upstream reader by itself.
- JSON nesting: at most eight levels below the root; at most 32 members per
  object or array and 256 values in the document. The v1 envelope itself has
  no arrays or arbitrary extension map. The generic bounds also cover legacy
  extension data before it is discarded.
- Identifiers: 1-128 ASCII bytes from letters, digits, `.`, `_`, `:` and `-`.
  These are opaque references, not paths, URLs, shell fragments or identities
  established by this codec. Authentication and namespace rules remain open.
- Timestamps: nonzero UTC RFC3339Nano, year 1970 or later, with canonical `Z`
  spelling and no redundant fractional zeros. A source time after receipt is
  representable; it must not be silently rewritten into a plausible order.
- Addresses: canonical unzoned IPs, without IPv4-mapped IPv6 aliases, or
  lowercase six-byte colon-separated MAC addresses. Other subjects remain
  explicitly unknown until a reviewed schema supports them.
- Invalid UTF-8, unpaired UTF-16 escapes, duplicate decoded keys, case aliases,
  unknown/missing fields, `null`, wrong types and trailing documents fail
  closed. A failure returns no partially usable event. Error messages never
  interpolate payload values.

`EncodeEvent` emits fields in the declared Go struct order, compact JSON,
explicit empty values and Go JSON string escaping, without a final newline.
There are no floating-point values, unordered maps or Unicode identifiers in
this envelope. Golden vectors pin the bytes. Whitespace and input key order
may differ on decoding; re-encoding yields the same schema-specific form.
This is **not RFC 8785 JCS** and not an approved signing format. The signed
evidence work package must choose and test its own accepted encoding before
using event representations in signatures.

The extra decoder checks address the compatibility behavior documented by the
[Go JSON package](https://pkg.go.dev/encoding/json), including duplicate
keys, case-insensitive field matching and replacement of invalid Unicode.

## Conservative migration of frozen v4 events

`ProjectLegacyV4` reads one bounded record from the existing v4 event contract.
It does not replace the v4 producer or parser. The
[six frozen input vectors](../../testdata/contracts/waf-events-v4.02.8.ndjson)
remain unchanged. The [projected vectors](../../src/core/syswarden-core/contracts/v5/testdata/legacy-projections.ndjson)
pin the result for each of their six action labels.

The caller supplies receipt time and explicit event, node and source identity
fields. Missing identities remain missing or unavailable. The adapter never
uses the payload IP or jail name to invent them. SHA-256 covers the exact bytes
passed to the adapter, including unknown fields and whitespace. The caller is
responsible for defining record framing and retaining original evidence.

The adapter retains the reported action label, canonical timestamp and address
when present. Empty timestamp/address strings become `missing`. Malformed
values, unsupported actions, ambiguous JSON or excessive input are rejected.
Unknown extension fields are bounded, hashed and left uninterpreted; reserved
field case aliases are rejected. This is a projection of the frozen contract,
not a claim to migrate every historical log format.

Numeric severity, raw payload text and jail names are not exported. Layer,
severity, policy/action/control/evidence references and all four context
references remain `unavailable`, even if extension fields claim attestation.
The validator rejects attempts to promote these fields while retaining the
`legacy_v4` representation marker. A future enrichment adapter needs its own
reviewed authority and evidence contract.

- `BANNED` does not establish a current block or a successful kernel operation.
- `ALLOWED` does not establish a trusted source, harmless traffic or an
  explicit allow policy.
- Shadow/simulated events do not establish real enforcement.
- A legacy jail name containing `L7` does not establish verified L7 coverage.

## Verification and remaining work

Golden tests cover native IP and non-IP L2 envelopes, stale/partial/rejected
contexts and all frozen legacy actions. Negative tests cover malformed JSON,
duplicate and escaped-equivalent keys, Unicode ambiguity, nulls, unknown
versions, bounds, clock/address normalization and evidence promotion. Fuzz
targets assert bounded failure, zero partial results and stable round trips.
The existing CI runs both new bounded fuzz targets along with its normal
package tests and race checks.

This slice leaves #224 open. Remaining work includes node enrollment and
identity rules; policy, incident, action, control-snapshot and evidence
contracts; shared rate formulas and eligibility; authenticated ingestion;
schema negotiation; cross-consumer adapters; and native migration evidence.
Future readers must test the same golden vectors and availability states before
their integration is accepted. No new UI or partner IVV is claimed here.
