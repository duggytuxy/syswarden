# v5 bounded node admission registry snapshot

Status: FA-01 collection component following the
[individual admission grants](NODE_ADMISSION_GRANTS.md). Refs #224, #233 and #315.
This is an inactive in-memory model, not a protected registry service, enrollment
endpoint or accepted v5.00.0 release. Stable remains v4.10.4.

## Complete candidate and explicit bounds

[BuildNodeAdmissionRegistry](../../src/core/syswarden-core/contracts/v5/node_registry.go)
consumes a snapshot ID, independent registry/policy generation binding, and the
complete intended working membership. Every member has one exact
`cluster_id/node_id/epoch`, an `active` or `revoked` status, and explicit transport
and producer admission slots. No grant is inferred from membership alone. A
member with no slots remains in the snapshot and receives no credential access.

| Bound | Initial enforced value |
| --- | --- |
| Registered members in one snapshot | 4,096 |
| Transport slots per member | Two |
| Distinct producer sources per member | 16 |
| Producer slots per source | Two, for one exact payload schema |
| Canonical complete snapshot | 16 MiB |
| Simultaneous admission during eligible rotation | At most one hour |

Counts include revoked/expired records retained in this working snapshot. This
prevents inactive entries from creating unbounded allocation or a key-reuse
loophole. An audit archive is separate. The future protected writer must account
for retired records under approved retention and continuity before freeing a
slot; this component deletes nothing and authorizes no silent history eviction.
The 16 MiB snapshot ceiling is a stricter component limit within the ADR's 32 MiB
working-state budget. It does not prove heap usage or leave an already measured
receipt allocation; aggregate storage and resource accounting remain FA-02/FA-07.

Preflight checks individual field and slot limits, then the exact encoded byte
budget, before copying the complete collection or allocating global indexes.
An invalid last member, conflicting record or oversized aggregate rejects the
entire candidate. No valid-prefix registry is returned.

## Identity and key separation

The builder rejects duplicate members, including identical duplicates, and
multiple epochs for the same cluster/node. Every grant must match its enclosing
member and the independent registry and policy references, including digests.

Transport credential IDs, certificate digests, producer grant IDs and producer
key IDs must each be unique in their respective namespace. All transport and
producer public-key digests share one uniqueness check across the snapshot.
This prevents key reuse across nodes, sources, rotation slots and transport vs
producer purposes, including records currently marked revoked.

This checks declared digests, not possession or the public key bytes themselves.
The existing certificate/key binding helpers still have to validate those bytes.
The snapshot cannot compare against keys held in other systems or forgotten
history. Release, browser, issuer, BunkerWeb and custody key separation requires
independent protected provisioning and historical denial state in later stages.

The first source profile has one literal payload schema per source and one grant
per key. Rotation cannot widen that source/schema or silently share a key across
permissions. A schema transition needs a separately approved registry/policy
transition, with history retained outside the bounded active working slots.

## Admission lifetime is distinct from certificate lifetime

Each slot carries `admit_from` and exclusive `admit_until`, both canonical UTC
instants inside its grant's original validity interval. A public certificate's
signed validity remains unchanged. The registry can end its admission sooner.

For an active member with two active records of one purpose/source, sort by
admission start and require all of the following:

- The successor has a strictly later admission start and end.
- Its grant validity starts at least 12 hours after the predecessor's transport
  grant starts, or at least 15 days later for a producer grant.
- Their admission windows overlap by at most one hour.
- All source/schema, member and policy bindings remain unchanged.

For example, a transport certificate valid from 09:00 on day one until 09:00 on
day two can stop being admitted at 22:00 on day one. Its successor can be valid
and admitted from 21:00. The overlap is one hour, although the predecessor's
public certificate remains cryptographically valid until the next morning.

Disjoint windows are permitted and remain a real gap, with no grace period.
Their structural validity does not authorize normal renewal of an expired node;
reviewed recovery and proof of both keys remain separate lifecycle requirements.
Revoked members or records receive no current admission. Retaining an old revoked
record does not require its historical overlap to satisfy active rotation rules,
but still consumes count limits and reserves its key against reuse.

## Canonical state without a circular hash

The compiled `syswarden.node-admission-registry.v1` manifest sorts members by
exact cluster/node/epoch, transport slots by credential ID and producer slots by
grant ID. Empty lists encode as arrays. The compact bytes and SHA-256 are pinned
by a synthetic independent
[golden vector](../../src/core/syswarden-core/contracts/v5/testdata/node-admission-registry.json).
Permutation does not alter the reference; changing any status, slot, grant or
member does. Accessors return defensive copies, including nested slot arrays.

There are two distinct references:

1. The independently approved registry generation in `binding.registry`, also
   embedded in each grant. It must be defined outside this aggregate.
2. `Reference()`, the exact snapshot ID and digest of the complete compiled
   manifest. The protected writer must approve and pin this full reference.

The first cannot be the hash of a document recursively containing itself. A
caller must not authenticate a submitted manifest by accepting its own hash.
`BuildNodeAdmissionRegistry` checks structure, not authority. The later
[protected snapshot reader](NODE_REGISTRY_STORAGE.md) decodes only a complete
canonical manifest with an independently expected reference. It does not expose
an upload endpoint or enrollment fallback.
The [continuity contract](NODE_REGISTRY_CONTINUITY.md) now defines the independent
generation and checkpoint formats, exact expected authority and ordinary
transition restrictions. Protected persistence and real approval remain open.

## Bound current lookup

The [read methods](../../src/core/syswarden-core/contracts/v5/node_registry_read.go)
require `NodeAdmissionRegistryReadContext`: the independently authenticated
current snapshot reference, exact generation/policy binding and trusted time.
They compare the whole aggregate before consulting a credential or grant ID.
Even an unchanged member cannot be read under the digest of an older aggregate.

`Transport` also requires the expected node identity and credential ID.
`Producer` separately requires the expected identity, grant ID, source and
payload schema. Both check active member status, exact identity, slot admission
window, active grant status and grant expiry. Failure returns zero grant and
zero per-record context, never partial authority.

Success returns the exact immutable grant plus a pinned `NodeGrantReadContext`
for the existing certificate or producer-key checker. It is not a reusable lease.
Retirement can precede certificate expiry, so retaining only that per-record
context would bypass later slot expiry. The caller must repeat complete current
registry admission at each request and durable commit boundary. Protected
serialization, live revocation and connection closure remain unimplemented.
Transport withdrawal and producer withdrawal are independent checks; accepting
an observation will require both, plus its signed source and replay evidence.

## Evidence and outstanding integration

Tests cover canonical vectors, permutation, deep copies and concurrent reads,
foreign node/epoch/policy/snapshot, all count ceilings, aggregate byte exhaustion,
late faults, cross-purpose keys, exact time boundaries and rotation in both input
orders. A generated certificate remains publicly valid after its shorter slot is
retired, while registry lookup rejects it. A 500-member synthetic credential
population checks complete per-node lookups without additional infrastructure.
This is a structural simulation, not a load benchmark or 500 physical servers.

The bounded `FuzzNodeRegistryPermutation` target verifies deterministic authority
under reordering and rejects cross-purpose key substitution. Native resource,
bootstrap, recovery, durable revocation, issuance, live TLS and signed-source
campaigns remain required. No file, server, network listener or installed service
is changed by this component. BunkerWeb retains its independent authentication,
source ownership, TTL, retries, withdrawal/cache behavior and HA contract.
