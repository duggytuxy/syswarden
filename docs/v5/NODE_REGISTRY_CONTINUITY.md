# v5 admission registry continuity contract

Status: inactive FA-02 prerequisite, following the
[bounded registry snapshot](NODE_ADMISSION_REGISTRY.md). Refs #224, #233 and #315.
This component defines exact approval inputs and ordinary transition rules. It
does not implement protected storage, an approver, durable revocation, enrollment
or a network service. Stable remains v4.10.4; final v5.00.0 IVVQ remains open.

## Independent generation and checkpoint

The [generation record](../../src/core/syswarden-core/contracts/v5/node_continuity.go)
has schema `syswarden.node-registry-generation.v1`. It names an authority, a
lineage, a generation ID and three exact policy references: observation policy,
client-certificate trust and administration policy. Its canonical digest is the
independent registry generation used in the snapshot and individual grants.
It contains no hash of that snapshot, avoiding a recursive digest dependency.

These references do not load a trust bundle or authenticate an administrator.
The future provisioning boundary must verify each referenced artifact and its
purpose independently. Client trust is separate from browser, server endpoint,
release, local custody and BunkerWeb trust. Generation changes require their own
reviewed migration/recovery path; this first transition profile rejects them.

The `syswarden.node-registry-checkpoint.v1` record names that generation, the
complete snapshot reference, an authority and lineage, a checkpoint ID, a sequence,
the previous checkpoint digest, and an explicit `active` or `disabled` state.
The sequence is a canonical positive uint64 decimal string, avoiding precision
loss in JSON consumers. Sequence one has a 64-zero predecessor sentinel; every
later sequence requires a nonzero digest. A sentinel does not authorize bootstrap.

Both encodings are compact JSON in their declared field order, with no trailing
newline. Each is bounded to 4 KiB before parsing. Decoders reject noncanonical
bytes, duplicates, missing/unknown fields, null aliases, case or Unicode aliases,
unsupported schemas and sequence overflow. A decoding failure returns no partial
record. Synthetic golden vectors independently pin their bytes and hashes:
[generation](../../src/core/syswarden-core/contracts/v5/testdata/node-registry-generation.json)
and [checkpoint](../../src/core/syswarden-core/contracts/v5/testdata/node-registry-checkpoint.json).

```mermaid
flowchart LR
    P[Independently approved generation] --> G[Grant generation binding]
    G --> S[Complete bounded snapshot]
    S --> C[Checkpoint and predecessor digest]
    A[Independent current checkpoint] --> R[Exact continuity check]
    C --> R
    R --> L[Current member and slot lookup]
```

## Reads require independently known current state

`NodeRegistryReadContext` takes the generation, checkpoint, compiled snapshot,
trusted clock and a `NodeRegistryContinuityContext`. The last input must come
from independently protected current custody. It pins the authority, lineage,
generation reference and exact checkpoint reference. A document cannot establish
its own authenticity by supplying these expected values alongside itself.

The check compares every binding, including the full snapshot and its grant
generation/policy. Only an active checkpoint returns the existing snapshot read
context. A disabled registry, missing custody, wrong generation or stale full
checkpoint returns no context. A returned context is not a lease. Recheck it at
each request and durable commit while serialized with registry changes.

An older snapshot can be internally consistent and still fail the current
checkpoint comparison. A higher presented sequence is not automatically trusted.
If the registry and its supposedly independent anchor are restored together,
this pure function cannot detect the shared rollback. Independent custody and
the startup recovery ceremony remain mandatory before service activation.

## Ordinary changes preserve withdrawn authority

`CheckNodeRegistryAdvance` requires independently known current continuity and
an independently authorized exact successor reference. It verifies both whole
states, the same authority/lineage/generation, a checkpoint ID different from its predecessor, consecutive
sequence without overflow and the exact previous checkpoint digest. Replaying
the same transition after advancing current custody is rejected.

The [history check](../../src/core/syswarden-core/contracts/v5/node_continuity_history.go)
then applies these rules to the complete candidate:

- Every previous member and epoch remains present. A removed or replaced identity
  requires separate reviewed recovery, even if it no longer has credentials.
- Revoked members cannot reactivate or gain new slots. Revoked transport and
  producer grants cannot reactivate independently either.
- Every old credential and producer grant remains with unchanged identity,
  scope, key, certificate, issuer and original validity. Only its status can move
  from active to revoked. Existing admission windows can narrow but never widen.
- New members and rotation slots need the exact independent successor approval
  and all existing registry bounds, key separation and rotation checks. This
  validator does not perform enrollment, certificate issuance or key possession.
- A snapshot ID cannot refer to different bytes in adjacent checkpoints. An
  unchanged snapshot may be explicitly disabled without changing its ID.
- Disabling is sticky for this ordinary path. Re-enabling requires a separately
  designed recovery operation, not another ordinary update or a fresh timestamp.

Transport withdrawal does not silently withdraw a different producer grant,
although admitting an observation will require both current transport and
producer authority. Withdrawing a member denies all of its credentials at lookup.

The first profile retains expired and revoked slots, reserving their keys and
identifiers. It therefore eventually reaches the existing count/byte limits and
refuses further growth. It does not silently delete history to renew forever.
Protected denial-state compaction and its independently approved retention
checkpoint are prerequisites for sustained operation. No audit or replay state
is erased by this component.

## What remains before activation

Success means that the supplied structural transition matches the supplied
independent approval inputs. It does not mean those inputs were authenticated,
approval was consumed once, storage was synchronized or revocation was committed.
A competing successor with the same predecessor still requires a single writer
to choose and durably commit one transition. The pure checker does not lock files
or prevent competing calls from succeeding against the same current input.

FA-02 still needs protected provisioning, durable snapshot publication,
single-writer serialization, authenticated approval and recovery, crash-safe
publication, independent continuity anchors, historical denial retention and
combined registry/receipt/audit resource accounting. Ordinary-user file attacks,
process death, storage exhaustion and restored snapshots must be tested there.
Later stages add invitation/CSR issuance, real TLS, signed producer samples,
replay receipts and native lifecycle acceptance.

The [protected snapshot reader](NODE_REGISTRY_STORAGE.md) now supplies the
canonical storage object and checked Linux read-only lease. It is a persistence
prerequisite, not the durable writer, independent anchor or approval authority.

These tests cover malformed encoding, exact references, generation substitution,
rollback, replay, disabled state, narrowing, retained rotation history, revoked
members/keys and sequence overflow. Bounded fuzzing checks canonical decoding
without partial authority. They are component evidence, not durable storage or
native acceptance. BunkerWeb keeps its independent API, source ownership, TTL,
retry, withdrawal/cache and HA contract; no registry state is consulted by it.
