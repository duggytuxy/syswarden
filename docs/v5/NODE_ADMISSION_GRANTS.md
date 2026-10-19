# v5 node admission grant and credential bindings

Status: first executable FA-01 slice of the
[fleet admission ADR](FLEET_ADMISSION_ADR.md). Refs #224, #233 and #315.
These are offline contract checks. They do not enroll nodes, open a listener,
issue certificates, authenticate a TLS peer or establish v5.00.0 IVVQ acceptance.
The published baseline remains v4.10.4.

## Separate authority records

The [grant types](../../src/core/syswarden-core/contracts/v5/node_admission.go)
use the existing exact `cluster_id/node_id/epoch` identity. Identifiers are
bounded ASCII, case-sensitive and literal. No hostname, address, subject common
name or inferred geography assigns identity.

| Schema | Purpose | Additional exact bindings |
| --- | --- | --- |
| `syswarden.node-transport-grant.v1` | One approved node-client credential | Credential ID, leaf DER SHA-256, canonical public-key SPKI SHA-256 and immediate issuer DER SHA-256; `ecdsa-p256` only |
| `syswarden.node-producer-grant.v1` | One producer verification key for one source and payload schema | Grant ID, source ID, payload schema, key ID and canonical public-key SPKI SHA-256; `ecdsa-p256-sha256` only |

Both records also require the independently approved registry generation and
admission-policy references, including their exact SHA-256 digests; an explicit
`active` or `revoked` status; and canonical UTC `not_before`/`not_after` values.
Each interval must be positive. Transport lifetime is at most 24 hours; producer
authority lasts at most 30 days. Exact expiry is inactive. A decoded revoked or
expired record can still be inspected as history and grants no current authority.

A registry reference identifies an independently established membership
generation. It must not be defined as the hash of an aggregate that recursively
contains this grant and its own digest. FA-02 must freeze the protected registry
format and transition binding before these references can drive admission.

There are no roles arrays, generic extension maps, wildcard source permissions,
credential fallback or default registry/policy values. A producer grant permits
exactly one `(source_id, payload_schema)` pair. A transport grant cannot stand
in for that separate record. Neither grants browser, response-action, HA-writer,
release-signing or BunkerWeb plugin authority.

## Strict bytes and independent context

The [codec](../../src/core/syswarden-core/contracts/v5/node_admission_json.go)
uses the shared bounded JSON parser and exact object shapes. Unknown fields,
duplicates, escaped duplicates, case aliases, null/missing fields, malformed
UTF-8, invalid surrogates and trailing documents are rejected. Failure returns
the zero value, without reflecting submitted identifiers in error messages.

Encoding is compact JSON in the declared struct field order, without a trailing
newline. Grant SHA-256 covers those exact encoded bytes. This is a versioned
local canonical format, not JCS and not a signature. Frozen synthetic
[transport](../../src/core/syswarden-core/contracts/v5/testdata/node-transport-grant.json)
and [producer](../../src/core/syswarden-core/contracts/v5/testdata/node-producer-grant.json)
vectors include independently calculated expected digests. Their placeholder
certificate/key hashes do not represent usable credentials.

`CheckCurrentNodeTransportGrant` and `CheckCurrentNodeProducerGrant` require a
`NodeGrantReadContext` obtained independently from current authenticated state:

- Exact record ID and canonical grant digest.
- Expected cluster/node/epoch.
- Current approved registry and policy references, including their digests.
- Explicit trusted time, with no implicit clock or permissive default.

The checks compare every binding and enforce `[not_before, not_after)`. An
unchanged ID with a changed digest, policy, registry generation or node epoch is
rejected. Changing status changes canonical bytes too. Copying the context out
of a submitted grant defeats these checks and is never an authentication step.
A stale trusted context can still accept stale authority. Registry serialization,
revocation and rechecking at each durable commit remain FA-02/FA-04 obligations.

## Client certificate binding

The [credential checker](../../src/core/syswarden-core/contracts/v5/node_credential.go)
accepts only bounded raw DER bytes: one leaf, one immediate issuer and one
independently pinned root. Each is limited to 4 KiB before parsing. The root pin
must come from the approved node-client trust purpose, never from a submitted
chain. No system root pool, remote AIA lookup, URL or file path is used.

`CheckNodeTransportCertificateBinding` first checks the current transport grant,
then exact leaf/issuer/root digests and the leaf's public-key digest. It requires:

- A non-CA leaf with canonical ECDSA P-256 SPKI and ECDSA-with-SHA-256 signature.
- Digital-signature key usage and client-authentication EKU only.
- The full SAN extension containing exactly
  `urn:syswarden:node:<credential_id>`. No extra DNS, IP, email, duplicate URI or
  GeneralName ignored by a projected parser is accepted.
- Certificate validity timestamps exactly equal to the grant interval.
- A valid X.509 client path at the explicit current instant. Issuer constraints,
  unknown critical extensions and signatures are checked by Go's verifier.
- A returned path of two or three certificates with the exact pinned immediate
  issuer and root. A directly issuing pinned root is also supported.

An approved corporate or alternative algorithm profile is not inferred. The
first leaf profile is deliberately narrow. Root and issuer trust distribution,
revocation and custody are separate administrative responsibilities. Standard
X.509 path validation does not fetch revocation status.

A successful check proves the binding of these public bytes to this supplied
context. It does **not** prove that a live peer possesses the private key. A
copied public certificate is expected to pass the same byte checks; only the
future verified TLS handshake can establish peer key possession. The future
listener must bound the handshake before parsing these bytes, enforce its
separate transport limits and reauthorize established connections per request.

## Producer verification-key binding

`CheckNodeProducerKeyBinding` independently requires a current producer grant,
its exact source/schema pair, and canonical P-256 SPKI bytes no larger than
256 bytes. The exact key digest must match. A different source, payload schema,
node epoch, registry generation, policy or public key is denied.

This helper does not verify a source sample signature, challenge, sequence,
receipt or observation freshness. FA-05 must do that before any sample is used.
Successful signature verification will still establish who signed a statement,
not whether the statement is true. The independent evidence evaluators remain
required for policy/protection claims and fleet percentages.

## Coverage and remaining work

The [grant tests](../../src/core/syswarden-core/contracts/v5/node_admission_test.go)
cover golden bytes, strict decoding, all contextual bindings, exclusive expiry,
revocation, lifetime limits and cross-schema refusal. The bounded
`FuzzNodeAdmissionRoundTrip` CI target exercises zero-on-failure, stable decoding
and rejection of a substituted epoch for accepted documents.

The [credential tests](../../src/core/syswarden-core/contracts/v5/node_credential_test.go)
generate synthetic keys in memory. They exercise positive direct/intermediate
paths, concurrent immutable reads, malformed/substituted DER, bad signatures,
wrong curves, client/server purpose confusion, extra/ambiguous SANs, unknown
critical extensions and expired/not-yet-valid/non-CA/wrong-purpose issuers.
No production key, filesystem mutation, network listener or native server is
used by these tests.

The [bounded registry snapshot](NODE_ADMISSION_REGISTRY.md) separately checks
collection limits, key uniqueness and rotation admission windows, then binds
lookups to an independently approved complete digest. These per-record helpers
alone cannot detect reuse or enforce an earlier registry retirement deadline.
Protected administration, historical key denial, FA-02 through FA-07, bootstrap,
issuance, real TLS, sample proofs, recovery, UI wiring and native lifecycle/capacity
evidence remain open.

BunkerWeb retains its independent API, source ownership, TTL, withdrawal, cache
and HA contract. No plugin token is accepted as a grant, and a node grant does
not authorize partner bans. This slice changes no installed service, firewall,
connector, listener, version reference or release asset.
