# ADR-002: Detached OpenPGP signatures for DEB release assets

Status: accepted for the v4.10.0 signing foundation

## Context

SysWarden currently distributes DEB packages as individual GitHub Release
assets. It does not publish the hierarchical metadata required by an APT
repository, including `Release`, `InRelease` and `Packages` indexes at stable
repository paths.

An `InRelease` signature authenticates an APT repository snapshot. Producing a
standalone `InRelease` file without the complete repository hierarchy and its
authenticated index bindings would simulate a repository that does not exist.
It would not provide the installation and freshness semantics that APT clients
expect.

## Decision

The existing GitHub Release channel uses one detached, ASCII-armored OpenPGP
signature named `<exact-deb-filename>.asc` for the exact DEB byte stream. The
DEB bytes are never rewritten by signing. Offline verification uses `gpgv` with
an isolated temporary home and a keyring derived only from the selected public
key. The policy pins that complete public-key file by SHA-256, its complete
primary OpenPGP fingerprint, validity interval, revocation state and rotation
lineage.

The DEB OpenPGP certificate is dedicated to detached DEB signatures. Its
stable policy ID, public-key SHA-256 and primary OpenPGP fingerprint are
distinct from the RPM identity. The DEB private key is never shared with
another package family.

The verifier first binds the exact package filename, size and SHA-256 to the
release inventory. It then requires one bounded detached signature, one
successful `GOODSIG` and `VALIDSIG` result, an RSA signing key between 3072 and
8192 bits, SHA-256, a complete policy-matching primary fingerprint and a
signature date coherent with the qualification date. Any additional status,
signature, trust root, altered package, altered signature or stale key fails
closed.

This decision does not authorize publication. Initial key enrollment uses the
non-publishing `bootstrap-qualification` mode while the policy remains
`foundation-not-qualified` and the DEB implementation remains
`implemented-not-qualified`. A successful bootstrap artifact is reviewed
before a separate policy commit can qualify the DEB lane. The packages and
detached signature are then rebuilt and verified from the new exact source
SHA. Bootstrap evidence cannot enter release qualification or publication.

## Consequences

GitHub Release consumers can verify a DEB asset directly and offline without
mistaking the channel for an APT repository. The detached signature and its
verification evidence are sealed into the protected signing bundle.

If SysWarden later publishes a real APT repository, that repository requires a
separate decision and qualification for its complete hierarchy, authenticated
`Packages` indexes, `Release` metadata, clear-signed `InRelease`, expiry and
rollback controls. This detached-signature decision neither implements nor
claims those repository semantics.
