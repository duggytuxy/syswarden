# Native package public keys

This directory is the only accepted distribution root for reviewed SysWarden
native package public keys. It must never contain a private key, passphrase,
revocation secret or recovery secret.

Each key file must be a regular, singly-linked file committed through review.
The v4.10.0 signature policy records its relative path, exact SHA-256,
cryptographic fingerprint, validity interval, revocation state and rotation
lineage. RPM and DEB OpenPGP public keys use an `.asc` suffix. APK RSA public
keys use a stable `.rsa.pub` basename because that basename is embedded in the
native APK signature member. DEB consumers verify the exact GitHub Release
asset and its matching `.deb.asc` file with an isolated `gpgv` keyring derived
only from the selected public key.

The foundation starts without production keys. A bootstrap policy may later
contain exactly one reviewed public key for each package family while remaining
`foundation-not-qualified` and non-publishing. Adding public-key bytes does not
authorize publication. Bootstrap proof, a separate policy promotion, a fresh
normal signing run and complete release qualification remain separate gates.

RPM, APK and DEB use three distinct signing identities. Key IDs and public-key
SHA-256 values are globally unique across the three families. RPM and DEB
primary OpenPGP fingerprints must also differ. Private key material must not be
reused across families.

Consumers must obtain these public keys from the reviewed source tree or from
a separately authenticated distribution channel, then compare the complete
SHA-256 and native fingerprint with the committed policy before importing a
key. A short key ID, filename, email address or web page alone is not a trust
anchor.

A key ID is globally unique and is never reused. Planned rotation permits a
bounded overlap in which the predecessor and replacement are both valid and
non-revoked. Every signing run explicitly selects one exact key ID and seals
that ID, native fingerprint and public-key SHA-256 into provenance. Release
consumers use the selected provenance record instead of counting active policy
records. After the overlap, the predecessor is no longer selected for new
signatures and remains an immutable historical record.

Revocation sets `revoked` to true through an emergency reviewed change and is
used for compromise, not ordinary planned retirement. Revoked and expired keys
remain historical records but cannot be selected by the gate. Recovery never
restores a compromised private key. It creates a new key outside this
repository, rotates only that family's protected secrets, commits only the
reviewed public key and policy record, and repeats the required qualification
sequence before signing resumes.
