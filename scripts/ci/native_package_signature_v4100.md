# Native package signature foundation for v4.10.0

Status: the protected signing foundation and fail-closed publication
integration are implemented. Three distinct candidate production public identities are
enrolled under the non-publishing foundation policy. Phase 1 bootstrap
qualification succeeded, and the exact immutable result recorded below is the
foundation evidence for phase 2. The committed policy remains non-qualified
until a distinct phase 2 `qualified-policy` run validates the permitted policy
transition. Policy promotion, normal native proof and publication approval
remain pending.
No workflow in this foundation creates a private key.

The offline gate binds one package byte stream to an exact release inventory
before native verification. It accepts only an explicitly selected, currently
valid and non-revoked public key whose bytes and identity match the policy.
The policy file, policy directory, selected public-key distribution directories
and every selected public key must remain owner-controlled, non-writable by
group or others and byte-stable throughout verification.
Verification evidence is created exclusively in an owner-controlled real
directory, with no replacement of an existing path and mode `0600`.
The signed bundle applies the same protected-parent and no-replacement rule to
every package, evidence document and checksum seal it creates.
Qualified policy state requires reviewed RPM, APK and DEB trust roots. The DEB
trust root is dedicated to detached signatures for GitHub Release assets. The
three package families use distinct signing identities. Policy key IDs and
public-key SHA-256 values are globally unique, and the RPM and DEB primary
OpenPGP fingerprints must differ.
Expired or revoked historical keys may remain recorded for rotation evidence,
but they cannot verify a selected package. A publishing invocation additionally
requires the policy's explicit publishing approval.

RPM verification uses a private temporary RPM database containing only that
OpenPGP key. APK verification uses a private temporary key directory containing
only the selected RSA public key. DEB verification uses isolated `gpgv` with a
temporary keyring derived only from the selected OpenPGP public key. The
repository policy contains exactly one candidate production public identity per
package family. Phase 1 has succeeded, but the policy remains intentionally
non-qualified and non-publishing until the separate reviewed phase 2 policy
commit and `qualified-policy` run complete. The APK signer is pinned to the
AMD64 manifest of the official Alpine Linux 3.24 build-base image at
`docker.io/alpinelinux/build-base@sha256:31d2a020ccd2058e6ab47940428bd0b7dc83e37b66880891f9ed903a12ea668b`.
It was reviewed as an offline runtime containing `abuild-sign`, `apk`, OpenSSL
and `tar`; changing this identity requires a new review and qualification.

The phase 1 trust inventory is exact:

| Family | Policy ID | Full fingerprint | Public key SHA-256 | Validity |
| --- | --- | --- | --- | --- |
| RPM | `rpm-prod-2026-01` | `A4C140FCF5408DCDB1E9209F6BCC4D258C321050` | `e9c0ffd66f3e6a9addd2b7e347b84e8d92b34d1cc8e4f4f438d02eabe59c3874` | 2026-09-08 through 2028-09-07 |
| APK | `apk-prod-2026-01` | `89d87c5d66ab184a379eb421deb5875d5fc699258ad7072edaed7c741f077869` | `89d87c5d66ab184a379eb421deb5875d5fc699258ad7072edaed7c741f077869` | 2026-09-08 through 2028-09-07 |
| DEB | `deb-prod-2026-01` | `2E40725EAD6A3AACB2FA31A577586532ABD300BF` | `7db8a9c4b1894cb7aef5b0f9f5c2b558d3526d121e19563e6f56dc28956fcf13` | 2026-09-08 through 2028-09-07 |

The RPM and DEB OpenPGP identities each use a 4096-bit certification primary
key and a distinct 4096-bit signing subkey. The APK identity uses a distinct
4096-bit RSA key. Private keys and passphrases are never distributed from this
directory.

## Two-phase trust qualification

Phase 1 is `bootstrap-qualification`. It is permitted only when the committed
policy has status `foundation-not-qualified`, `publishing` is false,
`deb.implementation` is `implemented-not-qualified`, and each package family
contains exactly one reviewed, currently valid and non-revoked public key. The
protected workflow signs and independently verifies all three package families
with purpose `qualification` and emits
`native-signatures-bootstrap-verified-not-release-qualified`. This artifact is
bootstrap evidence only. It cannot enter native lifecycle qualification,
release qualification or publication.

After a separate release-owner review of the bootstrap evidence, phase 2
starts with a distinct reviewed policy commit. That commit sets `status` to
`qualified` and
`deb.implementation` to `qualified`. The `publishing` value remains a separate
explicit release-owner decision and is never enabled during phase 1. Because
the policy commit changes the source SHA, the unsigned package artifact and
signed bundle must be rebuilt from the new exact `main` SHA. A fresh
`qualified-policy` run emits
`native-signatures-verified-not-release-qualified`. Bootstrap package bytes and
bootstrap evidence are never reused as phase 2 release evidence.

Phase 2 is machine-bound to the reviewed phase 1 result. Its dispatch inputs
must match the following immutable identity, which is also pinned independently
in the workflow and bundle verifier:

| Field | Exact value |
| --- | --- |
| Repository | `duggytuxy/syswarden` |
| Source SHA | `9598861f1be80a651658bf3ca8c10424bd70db6c` |
| Signing run | `34292701745`, attempt `1` |
| Signed artifact ID | `10088398939` |
| Signed artifact name | `syswarden-native-signed-packages-4.10.0-34292701745-1-9598861f1be80a651658bf3ca8c10424bd70db6c` |
| Signed artifact size | `63065295` bytes |
| Signed artifact digest | `sha256:a76917630d5d5a90bddcf936d47ec75a987f098c9048bce0d320d1ffda131ad3` |
| Foundation policy SHA-256 | `6b98b3b5bca83b9bc611c3b2e384636b5bbcbecc9e818e0f06104255200b011d` |

The workflow accepts only a completed successful
`workflow_dispatch` attempt 1 owned by the repository owner, with one unexpired
artifact whose ID, canonical bootstrap name, byte size, GitHub digest and source
SHA all match this identity. The bootstrap SHA must be a distinct Git ancestor
of the phase 2 SHA.
The extracted foundation policy must have the immutable SHA-256
`6b98b3b5bca83b9bc611c3b2e384636b5bbcbecc9e818e0f06104255200b011d`,
matching both the dispatch input and bootstrap provenance.
The policy transition permits only these changes:

* `status`: `foundation-not-qualified` to `qualified`
* `deb.implementation`: `implemented-not-qualified` to `qualified`
* `publishing`: false to true when separately approved, or false to false

Every key record, mechanism, signer image and other field must remain identical.
The exact bootstrap run, artifact and foundation policy reference is sealed into
both phase 2 provenance documents.

## Protected workflow

`.github/workflows/native-package-signing.yml` is manual-only and frozen to
v4.10.0. It has read-only repository and Actions permissions and uses the
`syswarden-native-package-signing-v4100` environment. Configure that environment
with required reviewers and prevent administrator bypass before adding any
secret. The workflow accepts only the repository owner's first attempt at the
exact current `main` SHA and requires the literal
`SIGN-NATIVE-PACKAGES-NO-PUBLISH` authorization. Its required
`qualification_mode` input accepts only `bootstrap-qualification` or
`qualified-policy`. Both modes are non-publishing.

The environment must provide:

| Name | Kind | Contract |
| --- | --- | --- |
| `SYSWARDEN_RPM_SIGNING_PRIVATE_KEY` | secret | Armored OpenPGP private key whose primary fingerprint exactly matches the selected committed RPM key |
| `SYSWARDEN_RPM_SIGNING_PASSPHRASE` | secret | Non-empty passphrase used through GnuPG loopback mode without command-line disclosure |
| `SYSWARDEN_APK_SIGNING_PRIVATE_KEY` | secret | Passphrase-encrypted RSA private key whose canonical OpenSSL public output is byte-identical to the selected committed APK public key |
| `SYSWARDEN_APK_SIGNING_PASSPHRASE` | secret | Non-empty passphrase used only to derive an ephemeral private key inside the private workspace |
| `SYSWARDEN_DEB_SIGNING_PRIVATE_KEY` | secret | Armored OpenPGP private key whose primary fingerprint exactly matches the selected committed DEB key |
| `SYSWARDEN_DEB_SIGNING_PASSPHRASE` | secret | Non-empty passphrase used through GnuPG loopback mode without command-line disclosure |
| `SYSWARDEN_APK_SIGNER_IMAGE` | variable | Reviewed OCI image reference pinned as `registry/path@sha256:<64 lowercase hexadecimal characters>`, exactly matching `apk.signer_image` in the committed policy and containing `abuild-sign`, `apk`, `openssl` and `tar` |

The signer image runs with no network, a read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, bounded memory, CPU and PIDs, and
only the exact work file or key mounts it needs. RPM and DEB tooling is
installed and checked before any signing secret enters a step environment. The
workflow verifies the required commands and retains the native verification
outputs in the sealed evidence. This runner package installation is not an
immutable RPM or DEB toolchain contract; a production decision that requires
such a contract must pin and qualify it before keys are activated. APK image
pulling also finishes before secrets enter a step environment, and signing and
verification invocations use `--pull never`.

Each secret-bearing operation is family scoped. The RPM step receives only the
RPM private key and passphrase, the DEB step receives only the DEB private key
and passphrase, and the APK step receives only the APK private key and
passphrase. Each step creates its own mode `0700` directory, installs an exit
cleanup before materializing secrets, stops its private GnuPG agent when
applicable, removes the family directory on success or failure, and proves its
absence. A separate gate requires the complete private workspace to be empty
before artifact assembly. No step receives all six signing secrets.

The workflow resolves exactly one successful attempt-1 `package.yml` push run
for the selected `main` SHA. It also requires the requested artifact ID, name,
size and GitHub SHA-256 artifact digest to agree, downloads by artifact ID, and
revalidates the original four-file package inventory before signing.

RPM signing changes only the signature header. The workflow proves that both
the RPM immutable-header SHA-256 and the `rpm2cpio` payload SHA-256 remain exact
before and after `rpmsign`, then verifies the result against a private temporary
RPM database containing only the selected public key. The native verdict must
identify an RSA/SHA256 signature made by one currently valid signing-capable
RSA primary key or subkey between 3072 and 8192 bits in that committed
certificate. APK signing isolates the exact first `control.tar.gz` gzip member
from the unsigned APK v2 byte stream and applies `abuild-sign -t RSA256` to that
member with the source commit timestamp. The assembler requires the signed
control stream to preserve the original control bytes exactly, then emits one
canonical, singular and bounded gzip archive containing only the expected
RSA256 signature followed by the complete unsigned APK byte stream. A second
offline container invocation runs native `apk verify` with a directory
containing only the selected public key. DEB signing writes one detached
ASCII-armored `.asc` signature and leaves the package bytes unchanged. The
offline gate accepts only one RSA/SHA256 signature, checks its complete primary
and signing-key identities against the selected certificate, and requires its
creation date to equal the qualification date.

## Immutable output contract

The unique artifact name includes the release, signing run ID, attempt and
release SHA. The immutable Phase 1 workflow uses its historical canonical name,
`syswarden-native-signed-packages-<version>-<run>-1-<sha>`. Phase 2 uses the
distinct name
`syswarden-native-signed-packages-qualified-<version>-<run>-1-<sha>`.
Artifact upload uses the immutable artifact protocol and no compression
transformation. The workflow also requires the upload action to return a
positive artifact ID and canonical GitHub SHA-256 digest. Its exact layout is:

```text
packages/
  SHA256SUMS.txt
  syswarden-4.10.0-1.x86_64.rpm
  syswarden_4.10.0_amd64.deb
  syswarden_4.10.0_amd64.deb.asc
  syswarden_4.10.0_x86_64.apk
evidence/
  APK_NATIVE_VERIFICATION.json
  DEB_NATIVE_VERIFICATION.json
  NATIVE_SIGNING_PROVENANCE.json
  RPM_NATIVE_VERIFICATION.json
  RPM_PAYLOAD_PROOF.json
  UNSIGNED_SHA256SUMS.txt
SIGNED_ARTIFACT_SHA256SUMS.txt
```

`native_package_signing_bundle.py verify` is qualified-only by default and
recomputes the complete file seal, signed package manifest, source artifact
binding, package transformations, selected-key evidence, bootstrap reference
and release SHA. Phase 1 verification requires the explicit `--mode bootstrap`
argument. Phase 1 uses provenance status
`native-signatures-bootstrap-verified-not-release-qualified`; phase 2 uses
`native-signatures-verified-not-release-qualified`. Both set
`release_qualified` and `public_release` to false. A signed artifact is not a
release qualification and is never evidence of publication. Release consumers
reject the bootstrap status.

## DEB GitHub Release decision

SysWarden publishes individual DEB files as GitHub Release assets and does not
currently publish an APT repository hierarchy. A real clear-signed `InRelease`
file authenticates repository metadata and its `Packages` indexes. Creating one
without that hierarchy would simulate repository semantics that do not exist.
ADR-002 therefore selects a detached OpenPGP signature for the existing asset
channel instead of a disconnected `InRelease` lane.

The signature is named after the exact DEB plus `.asc`. Before isolated `gpgv`
verification, the gate binds the DEB filename, bytes, size and SHA-256 to the
v4.10.0 inventory, checks the selected public-key bytes and full fingerprint,
and validates policy dates and revocation state. It accepts one bounded ASCII
armor block and exactly one positive `GOODSIG` and `VALIDSIG` identity. The
actual signing key and primary key must belong to the one committed certificate,
use 3072 to 8192-bit RSA, use SHA-256 and be valid on the qualification date.
The bundle includes the unchanged DEB, its detached signature and the complete
verification evidence.

A future real APT repository remains a separate design. It must qualify the
complete repository hierarchy, authenticated `Packages` indexes, `Release` and
`InRelease` metadata, expiry, freshness and rollback controls. This foundation
does not claim those semantics.

## Public key distribution and pinning

Only public keys belong under `scripts/ci/native-package-keys/`. Each accepted
key is pinned three ways: a stable policy ID, the complete public-key file
SHA-256, and its native identity. RPM and DEB keys use the full 40-digit
primary OpenPGP fingerprint. APK keys use the SHA-256 of the canonical RSA
public-key bytes, which must equal the policy fingerprint. The gate rejects
symbolic distribution directories, non-regular files, hard links, unsafe
paths, duplicate IDs, duplicate fingerprints and duplicate public-key bytes.
It also rejects a key ID or public-key digest reused by another package family
and an RPM fingerprint reused by DEB.
All native lanes require signing-capable RSA public keys between 3072 and 8192
bits so a weak or incompatible key cannot become qualified through policy
metadata alone.

The source tree is the canonical distribution point for qualification. Any
mirror or operator documentation must publish the same complete fingerprints
and file digests through an independently authenticated channel. Consumers
must compare those complete values before importing a key. Filenames, short
key IDs and account identities are informative only and are never sufficient
trust anchors.

The private keys never enter Git, package artifacts or provenance. They are
passphrase protected environment secrets and become available only after the
protected environment approval. The signing step rejects a private key that can
sign or decrypt with an empty passphrase before using the protected passphrase.
The APK signer image is separately pinned by its immutable OCI SHA-256 digest
in the committed policy. The protected environment variable must match that
reviewed value exactly. Changing a public key, private secret, image digest or
policy approval requires its own review and a new qualification run.

## Rotation, revocation and recovery

Planned rotation follows this order:

1. Generate and protect the replacement private key outside the repository.
2. Commit only its reviewed public key and complete policy record with a new
   globally unique ID, fingerprint, public-key SHA-256, validity interval and
   `supersedes` lineage.
3. Keep the predecessor and replacement valid and non-revoked during one
   explicitly bounded overlap.
4. Select one exact family-specific key ID for every protected signing run.
   Seal that ID, public-key path, complete fingerprint, public-key SHA-256 and
   validity interval into verification evidence and provenance.
5. Make downstream release consumers derive the selected identity from that
   provenance. They must not infer it by requiring exactly one non-revoked
   policy record.
6. Rotate only the selected family's protected private-key and passphrase
   secrets, then run wrong-key and positive native verification for the
   replacement.
7. Stop selecting the predecessor for new signatures after the overlap. Keep
   its immutable record for historical audit. Use `revoked: true` for
   compromise, not ordinary planned retirement.

For suspected compromise, stop signing and publishing first. Mark the affected
key `revoked: true` through an emergency reviewed policy change, disable or
remove its protected secret, preserve the last known good artifacts and audit
records, rotate to a new key, and requalify from an independently verified
source commit. A revoked private key is never recovered or reused. If protected
secrets are lost without evidence of compromise, restore only from the
authorized offline custody process, compare the derived public identity with
the committed policy, and require the normal environment approval. If that
identity cannot be proven exactly, rotate instead of restoring.

Past signed artifacts remain historical evidence, but current qualification
always evaluates the selected key against the current policy and date. A policy
rollback, deleted revocation, shortened lineage or substitution of an older
package is a new unqualified state and must not resume publishing.

## Negative assurance matrix

| Case | RPM | APK | DEB detached signature |
| --- | --- | --- | --- |
| Unsigned input or output | Input signature tags must be empty before signing; output requires a positive isolated RSA/SHA256 `rpmkeys` signature verdict bound to the actual strong signing key | Output requires isolated native `apk verify` and an exact singular RSA256 prefix | Missing, empty, multiple or invalid detached signatures fail closed |
| Wrong key | Full primary OpenPGP fingerprint and committed key bytes must match | Derived private-key public bytes, committed key bytes and isolated verifier key must match | Isolated `gpgv`, full primary fingerprint, signing fingerprint and committed key bytes must match |
| Substituted bytes | Inventory size and SHA-256, signed digest, immutable header and payload proof are bound | Inventory size and SHA-256 plus the complete unsigned suffix are bound | Inventory filename, size and SHA-256 bind the exact unchanged DEB before signature verification |
| Revoked, expired or not-yet-valid key | Policy date and native OpenPGP status fail closed | Policy date and revocation state fail closed | Policy date, revocation state, native key records and signature date fail closed |
| Rollback to an older package or release | Exact v4.10.0 filename, release inventory and SHA reject it | Exact v4.10.0 filename, release inventory and SHA reject it | Exact v4.10.0 filename, release inventory and SHA reject it |
| Tampered evidence or bundle | Canonical evidence and complete artifact seal reject it | Canonical evidence and complete artifact seal reject it | Signature bytes, verification evidence and complete artifact seal reject it |

Static and adversarial unit tests cover the fail-closed controls available in
this foundation. Real cryptographic fixtures and supported-host lifecycle labs
remain mandatory before policy status or publishing approval can change.

## Consumer contract

Qualification must resolve exactly one successful `qualified-policy` protected
signing run for the release SHA, require the unique artifact ID and GitHub
digest, require the canonical `qualified` artifact name, download it by ID,
execute the default qualified-only `native_package_signing_bundle.py verify`,
and independently rerun `native_package_signature_gate.py` for RPM, APK and
DEB with purpose `qualification`. It requires provenance status
`native-signatures-verified-not-release-qualified` and rejects bootstrap
provenance. The selected RPM, APK and DEB identities are read from that
provenance and revalidated against the committed policy. Native lifecycle labs
then consume only the exact `packages/` directory from the sealed phase 2
artifact.

A publisher may consume the exact signed bytes sealed into the qualification
artifact only after the committed policy
sets `publishing` to true through review, the public keys remain valid and
non-revoked, all three native gates succeed with purpose `publishing`, and the
DEB detached-signature lane is qualified. The release manager revalidates the
sealed qualification inventory and byte-compares its RPM, APK, DEB and detached
DEB signature before staging the public assets. With the current policy state,
qualification fails before those assets can reach the publisher.

Before qualification, the release owner must review the enrolled fingerprints,
validity intervals and empty initial rotation lineage, confirm the protected
secrets, and execute the non-publishing bootstrap. Real-host lanes must then
prove RPM
verification on RHEL 9 and RHEL 10, APK verification on supported Alpine
versions, DEB verification on supported Debian and Ubuntu versions, negative
verdicts after package and signature tampering, key expiry and revocation
handling, rotation overlap and retirement, upgrades and rollbacks, and
preservation of the existing signed update-manifest checks.
