# NODE01 Native Migration Qualification for v4.10.0

Status: owner-approved revision 2 of the procedure and evidence contract.
Fresh native execution on the exact candidate remains mandatory. This document
neither claims successful migration nor authorizes publication.

## Revised trust path

The native historical v4.02.8 to v4.03.2 attempt failed with the preserved GEO
selection: the immutable v4.03.2 downloader rejects country prefixes broader
than its IPv4 /24 and IPv6 /64 limits. A separate candidate rehearsal exposed
the same generic limits on inherited ASN files. Both failures remain recorded;
they cannot be relabeled as successful historical updater hops.

The owner approved a revised route on September 10, 2026:

1. Attest the prepared v4.02.8 installation and the exact approved ASN pair.
2. Independently verify the protected candidate bundle and detached native DEB
   signature, then install that exact DEB with the native package manager.
3. Verify configuration, state, actual capabilities and a real reboot.
4. Restore the verified prepared v4.02.8 snapshot, reapply only the exact
   separately reviewed ASN pin, and repeat the direct signed installation.
5. Purge the candidate, establish an independent v4.04.3 baseline on NODE01,
   then qualify the separate offline candidate updater, its preserved state,
   a real reboot and another purge.
6. Restore the original pre-lab v4.02.8 snapshot and its provider attachment.

The v4.02.8 updater predates signed update metadata and must never be used or
credited with a signed operation. The two direct installations use the native
package manager after independent verification. The separate pre-tag updater
case uses the candidate CLI extracted and attested from the signed candidate
DEB. Actual public v4.04.3 to v4.10.0 updater acceptance remains a distinct,
mandatory check after publication. No other native release gate is removed.

## Fixed identity and approval

The byte-pinned contract is
[`node01_migration_contract_v4.10.0.json`](../../scripts/ci/node01_migration_contract_v4.10.0.json).
Its identity is `syswarden-node01-native-migration/v2`; its SHA-256 is
`64d3b14484659ce9e79b3461a7bcca4359dcf9145417e52b9cfa2f81737372f4`.
It supersedes contract digest
`c5a4ad44c0d5f8a5e1d13fdbea4cdd89e235941ab10f837160fb97d3624f459e`.
Version 1 observations and the failed historical route are not accepted.

| Property | Required value |
| --- | --- |
| Repository | `duggytuxy/syswarden` |
| Host | `node01`, Debian 13, AMD64, DEB, systemd |
| Historical baseline | v4.02.8 at `371d353e871fedb410b08f0618a1ae6aa2f7fedc` |
| Independent stable baseline | v4.04.3 at `381c1f8d91459a9b20605629c725900abd81dee8` |
| Candidate | v4.10.0 at the exact SHA supplied to the validator |

The contract binds the owner-approved revision proposal and exact SHA-256
values for both existing `allowed_AS16276` files and their purpose-bound pin.
Follow [explicit ASN approval](OPERATOR_PINNED_ASN_POLICY.md). This approval
preserves the reviewed address union and does not authorize a future refresh.
The installer must never generate a pin automatically or suppress validation.

## Safety prerequisites

1. Use the already authorized native lab window and its spending limits.
2. Verify provider-console recovery separately from SSH. Record the original
   and prepared snapshots independently; preserve the original snapshot.
3. Independently verify and pin both the original SSH host key and the key of
   the prepared recovery image. Every checkpoint must use one of those keys;
   final original restoration must recover the original key. Never accept a
   changed network-observed key without independent verification.
4. Preserve operator SSH and the provider firewall. Export private raw captures
   to the operator workstation before every reboot, purge or restoration.
5. Record the original pre-lab configuration semantics and state canary before
   preparing the migration baseline. These values govern the final restoration.
6. Keep exact v4.04.3 and candidate packages, signed metadata and verification
   records locally. Do not depend on mutable latest-release resolution.
7. Prepare the producer-attested candidate bundle as a root-owned real directory
   with mode 0700. Its seven files must each be root-owned, mode 0600, regular,
   one-link files. Verify the producer, descriptor, manifest, Ed25519 signature,
   package size and SHA-256, and detached OpenPGP signature before installation.
8. Stop on unknown identity, missing proof, unsafe file, unhealthy package
   database, service failure or unexpected configuration or firewall change.

## Ordered checkpoints and preservation groups

| Sequence | Checkpoint | State |
| --- | --- | --- |
| 1 | `baseline-v4028` | Prepared historical state and exact approved ASN pin |
| 2 | `candidate-v4100-initial` | First direct signed native installation |
| 3 | `candidate-v4100-reboot` | Candidate after an actual reboot |
| 4 | `baseline-v4028-snapshot` | Prepared snapshot restored and reviewed pin reapplied |
| 5 | `candidate-v4100-reupgrade` | Repeated direct signed native installation |
| 6 | `purged` | Candidate and dedicated artifacts absent |
| 7 | `stable-v4043-independent` | Separately verified native stable installation |
| 8 | `candidate-v4100-updater` | Separate offline candidate updater completed |
| 9 | `candidate-v4100-updater-reboot` | Updated candidate after an actual reboot |
| 10 | `purged-updater` | Second complete purge |
| 11 | `original-v4028-restored` | Exact original pre-lab state recovered |

Every installed checkpoint binds native host and boot identity, package version,
source commit and digest, package-manager health, both services, configuration
semantics, operator canary, full persistent inventory, actual firewall digest,
and the approved ASN pin or its required absence.

Checkpoints 1 through 5 must preserve the same normalized operator-controlled
settings and state canary, including ASN, GEO, HIDS, HIPS, WAAP, HA and firewall
settings. Exclude secrets, comments, layout and generated timestamps. Compare
actual configuration values; a byte change from formatting is not a semantic
change. Inspect ownership, modes and the complete persistent-state inventory
separately. Confirm the exact approved ASN address union without additions or
removals. Each preserved legacy checkpoint must retain the exact approved pin.

Checkpoints 7 through 9 have their own stable-baseline configuration and canary.
They must remain unchanged within that independent updater case. They must not
be credited as successful preservation of the historical v4.02.8 configuration.
Checkpoint 11 must match the separately captured original pre-lab values and
configuration-file metadata. Both purge checkpoints require exact absence.

## Native operations and trust proofs

For each direct installation, independently verify the same protected bundle
used by the separate updater case. Bind its actual descriptor and producer
attestation to the exact candidate SHA; update manifest v1 has no commit field.
Verify the manifest Ed25519 signature, exact DEB identity, size and digest,
and the detached native signature using the externally qualified key policy.
Capture all verifier commands, exit codes and original outputs before invoking
the native package manager. The normalized installation channel is
`manual-signed-native-deb`, with invocation
`native-deb-install-after-independent-bundle-and-signature-verification`.
Record updater executable fields as `not-applicable` and attested as false.
The normalization label does not replace the actual native command transcript.

For the independent v4.04.3 baseline, verify its published manifest signature,
release/source binding and exact DEB digest before native installation. Use
channel `verified-native-baseline` and normalized invocation
`native-deb-install-after-manifest-verification`. Do not invent a detached
OpenPGP signature for that historical DEB or claim that an old updater ran.
Seed and capture this baseline's own configuration and state canary.

For the separate candidate updater, extract the CLI from the same signed
candidate DEB and attest it before execution. Use exactly:

```bash
syswarden update --qualification-bundle /absolute/path --candidate-version v4.10.0
```

Both flags are required together. The protected descriptor binds the selected
candidate outside update manifest v1. Prevalidation must load no configuration,
run no firewall recovery, make no network request and use no fallback. Preserve
operator and firewall state until installation starts after complete validation.
The updater executable must be bound to the signed candidate package. The
normalized channel is `offline-qualification-bundle`.

All three candidate operations bind the same exact signed package and protected
bundle. Record both prevalidation state digests and compare them to the actual
source checkpoint. Native command success alone is insufficient: independently
verify package-manager health, installed identity, services and firewall state.

The first candidate must also demonstrate real HIDS detection, a controlled
HIPS block, real WAAP classification, exact attested ASN/GEO enrichment and a
clean native audit. Preserve original event evidence; do not fabricate logs.
Verify the required real reboots and snapshot recovery with distinct boot IDs.
After each purge, confirm absent packages, services, processes and dedicated
firewall objects, configuration, state and logs; preserve unrelated host policy.

## Evidence and signature envelope

Use `syswarden-node01-migration-observations/v2` with exactly `schema`,
`campaign`, `host`, `checkpoints`, `scenarios` and `attestation`. The contract
requires 11 checkpoints and 15 scenarios. The raw directory contains exactly
28 distinct referenced regular JSON files: host attestation, 11 checkpoints,
15 scenarios and campaign attestation. Each raw file is bounded to 1 MiB.
Symlinks, hard links, missing or extra files, duplicate references and changed
bytes fail validation. Do not supply raw-file hashes; the assembler computes
and independently verifies them.

Every scenario must set `historical_bootstrap_claimed` to false. Record the
owner-approved proposal digest and both snapshot references in the campaign.
Record original configuration and canary digests before lab preparation.
Each checkpoint includes its independently pinned SSH key and exact ASN pin
SHA-256, or `absent` for the independent and purged states.

Candidate verification records include the protected source SHA, signed
manifest and signature digests, exact DEB name, size and digest, native detached
signature digest, qualified OpenPGP fingerprint, complete bundle identity and
producer-attestation digest. `manifest_contains_producer_commit` remains false.
The `qualification_prevalidation` record includes `exact_invocation_gate`, zero
configuration loads and recovery runs, unchanged operator/firewall digests and
confirmation that installation started only after bundle validation.

The final campaign requires a verified GitHub artifact attestation, Sigstore
bundle or operator-signed in-toto statement over the actual native observation
bundle. A plain JSON claim is insufficient. Protected native-evidence production
and release qualification independently revalidate all records and require
exactly two manual candidate operations and one separate candidate updater.

## Assemble and validate

From the repository root, with the exact candidate commit in `CANDIDATE_SHA`:

```bash
python3 scripts/ci/node01_migration_evidence.py assemble \
  --observations /secure/path/node01-v4100-migration/observations.json \
  --artifact-root /secure/path/node01-v4100-migration/artifacts \
  --candidate-sha "${CANDIDATE_SHA}" \
  --openpgp-fingerprint "${QUALIFIED_DEB_OPENPGP_FINGERPRINT}" \
  --candidate-package-name "${QUALIFIED_DEB_PACKAGE_NAME}" \
  --candidate-package-sha256 "${QUALIFIED_DEB_PACKAGE_SHA256}" \
  --candidate-package-size "${QUALIFIED_DEB_PACKAGE_SIZE}" \
  --release-tag v4.10.0 \
  --output /secure/path/node01-v4100-migration/evidence.json

python3 scripts/ci/node01_migration_evidence.py validate \
  --evidence /secure/path/node01-v4100-migration/evidence.json \
  --artifact-root /secure/path/node01-v4100-migration/artifacts \
  --candidate-sha "${CANDIDATE_SHA}" \
  --openpgp-fingerprint "${QUALIFIED_DEB_OPENPGP_FINGERPRINT}" \
  --candidate-package-name "${QUALIFIED_DEB_PACKAGE_NAME}" \
  --candidate-package-sha256 "${QUALIFIED_DEB_PACKAGE_SHA256}" \
  --candidate-package-size "${QUALIFIED_DEB_PACKAGE_SIZE}" \
  --release-tag v4.10.0 \
  --output /secure/path/node01-v4100-migration/verdict.json
```

The three candidate package values must come from the exact DEB record in
`.packages.signed` of the verified normal signing provenance. The validator
fails closed on an unreviewed contract, wrong candidate, wrong platform, false
or missing check, invalid transition, missing signature, mismatched package
bytes, changed configuration or canary, stale snapshot boot identity, unsafe
raw file, raw digest mismatch, incomplete inventory, non-native origin,
synthetic flag, unverified final attestation, or failed purge proof.

Only a `pass` verdict generated from the real native bundle may satisfy this qualification item. Unit-test fixtures exercise parser and policy behavior only. They are not native qualification evidence.
