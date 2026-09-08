# NODE01 Native Migration Qualification for v4.10.0

Status: procedure and fail-closed evidence contract implemented. Native execution is pending. This document does not claim that v4.10.0 is qualified or published.

## Purpose

This procedure qualifies the historical Debian 13 NODE01 installation across the complete supported trust path:

1. installed v4.02.8 baseline;
2. separately downloaded and checksum-verified manual first hop to v4.03.2;
3. signed `syswarden update` hop from v4.03.2 to the current stable v4.04.3 release;
4. exact v4.10.0 candidate installation through the offline qualification update channel after signed-manifest, digest, and detached OpenPGP verification;
5. operational, rollback, provider snapshot recovery, re-upgrade, and purge checks.

The v4.02.8 binary predates the signed updater protocol. Never label its first hop as a signed updater operation and never use an unsigned fallback. The first hop must follow the existing v4.02.8 to v4.03.2 manual migration procedure and must bind the downloaded DEB to the published release checksum.

## Fixed identity

The reviewed contract is [`node01_migration_contract_v4.10.0.json`](../../scripts/ci/node01_migration_contract_v4.10.0.json). It pins:

| Property | Required value |
| --- | --- |
| Repository | `duggytuxy/syswarden` |
| Host | `node01` |
| Operating system | Debian 13 |
| Architecture | AMD64 |
| Package family | DEB |
| Baseline | v4.02.8 at `371d353e871fedb410b08f0618a1ae6aa2f7fedc` |
| Trust bootstrap | v4.03.2 at `2eae757bbdee510fdd1058ba7770f2c5564ecb23` |
| Current stable | v4.04.3 at `381c1f8d91459a9b20605629c725900abd81dee8` |
| Candidate | v4.10.0 at the exact SHA supplied to the validator |

Verify the reviewed contract before collecting evidence:

```bash
python3 scripts/ci/node01_migration_evidence.py contract-digest
```

The expected digest is `c5a4ad44c0d5f8a5e1d13fdbea4cdd89e235941ab10f837160fb97d3624f459e`.

## Safety prerequisites

Before changing NODE01:

1. Obtain explicit approval for the native lab window.
2. Confirm console recovery access independently from SSH.
3. Pin and record the existing ED25519 SSH host-key fingerprint. Do not use `accept-new`.
4. Confirm the provider firewall still restricts SSH to the approved operator addresses.
5. Create a provider snapshot of the working v4.02.8 baseline and record its immutable provider reference.
6. Copy each raw capture to the trusted operator workstation immediately. A later snapshot restore erases files kept only on NODE01.
7. Keep the v4.03.2, v4.04.3, and candidate packages and verification metadata on the operator workstation. Do not depend on mutable latest-release resolution during rollback.
8. Prepare the candidate qualification bundle as a real directory owned by the invoking user with mode `0700`. Its manifest, signature, and selected package must each be a one-link regular file owned by that user with mode `0600`. Symbolic links and special files are forbidden.
9. Do not weaken host firewall, SSH, service, or signature controls to make a check pass.

The lab must stop on a changed SSH host key, failed package-manager state, missing signature, digest mismatch, service failure, unexpected firewall mutation, or missing raw capture.

## Evidence workspace

Create a private directory on the operator workstation, outside the repository:

```text
node01-v4100-migration/
  observations.json
  artifacts/
    raw/
      host-attestation.json
      checkpoint-1.json
      checkpoint-2.json
      checkpoint-3.json
      checkpoint-4.json
      checkpoint-5.json
      checkpoint-6.json
      checkpoint-7.json
      checkpoint-8.json
      checkpoint-9.json
      checkpoint-10.json
      scenario-1.json
      scenario-2.json
      scenario-3.json
      scenario-4.json
      scenario-5.json
      scenario-6.json
      scenario-7.json
      scenario-8.json
      scenario-9.json
      scenario-10.json
      scenario-11.json
      campaign-attestation.json
```

The `raw` directory must contain exactly the referenced 23 regular files. Symbolic links, hard links, missing files, extra files, changed files, duplicate references, and files larger than 1 MiB fail validation.

Every raw JSON file must preserve the native command, UTC capture time, exit status, relevant stdout and stderr, NODE01 identity, current boot-id digest, installed package record, and candidate SHA when applicable. Do not write fabricated authentication journal entries. HIDS and HIPS observations must originate from controlled real network activity, and WAAP observations must originate from a controlled real HTTP request.

## Canonical checkpoint data

Capture the ten checkpoints in contract order:

| Sequence | Checkpoint | Installed state |
| --- | --- | --- |
| 1 | `baseline-v4028` | v4.02.8 |
| 2 | `bootstrap-v4032-initial` | v4.03.2 after the verified manual first hop |
| 3 | `stable-v4043-initial` | v4.04.3 after signed update |
| 4 | `candidate-v4100-initial` | exact v4.10.0 candidate after the offline qualification update channel |
| 5 | `stable-v4043-rollback` | v4.04.3 after verified rollback |
| 6 | `baseline-v4028-snapshot` | v4.02.8 after provider snapshot restore and a new boot |
| 7 | `bootstrap-v4032-reupgrade` | v4.03.2 after repeating the verified manual first hop |
| 8 | `stable-v4043-reupgrade` | v4.04.3 after repeating signed update |
| 9 | `candidate-v4100-reupgrade` | exact v4.10.0 candidate after repeating the offline qualification update channel |
| 10 | `purged` | package, services, processes, dedicated firewall objects, configuration, state, and logs absent |

For every installed checkpoint, record:

- the exact installed version, source commit, and DEB SHA-256;
- a SHA-256 of `/proc/sys/kernel/random/boot_id`, without storing the raw boot ID;
- the active state of `syswarden-firewall.service` and `syswarden-core.service`;
- package-manager health;
- the exact SysWarden-owned nftables policy digest;
- the complete persistent-state inventory digest;
- a canonical configuration semantic digest;
- a canonical operator-state canary digest.

The configuration semantic digest must be calculated from a sorted, normalized export of operator-controlled settings after excluding comments, layout, generated timestamps, and secrets. The export must include the effective ASN, GEO, HIDS, HIPS, WAAP, HA, firewall, allow-list, and block-list settings. The operator-state canary must be seeded before the first transition and cover controlled entries whose preservation can be checked safely. Its canonical content and digest must remain identical at every installed checkpoint.

The complete persistent-state inventory may change because real security events are observed. Preserve the inventory and its digest for review, but do not substitute it for the invariant operator-state canary.

## Native sequence

### 1. Baseline

Attest Debian 13, AMD64, the pinned SSH host key, v4.02.8 package ownership, both active services, the SysWarden firewall objects, package-manager health, configuration semantics, and the seeded state canary. Capture `syswarden audit` output, noting that the command is an operational diagnostic and not a compliance certification.

### 2. Manual trust bootstrap to v4.03.2

Follow the historical migration procedure. Download the v4.03.2 DEB and published checksum file separately over HTTPS. Verify the checksum file through its documented release trust path, verify the DEB SHA-256 against that file, and only then install it with the native package manager. Capture all commands and exit codes. Do not run the v4.02.8 updater for this hop.

### 3. Signed update to v4.04.3

Run `syswarden update` from v4.03.2 while the public latest stable release is deliberately resolved and recorded as v4.04.3 for the controlled campaign. Capture the canonical update manifest, its Ed25519 signature, pinned signer key ID and public-key digest, selected DEB digest, and the updater output proving signature verification occurred before installation.

### 4. Verified installation of the exact v4.10.0 candidate

The v4.04.3 production updater resolves only GitHub's public latest stable release. It has no supported candidate endpoint and does not recognize qualification flags. Do not redirect DNS, replace certificates, or claim that the installed v4.04.3 updater installed a non-public candidate.

For pre-publication qualification, use the exact protected artifact emitted by
`candidate-update-bundle.yml` for the untagged `main` candidate after the
qualified native-signing phase. Before copying anything to NODE01, verify the
artifact inventory and checksums, the descriptor, its GitHub producer
attestation, the updater-manifest signature and the detached DEB signature.
Use only the artifact's exact `node01/` directory as the qualification bundle.
Only after this external verification, extract the candidate CLI from that
same verified candidate DEB, attest its digest and its source package digest,
and run exactly:

```text
syswarden update --qualification-bundle /absolute/path --candidate-version v4.10.0
```

Both flags are mandatory together. The command accepts no positional argument, performs zero network requests, makes no latest-release discovery, and has no fallback. It reopens and reattests the bundle, verifies the embedded-trust-root Ed25519 manifest signature and selected package digest, then installs and activates that same package. Capture:

- the canonical update manifest and detached Ed25519 signature;
- the pinned update signer key ID and public-key SHA-256;
- the selected candidate DEB SHA-256 and its manifest match;
- the candidate detached OpenPGP DEB signature;
- the exact selected DEB key ID, complete primary OpenPGP fingerprint,
  public-key SHA-256 and RSA with SHA-256 verification result from
  `qualified-policy` native-signing provenance;
- the candidate CLI digest and proof that it was extracted from the same verified package digest;
- the canonical bundle descriptor identity and SHA-256;
- the producer attestation that binds the protected producer candidate SHA to
  the descriptor, which in turn binds the updater manifest, its signature and
  the candidate package;
- the candidate CLI digest derived separately from that authenticated DEB and
  bound to its exact package digest;
- the updater stdout proving offline mode, current and candidate versions, selected DEB, verified manifest signature, verified package SHA-256, installation, and activation;
- counters proving that no configuration load and no firewall recovery hook ran before bundle validation;
- operator-state and firewall-state digests immediately before validation and at the installation boundary, each equal to the corresponding attested v4.04.3 source-checkpoint digest;
- proof that installation started only after complete bundle validation and only through the paired qualification flags;
- the installed package record and exact v4.10.0 candidate commit.

The update manifest v1 binds the version, asset identity, size, and package SHA-256. It does not contain a commit SHA. The protected producer candidate SHA must therefore be bound separately to the canonical qualification-bundle descriptor and its manifest digest. The evidence must not credit the v1 manifest with that commit binding.

No candidate package may be installed before all external and offline-channel checks pass. This proves the candidate package and candidate channel, not execution of the published v4.04.3 updater binary. A real `syswarden update` acceptance test from v4.04.3 to v4.10.0 remains a separate mandatory post-publication check after v4.10.0 becomes GitHub's public latest stable release.

### 5. Preservation and capabilities

Compare the canonical configuration and canary digests to the baseline. Review the full persistent-state inventory, ownership, modes, migration backup, and effective operator values.

On the native host, verify:

- both services remain active and the exact SysWarden nftables policy is effective;
- HIDS detects an event from the real Debian authentication log path;
- HIPS blocks a controlled real network attack at its configured jail threshold;
- WAAP classifies a controlled real HTTP request using the installed signature catalog;
- ASN and GEO enrichment match the attested provider result;
- `syswarden audit` returns a clean operational result.

Use reserved documentation or operator-controlled addresses where possible. Never attack an unrelated host or public service.

### 6. Verified rollback to v4.04.3

The updater is forward-only and resolves the latest release. Do not claim that `syswarden update` performs this rollback. Use the separately retained v4.04.3 package after re-verifying its canonical Ed25519 manifest, manifest signature, and DEB digest. Follow the supported native package rollback procedure. Recheck configuration, the state canary, services, firewall, and package-manager health.

### 7. Provider snapshot recovery

Use the provider console to restore the recorded v4.02.8 snapshot. After boot, re-pin and verify the expected SSH host key according to the approved snapshot identity. Require a new boot-id digest. Recheck the exact baseline package, configuration, state canary, services, firewall, and package-manager health.

### 8. Complete re-upgrade

Repeat the verified manual v4.02.8 to v4.03.2 first hop. Then repeat the signed updater hop to v4.04.3 and the offline candidate qualification channel. Capture both intermediate checkpoints. Re-verify all signatures and package digests. The candidate DEB and extracted candidate CLI must again be bound to the same producer-attested bundle before execution.

### 9. Clean uninstall and purge

Use the supported uninstall and Debian purge procedures. Capture proof that the package, both units, all SysWarden processes, dedicated nftables objects, `/opt/syswarden`, dedicated configuration, state, and logs are absent. Confirm that unrelated host firewall rules and services remain unchanged and that `dpkg` reports a healthy state.

## Observation and signature envelope

`observations.json` uses schema `syswarden-node01-migration-observations/v1`. It contains exactly these top-level members:

```json
{
  "schema": "syswarden-node01-migration-observations/v1",
  "campaign": {},
  "host": {},
  "checkpoints": [],
  "scenarios": [],
  "attestation": {}
}
```

Populate each object with the exact fields and check names declared by the contract and enforced by `node01_migration_evidence.py`. Do not add caller-supplied raw-file digests. The assembler calculates those digests itself.

Each signed manifest observation records the release tag, separately attested producer commit, a false `manifest_contains_producer_commit` value, manifest and signature SHA-256 values, selected package SHA-256, `Ed25519`, the exact `syswarden-update-2026-01` trust-root identity and public-key SHA-256, and successful pre-install verification flags. It also records the installation channel, normalized invocation, updater executable and source-package binding, network-request count, fallback state, operation-output digest, and installed-package-record digest.

v4.10.0 observations additionally record the detached DEB signature SHA-256,
`OpenPGP-RSA-SHA256`, the uppercase 40-hex fingerprint selected by normal
native-signing provenance, the offline bundle identity, canonical descriptor
digest, producer-attestation digest, and successful detached-signature result.
Bootstrap provenance is not accepted. During a rotation overlap, the
fingerprint comes from the exact DEB identity sealed in the phase 2 bundle,
not from implicit policy selection. v4.04.3 uses `not-applicable` for detached
DEB and qualification-bundle fields because that historical release did not
publish them.

The final campaign attestation must be a verified GitHub artifact attestation, Sigstore bundle, or operator-signed in-toto statement over the native observation bundle. Its raw verification record must bind the exact candidate SHA and must be independently accepted by the release-owner gate. A plain JSON self-assertion is not accepted.

For the official v4.10.0 release chain, the resulting NODE01 evidence is also
sealed into `NATIVE_RELEASE_EVIDENCE_MANIFEST.json`. The protected workflow
attests that manifest with the commit-pinned GitHub build-provenance action,
and release qualification verifies it for the exact repository before
accepting the migration verdict.

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
