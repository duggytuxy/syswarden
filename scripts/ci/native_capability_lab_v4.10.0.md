# SysWarden v4.10.0 native capability qualification

This laboratory qualifies HIDS, HIPS, WAAP, ASN, GEO, OSINT, TUI, and GRC behavior on real AMD64 hosts. It is a manual release-owner gate. GitHub Actions only tests the evidence harness and must never execute the native scenarios.

The HIDS claim in this contract is limited to native authentication log detection through the installed rsyslog imfile to UDS path. Generic file integrity monitoring is not a v4.10.0 capability claim. Its engine, baseline, change model, and qualification belong to the v5.00.0 scope.

## Frozen scope

Run one campaign for each profile, using the same candidate commit and candidate signature catalog:

| Profile | Native host | Platform | Package |
| --- | --- | --- | --- |
| `DEB-13` | `node01` | Debian 13 | DEB |
| `DEB-U2604` | `node02` | Ubuntu 26.04 | DEB |
| `RPM-A10` | `node03` | AlmaLinux 10.2 | RPM |
| `APK-324` | `node04` | Alpine 3.24 | APK |
| `RPM-A9-RHELPO` | `node05` | AlmaLinux 9.8 | package-owned RPM |
| `RPM-A10-RHELPO` | `node03` | AlmaLinux 10.2 | package-owned RPM |

The machine-readable contract is `scripts/ci/native_capability_contract_v4.10.0.json`. The validator pins its SHA-256 and rejects changes to its inventory, limits, order, or safety rules.

## Safety boundary

Use a clean provider snapshot and keep an independent recovery console available. Keep SSH access protected by an out-of-band provider firewall before starting.

The qualification harness is read-only with respect to the host. Native scenario actions are performed manually in the approved test window and must be limited to controlled fixtures. Restore the clean provider snapshot before setting `baseline_restored` to `true`.

The harness validates the schema, bounds, chronology, exact cross-field bindings, and bytes of referenced private evidence. It does not connect to a host and does not infer the meaning of an opaque raw capture. A pass is therefore a release-owner attestation bound to exact evidence digests, not an independently generated host verdict.

Authentication evidence must come from real controlled network attempts. Read the native authentication journal, but never use `logger`, `systemd-cat`, shell redirection, direct file writes, or another injection mechanism to fabricate authentication records. Raw logs remain private and must be redacted before any public summary.

Do not reuse background scanner activity. Record baseline counters immediately before every trigger and report exact deltas for the single controlled public source address.

## Host attestation

Capture the following JSON from the installed candidate before a campaign. Hash the boot identifier before placing it in the document. Do not store the raw boot identifier.

```json
{
  "schema_version": 1,
  "attestation_id": "standard-deb-u2604-boot-1",
  "captured_at": "2026-09-10T07:59:00Z",
  "host_id": "node02",
  "profile_id": "DEB-U2604",
  "os_id": "ubuntu",
  "os_version": "26.04",
  "architecture": "amd64",
  "package_family": "deb",
  "kernel_release": "6.17.0-generic",
  "boot_id_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
  "installed_version": "v4.10.0",
  "candidate_commit": "REPLACE_WITH_40_LOWERCASE_HEX",
  "package_binding": {
    "filename": "syswarden_4.10.0_amd64.deb",
    "package_family": "deb",
    "package_variant": "standard",
    "rpm_identity": null,
    "sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
    "signature": {
      "key": {
        "fingerprint": "REPLACE_WITH_40_UPPERCASE_HEX",
        "id": "REPLACE_WITH_APPROVED_KEY_ID",
        "public_key": "REPLACE_WITH_REPOSITORY_RELATIVE_PUBLIC_KEY",
        "public_key_sha256": "REPLACE_WITH_64_LOWERCASE_HEX"
      },
      "mechanism": "openpgp-detached"
    },
    "signed_bundle_seal_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
    "signed_subbundle_seal_sha256": null,
    "signing_provenance_profile": "syswarden-native-package-signing/v4.10.0",
    "signing_provenance_sha256": "REPLACE_WITH_64_LOWERCASE_HEX",
    "size": 12345678
  },
  "installed_signature_catalog_sha256": "REPLACE_WITH_64_LOWERCASE_HEX"
}
```

Hash the signature catalog installed by the candidate package. It must be byte-identical to the candidate catalog passed to the harness. The attestation, campaign, observations, evidence, verdict, and raw evidence directory must be stored outside the tested host before snapshot restoration.

Copy every `package_binding` value from the verified signing bundle. For a
package-owned profile, use the exact `1.rhelpo` filename, a non-null
`rpm_identity`, the `rpm-openpgp` mechanism, the approved RPM key and both the
root and RHEL sub-bundle seal digests. The validator rejects placeholders,
standard-RPM substitution and values inferred only from an installed filename.

## Prepare the campaign

Use absolute output paths. Existing outputs are never overwritten.

```bash
python3 scripts/ci/native_capability_evidence.py prepare \
  --candidate-commit "$CANDIDATE_COMMIT" \
  --campaign-id standard-deb-u2604-capability-1 \
  --created-at 2026-09-10T08:00:00Z \
  --host-attestation /private/evidence/node02/host-attestation.json \
  --signature-catalog src/core/syswarden-core/signatures.json \
  --signing-bundle /private/evidence/native-signing \
  --output /private/evidence/node02/campaign.json
```

The campaign binds the candidate commit, host attestation SHA-256, exact contract SHA-256, installed and candidate signature catalog SHA-256, catalog version, risk model, host identity, and platform profile.

## Exact native sequence

1. Record a clean baseline of telemetry, TUI, GRC, firewall state, active claims, and lifecycle counters.
2. Set the isolated lab SSH tracking threshold to four with a positive window. From the controlled public source, perform exactly four real failed SSH attempts inside that window. Confirm that the native authentication journal is read through the installed rsyslog imfile to UDS path, rule `ssh-auth` matches all four records, and no record is rejected. This is the HIDS detection proof. Do not write authentication records directly.
3. Confirm four admitted hits, four physical hits, four jail hits, four policy hits, threshold evidence, and a native ban decision for the same SSH sequence. This is the HIPS prevention proof. Record the first event, last event, enforcement, and active-state timestamps.
4. Delete the SSH ban through the supported SysWarden command. Capture `active`, `deleted`, then `tombstoned` runtime and projection states. Bind this lifecycle evidence to the HIPS scenario, source address, rule, and raw attack evidence digest.
5. Only after the SSH tombstone is observed, send one real SQL injection request from the same controlled public source to a supported test web service. The service must create its normal access record. Confirm rule `sqli`, one admitted hit, one physical hit, one policy hit, a native ban decision, and severity derived from the candidate catalog. Record the first event, last event, and enforcement timestamps.
6. After the WAAP enforcement timestamp, use the authenticated HA temporary-ban path to submit a 60-second ban with source `native-capability-lab`. Use a second public source address that you control and that is not local, whitelisted, protected as a peer, or already present in another claim. Capture the request and its digest, then capture `active`, `expired`, and `tombstoned` runtime and projection states. Do not describe this as expiry of the WAAP ban: native HIPS and WAAP decisions use the product's longer default ban lifetime.
7. Confirm that Top Attackers retains five physical hits for the source. Confirm that TUI and GRC expose the same hit count, selected jail, policy count, catalog identity, severity score, and severity label. Evidence quality must be `attested`, policy quality must be `attested`, hit quality must be `measured`, and degraded hits must be zero.
8. Confirm that ASN, uppercase country code, organization, and threat are returned by `ip.wiredalter.com` for the controlled source and are reproduced exactly in the TUI history.
9. Capture all private evidence files, calculate their SHA-256 values, and reference them with unique paths relative to one private artifact root.
10. Restore the clean provider snapshot, confirm SSH access and expected firewall state, then mark the campaign baseline as restored.

## Extended native controls

The same candidate-bound campaign must record the following controls in the
exact order frozen by `native_controls` in the machine-readable contract. Each
control requires its own real capture, SHA-256 binding, canonical observation
time and exact candidate commit. A unit-test result, copied fixture or narrative
statement is not native evidence.

1. Apply one bounded typed TCP rule and one bounded typed UDP rule, then compare
   the complete generated nftables rule bytes with the independently captured
   live ruleset.
2. Race one controlled CLI mutation with one controlled runtime mutation and
   prove serialization without a lost update.
3. Restart, roll back and reapply the candidate policy. Prove the expected
   SysWarden state returns and an independently inventoried third-party rule is
   byte-identical throughout.
4. Exercise authentication-log rotation, truncation, inode replacement and a
   delayed write. Record admitted events and duplicates for every boundary.
5. Separately present a symlink, special file, wrong-owner file and wrong-mode
   file as the configured HIDS source. Each case must fail closed before any
   event is accepted.
6. Generate BF SSH and BF SLOW through real controlled network attempts. Bind
   admitted hits and the selected jail to the corresponding raw records.
7. Generate the SQL injection scenario and bind its exploit category, action,
   score and label to the exact installed `signatures.json` digest.
8. Exercise duplicate WAAP input, bounded queue saturation and an integration
   delivery failure. Prove physical-hit accounting, degraded evidence and that
   the failure creates no recursive alert.

The evidence validator rejects missing, reordered, duplicated or unknown
controls, non-canonical timestamps, repeated evidence references, mismatched
digests, altered assertion keys and any control bound to another candidate SHA.

Each package-owned campaign also proves three ordered controls: staging inside
an offline `mock` or chroot without an active systemd instance, ownership of
configuration, firewall integration and systemd assets by the RPM, and service
activation on the first real boot. These controls are additional to the common
capability sequence and cannot reuse evidence from a standard RPM campaign.

Every lifecycle state must be linked to the runtime snapshot. Only `active` may be currently blocked or visible in the current TUI registry. Historical TUI evidence must remain visible for `deleted`, `expired`, and `tombstoned` states.

## Observation document

The exact observation schema is exercised by `NativeCapabilityEvidenceTests.observation_document` in `scripts/ci/native_capability_evidence_test.py`. Use that executable fixture as the structural reference, but replace every value with native observations and every digest with the digest of its private raw evidence file.

Each attack observation records first-event, last-event, and enforcement timestamps. The HIDS timestamps, source address, rule, and counters must match the HIPS authentication sequence exactly. The deletion lifecycle binds its capability, scenario, source address, rule, and attack evidence digest. The expiry lifecycle binds a distinct controlled public source, the exact temporary-ban source and TTL, trigger timestamps, and trigger evidence digest. The validator rejects a WAAP observation that begins before deletion of the HIPS ban is complete, a temporary ban requested before WAAP enforcement, or an expiry observed before the requested TTL.

Each `evidence_ref` is a relative path below the private artifact root. The harness rejects absolute paths, traversal, duplicate references, symbolic links, hard links, unsafe parent-directory chains, files larger than 1 MiB, files changed during reading, and SHA-256 mismatches. Inputs and outputs are opened relative to held directory descriptors so a replaced parent path cannot redirect the operation. New JSON outputs are private, bounded to 1 MiB, synchronized, and never overwrite an existing path.

## Bind and validate

```bash
python3 scripts/ci/native_capability_evidence.py bind \
  --candidate-commit "$CANDIDATE_COMMIT" \
  --campaign /private/evidence/node02/campaign.json \
  --observations /private/evidence/node02/observations.json \
  --artifact-root /private/evidence/node02/artifacts \
  --host-attestation /private/evidence/node02/host-attestation.json \
  --signature-catalog src/core/syswarden-core/signatures.json \
  --signing-bundle /private/evidence/native-signing \
  --output /private/evidence/node02/evidence.json

python3 scripts/ci/native_capability_evidence.py validate \
  --candidate-commit "$CANDIDATE_COMMIT" \
  --campaign /private/evidence/node02/campaign.json \
  --evidence /private/evidence/node02/evidence.json \
  --artifact-root /private/evidence/node02/artifacts \
  --host-attestation /private/evidence/node02/host-attestation.json \
  --signature-catalog src/core/syswarden-core/signatures.json \
  --signing-bundle /private/evidence/native-signing \
  --output /private/evidence/node02/verdict.json
```

A `pass` verdict attests only the named host campaign and cannot be reused for
another frozen profile. NODE03 may run both RPM profiles only after restoring
the approved clean snapshot; the campaigns, host attestations, evidence
namespaces and package bindings must remain distinct. After validating all six
campaigns, assemble the exact profile inventory:

```bash
python3 scripts/ci/native_capability_evidence.py aggregate \
  --candidate-commit "$CANDIDATE_COMMIT" \
  --verdict /private/evidence/node01/verdict.json \
  --verdict /private/evidence/node02/verdict.json \
  --verdict /private/evidence/node03/verdict.json \
  --verdict /private/evidence/node04/verdict.json \
  --verdict /private/evidence/node05-rhelpo/verdict.json \
  --verdict /private/evidence/node03-rhelpo/verdict.json \
  --signing-bundle /private/evidence/native-signing \
  --output /private/evidence/native-capability-aggregate.json
```

The aggregate rejects a missing, unknown or duplicate profile, a host that is
not bound to its frozen profile, reused attestation, campaign, evidence or
artifact-set identities, any non-pass verdict and any candidate mismatch. It
also revalidates the complete signed bundle and the separate `1.rhelpo` seal.
The release-owner decision requires this six-profile aggregate to pass.

The aggregate becomes release input only after the protected native-evidence
workflow seals it into `NATIVE_RELEASE_EVIDENCE_MANIFEST.json`, generates
GitHub build provenance with the commit-pinned attestation action, and release
qualification independently verifies that provenance for the exact repository.
An internal checksum or artifact digest does not replace this external
attestation.

## Local harness verification

This command is safe on a development workstation. It uses temporary files only and never connects to a host:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  scripts/ci/native_capability_evidence_test.py -v
```
