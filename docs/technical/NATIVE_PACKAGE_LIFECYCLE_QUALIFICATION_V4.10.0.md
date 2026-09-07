# Native Package Lifecycle Qualification for v4.10.0

This document defines the release evidence boundary for five real native
package lifecycle campaigns on Ubuntu 26.04, AlmaLinux 9.8, AlmaLinux 10.2 and
Alpine 3.24. It does not execute a lab, connect to a host, approve a candidate
or authorize publication.

The committed contract remains deliberately closed:

- qualification state: `candidate-not-qualified`
- publishing: `false`
- release: `v4.10.0`
- architecture: `amd64`
- baseline: `v4.04.3` at commit
  `381c1f8d91459a9b20605629c725900abd81dee8`

## Required native profiles

| Profile | Canonical host ID | Operator alias | Platform | Package | Services |
| --- | --- | --- | --- | --- | --- |
| `DEB-U2604` | `node02` | `NODE02` | Ubuntu 26.04 | DEB with `dpkg` | systemd |
| `RPM-A9` | `node05` | `NODE05` | AlmaLinux 9.8 | RPM with `rpm` | systemd |
| `APK-324` | `node04` | `NODE04` | Alpine 3.24 | APK with `apk` | OpenRC |
| `RPM-A9-RHELPO` | `node05` | `NODE05` | AlmaLinux 9.8 | package-owned RPM with `rpm` | systemd |
| `RPM-A10-RHELPO` | `node03` | `NODE03` | AlmaLinux 10.2 | package-owned RPM with `rpm` | systemd |

The lowercase host IDs intentionally match the native capability contract. The
uppercase names are operator-facing SSH aliases only. Evidence cannot substitute
one profile, host, SSH key, package family, or service manager for another.

## Lifecycle sequence

Each profile must complete the following ordered sequence on the real host:

1. Attest a clean host, its exact OS, AMD64 architecture, package manager, SSH
   host key, and provider firewall boundary.
2. Verify the candidate package digest and native signature before a clean native
   install.
3. Apply and validate the release configuration.
4. Remove and purge the clean installation and prove zero SysWarden residue.
5. Install and configure the exact public v4.04.3 baseline after verifying its
   published release digest and producer commit.
6. Upgrade the configured baseline to the candidate with the native package
   manager.
7. Perform the first real host reboot and revalidate package, services, firewall,
   configuration, state, SSH identity, and package database.
8. Perform a second real host reboot and repeat the same validation.
9. Roll back to the verified v4.04.3 package. This is a digest and provenance
   assertion, not a claim that v4.04.3 used the v4.10.0 native signature policy.
10. Reverify and re-upgrade to the candidate.
11. Exercise one controlled service and SysWarden firewall-state interruption,
    then prove one recovery operation restores both without an unexpected reboot.
12. Remove and purge the candidate, prove the package manager remains healthy,
    and attest the exact residue inventory.

Every installation event has its own package verification record. A verification
performed before the first installation cannot be reused as proof for an upgrade,
rollback, or re-upgrade.

For each package-owned profile, the clean-install scenario first installs the
RPM into an offline `mock` or chroot root where systemd is not active. It proves
that the RPM owns the configuration, firewall integration and systemd assets,
then boots the resulting system and proves both SysWarden services and the
firewall are active. The initial clean-host checkpoint has no real boot ID;
first boot and both later reboots carry distinct attested boot IDs.

## Preservation boundary

Every checkpoint carries separate SHA-256 canaries for:

- semantic SysWarden configuration;
- persistent SysWarden state selected by the lab procedure;
- operator-owned state outside SysWarden;
- third-party firewall state;
- the active SysWarden firewall state;
- the real boot identity.

The validator requires the operator and third-party firewall canaries to remain
identical across the entire campaign, including both purged states. The configured
SysWarden and persistent-state canaries must remain identical through upgrade,
both reboots, rollback, re-upgrade, and recovery. The boot identity must change
exactly for the two declared reboot transitions and must not change during the
recovery scenario.

## Package trust inputs

The validator does not discover or trust package keys from an observation file.
Its caller must supply all of these protected inputs:

- the exact selected DEB key ID, complete OpenPGP fingerprint and public-key
  SHA-256 from `qualified-policy` native-signing provenance;
- the exact selected RPM key ID, complete OpenPGP fingerprint and public-key
  SHA-256 from the same provenance;
- the exact selected APK key ID, canonical RSA public-key SHA-256 and signer
  image digest from the same provenance;
- the operator-approved SHA-256 SSH host-key fingerprint for node02;
- the operator-approved SHA-256 SSH host-key fingerprint for node03;
- the operator-approved SHA-256 SSH host-key fingerprint for node05;
- the operator-approved SHA-256 SSH host-key fingerprint for node04.

The values must come from the protected native-signing evidence and the
operator-controlled host-key inventory. The candidate RPM, DEB and APK package
digests must match the native-signing provenance. The `1.rhelpo` package must
also match the sealed package-owned signing sub-bundle and use the same approved
RPM key while remaining absent from the updater manifest. The v4.04.3 package
digest must match the published release checksum evidence.

The caller rejects bootstrap provenance. During a bounded rotation overlap,
the selected identities come from the exact signed-bundle provenance, never
from a requirement that the policy contain exactly one non-revoked key.

## Evidence layout

Use a protected staging directory owned by the qualification operator. Files and
directories must not be group-writable or world-writable. Every raw evidence item
must be a singly-linked regular JSON file. Symlinks, hard links, duplicate JSON
keys, non-finite values, reused references, reused digests, missing files, and
unlisted files are rejected.

The expected layout is:

```text
native-lifecycle/
  node02-ubuntu26.04.json
  node05-almalinux9.8.json
  node04-alpine3.24.json
  node05-almalinux9.8-rhelpo.json
  node03-almalinux10.2-rhelpo.json
  artifacts/
    DEB-U2604/raw/                 29 exact JSON captures
    RPM-A9/raw/                    29 exact JSON captures
    APK-324/raw/                   29 exact JSON captures
    RPM-A9-RHELPO/raw/             29 exact JSON captures
    RPM-A10-RHELPO/raw/            29 exact JSON captures
```

Each profile has one host attestation, two package provenance records, twelve
checkpoint records, twelve scenario records, one final-state record, and one
final signed attestation. The attestation binds the candidate commit, contract
digest, profile ID, and canonical inventory digest of all preceding raw records.

Raw captures should contain the exact command, exit status, normalized output,
capture time, host identity, and relevant file or service digests produced by the
native lab. Secrets, private keys, access tokens, public IP allowlists, and raw
configuration values must not be included. Store their reviewed digests instead.

## Validation command

Run the validator only after all five native campaigns and their external
attestations are complete:

```bash
python3 scripts/ci/native_lifecycle_evidence.py \
  --candidate-commit "$RELEASE_SHA" \
  --observation "$SOURCE_ROOT/native-lifecycle/node02-ubuntu26.04.json" \
  --observation "$SOURCE_ROOT/native-lifecycle/node05-almalinux9.8.json" \
  --observation "$SOURCE_ROOT/native-lifecycle/node04-alpine3.24.json" \
  --observation "$SOURCE_ROOT/native-lifecycle/node05-almalinux9.8-rhelpo.json" \
  --observation "$SOURCE_ROOT/native-lifecycle/node03-almalinux10.2-rhelpo.json" \
  --artifact-root "$SOURCE_ROOT/native-lifecycle/artifacts" \
  --rpm-signer-fingerprint "$RPM_SIGNER_FINGERPRINT" \
  --rpm-package-name "$RPM_PACKAGE_NAME" \
  --rpm-package-sha256 "$RPM_PACKAGE_SHA256" \
  --rpm-package-size "$RPM_PACKAGE_SIZE" \
  --rhel-rpm-package-name "$RHEL_RPM_PACKAGE_NAME" \
  --rhel-rpm-package-sha256 "$RHEL_RPM_PACKAGE_SHA256" \
  --rhel-rpm-package-size "$RHEL_RPM_PACKAGE_SIZE" \
  --deb-signer-fingerprint "$DEB_SIGNER_FINGERPRINT" \
  --deb-package-name "$DEB_PACKAGE_NAME" \
  --deb-package-sha256 "$DEB_PACKAGE_SHA256" \
  --deb-package-size "$DEB_PACKAGE_SIZE" \
  --apk-public-key-sha256 "$APK_PUBLIC_KEY_SHA256" \
  --apk-package-name "$APK_PACKAGE_NAME" \
  --apk-package-sha256 "$APK_PACKAGE_SHA256" \
  --apk-package-size "$APK_PACKAGE_SIZE" \
  --node02-ssh-host-key-sha256 "$NODE02_SSH_HOST_KEY_SHA256" \
  --node03-ssh-host-key-sha256 "$NODE03_SSH_HOST_KEY_SHA256" \
  --node05-ssh-host-key-sha256 "$NODE05_SSH_HOST_KEY_SHA256" \
  --node04-ssh-host-key-sha256 "$NODE04_SSH_HOST_KEY_SHA256" \
  --output "$OUTPUT_ROOT/native-lifecycle/VERDICT.json"
```

The RPM, DEB and APK package name, SHA-256 and size values must come from the
exact signed records in `.packages.signed` of the verified normal signing
provenance. The RPM identity and exact package tuple must also agree with
`RPM_NATIVE_VERIFICATION.json`; the corresponding DEB and APK records must agree
with their native verification documents. The package-owned RPM values must
come from its separately sealed provenance and agree with its native RPM
verification. The output path must be absolute, protected and absent before
validation. The validator creates a private mode
`0600` file without overwriting an existing result.

## Final residue inventory

The final checkpoint and final-state evidence require zero package records,
service units, processes, firewall objects, dedicated paths, dedicated users or
groups, scheduled jobs, and other SysWarden residue. In addition, the observation
must explicitly attest every path in the contract, including:

- product roots under `/opt`, `/etc`, `/var/lib`, and `/var/log`;
- CLI and TUI links plus shell completion and package documentation;
- systemd and OpenRC units, enablement links, legacy Web TUI remnants, and runtime
  files;
- the SysWarden cron and rsyslog integration files;
- dedicated WireGuard unit, runlevel, and configuration paths.

The complete authoritative list is
`scripts/ci/native_lifecycle_contract_v4.10.0.json`. A missing entry in the
observation is a hard failure.

## Release-chain integration

The protected native evidence producer should:

1. require the five observation files and their exact 145-file raw inventory;
2. derive the exact selected RPM, DEB and APK signer identities from the already
   validated `qualified-policy` native-signing provenance;
3. verify the complete package-owned signing sub-bundle and derive its exact
   RPM tuple from that provenance;
4. supply all four SSH pins from protected operator inputs;
5. run this validator before copying any lifecycle evidence;
6. copy the observations and raw files into a deterministic lifecycle archive;
7. record the contract digest, archive digest, verdict digest, candidate commit,
   workflow run, attempt, and artifact identities in the native evidence manifest.

Release qualification should extract that archive with bounded member count,
path, type, mode, and size checks, rerun this validator with the same protected
identities, compare the regenerated verdict byte for byte, and revalidate the
native evidence manifest inventory. The final publisher should consume only the
qualified release bundle that contains this revalidated evidence.

A lifecycle verdict with `status: pass` proves that the five evidence campaigns
satisfy this contract. It intentionally retains `candidate-not-qualified` and
`publishing: false`; only the complete release gate can make the separate release
qualification and publication decisions.
