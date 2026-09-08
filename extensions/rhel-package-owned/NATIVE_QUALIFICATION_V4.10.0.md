# Native qualification for the package-owned RHEL profile

Status: implemented and included in the v4.10.0 candidate scope. Native
qualification and release publication remain pending.

This document covers the explicit package-owned RPM variant for RHEL 9 or
newer image construction. A local assembly test is not native qualification
evidence.

## One authoritative qualification path

The package-owned variant uses the same hardened evidence path as the standard
native packages. The authoritative sources are:

- `scripts/ci/native_lifecycle_contract_v4.10.0.json` and
  `scripts/ci/native_lifecycle_evidence.py` for package lifecycle evidence;
- `scripts/ci/native_capability_contract_v4.10.0.json` and
  `scripts/ci/native_capability_evidence.py` for HIDS, HIPS, WAAP, ASN, GEO,
  OSINT, TUI and GRC evidence;
- `.github/workflows/native-release-evidence.yml` for candidate-bound
  aggregation and sealing;
- `docs/technical/NATIVE_PACKAGE_LIFECYCLE_QUALIFICATION_V4.10.0.md` and
  `scripts/ci/native_capability_lab_v4.10.0.md` for the operator procedure.

There is no second extension-specific validator or evidence format. This
prevents a weaker or contradictory qualification route from being accepted.

## Image-build boundary

Install the exact signed `syswarden-4.10.0-1.rhelpo.x86_64.rpm` through the
image pipeline's normal `mock`, `dnf --installroot` or chrooted RPM
transaction. The transaction must run without a live systemd manager.

The package transaction must prove all of the following:

- no SysWarden binary is executed by an RPM scriptlet;
- no service is started and no firewall state is mutated in the build root;
- only the two SysWarden units are preset on initial installation;
- an upgrade does not reapply the preset or replace administrator TOML files;
- an upgrade from the standard v4.04.3 RPM migrates only the exact legacy
  `/etc/systemd/system` units and keeps the administrator's enabled or disabled
  decision while making the vendor units authoritative;
- rollback restores the standard unit ownership model, and re-upgrade proves
  the same migration a second time;
- final removal requires verified runtime cleanup before the native RPM erase;
- an offline erase removes the enablement links without attempting a live
  service stop and rejects a missing cleanup boundary;
- service activation and dynamic nftables policy compilation occur only after
  the first real boot.

The package owns the units, preset, integration directories and protected
configuration directories. The image owner seeds the approved TOML files.
Those files are not RPM payload files and remain byte-for-byte under operator
control across an upgrade. A complete purge must prove the package record, both
vendor units, the drop-in file and directory, the preset, profile identity,
enablement links and all mutable SysWarden state are absent.

## Required independent campaigns

Exactly two package-owned campaigns are required:

| Profile | Host | Platform | Installation mode |
| --- | --- | --- | --- |
| `RPM-A9-RHELPO` | `node05` | AlmaLinux 9.8 | offline chroot, then first real boot |
| `RPM-A10-RHELPO` | `node03` | AlmaLinux 10.2 | offline chroot, then first real boot |

Both campaigns use the same candidate commit and exact signed profile RPM, but
must have distinct host attestations, snapshot references, boot identities,
evidence namespaces and raw evidence. Evidence from the standard `RPM-A9` or
`RPM-A10` profile cannot substitute for either package-owned campaign.

SELinux remains Enforcing on the real host. Record the selected firewall
frontend before installation and prove that it, its unrelated rules, SSH
access and the provider firewall boundary remain unchanged. The two complete
reboots, rollback, re-upgrade, interruption recovery, final erase and zero
residue checks are mandatory under the unified lifecycle contract.

## Signed artifact boundary

The profile RPM is a separate opt-in release asset. Its filename, NEVRA,
SHA-256, size, native RPM verification and RPM OpenPGP identity must match the
sealed `rhel-package-owned/` signing sub-bundle. Bootstrap provenance is not
accepted. The standard updater manifest must not contain this variant.

The capability campaigns must bind the same sealed package identity and
candidate commit as the lifecycle campaigns. Cross-profile package, evidence,
campaign or attestation reuse is rejected.

## Local contract checks

These checks are safe on a development workstation and do not connect to a
native host:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
  extensions/rhel-package-owned/tests/test_stage.py -v

bash extensions/rhel-package-owned/tests/test-rpm-assembly.sh
```

The assembly test builds the exact profile NEVRA, verifies its payload and
scriptlets, exercises clean install, v4.04.3 migration, rollback, re-upgrade and
erase inside an offline chroot, and proves that the first-install preset,
administrator enablement choice, cleanup barrier and zero-residue contract
behave as declared. Only passing native evidence for both hosts can qualify the
profile.

The final removal scenario must also inject a `%postun` failure after the RPM
record and payload are removed. It must prove that the root-owned durable helper
remains at `/var/lib/.syswarden-rhelpo-postun-recovery-v1`, that its metadata is
exactly `0:0:700:1:9843`, and that its SHA-256 is
`64aa4a61059a5b6dcf82b9bf6eeb1edfb402e0a5bf2ba262a99608b4eabcd75c`.
The package-executed wrapper uses the exact private `rpm-postun-v1` mode and
must not issue a nested RPM database query while the erase transaction holds
the package-manager lock. Its authority remains the exact PREUN identity,
ownership, payload and barrier evidence plus the reviewed POSTUN wrapper's
digest-bound helper invocation. Only the no-argument operator replay, outside
that transaction, performs the canonical package-absence query with empty
stderr.
After `LC_ALL=C rpm -q syswarden` reports exactly that the package is not
installed, replay `/bin/sh /var/lib/.syswarden-rhelpo-postun-recovery-v1` and
require the complete zero-residue result. A substituted helper or standalone
residual path must be refused without consuming the recovery boundary.
