# v4.10.1 Patch IVV acceptance plan

This versioned plan defines acceptance requirements, not a passed result. The
protected producer must complete on the reviewed publication commit and each
publisher boundary must independently authenticate its original report.

## Release and artifact identities

The originating transition is `Patch :` in [PR #284](https://github.com/duggytuxy/syswarden/pull/284),
merged as `9e4c76aa59da3a04746a9b957f962f1b47b6c1b2`, from public v4.10.0 to
v4.10.1. This is intermediate **IVV**. An `Upgrade` remains subject to complete
**IVVQ**, including across later corrective commits.

The frozen product is `8611c84cb8c245195dd5456bebad13a52b1d7217`. A later
publication commit may change only the explicitly listed acceptance tooling,
tests and documentation. It cannot rebuild or substitute the product packages,
CLI/Core/TUI bundle, signature catalogue, SBOM or signed updater.

| Material | Exact protected producer | Immutable artifact |
| --- | --- | --- |
| Four signed native package variants | [36978920291](https://github.com/duggytuxy/syswarden/actions/runs/36978920291) | `11214948349` |
| Candidate updater and Ed25519 manifest | [36980486519](https://github.com/duggytuxy/syswarden/actions/runs/36980486519) | `11215198424` |
| Attested product binary bundle | [36977471641](https://github.com/duggytuxy/syswarden/actions/runs/36977471641) | `11214900651` |
| Product SBOM | Same Security Audit run | `11213992094` |

The [machine-readable plan](../../scripts/ci/release_ivv_v4101_plan.json) binds
all archive, package and payload hashes, original producer identities, required
checks and post-acceptance requirements. The
[impact record](../../scripts/ci/release_ivv_v4101_impact.json) compares the
product with both the last public release and the native-tested candidate.

## Original native observations and continuity

The Debian 13 observations belong to
`1ac64bc56ee4b4ea9233713f94f415719b9f5ec0` and its original unsigned local test
package. They are retained under that identity, not rewritten as observations
on the final signed package. The protected IVV verifies the original scripts,
outputs, return codes, package bytes and kernel-test binary against a reviewed
private object inventory. Original failures remain failures.

The campaign covered direct v4.02.8 to official v4.10.0 migration behavior,
reconstruction of historical unmarked WireGuard state with a retained modern
manifest, successful exact candidate removal, ambiguous-rule refusal, read-only
configuration validation, alert guidance, controlled retry and six isolated
real-kernel nftables cases. Administrator rules were preserved. The final
snapshot restoration recovered the original package, active service and Geo/ASN
settings. The direct migration failed earlier than the reported removal error;
it is not counted as a successful v4.10.1 migration.

The hardening scope was the relevant Debian/WireGuard subset. Geo/ASN was
temporarily disabled with approval to isolate this test. Neither the reporter's
exact host history nor every successive upgrade path since v3 was reproduced.
Unmanifested or ambiguous state still requires explicit operator investigation.

The continuity verifier checks all 214 non-test Go module inputs. Between the
native-tested candidate and frozen product, only three RHEL version constants
in two CLI source files differ. It also compares complete DEB payload and
control inventories, permissions and script contents. The installation and
removal scripts are byte-identical. Core/TUI binary differences are restricted
to exact VCS metadata and ELF build identifiers. The CLI additionally differs
at the five reviewed compiled RHEL identity bytes. The generated FPM changelog
date follows the commit timestamp. Package-manager bookkeeping hashes are
recomputed against the corresponding original payloads.

The prior v4.10.0 protected IVV report is historical support with its original
product `8c3405758a9b369924f466d12652e99d3a84dc56`, producer
`3cc06b62d42b5adadc46fc9a252fece5adf670c1`, run `36853355288` and artifact
`11156960777`. It supports the selected unchanged platform/service paths. It
does not grant current acceptance. Fresh product CI and package integration
checks cover the RHEL identity and migration allowlist follow-ups. No new
all-platform native lifecycle, HA endurance or performance campaign is claimed.

## Protected verification and publication boundaries

The v4.10.1 producer uses the owner-reviewed, main-only
`syswarden-release-qualification` environment and the dedicated ephemeral IVV
runner. It receives the private input tree under the frozen product identity.
Private raw observations, configurations and test credentials are never part
of the public artifact.

The original native-test commit came from the reviewed PR history. The producer
and all three publisher boundaries fetch that exact commit explicitly, without
changing their publication checkout. They verify the complete source-impact
inventory and reject unlisted publication changes.

Acceptance requires all five product CI workflows and all five publication CI
workflows; the scoped native observations and continuity checks; fresh offline
verification of both RPM signatures, APK signature and detached DEB signature
under the publishing policy; the exact original updater archive, producer
attestation and Ed25519 manifest; the original binary bundle attestation and
SBOM; and verified lab restoration.

The report states `intermediate_release_validated=true` only after those checks.
It keeps `full_qualification_passed=false` and `publication_authorized=false`.
The coordinator, staging job and privileged publisher independently select the
required track, authenticate the report and its immutable artifact, recheck
source/artifact bindings and compare release assets. The signed annotated tag,
protected publication, Sigstore release manifest and downloaded public asset
verification remain separate requirements. Public documentation lives at
[syswarden.io/docs](https://syswarden.io/docs/).

The shared empty-proof reader ignores access-time updates caused by reading the
file itself. It still rejects changes to inode, device, ownership, permissions,
link count, size, modification time and change time, both at open and after
reading. This verifier correction does not alter any historical evidence bytes
or their original verdicts.
