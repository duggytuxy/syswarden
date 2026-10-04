# v4.10.3 Patch IVV

This plan defines intermediate Integration, Verification and Validation (IVV)
for the v4.10.3 Patch. It does not grant acceptance by itself. Upgrade generation
changes continue to require the full IVVQ track.

Publication hold: the protected run
[37188157105](https://github.com/duggytuxy/syswarden/actions/runs/37188157105)
failed native RPM verification because the tracked verifier lacked the candidate
RPM anchors. No protected acceptance was issued. A subsequent
[historical package-removal regression](../technical/HISTORICAL_PACKAGE_REMOVAL.md)
and an independently reproduced
[OSINT installation availability regression](../technical/OSINT_INSTALL_AVAILABILITY.md)
also require runtime corrections. The identities and observations below
remain bound to their original product. New reviewed source, signatures, native
observations and a revised IVV plan are required; this plan cannot accept the
changed product.

## Exact identities

The frozen signed product is
`3b39b37b0c9da6431a461d83799fc40c18de2e8f`. The fresh native campaign used
that product's protected native packages and candidate updater bundle. The
originating Patch transition is
`441a1f3edc55a97ac01de72313ea50d9788f78b8` from v4.10.2.

The [reviewed plan](../../scripts/ci/release_ivv_v4103_plan.json) pins the four
native packages, detached DEB signature, protected workflow runs, artifact IDs,
archive digests, binary build attestation and SBOM. The
[input manifest](../../scripts/ci/release_ivv_v4103_inputs.json) describes a
private content-addressed graph. Only opaque digests, typed assertions and
release identities are public. Raw host captures, credentials and infrastructure
details remain private.

The [source impact review](../../scripts/ci/release_ivv_v4103_impact.json)
compares the last public v4.10.2 commit with the signed product and records the
complete runtime module inputs. Later publication tooling may change only the
explicit allowlist. Runtime sources, version targets, changelog and signed
package bytes remain frozen.

## Fresh native scope

The current campaign contains 305 original files, 17 required native result
records, seven filesystem observations and seven successful encrypted traffic
probes. The archive verifier checks every original member, its private graph
object, exact signed payloads and semantic assertions. It never extracts the
archive or publishes its contents.

| Area | Required current observation |
| --- | --- |
| Actual historical updater | The installed official v4.02.8 CLI attempts the new package. Pre-unpack refusal preserves the old package, executable, VPN and firewall. Explicit recovery permits a subsequent signed upgrade. |
| Half-configured recovery | An actual official v4.02.8 to v4.10.2 attempt creates `install ok half-configured 4.10.2`. The staged verified recovery CLI retires the old claim, migrates recognized generated files and permits native v4.10.3 configuration. |
| Ownership boundaries | Seven negative cases and a stale plan are refused. Active VPN guards, exact private backups and original file and inode preservation remain required. |
| Interrupted migration | A reversible directory attribute fault leaves the durable journal. Ordinary installation refuses the incomplete state. A freshly reviewed digest resumes the same migration. |
| Client continuity | Original generated client bytes and keys remain unchanged. Encrypted bidirectional traffic and VPN NAT pass after reboot. |
| Filesystem identity | An official modern owned manifest acquires only UUID bindings. A complete stop/start produces a real device-number change while UUIDs, original bytes, inodes and manifest bytes remain unchanged. Encrypted traffic passes again. |
| Package consistency | Direct CLI uninstall refuses registered native packages. Native purge cleans exact shared rules even with the dedicated table already absent, preserves foreign policy and permits same-version reinstall. |
| Authenticated updater | The protected manifest installs the exact signed product. Invalid signatures and a modified package are refused before installation. |
| Final restoration | The original hardened baseline passes all 137 controls and seven cleanup checks after snapshot restoration. |

## Preserved failures and limits

The unchanged historical downloader encountered a stale temporary download under
temporary-file protection. Its exact verified file was privately preserved
before retrying the same executable. Its exit status alone is not a success
oracle because it can print an installation failure and still return zero.

The supplemental modern owned-manifest profile lacks shared forwarding
permissions. Its traffic probe uses three narrowly scoped temporary operator
rules. This does not claim automatic repair of unrelated firewall policy.

An original updater harness comparison failed on an existing nftables element
expiry decreasing by one second. The original capture remains in the graph.
The separate repeated test accepts only non-increasing existing expiry values
and packet counters; policy changes, new rules and expiry extensions are
rejected. The negative package and signature bytes remain unchanged evidence.

Provider snapshot restoration loses the two original append-only history
attributes. Reapplying only those attributes preserves file bytes and identity.
Default tmpfs sizing varied by four KiB across boots. Every mount flag and
other baseline control remains exact; no partition or mount policy is changed.

These observations use recognized official templates with disposable keys on
hardened Debian 13. They do not establish a production host outcome, every
historical upgrade chain, process-kill or power-loss durability, live feed
behavior, HA endurance, broad performance or fresh all-platform lifecycle
qualification. The prior v4.10.2 IVV remains bound to its original product,
producer and attestation. Its verdict is not transferred.

## Protected acceptance and publication

After this tooling is reviewed and merged, require the five exact-main checks
and dispatch `release-ivv-v4103.yml` with `VERIFY-V4103-IVV-NO-PUBLISH`.
The owner-reviewed qualification environment gates a dedicated ephemeral
runner. It rechecks the private evidence, native signatures, updater signature,
GitHub provenance, current CI, original binary bundle and source binding before
attesting the public IVV report.

All three existing publisher boundaries independently select the explicit
v4.10.3 profile and verify the unique protected result. A signed annotated tag,
production approval, Sigstore release attestations and independent verification
of the downloaded public assets remain separate requirements. The issue stays
open while acceptance or publication is incomplete. Operator guidance belongs
in [the canonical documentation](https://syswarden.io/docs/).
