# v4.10.3 Patch IVV

This plan defines intermediate Integration, Verification and Validation (IVV)
for the v4.10.3 Patch. It does not grant acceptance by itself. Upgrade generation
changes continue to require the full IVVQ track. Publication remains pending
until the protected producer and independent publication consumers accept this
exact reviewed plan.

## Exact identities

The frozen signed product is
`0a0fa7e7669fe61c36b6ed84e27a42d71cc7063e`. Every current native campaign used
that product's protected native package. The complementary migration and
updater campaign also used its protected candidate updater bundle. The
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
package bytes remain frozen. Earlier unsuccessful IVV attempts and superseded
package signatures do not authorize this product.

## Fresh native scope

The complementary migration, updater and restoration campaign contains 798
original files, 27 required native result records, seven filesystem observations
and eleven successful encrypted traffic probes. Four additional archives bind
independent removal campaigns to the same package and executable. The verifiers
check every original member, its private graph object, exact signed payloads and
semantic assertions without extracting or publishing the private archives.

| Area | Required current observation |
| --- | --- |
| Actual historical updater | The installed official v4.02.8 CLI attempts the new package. Pre-unpack refusal preserves the old package, executable, VPN and firewall. Explicit recovery permits a subsequent signed upgrade. |
| Half-configured recovery | An actual official v4.02.8 to v4.10.2 attempt creates `install ok half-configured 4.10.2`. The staged verified recovery CLI retires the old claim, migrates recognized generated files and permits native v4.10.3 configuration. |
| Ownership boundaries | Seven negative cases and a stale plan are refused. Active VPN guards, exact private backups and original file and inode preservation remain required. |
| Interrupted migration | A reversible directory attribute fault leaves the durable journal. Ordinary installation refuses the incomplete state. A freshly reviewed digest resumes the same migration. |
| Client continuity | Original generated client bytes and keys remain unchanged. Encrypted bidirectional traffic and VPN NAT pass after reboot. |
| Filesystem identity | An official modern owned manifest acquires only UUID bindings. Separate warm boot, cold boot and actual device renumbering checks preserve original bytes, inodes, UUIDs and manifest bytes. The original device mapping is restored and verified after another reboot. |
| Complete removal | CLI uninstall, independent APT remove, APT purge, and APT remove followed by an administrator edit and deferred purge each complete independently. Exact product artifacts disappear; administrator files, rules and independent protection remain effective after shared-service reloads and four distinct reboots. |
| Package consistency | Native purge also handles an already absent dedicated table, preserves explicitly reviewed administrator policy and private recovery backups, removes exact generated journald policy and permits same-version reinstall. |
| Optional OSINT | Disjoint optional-source intersection reproduces the old installation failure. The candidate permits installation with valid authenticated primary feeds, while explicit refresh disagreement and malformed source data still fail. A valid refresh and subsequent reboot pass. |
| Authenticated updater | The protected manifest installs the exact signed product. Invalid signatures and a modified package are refused before installation. |
| Final restoration | The original hardened baseline passes all 137 controls and ten cleanup checks after snapshot restoration. |

### Independent removal requirements

Each of the four removal cases requires 144 real packet outcomes, for 576
combined outcomes across IPv4 and IPv6 ICMP, TCP and UDP. Allowed traffic must
remain allowed and blocked traffic must remain blocked. The verifier separately
checks all 213 administrator file paths, independent Fail2ban protection, SSH
hardening, exact historical rule retirement and private backup contents.

Remove-only cannot reuse a remove-then-purge result. Deferred purge must preserve
the administrator's intervening edit. Each archive must carry its own completed
reboot identity. A zero package-manager exit code is insufficient without these
postconditions. Tests with invented evidence reject semantic substitutions even
when an attacker recalculates the fixture's archive hashes.

## Preserved failures and limits

The unchanged historical downloader encountered a stale temporary download under
temporary-file protection. Its exact verified file was privately preserved
before retrying the same executable. Its exit status alone is not a success
oracle because it can print an installation failure and still return zero.

The supplemental modern owned-manifest profile lacks shared forwarding
permissions. Its traffic probe uses three narrowly scoped temporary operator
rules. This does not claim automatic repair of unrelated firewall policy.

Original failed harness comparisons, connection timeouts, an incomplete archive
transfer and an initial traffic-probe timeout remain private evidence. A later
unchanged traffic probe passed; the initial timeout's cause was not established.
Archive consumption requires every original file hash and exact inventory.
The negative package and signature bytes remain unchanged evidence.

Snapshot restoration loses the two original append-only history attributes.
Reapplying only those attributes preserves file bytes and identity. Default tmpfs
sizing varied by four KiB across boots. Every mount flag and other baseline
control remains exact; no partition or mount policy is changed.

These observations use recognized official templates with disposable keys on
hardened Debian 13. Optional-feed and updater discovery scenarios use isolated
process-local HTTPS fixtures. They do not establish a production host outcome,
every historical upgrade chain, process-kill or power-loss durability, live feed
availability, HA endurance, broad performance or fresh all-platform lifecycle
validation. The prior v4.10.2 IVV remains bound to its original product, producer
and attestation. Its verdict is not transferred.

## Protected acceptance and publication

After this tooling is reviewed and merged, require the five exact-main checks
and dispatch `release-ivv-v4103.yml` with `VERIFY-V4103-IVV-NO-PUBLISH`.
The owner-reviewed `syswarden-release-qualification` environment gates a dedicated
ephemeral runner. It rechecks the private evidence, native signatures, updater
signature, GitHub provenance, current CI, original binary bundle and source
binding before attesting the public IVV report. The existing environment name
does not change this Patch's IVV classification.

All three existing publisher boundaries independently select the explicit
v4.10.3 profile and verify the unique protected result. A signed annotated tag,
production approval, Sigstore release attestations and independent verification
of the downloaded public assets remain separate requirements. The issue stays
open while acceptance or publication is incomplete. Operator guidance belongs
in [the canonical documentation](https://syswarden.io/docs/).
