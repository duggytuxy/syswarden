# v4.10.4 Patch IVV

This plan defines intermediate Integration, Verification and Validation (IVV)
for the v4.10.4 Patch. Its local verification does not grant release acceptance.
The protected producer, its owner approval and all three independent publication
consumers must accept the exact reviewed plan before publication. Upgrade
releases retain their separate full IVVQ requirements.

## Frozen product and private evidence

The signed product is `0e966d409b6b9d19116597edee1feafad0c83688`. The originating
Patch transition is `cbf45249fbe40e1fc70bf3145f28cc5c6601fb14`, from v4.10.3.
The [plan](../../scripts/ci/release_ivv_v4104_plan.json) pins all four native
packages, the detached DEB signature, the original attested binaries and SBOM,
and the protected updater bundle. The package-signing run is `38029436747`;
the updater producer is `38029762398`.

The [input manifest](../../scripts/ci/release_ivv_v4104_inputs.json) contains
opaque content digests and typed assertions. Private group descriptors bind
the original files, command identities, return codes, output hashes and failed
observations. Raw host evidence, keys, configuration contents and infrastructure
information remain private. The protected producer exports only the bounded
acceptance report and already public package and provenance material.

The [impact record](../../scripts/ci/release_ivv_v4104_impact.json) compares all
137 changed paths with the last public release and records the complete current
runtime module closure. Later publication tooling may change only the exact
allowlist. Runtime sources, signed package bytes, version targets and changelog
remain frozen. Earlier candidate runs and signatures cannot authorize this
product.

## Current native observations

| Area | Required evidence |
| --- | --- |
| Debian migration | The installed official v4.10.3 updater installs the exact authenticated candidate. Modified packages and invalid signatures fail before installation. Protected files, service startup, reload and reboot remain verified. |
| AlmaLinux installation and upgrade | Clean standard installation and the official v4.10.2 to signed candidate upgrade preserve pre-existing administrator groups, sudo authority, SSH policy and unrelated firewall behavior. |
| IPv6 control plane | Real neighbor discovery, router advertisements and DHCPv6 traverse both netdev and inet filtering hooks. Acquisition, product reload, feed refresh and firewalld reload are followed by real DHCP renewal observations. |
| Debian removal | Independent CLI uninstall, APT remove, APT purge and deferred purge after an administrator edit each verify package state, exact payload absence, retained administrator files, shared-service reload and a distinct reboot. |
| RPM removal | Standard DNF erase, separate CLI uninstall and dependency-absent retry validate exact removal and continued administrator protection. RPM does not expose a separate purge command. |
| Bounded recovery | Wrong review digests, fabricated feed provenance and mutation during removal are refused. Exact inactive backups are distinguished from active configuration, and explicitly retained administrator files remain intact. |
| Optional RPM | The package-owned profile requires explicit activation. A controlled POSTUN filesystem refusal preserves its original signed recovery helper after package payload removal. Recovery preserves administrator configuration, including a later edit. |
| VPN continuity | Original generated client bytes remain unchanged. Encrypted UDP round trips and DNS over NAT pass before and after reboot, with observed traffic in both directions and exact restoration of temporary administrator forwarding rules. |
| Reinstallation | Native installation after purge and same-version reinstallation preserve administrator files and start the complete product with a consistent package database. |
| Restorations | Both native hosts return to their initial baselines. The verifier checks original policies, service health, absence of test state and new boot identities. |

Five independent AlmaLinux reboot observations each include a 140-second
post-boot window and fourteen samples, with actual DHCP renewal, SELinux
Enforcing, preserved administrator policy and required service health. Debian
removal observations separately verify 188 protected file paths, twelve package
payload paths, three acknowledged administrator TOML files and ten inactive
legacy files. Native package-manager success alone is insufficient.

## Bounded performance and continuity

The fresh kernel comparison replays captured v4.10.3 and v4.10.4 native product
rules and set members. Only runtime handles, counters and the synthetic ingress
device binding change. Six paired rounds per address family produce 48,000
UDP request-response samples. The verifier recalculates capacity from elapsed
round time and latency percentiles from the raw samples, checks packet traversal
through both filtering hooks and rejects loss or a breached reviewed limit.

This is a bounded kernel comparison on one virtual host under the same CPU
quota. It does not establish physical-core affinity, NIC wire-rate throughput,
all-platform performance or HA endurance. APK has signature, construction and
payload verification, without a fresh Alpine native lifecycle in this campaign.
Observed successful external feed access does not guarantee future availability.

The previous accepted IVV remains bound to its original product
`0a0fa7e7669fe61c36b6ed84e27a42d71cc7063e` and its original plan. Selective
continuity uses the complete source review and current checks; no historical
native verdict becomes a fresh current pass.

## Preserved failures and restoration boundaries

Original transport failures and unsuccessful harness assertions remain part of
the private graph. One direct Debian purge succeeded when the initial harness
expected a refusal. Independent residual, reload and reboot observations verify
that outcome. Optional RPM observations distinguish generated inactive firewall
history from active administrator policy; a shared backup name alone does not
grant deletion authority.

Debian snapshot restoration loses two original append-only shell-history
attributes. Reapplying only those attributes preserves file bytes and identity;
all 137 original hardening checks and nineteen restoration checks then pass.
The AlmaLinux snapshot requires policy-based SELinux relabeling. The original
network profile bytes are verified before normal boot. Provider-generated
timestamps and IPv4 DNS entries are the only admitted post-boot profile changes;
all other original policy files and profile metadata remain exact.

## Protected acceptance

The separately versioned workflow runs on a private ephemeral verifier with
read-only repository permissions and the owner-reviewed
`syswarden-release-qualification` environment. It requires the exact merged
main commit and its checks, revalidates native signatures and updater identity,
and publishes no private input graph. Local preflight is preparation only.

After protected acceptance, a signed annotated tag, independent publisher
consumption, Sigstore attestation and downloaded public asset verification remain
mandatory. Only then may public release references and canonical operator
documentation advance to v4.10.4.
