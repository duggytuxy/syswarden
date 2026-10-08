# v4.10.3 publication record

SysWarden v4.10.3 was published on **08 October 2026 at 15:43:13 UTC**.
This stable **Patch** release passed its protected intermediate **IVV**.
An `Upgrade` generation still requires full **IVVQ**. This record does not
claim that broader qualification.

The patch covers recognized historical upgrade and recovery paths, complete
product removal and optional OSINT availability. The canonical
[historical recovery and removal guide](https://syswarden.io/docs/historical-recovery/)
explains operator decisions and supported boundaries. The
[change record](../../../changelog.md) contains the detailed correction list.

## Exact identities

| Boundary | Identity |
| --- | --- |
| Tested and signed product | `0a0fa7e7669fe61c36b6ed84e27a42d71cc7063e` |
| Publication commit | `2bbb1df10f0b6957a8393dec71f7135af3e098ca` |
| Signed annotated tag object | `17a93dd2557360e61b0124500042fdf63f54d69b` |
| Release | [v4.10.3, ID 406990678](https://github.com/duggytuxy/syswarden/releases/tag/v4.10.3) |
| Protected IVV producer | [37794518032](https://github.com/duggytuxy/syswarden/actions/runs/37794518032) |
| IVV artifact | `11557873608`, `syswarden-release-ivv` |
| IVV artifact SHA-256 | `c43357742e6eda57b22c859dc51d6587411f711cb875a5df65963dad73552bab` |
| Original IVV report SHA-256 | `010b4ae317508f19f6c669c67af076e5ca3d764d45967b585cad24c057cea05d` |
| Protected publisher | [37800868589](https://github.com/duggytuxy/syswarden/actions/runs/37800868589) |

The protected IVV accepted all fourteen required checks. Independent consumers
verified its original report attestation, native signatures, signed updater,
binary provenance, source continuity and exact tested package bytes. The
[reviewed acceptance plan](../../qualification/INTERMEDIATE_ACCEPTANCE_V4.10.3.md)
defines the current observations and retained historical support. Later
publication tooling does not change the frozen runtime payload.

Pre-publication flags in the original report describe acceptance time. The
candidate notice in the sealed change record describes when that record was
written. Neither is rewritten after publication. This dated record establishes
the subsequent verified public outcome.

The three required tag workflows passed:
[packages](https://github.com/duggytuxy/syswarden/actions/runs/37795960209),
[security](https://github.com/duggytuxy/syswarden/actions/runs/37795960166) and
[Plumber](https://github.com/duggytuxy/syswarden/actions/runs/37795960213).
The publisher completed through the protected production environment after
owner approval. The annotated tag signature was independently verified.

The first publisher attempt stopped while downloading the private draft's
DEB signature. Its failed result remains recorded. Independent readback then
verified all twelve draft files and their attestations without changing their
bytes. The standard protected rerun completed as attempt
`2` on the same tag, source and draft. The original
download failure's cause was not established; no failed attempt is counted as
a passing publication.

## Public files and signatures

The release contains twelve files, including four signed Linux package
variants: DEB, standard RPM, package-owned RHELPO RPM and APK. The remaining
files are the detached DEB signature, two checksum inventories, release archive,
SPDX SBOM, Plumber report and signed updater manifest with its signature.

All twelve files were downloaded from their public URLs without credentials.
Their names, sizes and SHA-256 digests match the release metadata and exact
staged inventory. Each GitHub Sigstore attestation verifies against the
release-manager workflow, publication commit and `refs/tags/v4.10.3`.
Native packages, updater, binaries and SBOM retain the exact bytes accepted
by the IVV consumer. Release metadata remained unchanged across verification,
and GitHub identifies v4.10.3 as the latest stable release.

The [independent verification record](PUBLIC_RELEASE_VERIFICATION.json)
lists each public asset ID, size and digest. It records verification and does
not replace the original cryptographic attestations. The exact public
[RELEASE_SHA256SUMS.txt](RELEASE_SHA256SUMS.txt) covers the eleven other files;
its own SHA-256 is `8cb069d7acae53e518a1691f5e472ff841a63e658811ef8197affcd9c8023ce8`.

With an independently trusted GitHub CLI, verify that manifest from this
directory:

```bash
gh attestation verify RELEASE_SHA256SUMS.txt \
  --repo duggytuxy/syswarden \
  --signer-workflow duggytuxy/syswarden/.github/workflows/release-manager.yml \
  --source-digest 2bbb1df10f0b6957a8393dec71f7135af3e098ca \
  --signer-digest 2bbb1df10f0b6957a8393dec71f7135af3e098ca \
  --source-ref refs/tags/v4.10.3 \
  --deny-self-hosted-runners
```

Verify each downloaded asset and its native package signature before use.
The [getting-started guide](https://syswarden.io/docs/getting-started/)
distinguishes checksums, workflow provenance and package authentication.

## Accepted correction scope

- The official historical v4.02.8 updater encounters the new pre-unpack guard
  without losing the old payload, VPN or firewall. Explicit reviewed recovery
  permits the signed upgrade.
- An actual v4.02.8 to v4.10.2 half-configured package can use the separately
  authenticated recovery executable, retire the old namespace claim and
  migrate recognized unmanifested generated VPN files before configuration.
- Migration preserves original client bytes and keys. Encrypted traffic,
  reboot persistence, interrupted migration recovery and filesystem identity
  across device renumbering are verified.
- Standalone uninstall, independent APT remove, APT purge and remove followed
  by an administrator edit and deferred purge complete separately. Each
  preserves administrator configuration and effective independent protection
  after shared-service reloads and its own real reboot.
- Removal retires proven historical systemd, rsyslog, Fail2ban, persistent
  nftables and compatibility rules without treating matching names as proof.
  Explicit administrator retention and independent policy transfer remain
  reviewed decisions.
- Valid optional OSINT sources with insufficient common entries can be
  omitted during installation. Primary authenticated feeds remain required;
  malformed sources and insufficient explicit-refresh intersection still fail.

The four removal cases include 576 packet outcomes across IPv4 and IPv6 ICMP,
TCP and UDP, and verify 213 administrator paths. The complementary campaign
includes eleven successful encrypted traffic probes. The final restored
baseline passed 147 controls. These counts describe the reviewed test scope,
not a guarantee about every deployment.

## Evidence limits

Fresh native observations use recognized official templates and disposable
keys on hardened Debian 13. They do not establish every customized installation
or historical upgrade sequence. Unknown ownership and changed evidence remain
safe refusals; complete removal cannot be claimed while ambiguity remains.

The modern owned-manifest traffic profile used explicit temporary operator
forwarding rules. The patch does not automatically repair unrelated firewall
policy. Optional-feed and updater-discovery scenarios use isolated HTTPS
fixtures. Controlled migration interruption is not a process-kill or power-loss
durability claim.

Earlier platform and HA observations retain their original identities under
the continuity plan. No new all-platform lifecycle, HA endurance, broad
performance or live-feed availability claim is made. Original failed attempts
remain retained evidence and are not relabeled as passes. Raw host captures,
private configuration and operational identifiers are not public artifacts.
