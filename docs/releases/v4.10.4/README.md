# v4.10.4 publication record

SysWarden v4.10.4 was published on **10 October 2026 at 15:22:08 UTC**.
This stable **Patch** release passed protected **IVV**, followed by independent
verification of its public assets. Upgrade generations retain their separate
full **IVVQ** requirements.

The patch preserves essential IPv6 control traffic across policy regeneration,
keeps existing administrator authority intact during hardening, and completes
the reviewed native removal and recovery corrections. It also removes the
obsolete mirror homepage probe and uses the reviewed updated Go toolchain and
dependency closure. Detailed changes remain in [changelog.md](../../../changelog.md).
Operator guidance belongs in the [canonical documentation](https://syswarden.io/docs/).

## Exact identities

| Boundary | Identity |
| --- | --- |
| Tested and signed product | `0e966d409b6b9d19116597edee1feafad0c83688` |
| Publication commit | `c4bb1f7fdf48fd80652b6870af5babda0b16ad6e` |
| Signed annotated tag object | `725bd2b5982b4388ec348dba615d9d251f2981ce` |
| Release | [v4.10.4](https://github.com/duggytuxy/syswarden/releases/tag/v4.10.4), ID `409028153` |
| Protected IVV producer | [38059926721](https://github.com/duggytuxy/syswarden/actions/runs/38059926721) |
| IVV artifact | `11673285722`, `syswarden-release-ivv` |
| IVV artifact digest | `sha256:7bbc0ee0615f45321741a4a5273d6d8c890c380324847edb6942937da21c5bf3` |
| Original IVV report SHA-256 | `69795da4d2c94dce63f516f5d333de1d5a221587b6f52a544ed488f0562f26b5` |
| Protected publisher | [38061490741](https://github.com/duggytuxy/syswarden/actions/runs/38061490741) |

All fifteen protected IVV checks passed. Independent consumption verified the
original report attestation, source binding, signed native package bytes,
updater signature and original binary/SBOM provenance. The
[reviewed plan](../../qualification/INTERMEDIATE_ACCEPTANCE_V4.10.4.md)
separates the frozen signed product from later reviewed publication tooling.
Historical evidence retains its original identity.

The three tag workflows passed:
[packages](https://github.com/duggytuxy/syswarden/actions/runs/38060306941),
[security](https://github.com/duggytuxy/syswarden/actions/runs/38060306965) and
[Plumber](https://github.com/duggytuxy/syswarden/actions/runs/38060306951).
The protected production environment required owner approval.

## Public files and signatures

All twelve public files were downloaded without credentials. Their names,
sizes and SHA-256 digests matched the verified publisher inventory and release
metadata. Each GitHub Sigstore attestation binds the release-manager workflow,
publication commit and `refs/tags/v4.10.4`. Native package, updater, binary and
SBOM bytes match the independently accepted IVV inputs.

The [verification record](PUBLIC_RELEASE_VERIFICATION.json) lists each asset
and digest. The exact [RELEASE_SHA256SUMS.txt](RELEASE_SHA256SUMS.txt) covers
the eleven other files; its own SHA-256 is `10f57844a22296b671a3fa465f97569c33b4dfccb6fd31107e2659fec1b978a3`.

With an independently trusted GitHub CLI, verify that checksum manifest:

```sh
gh attestation verify RELEASE_SHA256SUMS.txt \
  --repo duggytuxy/syswarden \
  --signer-workflow duggytuxy/syswarden/.github/workflows/release-manager.yml \
  --source-digest c4bb1f7fdf48fd80652b6870af5babda0b16ad6e \
  --signer-digest c4bb1f7fdf48fd80652b6870af5babda0b16ad6e \
  --source-ref refs/tags/v4.10.4 \
  --deny-self-hosted-runners
```

Verify downloaded package hashes and native signatures before installation.
See [Getting started](https://syswarden.io/docs/getting-started/).

## Accepted scope and limits

- AlmaLinux 10.2 installation and upgrade preserve administrator groups, sudo
  policy, SSH access and unrelated firewall behavior with NetworkManager and
  firewalld present. IPv6 observations cover discovery, Router Advertisements,
  DHCPv6 renewal, policy/feed/frontend reloads and reboot.
- Debian 13 migration from the official v4.10.3 updater retains the exact
  authenticated candidate, rejects modified update material, and preserves VPN
  client identity, encrypted traffic and DNS over NAT after reboot.
- Standalone uninstall, APT remove, APT purge and deferred purge after an
  administrator edit have separate observations. Standard RPM erase, CLI
  uninstall, dependency-absent retry and optional package-owned RPM recovery
  preserve unrelated protection and acknowledged administrator files.
- Bounded recovery verifies ownership and reviewed digests. Private inactive
  backups are distinct from active configuration. Unknown or modified state
  remains a refusal requiring review.
- A bounded IPv4/IPv6 kernel comparison uses six paired rounds per family and
  48,000 UDP request-response samples. It is not a wire-rate, all-platform or
  HA endurance claim. APK has signature, build and payload verification,
  without a fresh Alpine native lifecycle in this campaign.

Original failed attempts remain retained evidence. The reviewed laboratory
scope does not guarantee every customized installation, provider network or
future external feed response. Pre-publication fields in sealed reports and
the candidate changelog describe the time they were written; this dated record
establishes the subsequent verified public outcome. Private configurations and
operational evidence are not release artifacts.
