# v4.10.2 publication record

SysWarden v4.10.2 was published on **2 October 2026 at 19:30:48 UTC**.
This stable **Patch** release passed its protected intermediate **IVV**.
An `Upgrade` generation still requires full **IVVQ**; this record does not
claim that broader qualification.

The patch addresses historical WireGuard and package removal boundaries
tracked in [issue #283](https://github.com/duggytuxy/syswarden/issues/283).
The [recovery runbook](../../technical/WIREGUARD_LEGACY_RECOVERY.md) covers
recognized dual-generation state, interrupted removal and older installations
that cannot upgrade normally while their removal barrier remains present.

## Exact identities

| Boundary | Identity |
| --- | --- |
| Tested and signed product | `94d97f07cb5a054669dd66d6efd28ba55db5d173` |
| Publication commit | `4bb302512636b001ecf78490177d3d4883513838` |
| Signed annotated tag object | `e2cf94187648b532de9816934195110af3371444` |
| Release | [v4.10.2, ID 402098079](https://github.com/duggytuxy/syswarden/releases/tag/v4.10.2) |
| Protected IVV producer | [37050993460](https://github.com/duggytuxy/syswarden/actions/runs/37050993460) |
| IVV artifact | `11247310563`, `syswarden-release-ivv` |
| IVV artifact SHA-256 | `070c9add3b10b4802cba5366cfeb42df2f1a8b27e53d8eefea35502898813430` |
| Original IVV report SHA-256 | `4435ec37ad3b1dc624bc950a0d8c234745f77dbfb10c037545f2ca8c629de221` |
| Protected publisher | [37053860325](https://github.com/duggytuxy/syswarden/actions/runs/37053860325) |

The protected IVV accepted all eleven required checks. Its original report and
GitHub attestation remain in the producer artifact, unchanged. Pre-publication
flags in that report describe acceptance time and are not rewritten after
publication. Private raw observations are not included in this record.

All three required tag workflows passed: [packages](https://github.com/duggytuxy/syswarden/actions/runs/37052260264),
[security](https://github.com/duggytuxy/syswarden/actions/runs/37052260278) and
[Plumber](https://github.com/duggytuxy/syswarden/actions/runs/37052260169).
The publisher then completed through its protected production environment
after the required owner approval. No manual publication recovery was needed.

## Public files and signatures

The release contains twelve files, including four signed Linux package
variants: DEB, standard RPM, package-owned RHELPO RPM and APK. The remaining
files are the detached DEB signature, two checksum inventories, release archive,
SPDX SBOM, Plumber report and signed updater manifest with its signature.

All twelve files were downloaded from their public URLs without credentials.
Their names, sizes and SHA-256 digests match the release metadata and exact
staged inventory. Each GitHub Sigstore attestation verifies against the
release-manager workflow, publication commit and `refs/tags/v4.10.2`.
The native packages, updater and product archive retain the exact bytes
accepted by the IVV consumer. The updater's Ed25519 signature was verified
separately. Release metadata remained unchanged across the download check.

The [independent verification record](PUBLIC_RELEASE_VERIFICATION.json)
lists each file, public asset ID, size and SHA-256 digest. It records the
post-publication verification; it is not a replacement for the original
cryptographic attestations.

The exact public [RELEASE_SHA256SUMS.txt](RELEASE_SHA256SUMS.txt) covers the
eleven other release files. Its own SHA-256 is
`dc05f47c680c17face9deee2f2f4068b83007f819285177a34f1c1cc220452c6`.

## Personal Sigstore signature

The maintainer additionally signed the exact checksum manifest with Sigstore
identity `laurent@data-shield.eu`, issuer `https://github.com/login/oauth`.
The original [verification bundle](RELEASE_SHA256SUMS.sigstore.json) preserves
its certificate, signature and transparency-log proof without modification.
Independent verification checked this exact identity, issuer and manifest
SHA-256. The [Rekor entry 3060931957](https://search.sigstore.dev/?logIndex=3060931957)
records the signature. This additional signature complements the twelve
workflow attestations; it does not change the release asset inventory.

With a separately trusted Cosign installation, run from this directory:

```bash
cosign verify-blob \
  --bundle RELEASE_SHA256SUMS.sigstore.json \
  --certificate-identity laurent@data-shield.eu \
  --certificate-oidc-issuer https://github.com/login/oauth \
  RELEASE_SHA256SUMS.txt
```

## Accepted correction scope

- Detect recognized historical claims on the reserved WireGuard namespace
  before installation, reconciliation or a new removal barrier.
- Produce a read-only retirement plan, reject active or enabled historical
  VPNs, and require explicit authorization bound to the exact plan digest.
- Retire supported historical state after the operator stops the old service,
  including an already absent NAT table and exact residual forward rules.
- Preserve current manifest-owned state, unrelated administrator policy and
  private recovery backups; reject unsupported or drifting ownership.
- Resume interrupted removal through the native package manager and cover the
  original single-generation cleanup case.
- Prevent direct CLI uninstall from deleting registered package payload,
  including unpacked and half-configured registrations. Verify native removal,
  same-version reinstall and repair of the older missing-payload condition.
- Verify recurrence prevention across update and reboot after retirement.

## Evidence limits

Fresh native observations cover supported historical state reconstructed on
Debian 13 with synthetic keys and a relevant hardening subset. They do not
reproduce every customized installation or every upgrade sequence since v3.
Historical VPN retirement remains an explicit operator decision requiring
independent administrative access. Unknown ownership and custom configurations
remain safe refusals.

Retry after a controlled archival I/O failure was tested. Process-kill and
power-loss durability are not claimed. Operator configuration and lists were
explicitly restored after purge; automatic retention across purge is not
claimed. The offline update observation used the attested candidate CLI, not
the installed older production updater.

Earlier platform, service and HA observations keep their original identities
under the named continuity plan. No fresh all-platform lifecycle, HA endurance
or broad performance campaign is claimed. The test baseline was restored and
verified. Original failed harness captures remain in the private evidence and
are not relabeled as successful observations.

The earlier v4.10.1 tag and unpublished draft remain unchanged. Their evidence
is not relabeled as v4.10.2 acceptance. This record claims neither regulatory
certification nor zero regression risk.
