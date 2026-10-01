# v4.10.0 publication record

SysWarden v4.10.0 was published on **1 October 2026 at 11:49:43 UTC**.
It is a stable intermediate **IVV** release. Full **IVVQ** remains required for
`Upgrade` generations such as v5.00.0 and v6.00.0.

## Exact identities

| Boundary | Identity |
| --- | --- |
| Tested product | `8c3405758a9b369924f466d12652e99d3a84dc56` |
| Publication commit | `3cc06b62d42b5adadc46fc9a252fece5adf670c1` |
| Signed annotated tag object | `9d4945fa44c8095c8401950cfb21630c833598b5` |
| Release | [v4.10.0, ID 400909549](https://github.com/duggytuxy/syswarden/releases/tag/v4.10.0) |
| Protected IVV producer | [36853355288](https://github.com/duggytuxy/syswarden/actions/runs/36853355288) |
| IVV report SHA-256 | `fbe8be950f07b2518be34a9902dbd1253ff6c32f4f700b917c6ea49c67384047` |

The protected producer accepted all twelve required checks. The original
[report](RELEASE_IVV.json) and its [GitHub attestation](RELEASE_IVV.intoto.jsonl)
are preserved byte for byte. Their pre-publication flags describe acceptance
time; they are not rewritten to describe the later publication.

All three applicable tag workflows passed: [packages](https://github.com/duggytuxy/syswarden/actions/runs/36854246468),
[security](https://github.com/duggytuxy/syswarden/actions/runs/36854246367) and
[Plumber](https://github.com/duggytuxy/syswarden/actions/runs/36854246376).
Plumber on the exact publication commit reported **A, 100/100**, with zero
critical, high, medium or low findings in the verified report.

## Signed assets

The twelve release files include four Linux package variants: DEB, standard
RPM, package-owned RHELPO RPM and APK. The remaining files are the detached DEB
signature, two checksum inventories, the release archive, SPDX SBOM, Plumber
report and the signed updater manifest with its detached signature.

All twelve files were downloaded again through their public URLs without
credentials. Their sizes and SHA-256 digests match the exact validated private
draft; all twelve original GitHub build-provenance attestations verify against
the release-manager workflow and publication commit above. Native package
signatures and the updater's Ed25519 trust boundary remain distinct controls.

The maintainer personally signed [RELEASE_SHA256SUMS.txt](RELEASE_SHA256SUMS.txt)
with Sigstore identity `laurent@data-shield.eu`, issuer
`https://github.com/login/oauth`. This manifest covers the eleven other release
files. The [verification bundle](RELEASE_SHA256SUMS.sigstore.json) includes the
certificate, signature and transparency-log evidence. The public
[Rekor entry 3035233768](https://search.sigstore.dev/?logIndex=3035233768)
records its digest and signing identity, not the private native captures.

Using a separately trusted cosign installation, run from this directory:

```bash
cosign verify-blob \
  --bundle RELEASE_SHA256SUMS.sigstore.json \
  --certificate-identity laurent@data-shield.eu \
  --certificate-oidc-issuer https://github.com/login/oauth \
  RELEASE_SHA256SUMS.txt
```

## Publication recovery

The [original protected publisher](https://github.com/duggytuxy/syswarden/actions/runs/36855763817)
created and attested the complete draft, then failed while reading that private
draft through GitHub's published-release-by-tag endpoint. Its failed conclusion
is preserved; it is not reported as a successful workflow.

The owner explicitly approved a bounded recovery from the owner session. The
frozen publication step was executed with only the read endpoint corrected to
its previously verified release ID. Protected-environment and immutable-tag
checks, the exact metadata snapshot, asset inventory and tag identity were
rechecked before publication. No file, tag, package, protection setting or
acceptance verdict was changed. Public downloads and signatures were then
independently verified again. This exception is specific to this release;
normal protected publication remains the policy for future releases.

## Evidence scope

Fresh product checks cover the four firewalld profiles and functional HA.
Earlier Ubuntu, Alpine, migration and offline DEB-update evidence retains its
original candidate identity and is admitted only through the named source and
payload continuity assessment. Historical thirty-minute HA campaigns remain
bound to their original candidate; no new thirty-minute campaign is claimed
for `8c340575`. Native traffic evidence is IPv4. IPv6 lists and kernel states
were checked, without a native IPv6 traffic claim. The private APK 3
qualification-bundle updater path is outside this IVV plan.

All five laboratory nodes were restored and temporary access removed. Private
captures remain encrypted in the maintainer's evidence store. This record does
not claim regulatory certification, zero regression risk or full IVVQ.
The original release notes preserve the frozen development changelog wording;
this dated record states the completed release decision.
