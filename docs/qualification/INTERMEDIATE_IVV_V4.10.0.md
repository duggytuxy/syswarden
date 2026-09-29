# v4.10.0 intermediate IVV plan

Status: reviewed-plan proposal and input preflight, not release acceptance.
The existing publisher remains closed until the protected IVV producer and
independent publishing consumers are implemented and the required checks pass.

## Frozen identities

- Last public release: v4.04.3, commit
  `381c1f8d91459a9b20605629c725900abd81dee8`, GitHub release `384037482`.
- Product candidate: `f334beaddc5c6005f40d79c7bab4e43598bfc5ed`.
- Historical tested candidate: `24c3c6e1548b8db0ccf64c37a33e05b351be5a18`.
- Original transition: `76535e03ee10b78f9c6ed1665d7fbeb8c2b8ee68`,
  `Major`, from v4.04.3. This selects IVV. An Upgrade remains IVVQ after
  corrective follow-ups; it cannot use this v4.10.0 plan.
- Publication commit: recorded separately at preflight time. Only the exact
  reviewed documentation and release-tooling paths may differ from the product.
  Unknown paths, package recipes, toolchains, runtime, catalogue, native trust
  roots and other build inputs remain frozen.

The machine-readable plan is `scripts/ci/release_ivv_plan_v4.10.0.json`.
Its SHA-256 is pinned in `release_ivv_plan.py`. It anchors all four signed package
variants and the detached DEB signature. No package is rebuilt or relabeled by
this preflight. It also anchors seven retained receipts without publishing raw
captures, host addresses or local filesystem paths.

## Finite IVV scope

The fourteen groups below are requirements, not fourteen new native campaigns.
Several use existing evidence. An available receipt is not independently
authenticated merely because it is listed here.

| Group | Disposition |
| --- | --- |
| Exact CI and security | Retain product CI and verify the final publication commit's applicable CI. Resolve every release-blocking finding. |
| Native signatures | Keep the frozen four signed variants; independently verify their production identities, signature validity and provenance before publication. |
| Source and payload continuity | Prove product inputs and signed bytes unchanged across documentation/tooling commits. Keep both commit identities. |
| List regressions | Cover IPv4/IPv6, seeded entries, shared blocklists, first reload, missing files after initialization and unsafe input rejection. |
| Native activation | Target DEB-U2604, RPM-A9, RPM-A10, RPM-A9-RHELPO and APK-324 for changed list activation, real expected SSH blocking, legitimate operator access, reload and restart persistence. Keep the full exact-product RPM-A10-RHELPO PASS with its verified restoration. |
| Alpine SSH provenance | Keep the failed original reproduction. Confirm authentic native envelopes are recognized and untrusted lookalikes are rejected. |
| Lifecycle continuity | Revalidate the retained five-profile lifecycle record on its original candidate, then pair it with fresh affected activation coverage. Do not rewrite its verdict. |
| NODE01 migrations | Complete the two still-missing native migration paths, including service/configuration ownership, recovery and restoration. |
| Offline update | Complete the independent signed candidate update, with exact package and installed CLI binding, substituted-input rejection and no network fallback. |
| HA | Retain both historical 30-minute campaigns and their signed statement. Review all unpublished HA changes; add final-package functional bootstrap, replication and restart/recovery coverage. Repeat endurance only when an affected mechanism, observed regression or release claim requires it. |
| Feed and allocation | Preserve original measurements, verify unchanged mechanisms and affected list integration. Broad performance qualification is outside this intermediate claim unless justified by impact. |
| Restorations | Verify every modified native host and its original network protection after testing. |
| Protected acceptance | Seal and independently recompute the IVV decision under the protected release environment, using the reviewed plan, exact inputs and completed checks. This is not implemented by the input preflight. |
| Release authenticity | After acceptance, verify the signed annotated tag, immutable release manifest, Sigstore identity and downloaded asset digests before publication. |

This scope considers both the previous public release and the previous tested
candidate. The final whitelist correction does not erase earlier unpublished
HA, update, migration, logging or packaging changes. The existing exact-product
RHELPO result remains valid for its original profile; the historical HA,
lifecycle, APK, standard RPM, feed and allocation results retain their original
candidate and package bindings.

## Claim boundary

The release may claim validation under this IVV policy only after protected
acceptance passes. It may not claim full IVVQ qualification or absence of all
regressions. The performance and qualification producers described in the
changelog are implemented mechanisms, not proof that every campaign has passed
on the final publication commit. Existing frozen IVVQ contracts and historical
verdicts are not edited by this plan.

## Read-only input preflight

Use a clean publication checkout with full history and the pinned Go toolchain.
Stage exact private receipt bytes as `<id>.json` for each `retained_records` ID.
The package root is the original signed bundle, retaining its existing paths.

```sh
python3 scripts/ci/release_ivv_plan.py \
  --repository "$(pwd)" \
  --publication-sha "$(git rev-parse HEAD)" \
  --evidence-root /absolute/private/retained-evidence \
  --package-root /absolute/private/signed-product-bundle \
  --output /absolute/private/new-ivv-preflight.json
```

This verifies the original version transition, complete source diff, reviewed
plan hash, package/signature bytes and original receipt hashes. It rejects dirty
checkouts, unknown source changes, Git replacement history, symlinks, hard links,
altered inputs, historical-candidate relabeling and Upgrade downgrades. It never
overwrites an existing output. All release-acceptance and publication flags in
its distinct `syswarden-intermediate-ivv-preflight/v1` schema remain false.

The protected acceptance consumer must not accept this preflight as a passing
release report. Cryptographic revalidation, targeted native observations, explicit
evidence admission and the protected publisher integration remain required.
