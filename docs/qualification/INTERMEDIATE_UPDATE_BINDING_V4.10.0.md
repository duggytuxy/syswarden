# Protected offline updater for a retained IVV product

The v4.10.0 product remains `f334beaddc5c6005f40d79c7bab4e43598bfc5ed`.
The reviewed IVV release tools advance independently. Previously the protected
candidate updater required both identities to be identical, preventing the
remaining NODE01 migration and offline-update tests from using those frozen
packages after policy-only changes.

`candidate-update-bundle.yml` now accepts an optional `publication_sha`. When
omitted, the existing exact-product producer and descriptor v1 remain unchanged.
When provided, the workflow must run on that exact reviewed main commit, in the
same protected environment, on a GitHub-hosted runner, as the repository owner.
`release_sha` still identifies the product and its native signing run. The new
relation is restricted to the pinned v4.10.0 IVV plan, never an Upgrade exception.

Before the signing secret is exposed, `candidate_update_binding.py` independently
checks complete version history, the original Major transition, the exact
reviewed tooling allowlist, and all five frozen package/signature file hashes.
It repeats these checks immediately before signing and while sealing the bundle.
The manifest generation tool, embedded updater trust root and product inputs
remain byte-identical to the product commit. Native signing provenance is checked
through the existing qualified bundle verifier and immutable artifact selection.

A distinct-product run emits descriptor **v2**, embedding the recomputable source
binding. Its release SHA is the original product; its producer workflow SHA and
GitHub attestation identify the publication/tooling commit. Attestation consumers
must verify that exact producer digest and the full reviewed binding. A v1-only
consumer must reject v2 rather than silently equating the commits. The node's
three-file offline package channel and signed manifest v1 remain unchanged.

This producer signs a candidate updater for testing, not a release. It has no
contents-write permission and neither creates a tag nor publishes packages.
No native result is transferred or marked as newly passed. Protected IVV
acceptance, remaining native observations and
release publisher integration remain required. Full IVVQ contracts are unchanged.

Validation covers the real context shell guards, independent Git/file binding,
wrong product or producer, altered package bytes, links, dirty/hidden changes,
concurrent source changes and an Upgrade attempting intermediate validation.
All inputs used in unit tests are synthetic and never native evidence.

## Independent consumer before a NODE01 test

`candidate_update_bundle_verify.py` consumes v2 explicitly. It requires the clean
producer checkout, the original four-variant native signing bundle, the downloaded
candidate bundle and the exact successful producer run. It recomputes the source
relation and signed package bytes, validates the complete inventory and descriptor,
checks the GitHub run identity, cryptographically verifies the GitHub/Sigstore
attestation against the producer digest and exact invocation, and executes the
unchanged Ed25519 update-manifest verifier. It rereads all inputs afterward. Its
receipt remains explicitly non-accepting for release; a failed cryptographic
check or unknown schema produces no receipt.

```sh
python3 scripts/ci/candidate_update_bundle_verify.py \
  --repository /absolute/clean/producer-checkout \
  --publication-sha <reviewed-producer-commit> \
  --product-sha f334beaddc5c6005f40d79c7bab4e43598bfc5ed \
  --native-bundle /absolute/private/original-native-bundle \
  --candidate-bundle /absolute/private/downloaded-candidate-bundle \
  --producer-run-id <successful-protected-run-id> \
  --output /absolute/private/new-consumption-receipt.json
```

The verifier invokes the installed `gh` and pinned Go toolchain. It performs
read-only GitHub requests and verification, with no signing key or host mutation.
