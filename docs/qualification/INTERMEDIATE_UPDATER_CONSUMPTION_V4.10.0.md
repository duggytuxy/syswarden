# Reusing the original signed IVV updater

The signed updater run `36622881503` was produced on
`2b35616c686210886c71d0e207f0ded2ccf256a4`. Its packages belong to product
`f334beaddc5c6005f40d79c7bab4e43598bfc5ed`. Publication tooling can advance
without rebuilding these packages or changing either original identity.

`scripts/ci/release_ivv_updater.py` verifies this prerequisite using two clean
checkouts: the original producer and the proposed publication commit. It runs
the original independent consumer again, including its GitHub run, Sigstore
provenance and Ed25519 manifest checks. An old pass JSON is not an input.

The consumer pins GitHub artifact `11059596903`, its exact archive bytes and its
descriptor. Every staged file must equal its corresponding original ZIP entry.
Download expiry does not invalidate locally retained signed bytes. Verification
still queries the original artifact/run identities and checks its signatures.

The original plan and verification code stay unchanged. A narrowly scoped
extension allows only this consumer, its tests and this document beyond the
existing reviewed plan. The publication must descend from the original producer.
Changes to frozen runtime, packaging, native trust roots or verifier dependencies
are rejected. Further acceptance/publisher integration needs a separate reviewed
extension; these files do not enable the publisher.

```sh
python3 scripts/ci/release_ivv_updater.py \
  --repository /absolute/publication-checkout \
  --publication-sha FULL_PUBLICATION_COMMIT \
  --producer-repository /absolute/clean-producer-checkout \
  --native-bundle /absolute/original-signed-native-bundle \
  --candidate-bundle /absolute/original-extracted-updater \
  --archive /absolute/original-updater-artifact.zip \
  --output /absolute/new-verification.json
```

The output keeps native update acceptance, intermediate release validation,
qualification and publication authorization false. The two native migrations,
independent offline update, restorations and protected global IVV acceptance
remain separate requirements. No historical verdict is transferred.

Regression tests use explicitly synthetic archives and Git histories. They
cover input replacement, unsafe/duplicate ZIP entries, branch/fork/run identity,
dirty checkouts, altered verifier code, changed product inputs and a rejected
Upgrade classification. They provide no native migration evidence.
