# Publication source continuity and required assurance producer

The product remains `f334beaddc5c6005f40d79c7bab4e43598bfc5ed`. The original
signed updater producer remains `2b35616c686210886c71d0e207f0ded2ccf256a4` and
its merged independent consumer remains `3e66ea186f5b1ae5eb851859aa72d2440157bf17`.
A publication checkout is a separate identity. None of these helpers transfers a
native verdict or rebuilds the frozen signed packages.

`release_ivv_publication.py` extends the original input preflight without editing
its historical plan or verification dependencies. It admits the three PR276
consumer files, the exact README addition merged in PR277, and these two new
helpers, their tests and this document. The README Git blob must match the reviewed
addition. Every original updater verification dependency, including the merged
independent consumer, must still match its original Git blob. Runtime, package,
trust-root and unlisted build-input changes are rejected.

The helper rechecks the five frozen package/signature inputs and seven retained
records against their original reviewed hashes. Historical records keep their
original candidate and remain unaccepted as current passes. A clean, complete
Git checkout is mandatory. Replacement refs, grafts, hidden index changes and
uncommitted changes are rejected.

`release_assurance_contract.py` derives the producer contract from the actual Git
version transition. Upgrade always selects the full IVVQ workflow. The reviewed
v4.10.0 Major transition selects the separate IVV producer identity. Future
intermediate releases require a new reviewed product plan. No user-provided skip
flag or claimed pass can change this selection.

Its metadata checks require one completed, successful, owner-dispatched attempt
on exact main, the correct workflow and repository, no concurrent producer, and
one unexpired digest-bound artifact from the same run. A fork with the same SHA,
another workflow, a retry, an ambiguous run or a substituted artifact is rejected.
These are metadata checks only. A real consumer must additionally authenticate
the producer attestation, inspect the exact report and verify all required checks
and frozen asset bytes.

## Revalidate the original updater from publication tooling

Supply all four optional updater inputs to the publication preflight:
`--original-consumer-repository`, `--original-producer-repository`,
`--candidate-bundle` and `--candidate-archive`. The consumer checkout must stay
at `3e66ea18` and the producer checkout at `2b35616c`. The package root is the
complete original native-signed bundle. Partial input sets are rejected.

This path executes the unchanged updater verifier, including the producer-era
consumer, GitHub run and artifact checks, Sigstore provenance and Ed25519 manifest
verification. It binds that fresh result to the separately verified publication
checkout. The original verifier dependencies stay pinned; a supplied success
receipt cannot replace execution. Source identities are rechecked afterwards.
Without these four inputs, the output remains only a source/input preflight.
Neither output grants native-update acceptance or release acceptance.

## Integration still required

These helpers do not modify or enable the publisher. The protected IVV producer,
its evidence validator and the three independent publication boundaries still
need integration and review. `.github/workflows/release-ivv.yml` is the required
future producer identity, not a claim that such a run exists. The current Upgrade
workflow and its frozen verifier remain untouched.

Before any release, finish the native final-package HA observations and all
restorations, explicitly review the known private APK3 offline-updater limitation,
and execute protected global IVV acceptance. Tag and release authenticity remain
separate post-acceptance requirements. Local synthetic tests do not replace any
of these observations.
