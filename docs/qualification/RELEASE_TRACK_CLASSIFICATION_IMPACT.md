# Release-track classification impact

Product baseline: `f334beaddc5c6005f40d79c7bab4e43598bfc5ed`.

This change implements the approved IVV/IVVQ distinction in version history and records it in Auto-Versioning, full qualification, release coordination and privileged publication. It adds no release verdict and does not yet activate intermediate acceptance or replace the existing publisher contract.

The original v4.10.0 transition is `76535e03ee10b78f9c6ed1665d7fbeb8c2b8ee68`, from v4.04.3 using `Major`. On the product baseline, the resolver traversed 74 non-versioning follow-ups and selected `intermediate-validation`. The intermediate track requires IVV (Integration, Verification and Validation). An Upgrade from v4 to v5 or v5 to v6 selects `full-qualification`, requiring IVVQ with Qualification added, even after corrective follow-ups.

No runtime, catalogue, package recipe, native qualification contract, signature validator or historical verdict changes. The version-chain validation implementation is shared between the existing tagged-release command and the new read-only pre-tag classification command. Existing tagged-release requirements remain tested.

A successful classification is not completed product validation. The report explicitly sets `qualification_passed` and `publication_authorized` to false. Existing exact-candidate CI, signing and acceptance requirements continue to apply. All prior product proofs retain their original commit and package digests; this CI change does not transfer them to its eventual merge commit.

The separate intermediate acceptance/publishing implementation must bind the frozen product candidate and package digests separately from the policy/tooling commit, verify the approved impact plan and required fresh observations, and reject an Upgrade downgrade. In particular, it must not treat an intermediate prefix as proof that the new generation's initial Upgrade was already qualified. This is the next implementation boundary, not a successful gate supplied by this PR.

Validation: Go 1.26.6 versionctl tests and vet; all 181 release validator/workflow Python tests; YAML parsing and bash syntax checks for the five classification steps; an actual v4.10.0 history resolution. These are tooling regressions, not newly executed native product campaigns.
