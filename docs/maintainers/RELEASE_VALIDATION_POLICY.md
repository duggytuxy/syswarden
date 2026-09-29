# SysWarden release validation policy

Status: approved release strategy, 29 September 2026. Version-derived track classification is implemented. The separate intermediate acceptance and publication path remains pending; the current publisher still requires its existing qualification evidence. Track classification grants no release verdict.

## Two release tracks

**IVV** means Integration, Verification and Validation. It is the required assurance level for intermediate `Patch`, `Minor` and `Major` releases. **IVVQ** adds Qualification and applies to `Upgrade` generation releases such as v5.00.0 and v6.00.0. These terms describe the required work; classifying a release does not mean that work has passed.

| Track | Releases | Required assurance | Public claim |
| --- | --- | --- | --- |
| Upgrade IVVQ qualification | `Upgrade` transitions, including v5.00.0 LTS and v6.00.0 | Complete IVVQ against a versioned qualification plan, including all supported native profiles, lifecycle, migrations, HA endurance, performance, protected acceptance and verified restoration | Fully qualified only after acceptance passes |
| Intermediate IVV validation | `Patch`, `Minor` and `Major` transitions within a generation, including v4.10.0 | IVV through CI, security checks, package integrity, functional non-regression, installation/update coverage and tests selected by documented change impact | Validated for release under the named policy, with scope and limitations |

## Exact distinction in auto-versioning

The main release PR uses the canonical title prefix `Upgrade : <description>` to prepare a new generation. Preserve that prefix in the first line of its resulting commit on `main`: the current Auto-Versioning workflow validates the pushed head commit message, not a mere occurrence of the word in the PR body.

The release track follows the validated transition defined by `scripts/versionctl/version.go`:

| PR/commit prefix | Version effect | Example | Validation track |
| --- | --- | --- | --- |
| `Patch :` | Increment the last component | v0.00.0 to v0.00.1 | IVV |
| `Minor :` | Increment the middle component; reset the last to zero | v0.00.0 to v0.01.0 | IVV |
| `Major :` | Advance the middle component to its next multiple of ten; reset the last to zero | v0.00.0 to v0.10.0 | IVV |
| `Upgrade :` | Increment the first component; reset the other components to `00.0` | v0.00.0 to v1.00.0; subsequently v4.xx.y to v5.00.0 and v5.xx.y to v6.00.0 | Complete IVVQ qualification |

`Major` is a distinct SysWarden auto-versioning operation and does not mean `Upgrade`. It remains in the same generation. `Patch`, `Minor` and `Major` cannot overflow the middle component into the next generation; the version validator requires an explicit `Upgrade` instead.

Record the originating release PR, its recognized prefix, previous version and resulting version in the release plan. Subsequent corrective or policy-only PRs on that candidate do not downgrade an Upgrade release to intermediate validation. A v5.00.0 or v6.00.0 release remains on the full-qualification track until accepted. An inconsistent prefix/version combination is rejected.

The LTS label and the approximate three-month v5 development estimate do not select the track. The estimate is not an acceptance criterion or a promised release date.

## IVV checks for every intermediate release

1. Identify the previously published release, the exact candidate commit, source tree, build inputs, package hashes and policy revision. Freeze the release payload while validating it.
2. Require the applicable CI and security workflows to pass for that exact candidate. Preserve regression tests, provenance, package checks and security scanning. Record unresolved findings and their release disposition.
3. Verify the native signatures of all distributed package variants and the relation between source, build and final signed bytes. Reject altered packages, unknown signing identities and mismatched digests.
4. Cover installation, service startup, reload, persistence after restart, supported update paths and recovery. Test the affected packaging, init-system and platform variants. A platform newly supported by the release needs actual validation; a label or a container-only result cannot stand in for an untested native claim.
5. Exercise changed protections with positive and negative tests: a real expected block, legitimate traffic allowed, preserved operator access and rejection of invalid inputs. Include shared callers and dependencies in the impact analysis.
6. Resolve release-blocking defects and verify restoration of every modified lab node. Preserve failures, observations and cleanup evidence.
7. Produce a protected release-validation report binding the policy, exact source/payload identity, checks, retained evidence, justified omissions and known limitations. Only completed required checks may pass.
8. Create and verify an annotated signed Git tag. Attest the immutable release manifest and asset digests using Sigstore, then verify identity, issuer, source binding and all downloaded assets before publication. Native package signatures remain required. This defines what is signed; mutable GitHub page text alone is not the signed release payload.

Signing establishes the origin and integrity of the identified material. The validation report establishes which checks were performed. Neither substitutes for the other.

## Selective regression and retained evidence

Compare changes both with the last public release and with the last tested candidate. A short final patch does not erase the risks of earlier unpublished changes.

Retain every historical result with its original commit, package hashes, environment, timestamps and verdict. A new decision may cite that result as support; it must not rewrite it as a fresh pass on another candidate.

An explicit impact record must identify changed runtime code, shared dependencies, configuration, package scripts, toolchain, catalogue and test machinery. It states which checks remain relevant, which require fresh observations and which complete-qualification campaigns are outside the intermediate release claim. Unknown impact requires investigation or additional testing.

Long endurance and broad performance campaigns are not automatic requirements for an intermediate release. Run targeted functional HA and recovery checks when activation or integration changes. Repeat the relevant endurance or performance campaign if the changed mechanism, an observed regression or the release's advertised claim requires it. A security, compatibility or migration defect is not waived merely because the version is intermediate.

For policy-only or documentation-only commits, retain product evidence only after verifying identical release inputs and payloads, or documenting and verifying an explicitly allowed build-metadata difference. Record `product_candidate`, `publication_commit` and `policy_commit` separately. A changed full commit hash alone need not trigger every native campaign, but no identity substitution or unverified binary equivalence is allowed.

## CI integration

Implement a versioned `intermediate-release-validation` contract alongside full qualification. Keep its schema, artifact and success claim distinct from `syswarden-release-qualification`.

The publisher must select the track from validated version-transition data and the originating release PR recorded in the reviewed release plan, using the mapping above. Do not infer the track from the generic word "major" or only from the latest corrective PR. Reject unknown policies, inconsistent prefix/version combinations, missing checks and attempts to select the intermediate track for an `Upgrade`. Do not implement a free-form `skip_qualification` switch or convert old missing gates into successful qualification results.

Adapt both release coordination and the privileged publishing job to verify the same report, exact candidate, policy and artifacts independently. Preserve the protected release environment, native signing and final provenance verification.

Regression tests for this workflow change must reject a wrong candidate, substituted package, untrusted signer, missing required check, old verdict relabeled as current, unapproved evidence continuity and an `Upgrade` using intermediate validation. Include valid cases for all four prefixes, v4 to v5 and v5 to v6 Upgrade transitions, rejection of a `Major` generation change, and preservation of the Upgrade track across subsequent corrective PRs.

The existing frozen qualification contracts and their historical verdicts remain unchanged. The new track changes the release assurance claim prospectively. Publication remains unavailable through the current workflow until this implementation has been reviewed and merged and the selected track has passed.

## Read-only implementation

`./scripts/versioning.sh release-track --repo . --tag v4.10.0` validates the same source, changelog and linear release history as `validate-release`, but also works before a tag is created. It emits JSON identifying the candidate, originating transition, prefix, track and intervening corrective commits. An existing tag must still resolve to HEAD. Historical versions before the existing v4.03.3 release-chain boundary remain outside this command; the v0 examples above illustrate version arithmetic.

The Auto-Versioning, qualification and publication workflows record this classification. Its JSON explicitly sets `qualification_passed` and `publication_authorized` to false. It does not admit old results to a new candidate or bypass the frozen publisher gates.
