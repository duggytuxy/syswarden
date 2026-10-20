# Plumber control coverage

The GitHub compliance workflow pins both the action and the scanner to Plumber
v0.7.9. The action is pinned by commit, and the downloaded Linux AMD64 scanner
must pass checksum and build-provenance verification. Checkout remains pinned
to v7.0.1 with credential persistence disabled.

## Coverage and score

The public score page's enabled-control fraction is not the number of passing
CI checks. It can include controls introduced after the scanner used by the
published analysis. Inspect the report from the exact commit and its scanner
version before interpreting that fraction.

The earlier v0.4.55 report passed its enabled controls but did not contain the
new workflow-validity and untrusted-cache-write checks. The current default
policy includes those checks and revised checkout analysis. SysWarden also
requires the presence of Plumber, Scorecard and build-provenance actions as
one mandatory group. This presence check complements the workflow contract
tests; it does not prove that every action executed on every event.

The gate remains 100 points, with warnings treated as failures. There is no
soft failure, skipped-control list or finding exemption. Pull requests have
read-only repository and Actions permissions. Score publication and SARIF
upload run only on push or schedule with their dedicated permissions.
Publication jobs cannot replace the pull-request check, or conversely.

## Direct Trivy execution

The security workflow already installs Trivy 0.70.0 from a SHA-256-pinned
Linux AMD64 archive. It now invokes that verified binary directly for the
source SBOM and vulnerability scan. This removes the unused nested installer
and its checkout from the third-party action graph. SPDX/SARIF output,
CRITICAL/HIGH failure, OS/library scope and artifact validation remain required.

## Exact Markdown bundle

Markdown lint retains the bundled v23.2.0 action code, including
markdownlint-cli2 v0.22.1. The runner downloads its immutable Git blob through
the GitHub API, decodes base64 and verifies SHA-256 before Node executes it.
This avoids a source-fetch failure in the scanner and preserves control bytes.
Node is pinned to 24.19.0; no package installation or mutable dependency
resolution occurs. Incorrect runtime, download, digest or lint results fail
the step. The temporary bundle is removed after execution or refusal.

The unused Markdown and Trivy action entries are removed from the custom
trusted-action list. Neither analyzer has been removed from the security gate.

## Release evidence

The release gate continues to require a successful report, exactly 100 points,
no severity findings, complete branch-protection data, the exact release
commit and identical analyzed workflow bytes. It rejects degraded collection.
The newer report includes more evidence: the independent limits are 1 MiB for
the uncompressed report and 2 MiB for the whole uncompressed archive. Member
type, path, duplicate, compression and declared/actual size checks remain in
place. A compressed ZIP size is not evidence of bounded extracted content.

Historical sealed reports are not rewritten. The isolated GitLab template
has a separate component and registry-digest contract; its old mirrored
v0.4.55 image is not silently relabelled as this GitHub scanner upgrade.
Updating it requires verification of the replacement component and image.

## Verification boundary

Local checks can validate the policy, workflows, real scanner output and
release-reader compatibility without publishing a score. Hosted checks must
still prove the GitHub token permissions, OIDC publication and uploaded
artifacts on the exact candidate commit. A CI compliance score is not final
SysWarden v5.00.0 IVVQ acceptance.

References:

- [Plumber v0.7.9 release](https://github.com/getplumber/plumber/releases/tag/v0.7.9)
- [Pinned action and inputs](https://github.com/getplumber/plumber/blob/93ea968a173204b9a7f91df270a4e853845aefa3/action.yml)
- [Pinned default policy](https://github.com/getplumber/plumber/blob/93ea968a173204b9a7f91df270a4e853845aefa3/defaultConfig/.plumber.yaml)
