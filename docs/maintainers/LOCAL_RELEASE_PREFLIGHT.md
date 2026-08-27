# Local Release Preflight and Prequalification

This procedure requires a complete local pre-push gate for every
repository-local check that can be reproduced safely before a GitHub push. It
also defines an optional hardware-dependent local prequalification rehearsal.
Neither phase replaces the required checks on the merged `main` SHA or the
protected remote qualification.

## Authority boundary

The preflight and rehearsal phases are read-only with respect to GitHub and
release state. They must not create or update a remote branch, tag,
environment, deployment or Release. They may write only to ignored local
cache, evidence, package and test directories. The later push is a separate
post-preflight action governed by the release sequence below.

The workflow files in `.github/workflows/` remain authoritative. A gate may be
reported as reproduced only when it used the workflow's command, tool version,
working directory, environment and architecture. A translated command or
different tool is supplemental evidence, not a mirrored gate. GitHub service
controls and host-bound controls that the local runner cannot provide must be
listed explicitly as remote-only. They must never be reported as locally
passed.

## Entry conditions

Before starting:

1. Identify one full candidate commit SHA and verify its signature against the
   approved maintainer key.
2. Require exactly one recognized `Patch :`, `Minor :`, `Major :` or
   `Upgrade :` transition after the current reviewed release version. Any later
   candidate commits must form one linear, non-versioning chain, preserve every
   version target and keep `changelog.md` byte-for-byte identical. The release
   validator must trace that chain back to the exact transition. This generic
   chain contract validates v4.03.3 and later releases. Earlier immutable
   releases are revalidated from their published tag, asset and digest evidence,
   not replayed through the current release orchestrator.
3. Require a clean main repository worktree and a clean, explicit wiki
   checkout.
4. Confirm that no candidate tag or public Release exists.
5. Confirm the expected previous public tag and candidate version with
   `scripts/versioning.sh`.
6. Create fresh ignored cache and evidence directories bound to the candidate
   SHA. Never reuse a prior candidate's outputs.
7. Record the Go, Python, gosec, ShellCheck, Bubblewrap, nftables, package
   manager and container runtime versions before executing a gate.

Any failed entry condition stops the procedure without changing remote state.

## Workflow coverage ledger

Every workflow must be classified before a release PR is pushed. A local PASS
applies only to the controls listed in the local column. The remote-only column
remains mandatory on the exact GitHub candidate or merged SHA.

| Workflow | Mandatory or available local evidence | Remote-only evidence |
| --- | --- | --- |
| `auto-versioning.yml` | Version inspection, recognized transition validation and candidate-bound Act event | Actual `main` push identity and protected branch result |
| `security-audit.yml` | Hygiene, tests, race, vet, fuzz, lint, gosec, nosec debt, Gitleaks, Trivy, SBOM, bundle and isolated golden test | Exact Ubuntu AppArmor host proof when unavailable locally, SARIF upload, OIDC attestation and GitHub artifact identity |
| `package.yml` | Validators, reproducible AMD64 builds, three package files, metadata, inventory and checksums in the pinned build environment | Unique successful `main` run and immutable GitHub package artifact identity |
| `scorecard.yml` | Workflow and policy contract tests | GitHub repository posture, Scorecard service result and SARIF publication |
| `compliance.yml` | Workflow and policy contract tests | Plumber service execution, GitHub OIDC result and remote score publication |
| `release-qualification.yml` | Optional native lifecycle, kernel and evidence-schema rehearsal when matching hardware and inputs exist | Protected environment review, ephemeral runner identity, authoritative run and artifact IDs, sealing and protected signing secret |
| `release-manager.yml` | Static release gates, version and signature checks, asset inventory and non-mutating negative tests | Ruleset revalidation, protected dispatch, tag creation, production approval and public Release publication |

## Candidate-bound Act event

The tracked `.github/act/push.json` fixture is test-only and is never release
evidence. Before any Act invocation, generate and validate a fresh ignored event
that binds the reviewed base and exact candidate commit:

```bash
set -euo pipefail
umask 077

SW_REPO="$(git rev-parse --show-toplevel)"
SW_BASE="$(git -C "${SW_REPO}" rev-parse origin/main)"
SW_SHA="$(git -C "${SW_REPO}" rev-parse HEAD)"
SW_MESSAGE="$(git -C "${SW_REPO}" log -1 --format=%B "${SW_SHA}")"

test -d "${SW_REPO}/tmp"
test ! -L "${SW_REPO}/tmp"
[[ -O "${SW_REPO}/tmp" ]]
SW_RUN="$(mktemp -d "${SW_REPO}/tmp/local-release-preflight.XXXXXX")"
SW_EVENT="${SW_RUN}/push.json"

jq -n \
  --arg base "${SW_BASE}" \
  --arg sha "${SW_SHA}" \
  --arg message "${SW_MESSAGE}" \
  '{
    act: true,
    ref: "refs/heads/main",
    before: $base,
    after: $sha,
    repository: {
      default_branch: "main",
      full_name: "duggytuxy/syswarden",
      name: "syswarden",
      owner: {login: "duggytuxy"}
    },
    commits: [{id: $sha, message: $message}],
    head_commit: {id: $sha, message: $message}
  }' > "${SW_EVENT}"

jq -e \
  --arg base "${SW_BASE}" \
  --arg sha "${SW_SHA}" \
  '(.act == true) and
   (.ref == "refs/heads/main") and
   (.before == $base) and
   (.after == $sha) and
   (.repository.full_name == "duggytuxy/syswarden") and
   (.commits | length == 1) and
   (.commits[0].id == $sha) and
   (.head_commit.id == $sha)' \
  "${SW_EVENT}" >/dev/null
```

Run Act only from a disposable clone bound to the exact candidate. The bind is
required because Act's copy mode can omit the Git index and turn the clean-tree
gate into a false result. Keep the digest-pinned runner mapping from `.actrc`
and require Act to pull that content-addressed reference:

```bash
set -euo pipefail

SW_CLONE="${SW_RUN}/candidate"
git clone --no-hardlinks --local "${SW_REPO}" "${SW_CLONE}"
test "$(git -C "${SW_CLONE}" rev-parse HEAD)" = "${SW_SHA}"
test -z "$(git -C "${SW_CLONE}" status --porcelain=v1 --untracked-files=all)"

(
  cd "${SW_CLONE}"
  act push \
    --workflows .github/workflows/auto-versioning.yml \
    --eventpath "${SW_EVENT}" \
    --bind \
    --pull=true
)

test "$(git -C "${SW_CLONE}" rev-parse HEAD)" = "${SW_SHA}"
test -z "$(git -C "${SW_CLONE}" status --porcelain=v1 --untracked-files=all)"
```

Pass `--eventpath "${SW_EVENT}"` explicitly to every Act command. Never rely on
the event path from `.actrc` for candidate evidence. Never bind the maintainer's
primary worktree; only the disposable clean clone is an allowed Act workspace.

## Mandatory local pre-push gate

Run the following groups before every push that can affect a release PR.

### Source and version contract

- `git diff --check` and an exact clean-worktree check;
- signed-commit verification against the approved SSH allowed-signers file;
- versionctl tests and vet with `GOWORK=off`;
- candidate version inspection and recognized transition commit-message
  validation;
- secret scanning over both Git history and the checked-out candidate;
- validation that ignored private evidence and build outputs are not tracked.

### Go modules

For CLI, Core and TUI, run the normal tests, race tests and vet with Go 1.26.6,
`GOFLAGS=-mod=readonly`, the repository `go.work` file and isolated per-module
caches. Run versionctl as its own module with `GOWORK=off`.

Build all three Linux binaries for AMD64 with the same PIE, linker, version and
reproducibility flags used by `build.ps1` and the Package workflow.

### Security workflow

Reproduce the Security Audit workflow with its pinned versions:

- gosec v2.28.0, including tests, for CLI, Core, TUI and versionctl;
- the reviewed nosec contract and empty gosec-baseline policy;
- Gitleaks history and candidate scans;
- Trivy and source SBOM validation;
- formatting, fuzz, lint and vulnerability checks.

Run the isolated nftables golden test in the pinned local sandbox. When an
Ubuntu 24.04 runner with the exact Bubblewrap package and AppArmor host policy
is available, also run the workflow's host AppArmor proof.

The golden test is mandatory before push. The AppArmor host proof may be marked
`REMOTE-ONLY` only when the local host cannot provide that exact Ubuntu kernel
and policy context. Act's sandbox shortcut is not an AppArmor proof. The remote
Security Audit check remains mandatory.

Do not make a baseline larger merely to obtain a green result. Fix production
findings. A test-only suppression is acceptable only when it names the exact
rule and documents the controlled fixture invariant on the same line.

### Package workflow

Run the package, stage, repository-state and release validators with the exact
Package workflow environment. Build and validate the three candidate packages:
DEB amd64, RPM x86_64 and APK x86_64. Package
lifecycle execution belongs to the optional prequalification rehearsal, not
the mandatory pre-push package build.

No local package output is public release evidence. It is an unsigned preflight
artifact bound to the candidate SHA.

### Documentation and image staging

Run the documentation unit tests and `scripts/ci/validate_documentation.sh`
against the explicit wiki checkout. Preserve its truth report and wiki line
inventory. Run the RHEL image-staging Bash syntax check, ShellCheck and complete
adversarial harness.

Public documentation must remain English and ASCII. The reserved DSI term and
the maintainer identity must remain confined to the private DSI report.

## Optional hardware-dependent local prequalification rehearsal

After the complete pre-push gate is green, a maintainer may rehearse the
non-secret technical qualification shards against the same candidate SHA. This
rehearsal is optional and never authorizes a merge, lot closure, tag or Release.

Use the three candidate packages produced by the Package workflow mirror. The
protected qualification downloads the unique successful Package `main`
artifact. It does not rebuild packages.

Run AMD64 lifecycle tests only on native AMD64 hardware. The workflow forbids
emulation. If native AMD64 hardware is unavailable, do not claim complete local
qualification.

Local and protected evidence files are not byte-comparable. They contain
timestamps, workflow run IDs, artifact IDs, host context and temporary paths.
Compare reproducible package bytes only when both builds used the same pinned
environment. Compare evidence schemas, bindings, inventories and embedded
digests semantically. Protected evidence remains authoritative.

The rehearsal must record each job name, command, working directory,
environment, tool version, start time, end time, exit code and log SHA-256. It
must also record every produced file path, size and SHA-256. A missing log or
output makes the rehearsal incomplete.

## GitHub-only gates

The following controls cannot be replaced by a local run:

- branch protection, Code Owner review and last-push approval;
- required GitHub checks on the exact merged `main` SHA;
- the protected qualification environment and its reviewer;
- unique workflow run and attempt validation;
- ephemeral self-hosted runner registration and remote identity checks;
- GitHub-hosted sealing, OIDC attestation and protected signing secrets;
- immutable tag rules, production approval and public Release publication.

Local prequalification may provide supplemental readiness evidence. Only the
protected remote sequence may authorize a lot closure, tag or Release.

## Failure handling

If any local group fails:

1. preserve the failing log and its SHA-256;
2. fix only the demonstrated cause;
3. rerun the affected group;
4. rebuild and sign a linear candidate history with exactly one recognized
   version transition and only non-versioning follow-ups that preserve every
   version target and `changelog.md` byte-for-byte;
5. rerun the complete mandatory pre-push gate on that exact clean commit
   because the candidate bytes and SHA changed;
6. push only the green commit, then request a fresh last-push review.

Never reuse a prior green result after a source, workflow, documentation or
wiki change.

## Release sequence

The maintainer may push the signed branch only after the complete mandatory
pre-push gate is green and every unavailable host-bound control is recorded as
remote-only. Push an amended candidate with `--force-with-lease`, never an
unchecked force update. The optional local prequalification rehearsal may run
when matching hardware is available, but it is not a condition for pushing.

After review and user-approved merge, require all main-push checks on the exact
merged SHA, then run the protected qualification. Compare eligible package
bytes and semantic evidence contracts with any local rehearsal, never evidence
file digests. Treat the protected result as authoritative.

After qualification succeeds, create the exact inspected candidate version
locally as an annotated SSH- or GPG-signed tag whose peeled commit is the exact
qualified `main` SHA. Verify the tag locally against the approved signer before
pushing only that tag reference.
The publisher rejects a lightweight tag, a tag that peels to another commit, or
a tag object whose signature GitHub does not report as valid.

A technical lot may close after its exact merged SHA passes the required
protected gates. Tagging and publication remain separate decisions and require
their own protected approvals.
