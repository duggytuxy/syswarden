# Current v4.10.0 intermediate IVV acceptance

This is the implementation and review plan for an intermediate release. It is not a completed acceptance report and does not claim full IVVQ qualification.

## Product and publication identity

The product candidate is `8c3405758a9b369924f466d12652e99d3a84dc56`. The native RPM, RHEL package-owned RPM, DEB and APK bytes remain those of protected signing run [36813812232](https://github.com/duggytuxy/syswarden/actions/runs/36813812232), artifact `11140952643`. The binary tarball and source SBOM retain their original security run `36813024209` artifacts, with the same three binary hashes as the native tests and the original GitHub build attestation. Tag CI still runs, but its rebuilt binaries cannot replace these retained product bytes. The exact package, binary bundle and SBOM digests and sizes are pinned in `scripts/ci/release_ivv_current_v4.10.0.json`.

A later publication commit may change only the enumerated documentation and acceptance/publication tooling. It cannot change runtime, build inputs, trust roots, native policies or frozen verifiers. The source binding rejects changed paths outside that allowlist, dirty checkouts, shallow history, replacement refs, grafts and hidden index changes. The originating `Major` transition remains `76535e03ee10b78f9c6ed1665d7fbeb8c2b8ee68`; these changes do not increment v4.10.0.

The original f334 plan and updater consumer remain unchanged. The new updater belongs to product/producer `8c340575`, run [36842481776](https://github.com/duggytuxy/syswarden/actions/runs/36842481776), artifact `11152415554`. Its original archive, exact workflow, owner, repository IDs, attempt, descriptor, SLSA statement and embedded Ed25519 trust roots are verified independently. An older f334 updater cannot satisfy that check.

## Reviewed evidence and selective replay

| Area | Evidence admitted by the current IVV plan |
| --- | --- |
| Firewalld activation and list persistence | Fresh 8c340575 native RPM-A9, RPM-A10, RPM-A9-RHELPO and RPM-A10-RHELPO observations, with standard/RHELPO snapshot separation |
| HA integration | Fresh 8c340575 native functional replay and verified restoration; two 30-minute 24c3 campaigns remain historical support |
| Ubuntu and Alpine activation | Original f334 observations, exact package payload comparison, reviewed source closures and new candidate CI/signatures |
| NODE01 migrations and updater | Original f334 two migration steps, independent offline DEB update, reboot, purge and restoration; paired with source/payload continuity and the independently signed current updater |
| Lifecycle, feed and allocation | Original 24c3 raw proofs and frozen verdicts, locally recomputed byte-identically; these are supporting evidence, not new candidate verdicts |
| Restoration | Original native and cloud restoration records for NODE01 through NODE05, including intermediate A9/A10 snapshot restorations |

The private input manifest binds 29 reviewed roots and 1,184 content-addressed objects. Public source contains their digests and selected assertion values. Raw logs, private file paths and captures stay on the local runner and in the owner's encrypted evidence archive. Original candidate identities and verdicts are preserved. The plan maps each required IVV check to its actual reviewed observations. The historical HA statement has been reverified with its original Sigstore identity and issuer; no replacement statement was signed.

The final runtime difference from f334 accepts the annotated `(default)` display token in a firewalld zone header. Both affected callers are conditional on active firewalld. All four firewalld platform variants and functional HA were replayed. Other reviewed source closures remain identical. DEB/APK payload inspection retains exact scripts and non-binary payloads, with the recorded DEB changelog timestamp difference. Go build metadata retains each original VCS identity; binary equivalence is not inferred from the version string.

## Protected production and independent consumption

`release-ivv.yml` accepts only an owner `workflow_dispatch` on `main`, attempt 1, on the dedicated ephemeral self-hosted runner. It requires the existing main-only environment with the owner as its sole reviewer and administrator bypass disabled. The verifier rechecks all private object hashes, original assertions, source continuity, exact product/publication CI, four native signatures for publishing on the current date and the current signed updater. A missing required check cannot become a pass.

The producer emits `RELEASE_IVV.json` and a GitHub artifact attestation, together with the exact public signed native bundle and updater. It uploads no raw native captures and has no permission to publish a release. Its successful claim is `intermediate_release_validated: true`, while `full_qualification_passed` and `publication_authorized` remain false.

Each of the three release boundaries independently derives the assurance level from validated Git version history, selects the unique successful protected run, downloads the original artifact by ID, verifies the API digest and safe archive inventory, authenticates the exact attested workflow/source/run, verifies the pinned plan and every required check, rechecks required CI and validates the updater signature. The privileged consumer also compares the staged release packages and update manifest byte-for-byte with the protected originals.

The report is accepted for at most 24 hours, with a five-minute clock-skew allowance. Native publishing-signature verification must be from the current UTC date. An expired artifact or superseded acceptance is rejected. Renewing acceptance does not silently rerun or relabel native campaigns.

Signed annotated tags, exact tag CI, Plumber grade A, release asset inventory, protected publication, immutable tag rules, artifact attestation and downloaded release verification remain separate mandatory checks. Upgrade transitions still select the existing complete IVVQ workflow and its full evidence validation. There is no skip-qualification input.

## Claim limits

- Intermediate IVV validation is not complete IVVQ qualification.
- Historical native evidence keeps its original candidate, packages, timestamp and verdict.
- The private APK3 qualification-bundle update path is outside this acceptance plan. The retained native offline updater observation is DEB only.
- IPv6 list persistence and kernel membership were checked; real inter-node activation probes were IPv4.
- The two 30-minute HA campaigns belong to 24c3. The current 8c340575 replay is functional and does not claim a new endurance campaign.

## Operator execution

After the implementation is merged and its exact main CI is green, stage the pinned private objects, original native archive/bundle and original updater archive/bundle under the dedicated runner's `~/.local/share/syswarden/native-release-evidence/8c3405758a9b369924f466d12652e99d3a84dc56/intermediate-ivv/` directory. Dispatch `release-ivv.yml` with `VERIFY-V4100-IVV-NO-PUBLISH` and approve the protected environment. Retain the run ID, public report, original ZIP, attestation and private verification traces in the encrypted archive.

Do not create a release from a local preflight. A successful protected result must first survive the independent publisher consumers and all publication gates. The release must identify the distinct product and publication commits and retain the claim limits above.
