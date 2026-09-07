# Go 1.27 Evaluation and Rollback

## Current release decision

Go 1.26.6 remains the SysWarden release toolchain. The isolated Go 1.27.1
lane is non-publishing and currently emits only this decision:

`defer-go1.27-keep-go1.26.6`

The evaluation does not qualify Go 1.27.1 for a release. Adoption remains
blocked until separately bound native package, lifecycle, and performance
evidence is green.

## Evaluation contract

The manual `SysWarden Go 1.27 Evaluation` workflow downloads Go 1.26.6 and Go
1.27.1 from the pinned official URLs and verifies their exact sizes and
SHA-256 digests before execution. It has read-only repository permission and
does not publish a package or release.

The lane performs these checks on the candidate commit:

- normal, race, vet, stdversion, bounded fuzz, and goroutine leak checks;
- JSON v1 and JSON v2 experiments;
- reproducible builds of all three Linux AMD64 binaries;
- nine alternating local protocol campaigns for each toolchain;
- HTTP/1.1 connection reuse, TLS 1.3, bounded response headers, strict JSON,
  and Ed25519 manifest verification;
- paired CPU, RSS, allocation, allocated byte, and HTTP throughput samples;
- actual DEB, RPM, and APK assembly in isolated local clones;
- per-binary, per-package, and total size comparisons;
- an isolated byte-exact source rollback rehearsal to Go 1.26.6.

Every relative regression limit is fixed at 10 percent. CPU, RSS, and
allocation measurements also use the small absolute noise allowances declared
in `scripts/ci/go_toolchain_evaluation.json`. Binary size, package size, and
throughput do not use an absolute allowance. A missing sample, protocol
failure, malformed record, incomplete inventory, or exceeded bound fails the
lane.

## Rollback rehearsal

The workflow creates a fresh local clone of the exact candidate commit. Inside
that clone only, it changes the five declared Go source directives and the
package builder pin and labels from Go 1.26.6 to Go 1.27.1. It then runs:

```bash
python3 scripts/ci/go_toolchain_rollback.py \
  --repository /absolute/path/to/isolated-clone \
  --from-toolchain go1.27.1 \
  --to-toolchain go1.26.6
```

The rehearsal requires these six files and no substitutes:

- `go.work`
- `src/core/syswarden-cli/go.mod`
- `src/core/syswarden-core/go.mod`
- `src/core/syswarden-tui/go.mod`
- `scripts/versionctl/go.mod`
- `build_packages.sh`

The workflow compares every restored file byte for byte with the original
Go 1.26.6 source. It also proves that `build_packages.sh` again selects exactly
`go1.26.6`, contains the exact Go 1.26.6 attestation labels, contains no
Go 1.27.1 selector or label, and remains valid Bash. It then reruns the
protocol-relevant CLI, core, telemetry, webhook, and TUI tests with the
checksum-pinned Go 1.26.6 binary. The rollback proof is sealed only after all
comparisons and tests pass.

## Maintainer rollback procedure after a future adoption

Do not run the rollback helper against an unreviewed or dirty checkout. Create
a dedicated clean clone or worktree at the affected commit, verify the commit
identity, and retain the failing evaluation evidence.

1. Confirm that the five declared module files contain exactly one
   `go 1.27.1` directive each and that `build_packages.sh` contains only the
   exact Go 1.27.1 builder pin and attestation labels.
2. Run the rollback helper with the exact arguments shown above.
3. Inspect the resulting diff. It must contain only the five directive changes
   and the package builder pin and label changes to Go 1.26.6.
4. Run normal tests, race tests, vet, stdversion, protocol tests, reproducible
   builds, and package qualification with Go 1.26.6.
5. Submit the rollback as a reviewed source change. Do not retag or replace an
   existing release artifact.
6. Regenerate candidate packages and evidence from the reviewed rollback
   commit through the protected release process.

If any source identity or byte comparison is ambiguous, discard the isolated
checkout and restart from the attested commit. The helper never changes
dependencies, checksums, release versions, tags, or published artifacts.
