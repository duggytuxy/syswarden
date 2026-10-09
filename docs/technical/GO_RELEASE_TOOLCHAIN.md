# Go Release Toolchain Security

Applies to: the v4.10.4 candidate. Publication and native IVV remain pending.

The candidate requires exactly Go 1.26.9 for production builds, package
provenance checks and active release workflows. Go published this security
update on October 8, 2026. The merged-main vulnerability scan rejected the
previous Go 1.26.6 build before native package signing.

The reported reachable standard-library findings were GO-2026-6603,
GO-2026-6604, GO-2026-6605, GO-2026-6607, GO-2026-6608, GO-2026-6610,
GO-2026-6611, GO-2026-6612, GO-2026-6613 and GO-2026-6617. The scan must pass
against the current Go vulnerability database after rebuilding with the
corrected toolchain. A prior successful scan is not a waiver for a new finding.

## Official compiler identity

For Linux AMD64, the official archive is `go1.26.9.linux-amd64.tar.gz`:

- Size: 66,935,201 bytes.
- SHA-256: `42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d`.
- Version output: `go version go1.26.9 linux/amd64`.

Verify the archive against the [official download metadata](https://go.dev/dl/?mode=json)
before local execution. The build scripts refuse an implicit toolchain
download. Hosted workflows request the exact compiler version, and the package
provenance gate rejects binaries built by a different compiler.

## Validation and release boundary

The security update changes the compiled product even when application source
is unchanged. Rebuild all native package variants, repeat the local pre-push
gate, require successful checks on the reviewed merge, and regenerate native
signatures and the candidate updater manifest. Perform native IVV with those
exact signed artifacts before protected publication.

Keep original failed logs and earlier artifact digests. Do not relabel old
packages as corrected, replace a published asset, suppress the vulnerability
scan or reuse a previous candidate's native acceptance as proof of the rebuilt
product.

## Historical evidence

The [Go 1.27 evaluation](GO_1_27_EVALUATION_AND_ROLLBACK.md), its rollback helper,
and v4.10.0 allocation evidence retain their original Go 1.26.6 identities.
They describe historical measurements. They cannot authorize current builds
or a downgrade of the security update. Their original signatures, hashes and
test inputs must remain unchanged.

Sources: [Go release history](https://go.dev/doc/devel/release#go1.26.9),
[Go vulnerability database](https://vuln.go.dev/), and the
[GO-2026-6617 advisory](https://pkg.go.dev/vuln/GO-2026-6617).
