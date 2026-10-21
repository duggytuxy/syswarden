# Go Release Toolchain Security

Applies to: current development builds and active CI/release workflows.
The published v4.10.4 release remains bound to its original Go 1.26.9 compiler
and [publication record](../releases/v4.10.4/README.md). This policy update does
not republish that release or establish v5.00.0 acceptance.

Current builds require exactly Go 1.26.10 for package provenance checks and
active release workflows. Go published this security update on October 19,
2026. The vulnerability database added GO-2026-6809 on October 21, and the
development vulnerability scan rejected the previous Go 1.26.9 compiler.

GO-2026-6809 (CVE-2026-111943) adds an explicit rejection of compromised
intermediate certificates in `crypto/x509`. The current vulnerability scan
reports a reachable `Certificate.Verify` path. Rebuild with the corrected
compiler and require the scan to pass against the current vulnerability
database. A prior successful scan is not a waiver for a new finding.

## Official compiler identity

For Linux AMD64, the official archive is `go1.26.10.linux-amd64.tar.gz`:

- Size: 66,936,659 bytes.
- SHA-256: `ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5`.
- Version output: `go version go1.26.10 linux/amd64`.

Verify the archive against the [official download metadata](https://go.dev/dl/?mode=json)
before local execution. The build scripts refuse an implicit toolchain
download. Hosted workflows request the exact compiler version, and the package
provenance gate rejects binaries built by a different compiler.

## Validation and release boundary

The security update changes the compiled product even when application source
is unchanged. Rebuild all native package variants, repeat the local pre-push
gate, require successful checks on the reviewed merge, and regenerate native
signatures and the candidate updater manifest when preparing a release.
The v5.00.0 major transition requires IVVQ with those exact signed artifacts;
intermediate minor and patch releases require IVV. Component checks alone do
not establish either acceptance boundary.

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

The published v4.10.4 records retain their Go 1.26.9 identities, including the
October 8 security correction and original artifact digests. Do not modify
historical evidence to make it appear built with the current compiler.

Sources: [Go release history](https://go.dev/doc/devel/release#go1.26.10),
[Go vulnerability database](https://vuln.go.dev/), and the
[GO-2026-6809 advisory](https://pkg.go.dev/vuln/GO-2026-6809).
