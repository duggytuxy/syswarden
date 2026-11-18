# Go Release Toolchain Security

Applies to: current development builds and active CI/release workflows.
The published v4.10.4 release remains bound to its original Go 1.26.9 compiler
and [publication record](../releases/v4.10.4/README.md). This policy update does
not republish that release or establish v5.00.0 acceptance.

Current builds and active release workflows require Go 1.26.11. The November
10, 2026 patch fixes GO-2026-6859 (CVE-2026-97054) in the standard library.
The development vulnerability scan reported affected `net/http` symbols in
binaries built with Go 1.26.10. Rebuild with the patched compiler and verify
the result against the current Go vulnerability database.

## Official compiler identity

For Linux AMD64, the official archive is `go1.26.11.linux-amd64.tar.gz`:

- Size: 66,999,944 bytes.
- SHA-256: `9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec`.
- Version output: `go version go1.26.11 linux/amd64`.

Verify the archive against the [official download metadata](https://go.dev/dl/?mode=json)
before local execution. The build scripts refuse an implicit toolchain
download. Hosted workflows request the exact compiler version, and the package
provenance gate rejects binaries built by a different compiler.

## Validation and release boundary

The security update changes the compiled product even when application source
is unchanged. Rebuild all native package variants, repeat the local pre-push
gate, require successful checks on the reviewed merge, and regenerate native
signatures and the candidate updater manifest when preparing a release.
Release acceptance requires IVV with the exact signed artifacts and the
protected acceptance workflow, including for v5.00.0.

Keep original failed logs and earlier artifact digests. Do not relabel old
packages as corrected, replace a published asset, suppress the vulnerability
scan or reuse a previous candidate's native acceptance as proof of the rebuilt
product.

## Historical evidence

The previous development compiler, Go 1.26.10, addressed the compromised
intermediate certificate issue in `crypto/x509` reported in
[GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809).

The [Go 1.27 evaluation](GO_1_27_EVALUATION_AND_ROLLBACK.md), its rollback helper,
and v4.10.0 allocation evidence retain their original Go 1.26.6 identities.
They describe historical measurements. They cannot authorize current builds
or a downgrade of the security update. Their original signatures, hashes and
test inputs must remain unchanged.

The published v4.10.4 records retain their Go 1.26.9 identities, including the
October 8 security correction and original artifact digests. Do not modify
historical evidence to make it appear built with the current compiler.

Sources: [Go release history](https://go.dev/doc/devel/release#go1.26.11),
[Go vulnerability database](https://vuln.go.dev/), and the
[GO-2026-6859 advisory](https://pkg.go.dev/vuln/GO-2026-6859).
