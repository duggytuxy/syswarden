# SysWarden Lot 1 Public Security Delivery Report

| Field | Value |
| :--- | :--- |
| Lot 1 source status | VALIDATED |
| Product release decision | NO-GO until protected qualification |
| Candidate | v4.02.10 |
| Historical public baseline | v4.02.8 |
| Report date | 15 August 2026 |
| Scope | Lot 1 source, package and release-qualification closure |
| Audience | Public, anonymized |

## 1. Executive outcome

This report describes the repository candidate. It does not claim that an
untagged build is a public release, that every environment is supported, or
that a package is safe merely because a workflow produced it.

The frozen source candidate passed the complete local source matrix. It may
proceed to its Patch commit and pull request after the maintainer approves each
Git operation. No tag or public Release is authorized until the protected
package, ARM64, FreeBSD, signed-updater and release-governance qualification
passes on that exact commit.

## 2. Delivered controls

| Area | Delivered behavior | Security boundary |
| :--- | :--- | :--- |
| Configuration | Transactional migration, strict validation, durable recovery phases, concurrency controls and preservation of operator overrides | Mutating commands stop when the active configuration is unavailable or degraded |
| Linux firewall | Validated nftables candidate, shared lock, atomic commit, post-commit verification, TTL preservation and bounded compatibility wrappers | A policy change can still interrupt remote access; console recovery remains mandatory |
| High availability | TLS 1.3, bearer authentication, bounded payloads, canonical peer scope, durable ledgers and bidirectional persistent-ban exchange | CIDRs authorize inbound peers only and are never dialed as outbound destinations |
| BunkerWeb integration | Additive TTL, provenance and batch extensions behind an explicit gate | Durable node-to-node L7 and WAAP ban exchange remains active with the partner gate false or true |
| Signed updates | Canonical manifest, detached Ed25519 signature, exact platform binding, private staging and a final size and SHA-256 verification before installation | The historical v4.02.8 binary predates this trust root and requires one separately verified manual first hop |
| Alpine packages | Dedicated CGO-free static x86_64 and aarch64 package executables | Exact protected lifecycle evidence is still required for the release SHA |
| FreeBSD package | ABI 14 amd64 TXZ, native `/usr/local` layout, rc.d services, PF recovery contract, host-state restoration and native signed updater support | Fresh installation requires PF disabled with an empty live ruleset; arbitrary pre-existing PF coexistence is not claimed |
| Release governance | Exact tag ruleset, protected signing environment, byte-bound qualification evidence and two independent publisher revalidations | A public tag and Release remain blocked until protected qualification succeeds |

## 3. Upgrade contract

The signed update protocol applies to v4.02.9 and later candidates. The
v4.02.10 manifest binds seven package identities: two DEB, two RPM, two APK and
one FreeBSD TXZ. A package is selected by exact operating system, architecture,
name, size and SHA-256, then rehashed immediately before its package manager is
invoked.

The immutable v4.02.8 binary has no embedded signed-manifest verifier. Its first
hop to v4.02.10 must therefore use a separately verified package and the native
package manager. On FreeBSD, the standalone TXZ also requires `curl`, `jq`,
`libqrencode`, `rsyslog` and `wireguard-tools` to be installed first. Once
v4.02.10 is installed, signed updates support the six Linux targets and
FreeBSD amd64.

## 4. Package and platform boundaries

| Platform | Candidate evidence | Remaining release gate |
| :--- | :--- | :--- |
| DEB amd64 and arm64 | Contents, dependencies, maintainer scripts and lifecycle contracts | Protected exact-package lifecycle |
| RPM x86_64 and aarch64 | Contents, dependencies, maintainer scripts and lifecycle contracts | Protected exact-package lifecycle |
| APK x86_64 and aarch64 | Static package executables; amd64 executes on standard Alpine musl | Protected x86_64 and aarch64 lifecycle |
| FreeBSD amd64 | Cross-build, ABI, inventory, native paths, rc.d, PF, uninstall and updater contracts | Disposable VM lifecycle and signed updater transition |

Raw `pkg delete` is not the supported FreeBSD cleanup path because the package
manager does not guarantee that a failing pre-deinstall script aborts payload
removal, and its no-script mode bypasses recovery hooks. Operators must use
`syswarden uninstall` with backups and console access.

## 5. Verification snapshot

The frozen v4.02.10 candidate passed the following final checks:

- 358 Python CI tests, including 141 package and FreeBSD checks and 105 release, qualification, ruleset and adversarial mutation checks;
- native tests across 22 Go packages in CLI, core, TUI and versionctl, followed by the race detector on all four modules with no race;
- Go vet on all four modules for Linux and FreeBSD, plus FreeBSD amd64 cross-compilation of all 22 packages;
- gosec v2.28.0 across eight Linux and FreeBSD module matrices with zero finding, and golangci-lint on all four modules;
- 52 CLI process-compatibility cases against the historical baseline;
- strict parsing of 11 workflow files, strict workflow validation and ShellCheck of 102 workflow shell blocks and five repository scripts;
- the nosec gate with 265 annotations: 61 qualified and 204 legacy, with no new, moved or reintroduced suppression;
- Gitleaks scans of the candidate and 1,267 historical commits with no exposed secret;
- govulncheck on all four modules with no called vulnerable function. One dependency-module advisory is reported as not called and remains tracked;
- the documentation truth gate for README, the built-in manual and four Wiki pages, including identical verified latest-Release installation blocks.

The protected real-machine qualification remains deliberately separate. It
must execute the exact committed packages on ARM64 and FreeBSD, including the
signed FreeBSD updater transition, before the tag is created.

## 6. Expected public Release inventory

A qualified v4.02.10 Release must contain exactly these 14 public assets:

1. `syswarden_4.02.10_amd64.deb`;
2. `syswarden_4.02.10_arm64.deb`;
3. `syswarden-4.02.10-1.x86_64.rpm`;
4. `syswarden-4.02.10-1.aarch64.rpm`;
5. `syswarden_4.02.10_x86_64.apk`;
6. `syswarden_4.02.10_aarch64.apk`;
7. `syswarden-4.02.10.txz`;
8. `SHA256SUMS.txt`;
9. `RELEASE_SHA256SUMS.txt`;
10. `syswarden-release.tar.gz`;
11. `syswarden-sbom.spdx.json`;
12. `plumber-report.zip`;
13. `syswarden-update-manifest-v1.json`;
14. `syswarden-update-manifest-v1.json.sig`.

This inventory contains seven packages plus seven evidence and update assets.
A successful source merge alone does not create the tag or these Release
assets.

## 7. Deferred Lot 2 work

The following items are explicitly outside this Lot 1 closure:

- a package-level `[webtui] enabled = false` default and conditional TCP 62027
  ownership;
- an external BunkerWeb plugin, UI and end-to-end partner qualification;
- per-client HA tokens and remote whitelist mutation privileges;
- FreeBSD jails and coexistence with arbitrary pre-existing PF policy;
- a public FreeBSD package repository instead of standalone TXZ installation;
- additional product UX and policy controls that do not alter the v4.02.10
  upgrade safety boundary.

## 8. Final decision rule

The documentation, exact version targets and final local matrix now agree. The
source candidate may proceed to its Patch commit and pull request only after
the maintainer explicitly approves each Git operation.
The v4.02.10 tag may be created only after the protected qualification binds the
same release SHA and passes the package, ARM64, FreeBSD, PF, signed updater and
release-governance gates. Any failed coordinate keeps the public Release closed.
