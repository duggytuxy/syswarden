# SysWarden Lot 1 Public Security Delivery Report

| Field | Value |
| :--- | :--- |
| Lot 1 source status | CANDIDATE |
| Product release decision | NO-GO until protected qualification |
| Candidate | v4.02.11 |
| Historical public baseline | v4.02.8 |
| Prior source candidate | v4.02.10, merged but never tagged or published |
| Report date | 15 August 2026 |
| Scope | Lot 1 source, package and release-qualification closure |
| Audience | Public, anonymized |

## 1. Executive outcome

This report describes the v4.02.11 repository candidate. It does not claim
that an untagged build is a public release, that every environment is
supported, or that a package is safe merely because a workflow produced it.

The v4.02.10 source candidate was merged, but it was never tagged and was never
published as a GitHub Release. It therefore has no public v4.02.10 Release
inventory. The replacement v4.02.11 candidate is NO-GO until the complete
protected qualification passes on its exact commit and produces byte-bound
evidence. No v4.02.11 tag or public Release is authorized before that result.

## 2. Delivered controls

| Area | Candidate behavior | Security boundary |
| :--- | :--- | :--- |
| Configuration | Transactional migration, strict validation, durable recovery phases, concurrency controls and preservation of operator overrides | Mutating commands stop when the active configuration is unavailable or degraded |
| Linux firewall | Validated nftables candidate, shared lock, atomic commit, post-commit verification, TTL preservation and bounded compatibility wrappers | A policy change can still interrupt remote access; console recovery remains mandatory |
| High availability | TLS 1.3, bearer authentication, bounded payloads, canonical peer scope, durable ledgers and bidirectional persistent-ban exchange | CIDRs authorize inbound peers only and are never dialed as outbound destinations |
| BunkerWeb integration | Additive TTL, provenance and batch extensions behind an explicit gate | Durable node-to-node L7 and WAAP ban exchange remains active with the partner gate false or true |
| Signed updates | Canonical manifest, detached Ed25519 signature, exact platform binding, private staging and a final size and SHA-256 verification before installation | The historical v4.02.8 binary predates this trust root and requires one separately verified manual first hop |
| Alpine packages | Dedicated CGO-free static x86_64 and aarch64 package executables | Exact protected lifecycle evidence is still required for the release commit |
| FreeBSD package | ABI 14 amd64 TXZ, native `/usr/local` layout, rc.d services, PF recovery contract, host-state restoration and native signed updater support | Fresh installation requires PF disabled with an empty live ruleset; arbitrary pre-existing PF coexistence is not claimed |
| Release governance | Exact tag ruleset, protected signing environment, byte-bound qualification evidence and independent publisher revalidation | A public tag and Release remain blocked until protected qualification succeeds |

## 3. Upgrade contract

The signed update protocol applies to v4.02.9 and later candidates. A qualified
v4.02.11 manifest must bind seven package identities: two DEB, two RPM, two APK
and one FreeBSD TXZ. A package is selected by exact operating system,
architecture, name, size and SHA-256, then rehashed immediately before its
package manager is invoked.

The immutable v4.02.8 binary has no embedded signed-manifest verifier. Its first
hop to v4.02.11 must therefore use a separately verified package and the native
package manager. On FreeBSD, the standalone TXZ also requires `curl`, `jq`,
`libqrencode`, `rsyslog` and `wireguard-tools` to be installed first. Once
v4.02.11 is installed from a qualified Release, signed updates support the six
Linux targets and FreeBSD amd64.

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

The Web-TUI is enabled by the current package path. A package-level disabled
default and conditional TCP 62027 ownership remain Lot 2 work.

## 5. Qualification state

The v4.02.10 protected pre-tag attempt stopped before privileged platform labs.
It produced no successful qualification artifact, tag or Release. Its source
checks are not final release evidence for v4.02.11.

The v4.02.11 candidate must pass all source and governance checks again on its
exact commit. The protected run must then verify package install, upgrade,
restart and rollback lifecycles; ARM64 execution; the FreeBSD PF and package
lifecycle; the signed FreeBSD updater transition; staged artifact integrity;
and publisher revalidation. Any failed coordinate keeps the release closed.

## 6. Expected public Release inventory

A qualified v4.02.11 Release must contain exactly these 14 public assets:

1. `syswarden_4.02.11_amd64.deb`;
2. `syswarden_4.02.11_arm64.deb`;
3. `syswarden-4.02.11-1.x86_64.rpm`;
4. `syswarden-4.02.11-1.aarch64.rpm`;
5. `syswarden_4.02.11_x86_64.apk`;
6. `syswarden_4.02.11_aarch64.apk`;
7. `syswarden-4.02.11.txz`;
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

The following items remain outside this Lot 1 closure:

- a package-level `[webtui] enabled = false` default and conditional TCP 62027
  ownership;
- an external BunkerWeb plugin, UI and end-to-end partner qualification;
- per-client HA tokens and remote whitelist mutation privileges;
- FreeBSD jails and coexistence with arbitrary pre-existing PF policy;
- a public FreeBSD package repository instead of standalone TXZ installation;
- additional product UX and policy controls that do not alter the v4.02.11
  upgrade safety boundary.

## 8. Final decision rule

v4.02.11 remains NO-GO. The tag may be created only after protected
qualification binds the exact release commit and passes the package, ARM64,
FreeBSD, PF, signed-updater and release-governance gates. The publisher must
then revalidate the qualified evidence and exact asset inventory before it can
publish the GitHub Release. Any failed coordinate keeps the public Release
closed.
