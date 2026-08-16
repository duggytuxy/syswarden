# SysWarden Lot 1 Public Security Delivery Report

| Field | Value |
| :--- | :--- |
| Lot 1 source status | CANDIDATE |
| Product release decision | NO-GO until protected qualification |
| Candidate | v4.02.12 |
| Historical public baseline | v4.02.8 |
| Prior source candidate | v4.02.11, merged but never tagged or published |
| Report date | 16 August 2026 |
| Scope | Lot 1 source, package and release-qualification closure |
| Audience | Public, anonymized |

## 1. Executive outcome

This report describes the v4.02.12 repository candidate. It does not claim
that an untagged build is a public release, that every environment is
supported, or that a package is safe merely because a workflow produced it.

The v4.02.11 source candidate was merged, but it was never tagged or published.
Protected qualification run `31905061431` stopped before signing after it
detected an invalid mixed-family laboratory fixture and a real HA and threat-feed
cron reconciliation defect. No v4.02.11 qualification artifact, tag, public
Release or Release asset was created.

v4.02.12 supersedes that unpublished candidate. v4.02.12 remains NO-GO until
protected qualification passes on its exact commit and produces byte-bound
evidence. No v4.02.12 tag or public Release is authorized before that result.

## 2. Candidate corrections and delivered controls

The v4.02.12 source candidate separates IPv4 and IPv6 lifecycle fixtures,
proves their independent content and metadata, and exercises the exact
historical v4.02.8 package before seeding operator configuration. The lifecycle
adapter recomputes the installed version after container restarts and limits
the Alpine downgrade exception to the SHA-bound historical rollback. These are
candidate corrections, not release qualification results.

| Area | Candidate behavior | Security boundary |
| :--- | :--- | :--- |
| Configuration | Transactional migration, strict validation, durable recovery phases, concurrency controls and preservation of operator overrides | Mutating commands stop when the active configuration is unavailable or degraded |
| Linux firewall | Validated nftables candidate, shared lock, atomic commit, post-commit verification, TTL preservation and bounded compatibility wrappers | A policy change can still interrupt remote access; console recovery remains mandatory |
| Scheduling | Feed and HA cron entries are reconciled independently, operator lines are preserved byte-for-byte, and unexpected crontab errors fail closed | The exact package lifecycle must still prove these properties on every release coordinate |
| High availability | TLS 1.3, bearer authentication, bounded payloads, canonical peer scope, durable ledgers and bidirectional persistent-ban exchange | CIDRs authorize inbound peers only and are never dialed as outbound destinations |
| BunkerWeb integration | Additive TTL, provenance and batch extensions behind an explicit gate | Durable node-to-node L7 and WAAP ban exchange remains active with the partner gate false or true |
| Signed updates | Canonical manifest, detached Ed25519 signature, exact platform binding, private staging and final size and SHA-256 verification before installation | The historical v4.02.8 binary predates this trust root and requires one separately verified manual first hop |
| Alpine packages | Dedicated CGO-free static x86_64 and aarch64 package executables | Exact protected lifecycle evidence is still required for the release commit |
| FreeBSD package | ABI 14 amd64 TXZ, native `/usr/local` layout, rc.d services, PF recovery contract, host-state restoration and native signed updater support | Fresh installation requires PF disabled with an empty live ruleset; arbitrary pre-existing PF coexistence is not claimed |
| Release governance | Exact tag ruleset, protected signing environment, byte-bound qualification evidence and independent publisher revalidation | A public tag and Release remain blocked until protected qualification succeeds |

## 3. Upgrade contract

The signed update protocol applies to v4.02.9 and later candidates. A qualified
v4.02.12 manifest must bind seven package identities: two DEB, two RPM, two APK
and one FreeBSD TXZ. A package is selected by exact operating system,
architecture, name, size and SHA-256, then rehashed immediately before its
package manager is invoked.

The immutable v4.02.8 binary has no embedded signed-manifest verifier. Its first
hop to v4.02.12 must therefore use a separately verified package and the native
package manager. On FreeBSD, the standalone TXZ also requires `curl`, `jq`,
`libqrencode`, `rsyslog` and `wireguard-tools` to be installed first. Once
v4.02.12 is installed from a qualified Release, signed updates support the six
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

The failed v4.02.11 protected attempt is diagnostic evidence only. It is not
release evidence for v4.02.12, and none of its unfinished outputs may be reused
to authorize a tag.

The v4.02.12 candidate must pass all source and governance checks on its exact
merged commit. The protected run must then verify package install, upgrade,
reinstall, restart, rollback, recovery, removal and purge lifecycles; independent
IPv4 and IPv6 preservation; ARM64 execution; FreeBSD PF and package lifecycle;
the signed FreeBSD updater transition; isolated nftables behavior; staged
artifact integrity; and publisher revalidation. Any failed coordinate keeps the
release closed.

## 6. Expected public Release inventory

A qualified v4.02.12 Release must contain exactly these 14 public assets:

1. `syswarden_4.02.12_amd64.deb`;
2. `syswarden_4.02.12_arm64.deb`;
3. `syswarden-4.02.12-1.x86_64.rpm`;
4. `syswarden-4.02.12-1.aarch64.rpm`;
5. `syswarden_4.02.12_x86_64.apk`;
6. `syswarden_4.02.12_aarch64.apk`;
7. `syswarden-4.02.12.txz`;
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

## 7. Release notes contract

The public v4.02.12 Release notes must come from the complete v4.02.12 changelog
section. They must retain the fixes, security properties, release status and
upgrade notes, including the manual v4.02.8 first hop, exact native package
commands, the FreeBSD dependency and cleanup limits, and the 14-asset inventory.
Publisher revalidation must bind those notes and every public asset to the
qualified commit without rewriting the failed v4.02.11 history.

## 8. Deferred Lot 2 work

The following items remain outside this Lot 1 closure:

- a package-level `[webtui] enabled = false` default and conditional TCP 62027
  ownership;
- an external BunkerWeb plugin, UI and end-to-end partner qualification;
- per-client HA tokens and remote whitelist mutation privileges;
- FreeBSD jails and coexistence with arbitrary pre-existing PF policy;
- a public FreeBSD package repository instead of standalone TXZ installation;
- additional product UX and policy controls that do not alter the v4.02.12
  upgrade safety boundary.

## 9. Final decision rule

v4.02.12 remains NO-GO. The tag may be created only after protected
qualification binds the exact release commit and passes the package, ARM64,
FreeBSD, PF, nftables, signed-updater and release-governance gates. The publisher
must then revalidate the qualified evidence, complete Release notes and exact
asset inventory before it can publish the GitHub Release. Any failed coordinate
keeps the public Release closed.
