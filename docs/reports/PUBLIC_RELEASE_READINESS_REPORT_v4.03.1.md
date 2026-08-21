# SysWarden v4.03.1 Public Release Readiness Report

## Document status

| Field | Value |
|---|---|
| Candidate | v4.03.1 |
| Distribution boundary | Linux packages only |
| Public package count | 6 |
| Public release asset count | 13 |
| Decision | NO-GO until protected qualification passes on the exact merged SHA |
| Scope | Source, package, firewall, HA migration, documentation and release governance |

This report describes the intended v4.03.1 candidate contract. It is not a
release authorization, does not assert that final qualification has passed and
does not authorize a tag or public Release.

## Executive summary

v4.03.1 narrows the supported distribution surface to six Linux packages,
removes the network-facing browser terminal while retaining the native local
TUI, and introduces a verifiable HA migration fence for the BunkerWeb partner
handoff from historical static ownership to provenance-aware ownership.

The release remains blocked until the exact merged commit passes native AMD64
and ARM64 package lifecycles, isolated nftables qualification, security and
supply-chain gates, partner migration acceptance, exact evidence sealing and
the immutable thirteen-asset publisher.

## Supported package matrix

| Package family | Architecture | Expected asset |
|---|---|---|
| DEB | amd64 | `syswarden_4.03.1_amd64.deb` |
| DEB | arm64 | `syswarden_4.03.1_arm64.deb` |
| RPM | x86_64 | `syswarden-4.03.1-1.x86_64.rpm` |
| RPM | aarch64 | `syswarden-4.03.1-1.aarch64.rpm` |
| APK | x86_64 | `syswarden_4.03.1_x86_64.apk` |
| APK | aarch64 | `syswarden_4.03.1_aarch64.apk` |

No current package or updater route exists outside this matrix. ARM64 package
qualification runs on a native ARM64 runner rather than through emulation.

## Exact public release inventory

A qualified v4.03.1 Release must contain exactly these thirteen assets:

1. `syswarden_4.03.1_amd64.deb`
2. `syswarden_4.03.1_arm64.deb`
3. `syswarden-4.03.1-1.x86_64.rpm`
4. `syswarden-4.03.1-1.aarch64.rpm`
5. `syswarden_4.03.1_x86_64.apk`
6. `syswarden_4.03.1_aarch64.apk`
7. `SHA256SUMS.txt`
8. `RELEASE_SHA256SUMS.txt`
9. `syswarden-release.tar.gz`
10. `syswarden-sbom.spdx.json`
11. `plumber-report.zip`
12. `syswarden-update-manifest-v1.json`
13. `syswarden-update-manifest-v1.json.sig`

Every asset must be rebuilt from the exact qualified SHA. The publisher must
reject missing, duplicate or unexpected assets and must verify both checksum
inventories plus the detached Ed25519 update signature before publication.

## Local terminal boundary

`syswarden tui` is the supported terminal dashboard. It runs in the invoking
terminal, reads local telemetry and opens no network listener. The candidate
contains no browser frontend, HTTPS or WebSocket terminal, remote PTY bridge,
token-management command, network service or SysWarden-owned TCP 62027 rule.

Upgrade qualification must prove that legacy service state is removed without
stopping an unrelated process using the same port, unrelated configuration is
preserved and the local TUI remains functional.

## Configuration and persistent-list contract

The current modular format is `schema_version = 1`. When `schema_version` is
absent, both loaders treat the configuration as historical input. Future,
negative and non-integer versions fail closed.

`syswarden config validate --path /etc/syswarden/config` performs descriptor-rooted reads and is non-mutating.
It does not rewrite compatibility state or apply environment overrides;
unknown and deprecated keys are returned as
sorted diagnostics; structural and semantic violations fail validation. The
CLI validator and core runtime use the same validation matrix for blocklist
choice, URL and hash combinations, Wazuh endpoint completeness, compliance
intervals, SHA-256 prefixes, trimmed HA peers and SSH/HA port separation while
WireGuard is enabled.

`syswarden config migrate --dry-run` performs zero source or destination
writes, even when an unfinished transaction would otherwise require recovery.
`syswarden migrate-config` remains a compatibility alias with the same
transactional and dry-run guarantees.

The authoritative SaaS monitor key is
`network.saas.allow_monitors`. It takes precedence over the deprecated
`integrations.saas.enabled` alias, and absence of both settings means false.
When enabled, the required feed path accepts only absolute HTTPS URLs without
credentials or fragments, requires TLS 1.3, rejects redirects and enforces a
10-second request timeout, 1 MiB body, 1,024-byte line, 20,000-line and
10,000-entry limits. Every non-comment line must be a canonicalizable IP or
CIDR. Any required-feed, syntax or bound failure retains the previous lists.
The validated IPv4 and IPv6 files are published as one lock-coordinated atomic
pair with an SHA-256 pair manifest and rollback on failure.

WAAP log settings use canonical single-space-separated absolute patterns.
Configured globs are reduced to verified exact real regular-file matches. The
core opens them descriptor-relative without following links and revalidates the
file identity and type after every rotation; it never creates a missing target.
Rsyslog inputs are emitted only for paths that pass the same validation at
configuration time, but rsyslog later reopens those names itself, so operators
must keep every parent directory protected against untrusted replacement.
Rsyslog strings and WireGuard values are validated and encoded for their
destination grammars before configuration publication.

Persistent lists accept exact canonical IPv4 and IPv6 addresses, masked CIDRs
and a port-qualified form only where that registry supports a service scope.
They reject hostnames, address zones, IPv4-mapped IPv6 values, invalid ports,
control characters and family mismatches. The command
`syswarden whitelist <IP-or-CIDR> --port <PORT>` limits an entry to that TCP
service; omitting `--port` keeps the entry address-wide.

Every SSH exception is rendered only for the effective SSH port. An explicit
port must match it. If the effective SSH port changes while a stale qualified
entry remains, candidate nftables application fails closed until the operator
reconciles the registry from verified recovery access.

## HA ownership and migration contract

The two HA ownership stores remain deliberately separate:

- `DELETE {"bans": [...]}` removes provenance ledger entries only;
- `DELETE {"ips": [...]}` is the explicit historical static cleanup operation;
- a cleanup set comes only from the integrator's durable per-peer record of
  addresses that it previously submitted;
- ownership is never inferred from `GET /ha/sync`, provenance pagination or
  another peer's effective union.

Dialect discovery uses one authenticated `GET /ha/status` for one serialized
peer cycle. Enriched operations require both `sync_ttl` and `sync_provenance`.
Missing, partial or malformed capabilities stop the handoff for that peer and
never relax TLS or bearer authentication.

## Cluster fence and partner verification

Before migration, one operator control host creates and verifies one canonical
activation manifest containing the complete member inventory, live TLS leaf
fingerprints, external legacy-writer identifiers, one epoch and both declared
digests. The same protected manifest is distributed to every member and to the
integrator.

For each peer, the integrator must obtain one fresh authenticated,
challenge-bound `GET /ha/status` response and accept fence evidence only when:

- capability `native_sync_fence_v1` is present;
- the challenge echo matches the request;
- `native_sync_fence.state` equals `active_drained`;
- the live TLS leaf fingerprint matches the manifest member;
- `epoch` equals the manifest epoch exactly;
- `membership_sha256` equals the manifest value exactly;
- `legacy_writer_inventory_sha256` equals the manifest value exactly;
- the response header `X-SysWarden-HA-Fence-Condition` equals the JSON
  `condition` value exactly;
- the server instance, generation and condition remain stable for the accepted
  observation.

The epoch and both digests are opaque, case-sensitive strings for the
integrator. The integrator does not recalculate the digests and does not
reimplement SysWarden canonicalization.

The explicit historical cleanup request carries the observed condition in
`X-SysWarden-HA-Fence-Condition`. A missing condition receives HTTP 428, a
malformed condition receives HTTP 400 and a stale condition receives HTTP 412.
Each rejected request performs no mutation. A 412 means the fence changed and
requires a fresh all-member observation plus an operator decision.

An unreachable member, changed membership, changed certificate identity,
restarted server instance, changed generation, blind interval or reappearing
address resets partner observation. A one-hour absence window is supporting
evidence only. It is never proof of drain and never permits claim release from
a partial cluster view.

Fence release additionally requires durable terminal closure evidence for
every external legacy writer in the manifest. No queued historical write may
become eligible after release.

## Required qualification evidence

The final protected qualification must seal exactly two product evidence
families:

1. native Linux package lifecycle evidence, including AMD64 and ARM64 shards;
2. isolated nftables kernel evidence.

The adapter and aggregate gate bind both evidence families to the repository,
release tag, release SHA, workflow run, package artifact and previous public
release. All status files must be regular, owner-controlled, numeric and zero.
Any invalid status, stale binding, time skew, unexpected file or failed shard
blocks signing and publication.

## Security posture and limitations

- HA uses TLS 1.3 and bearer authentication. Operators remain responsible for
  verified trust distribution and complete cluster membership.
- The WAAP engine analyzes logs out of band. It is not an inline HTTP proxy and
  does not sanitize request traffic.
- `reload` reapplies firewall policy and normally restarts the core. Keep
  verified console access and a ruleset backup.
- On Alpine Linux, SysWarden does not configure automatic operating-system
  security updates. Repository selection and the `apk` update policy remain
  an explicit operator responsibility.
- `uninstall` deletes SysWarden configuration, data, logs, services and
  firewall state. It is not a general host rollback.
- A downgrade is an emergency operation. It requires host-boundary containment
  of TCP 62027 and must not restore retired authentication material.
- No statement in this report is a regulatory certification or a guarantee for
  untested distributions, modified package managers or incomplete HA topology.

## Release decision

Written partner freeze confirmation was received on 20 August 2026. This
closes the written partner-confirmation gate only; the technical residue-free
migration evidence remains pending.

The v4.03.1 candidate remains NO-GO until all required gates pass on the exact
merged commit, no unexplained partner-attributable static residue remains, and
the publisher verifies exactly thirteen public assets. Only then may the
maintainer authorize the immutable tag and public Release.
