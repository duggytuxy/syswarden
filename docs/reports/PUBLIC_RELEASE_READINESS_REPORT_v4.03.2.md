# SysWarden v4.03.2 Public Release Readiness Report

## Document status

| Field | Value |
|---|---|
| Candidate | v4.03.2 |
| Distribution boundary | Linux packages only |
| Public package count | 3 |
| Public release asset count | 10 |
| Decision | NO-GO until protected qualification passes on the exact merged SHA |
| Scope | Source, package, firewall, HA migration, documentation and release governance |

This report describes the intended v4.03.2 candidate contract. It is not a
release authorization, does not assert that final qualification has passed and
does not authorize a tag or public Release.

The historical v4.03.1 candidate completed its protected technical
qualification but was deliberately left untagged and unpublished. Its evidence
does not authorize or replace the required v4.03.2 qualification.

## Executive summary

v4.03.2 limits the supported distribution surface to three Linux packages,
removes the network-facing browser terminal while retaining the native local
TUI, retains the verifiable HA migration fence and targets closure of the LOT
2S controls selected from security audit BW-SW-2026-002.

The release remains blocked until the exact merged commit passes native AMD64
package lifecycles, isolated nftables qualification, security and
supply-chain gates, partner migration acceptance, exact evidence sealing and
the immutable ten-asset publisher.

## Supported package matrix

| Package family | Architecture | Expected asset |
|---|---|---|
| DEB | amd64 | `syswarden_4.03.2_amd64.deb` |
| RPM | x86_64 | `syswarden-4.03.2-1.x86_64.rpm` |
| APK | x86_64 | `syswarden_4.03.2_x86_64.apk` |

No current package, updater or qualification route exists outside this
AMD64/x86_64 matrix.

## Exact public release inventory

A qualified v4.03.2 Release must contain exactly these ten assets:

1. `syswarden_4.03.2_amd64.deb`
2. `syswarden-4.03.2-1.x86_64.rpm`
3. `syswarden_4.03.2_x86_64.apk`
4. `SHA256SUMS.txt`
5. `RELEASE_SHA256SUMS.txt`
6. `syswarden-release.tar.gz`
7. `syswarden-sbom.spdx.json`
8. `plumber-report.zip`
9. `syswarden-update-manifest-v1.json`
10. `syswarden-update-manifest-v1.json.sig`

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

A historical `SYSWARDEN_FIREWALL_BACKEND="firewalld"` value maps to
`core.firewall_backend = "keep"`, preserving the existing service without an
automatic transition. Historical WireGuard configurations using any backend
other than `nftables` are rejected for explicit operator remediation rather
than silently changing the backend choice.

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

## Firewall backend selection and compatibility

SysWarden v4.03.2 uses nftables as its single authoritative Linux policy engine.
Fresh configurations default to `core.firewall_backend = "keep"`, which does
not start, stop, enable or disable the operator-managed firewall service. It
refuses policy mutation while an iptables-services or netfilter-persistent
service is active or enabled. Operational mutation requires an active,
unambiguous supported service manager. Package hooks running with no
service-manager runtime defer `install` and `reload` instead of invoking host
firewall or kernel tools.

If exactly one supported compatibility frontend is already active, SysWarden
may reconcile only its bounded trusted-source and HA-port allow rules through
firewalld or UFW. Installed but inactive tools and the mere presence of
iptables or ip6tables compatibility binaries are not treated as active
backends. Existing unowned rules are not claimed or removed. Active-frontend,
executable, zone, legacy-ownership, and inactive or pending ownership ambiguity
detected in the initial wrapper preflight fails before the authoritative
nftables commit. Exact rule-plane inconsistency or a frontend or zone change
detected during postcommit reconciliation is reported with the nftables
transaction authoritative and ownership debt retained where applicable.

The `nftables` value is a validation-only assertion. It requires the `nft`
executable and an already active and enabled nftables service. It refuses any
active or enabled firewalld, UFW, iptables-services or netfilter-persistent
frontend. It never triggers an automatic service transition. A required
transition causes the mutation to fail before host changes.

The `iptables` value remains parseable for configuration compatibility but is
not an operational policy mode in v4.03.2. Operational firewall policy mutation
paths reject this choice before changing persistent policy inputs or kernel
firewall state. Automatic firewalld, nftables and iptables service migration
is outside the qualified v4.03.2 contract.

The protected release qualification includes the isolated nftables kernel
laboratory. Existing package lifecycle evidence is nftables-oriented and does
not qualify active firewalld, active UFW, iptables services or automatic service
migration. Those modes require separate target-host evidence before any future
support claim can be widened.

WireGuard requires the explicit `nftables` backend. The bounded firewalld and
UFW compatibility path does not open the WireGuard UDP port or forwarding
rules. That combination requires separate operator-managed frontend rules and
is not part of the v4.03.2 runtime contract.

## Optional RHEL-compatible image staging extension

The repository provides a separate, opt-in extension for an extracted, fresh
and unmounted RHEL-family 9 or newer image root. It is not invoked by the normal
build, package installation, update or reload workflows.

The extension consumes one local RPM plus its expected SHA-256, verifies the
target RPM database and dependencies, and installs only that package with RPM
plugins, package scripts and triggers disabled. During offline staging it does
not enter the image root, execute a product binary, contact a network endpoint,
inspect or signal a process, edit cron, invoke a service manager, or invoke a
firewall or kernel-policy tool.

After payload verification it publishes a marker-guarded first-boot unit inside
the image. Runtime convergence uses the normal `install` and `reload` commands.
Fresh configuration generation defaults to `core.firewall_backend = "keep"`.
An already active firewalld frontend may be used only through the normal bounded
compatibility path, without an automatic service transition. nftables remains
the authoritative SysWarden policy engine.

This extension stages an image filesystem only. It does not establish runtime
readiness, qualify a target-host firewalld deployment, build or sign an ISO, or
expand the protected release matrix. Those activities require separate
image-builder and target-host evidence.

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

1. native AMD64 Linux package lifecycle evidence;
2. isolated nftables kernel evidence.

The adapter and aggregate gate bind both evidence families to the repository,
release tag, release SHA, workflow run, package artifact and previous public
release. All status files must be regular, owner-controlled, numeric and zero.
Any invalid status, stale binding, time skew, unexpected file or failed shard
blocks signing and publication.

## LOT 2S security remediation

The bounded LOT 2S scope targets closure of H1 through H5 and the selected M1,
M6, M9 and M13 controls from security audit BW-SW-2026-002. Retired
network-terminal and non-Linux surfaces are outside this scope. The expanded
v4.03.2 snapshot completed independent local re-audit on the frozen candidate
tree recorded by the private evidence manifest. The bounded review closed with
0 P0 and 0 P1. This local result applies only to the reviewed scope and does not
replace protected CI or release qualification.

The reviewed controls establish these boundaries:

- one validated authoritative source address is carried from log parsing to
  WAAP or UDS enforcement; ambiguous JSON, conflicting captures and hostless
  records do not select a firewall target;
- SysWarden internal security records use process-local HMAC authentication and
  do not copy raw attacker-controlled payloads back into the ingestion path;
- custom feeds require an exact SHA-256, supported multi-origin feeds require
  independent agreement, downloads and stored inputs are bounded, unsafe
  prefixes are rejected and failed authority preserves the last known good
  state;
- WAAP, UDS and HA reject default routes, unsafe networks, local interfaces, HA
  peers and strict-whitelist targets before any firewall mutation;
- unsafe historical list entries remain visible and removable through bounded
  recovery parsing but cannot be reintroduced through normal mutation paths;
- HA setup propagates automatic-whitelist failure and disables an existing sync
  schedule instead of reporting a partially enabled cluster.

Remaining non-blocking and deferred findings stay assigned to later remediation
lots. This report does not claim closure outside the explicit LOT 2S matrix.

## LOT 2 closure boundary

LOT 2 combines the completed Linux-only surface reduction in LOT 2A, the
three-package reproducibility work in LOT 2B and the bounded security remediation
in LOT 2S. The candidate contains all three sublots. The aggregate decision is
`LOT 2: CLOSED` only for the exact merged commit after its protected main and
qualification gates pass.

That technical decision is separate from publication. It does not authorize a
tag or public Release, does not replace the remaining partner residue evidence
and does not extend qualification beyond the stated package and runtime matrix.

## Qualification signing boundary

The self-hosted native qualification job has no release-signing environment,
no signing secret and no final release-evidence upload. It emits a short-lived
unsigned evidence artifact only after its native package and nftables gates
pass.

A separate GitHub-hosted sealing job is the sole consumer of the protected
signing environment. Before the signing step it revalidates the exact owner,
event, attempt, main SHA, tag absence, unsigned artifact identity and inventory,
the unique main package artifact, byte equality, evidence adapter and aggregate
gate. It then rebuilds and verifies the signing tool, signs the canonical update
manifest, removes signing material and uploads the final qualification artifact.

The remote qualification environment must require exactly one owner review,
remain limited to `main` and disallow administrator bypass. Missing or changed
environment protection fails closed before the secret-bearing job can run.

## Security posture and limitations

- HA uses TLS 1.3 and bearer authentication. Operators remain responsible for
  verified trust distribution and complete cluster membership.
- The WAAP engine analyzes logs out of band. It is not an inline HTTP proxy and
  does not sanitize request traffic.
- `reload` reapplies firewall policy and normally restarts the core. Keep
  verified console access and a ruleset backup.
- The default `keep` choice preserves service state. `nftables` validates an
  operator-prepared service without transitioning it, while mutating commands
  reject `iptables` in v4.03.2. Active firewalld and UFW compatibility remains
  bounded and is not claimed as equivalent privileged qualification.
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

The v4.03.2 candidate remains NO-GO until all required gates pass on the exact
merged commit, no unexplained partner-attributable static residue remains, and
the publisher verifies exactly ten public assets. Only then may the
maintainer authorize the immutable tag and public Release.
