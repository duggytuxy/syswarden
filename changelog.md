# Release v4.03.0

> Candidate status: this block describes the intended v4.03.0 release. It does not authorize a tag or publication. The exact merged commit must pass every protected qualification and release-governance gate first.

### BREAKING CHANGES

- **Linux-only distribution:** The supported package matrix is now limited to
  Debian or Ubuntu DEB, RHEL-family RPM and Alpine APK targets on their listed
  amd64 or ARM64 architectures. No package or updater route exists outside that
  matrix.
- **Local terminal dashboard only:** The network-facing browser terminal,
  remote PTY bridge, token commands, listener, service, browser assets and
  SysWarden-owned TCP 62027 policy have been removed. `syswarden tui` remains a
  local terminal application and opens no listening socket.
- **Upgrade access requirement:** Operators must retain verified local console
  or SSH access before upgrading. A controlled downgrade can reintroduce the
  removed network surface and must keep TCP 62027 blocked at the host boundary.

### ADDED

- **HA migration fence:** Add root-only manifest creation, manifest
  verification, engagement, recovery, status and release commands for the
  native-sync migration fence.
- **Read-only configuration validation:** Add `syswarden config validate` for
  descriptor-rooted modular reads, schema and policy validation, and sorted
  unknown/deprecated-key diagnostics without rewriting configuration.
- **Transactional configuration migration:** Add `syswarden config migrate`
  while retaining `syswarden migrate-config` as a compatibility alias. Both
  expose a dry-run that performs zero source or destination writes.
- **Challenge-bound attestation:** Extend authenticated `GET /ha/status` with a
  dynamic `native_sync_fence` object and challenge echo. The capability name
  announces schema support only; it is never accepted as proof of an active
  and drained fence.
- **Conditional cleanup:** Require
  `X-SysWarden-HA-Fence-Condition` on historical static cleanup while a fence
  is active. Missing, malformed and stale conditions fail without mutation.

### CHANGED

- **Partner migration contract:** Keep provenance deletion ledger-only and
  historical static deletion explicit. Integrators may clean only addresses
  from their durable per-peer ownership journal and must never infer ownership
  from the peer's effective union.
- **Opaque manifest comparison:** The operator distributes one verified
  activation manifest. Integrators compare its epoch, membership digest and
  legacy-writer digest with fresh live attestations as exact case-sensitive
  strings and do not recalculate either digest.
- **Release inventory:** Publish exactly six Linux packages and thirteen public
  assets. The Ed25519 update manifest and detached signature remain mandatory
  release assets.
- **Qualification:** Limit platform qualification evidence to native Linux
  package lifecycle shards and the isolated nftables kernel laboratory, with
  exact inventories and fail-closed aggregation.
- **Host hardening:** Make enabled Linux hardening stages propagate failures,
  validate effective state and roll back critical file mutations. Alpine
  repository selection and automatic operating-system update policy remain an
  explicit operator responsibility.
- **Configuration contract:** Set modular schema version 1 as current and treat
  an absent schema version as historical input. Keep the CLI validator and core
  loader aligned on blocklist URL/hash choices, Wazuh endpoint completeness,
  compliance intervals, SHA-256 prefixes, trimmed HA peers and SSH/HA port
  separation while WireGuard is enabled.
- **SaaS monitor setting:** Make `network.saas.allow_monitors` authoritative
  over deprecated `integrations.saas.enabled`, with disabled as the fallback.
  Publish bounded, validated HTTPS feed results as one lock-coordinated IPv4 and
  IPv6 pair with a digest manifest and rollback.
- **Canonical persistent lists:** Parse exact canonical IPv4, IPv6, CIDR and
  supported service entries. `whitelist --port` creates a TCP-service-scoped
  entry while an omitted port remains address-wide.
- **Typed log inputs:** Require canonical WAAP log patterns and reduce globs to
  verified exact real regular-file matches before core tailing or custom
  rsyslog input generation.

### SECURITY

- **Fence persistence:** Store active fence state, epoch tombstones and writer
  closure records in owner-only, non-symlinked files with atomic publication.
- **Race handling:** A concurrent fence transition invalidates the previously
  observed condition. Cleanup receives HTTP 412 and stops for operator review
  instead of retrying against an unverified state.
- **Cluster completeness:** An unreachable member, changed membership, changed
  certificate identity, partial view or unclosed external writer keeps the
  migration campaign open and retains every ownership claim.
- **No timer as proof:** A partner observation window remains useful supporting
  evidence but can never substitute for a fresh, all-member `active_drained`
  attestation under the unchanged operator manifest.
- **Fail-closed list application:** Reject malformed or ambiguous persistent
  entries instead of partially applying them. SSH exceptions target only the
  effective SSH port, and stale port-qualified entries block a changed-port
  candidate until the operator reconciles them.
- **Bounded feed publication:** Require TLS 1.3 HTTPS without redirects, reject
  invalid entries and configured limits, retain the previous pair on required
  feed failure, and publish owner-only files through locked staging and
  rollback.
- **Configuration-sink encoding:** Validate and encode operator-controlled
  rsyslog and WireGuard values for their destination grammars. The core opens
  WAAP logs without following links and revalidates identity after rotation;
  rsyslog inputs remain subject to operator protection of their parent paths.

### RELEASE GATE

- Written partner freeze confirmation was received on 20 August 2026. The
  technical residue-free migration gate remains pending.
- The tag and all thirteen public assets remain blocked until source, tests,
  security scans, six native package lifecycles, nftables qualification,
  documentation truth checks, signed update verification and exact release
  inventory validation pass on one immutable commit.
- The residue-free migration scenario remains required before the v4.03.0
  freeze can be accepted.

---
Archived pre-v4.03.0 changelog SHA-256: a6ebcab7a81769c52147be710622995779cedf9523270cf08cf03e275501cde5
