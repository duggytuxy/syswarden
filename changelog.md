# Release v4.03.2

> Candidate status: v4.03.2 is the Patch candidate that supersedes the
> technically qualified but unpublished v4.03.1 candidate. v4.03.1 was
> deliberately left untagged and no public Release was created. Requirements
> recorded in the historical v4.03.1 block describe that candidate's original
> gate and do not authorize or apply to v4.03.2.

### SECURITY

- **LOT 2 aggregate closure:** Assemble the completed Linux-only surface
  reduction from LOT 2A, three-package reproducibility from LOT 2B and bounded
  security remediation from LOT 2S. LOT 2 closes only on the exact merged
  commit after the protected main and qualification gates pass. This closure
  does not authorize a tag or public Release.
- **LOT 2S audit closure:** Close the five high-severity findings and the
  selected M1, M6, M9 and M13 medium-severity controls from security audit
  BW-SW-2026-002. Retired network-terminal and non-Linux surfaces remain
  outside this remediation scope.
- **Log-derived enforcement authority:** Carry one validated source address
  through the matching engine, reject ambiguous embedded JSON and untrusted
  captures, arbitrate competing signatures deterministically and synchronize
  threshold state before WAAP or UDS can request a firewall mutation.
- **Internal-log recursion boundary:** Authenticate SysWarden internal security
  records with a process-local HMAC, exclude raw attacker payloads and require
  the authenticated grammar before WAAP or UDS suppresses an input record.
- **Feed and SaaS integrity:** Bound downloads and stored inputs, reject
  redirects and unsafe prefixes, require hashes for custom feeds, require
  independent-origin agreement where supported and retain the last known good
  state when authority cannot be established.
- **Firewall and HA mutation policy:** Reject default routes, unsafe networks,
  local interfaces, HA peers and strict-whitelist targets before WAAP, UDS or
  HA can mutate enforcement state. Keep unsafe historical entries detectable
  and removable without allowing them to be reintroduced.
- **Firewall backend boundary:** Keep nftables as the single authoritative
  policy engine. Default to a no-transition `keep` mode that refuses active or
  enabled iptables compatibility services, treat `nftables` as an assertion of
  an operator-prepared active service with no active or enabled compatibility
  frontend, and reject the parseable `iptables` value before operational
  firewall policy mutation changes persistent inputs or kernel state.
- **WireGuard backend boundary:** Require the explicit `nftables` backend for
  WireGuard. Do not infer WireGuard UDP or forwarding permissions from the
  bounded firewalld or UFW compatibility path.
- **Qualification signing isolation:** Remove the release-signing environment
  and key from the self-hosted qualification job. Revalidate the exact unsigned
  evidence and package bytes in a separate GitHub-hosted sealing job before the
  protected signing step.

### CHANGED

- **Optional RHEL image staging extension:** Add a separate, opt-in module for
  staging one checksum-bound local RPM into a fresh, unmounted RHEL-family 9 or
  newer image root with package scripts, triggers and plugins disabled. Defer
  all product, service, firewall and kernel activity to a marker-guarded
  first-boot convergence. The extension is not invoked by the normal build,
  package installation, update or reload paths.
- **Forward-only release path:** Rebind the historical public v4.02.8 APK
  transition to v4.03.2 because neither v4.03.0 nor v4.03.1 was published.
- **AMD64-only package scope:** Retire ARM64 and aarch64 build, qualification,
  updater and publication routes. Distribute exactly one amd64 DEB, one x86_64
  RPM and one x86_64 APK. Historical v4.02.8 package records remain immutable
  release evidence and cannot be selected by the current updater.
- **Evidence boundary:** Retain the successful v4.03.1 qualification as
  technical evidence only. v4.03.2 requires its own protected merge checks,
  attempt-1 pre-tag qualification, immutable signed tag and byte-exact
  ten-asset publisher gates.
- **Residual risk tracking:** Keep remaining non-blocking and deferred findings
  in later remediation lots. This Patch does not claim closure of findings
  outside the explicit LOT 2S acceptance matrix.

### RELEASE GATE

- v4.03.2 remains NO-GO until the exact merged commit passes every protected
  main and qualification gate, the qualification environment has the required
  owner review rule, and the signed-tag rebuild matches the qualified packages
  byte for byte. No v4.03.2 tag or public Release is authorized by this block.

---

# Release v4.03.1

> Release status: v4.03.1 supersedes the unpublished v4.03.0 candidate. The
> signed v4.03.0 tag remains immutable and was not moved or published.

### RELEASE RECOVERY

- **Unpublished v4.03.0:** The v4.03.0 publisher stopped before asset staging
  or publication. Its byte-exact gate correctly rejected DEB, RPM and APK
  archives rebuilt from the same commit because their build timestamps, build
  host data and archive metadata were not reproducible.
- **Reproducible packages:** Generate the six Linux packages from a deterministic
  release epoch with normalized package metadata so independent qualification
  and signed-tag builds produce the same bytes.
- **Fail-closed publication:** Keep the exact pre-tag-to-tag byte comparison.
  v4.03.1 fixes package production rather than weakening the release gate or
  accepting payload-only equivalence.

### INCLUDED PRODUCT SCOPE

- **Complete candidate content:** Carry forward the complete intended v4.03.0
  product and security scope into v4.03.1. This includes the Linux-only DEB,
  RPM and APK matrix, removal of the network-facing browser terminal, the local
  terminal dashboard, HA migration fencing, challenge-bound attestations and
  strict partner cleanup conditions.
- **Configuration and lists:** Retain read-only modular configuration
  validation, transactional migration, authoritative SaaS monitor settings,
  canonical persistent lists and typed WAAP log inputs.
- **Security hardening:** Retain owner-only fence state, race-safe conditional
  cleanup, fail-closed list application, bounded feed publication and
  destination-specific configuration encoding.

### RELEASE GATE

- v4.03.1 still requires a fresh protected qualification and signed-tag gate on
  one immutable commit. Publication remains limited to the exact six packages
  and thirteen public assets only after every existing release check passes.

---

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
