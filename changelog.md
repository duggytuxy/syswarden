# Release v4.04.1

> Candidate status: v4.04.1 is the Patch candidate for the release
> qualification contract correction and includes the complete unpublished
> v4.04.0 candidate scope. This block does not authorize a tag or public
> Release.

### ADDED

- **Typed ICMP operator policy:** Add a closed `[[operator_policy.rules]]`
  schema for inbound IPv4 ICMP and IPv6 ICMPv6 echo requests. Rules are
  declared only in `modules/99-user.toml`, use canonical IP or CIDR sources and
  support the bounded `accept` action without exposing raw nftables input.
- **Deterministic nftables compilation:** Compile validated rules into one
  dedicated `operator-policy` chain, sort them by canonical identifier and
  dispatch to the chain immediately before the product-owned catch-all deny.
  A non-match always returns to the existing terminal policy.

### FIXED

- **Exact qualification schema consumption:** Align both unprivileged and
  privileged release-manager validators with qualification context schema 2,
  require the `previous_commit_sha` field and bind it to the frozen baseline
  commit in the AMD64 qualification matrix.
- **Release-chain regression coverage:** Require both publisher stages to
  consume schema 2 and the exact baseline commit binding so producer and
  consumer drift fails during pre-merge validation.

### SECURITY

- **Closed configuration provenance:** Reject unknown or missing fields,
  duplicate identifiers, protocol and family mismatches, non-canonical or
  overlapping sources, IPv4-mapped IPv6 values and every environment variable
  prefixed with `SYSWARDEN_OPERATOR_POLICY`. Limit the operator module to
  256 KiB, the policy to 64 rules and the compiled fragment to 64 KiB.
- **Commit-bound source attestation:** Bind a non-empty policy to the exact
  validated `99-user.toml` identity and digest, then revalidate and reattest it
  at the pre-apply commit boundary and again after post-apply verification,
  before persistent publication.
- **Exact post-apply verification:** Verify the dedicated chain, ordered rule
  expressions, provenance comments, terminal return, unique dispatch and
  catch-all log and drop sequence from nftables JSON. Any mismatch restores the
  previous policy and prevents publication.
- **Durable interrupted-transaction recovery:** Journal the previous kernel and
  persistent firewall state before apply, preserve only live bounded dynamic
  bans, quarantine legacy maximum-ending intervals and recover an interrupted
  transaction before a new reload. An indeterminate apply result is rolled back
  and never treated as an unchanged ruleset.
- **Frontend ownership boundary:** Refuse a non-empty operator policy when UFW
  or firewalld is active so nftables remains the sole authoritative policy
  owner for this capability.
- **Immutable publication recovery:** Preserve the signed v4.04.0 tag and its
  successful qualification evidence without moving the tag, rewriting the
  evidence or bypassing tag-bound provenance. Require v4.04.1 to complete a new
  qualification, signed tag and protected publication sequence.

### TESTING

- **Shared CLI and daemon contract corpus:** Exercise the same raw TOML,
  semantic, environment, 64/65-rule and 256 KiB boundary cases in both config
  implementations without coupling their Go modules.
- **Real nftables and failure-path coverage:** Add deterministic golden
  fixtures, validate the generated topology and populated IPv4/IPv6 rules in
  isolated real-nftables namespaces, and add exact JSON mutation tests plus
  injected failures for apply, verification, persistence, rollback and restart
  recovery.
- **Executable publisher schema regression:** Execute both embedded release
  manager predicates against a valid schema 2 context and reject schema, key or
  baseline commit mutations before merge.

---

# Release v4.04.0

> Candidate status: v4.04.0 is the Minor candidate for the typed operator
> policy foundation. This block does not authorize a tag or public Release.

### ADDED

- **Typed ICMP operator policy:** Add a closed `[[operator_policy.rules]]`
  schema for inbound IPv4 ICMP and IPv6 ICMPv6 echo requests. Rules are
  declared only in `modules/99-user.toml`, use canonical IP or CIDR sources and
  support the bounded `accept` action without exposing raw nftables input.
- **Deterministic nftables compilation:** Compile validated rules into one
  dedicated `operator-policy` chain, sort them by canonical identifier and
  dispatch to the chain immediately before the product-owned catch-all deny.
  A non-match always returns to the existing terminal policy.

### SECURITY

- **Closed configuration provenance:** Reject unknown or missing fields,
  duplicate identifiers, protocol and family mismatches, non-canonical or
  overlapping sources, IPv4-mapped IPv6 values and every environment variable
  prefixed with `SYSWARDEN_OPERATOR_POLICY`. Limit the operator module to
  256 KiB, the policy to 64 rules and the compiled fragment to 64 KiB.
- **Commit-bound source attestation:** Bind a non-empty policy to the exact
  validated `99-user.toml` identity and digest, then revalidate and reattest it
  at the pre-apply commit boundary and again after post-apply verification,
  before persistent publication.
- **Exact post-apply verification:** Verify the dedicated chain, ordered rule
  expressions, provenance comments, terminal return, unique dispatch and
  catch-all log and drop sequence from nftables JSON. Any mismatch restores the
  previous policy and prevents publication.
- **Durable interrupted-transaction recovery:** Journal the previous kernel and
  persistent firewall state before apply, preserve only live bounded dynamic
  bans, quarantine legacy maximum-ending intervals and recover an interrupted
  transaction before a new reload. An indeterminate apply result is rolled back
  and never treated as an unchanged ruleset.
- **Frontend ownership boundary:** Refuse a non-empty operator policy when UFW
  or firewalld is active so nftables remains the sole authoritative policy
  owner for this capability.

### TESTING

- **Shared CLI and daemon contract corpus:** Exercise the same raw TOML,
  semantic, environment, 64/65-rule and 256 KiB boundary cases in both config
  implementations without coupling their Go modules.
- **Real nftables and failure-path coverage:** Add deterministic golden
  fixtures, validate the generated topology and populated IPv4/IPv6 rules in
  isolated real-nftables namespaces, and add exact JSON mutation tests plus
  injected failures for apply, verification, persistence, rollback and restart
  recovery.

---

# Release v4.03.3

> Candidate status: v4.03.3 is the Patch candidate for observed webhook,
> nftables interval and OSINT installation defects. This block does not
> authorize a tag or public Release.

### FIXED

- **Provider-bound webhook serialization:** Select Discord, Microsoft Teams and
  Slack wire formats from the configured provider field instead of matching URL
  hostname text. Build a Microsoft Teams Adaptive Card 1.2 message envelope for
  `teams_url` without assuming the legacy `webhook.office.com` hostname, while
  preserving Discord embeds and Slack text payloads. Keep credential-bearing
  endpoint details out of transport-failure logs.
- **Regression coverage:** Add HTTP contract tests for ban, detected, allow,
  shadow/insider and local-check drift/OK alerts across all three providers on
  one synthetic hostname. Assert that Teams payloads are not Discord-shaped and
  that transport-failure logs expose neither endpoint hostnames nor credentials.
- **Kernel-compatible nftables intervals:** Encode IPv4 and IPv6 host or CIDR
  mutations in nftables interval sets as a start element followed by the exact
  exclusive end marker expected by the kernel. Detect an unterminated start,
  repair it before replacement, reject ambiguous forms and any requested
  interval containing an existing internal boundary, and verify the exact state
  across every available inet and netdev layer before a mutation can report
  success. Treat an end-marker residue after timed expiry as absent when the
  kernel retains it, accept kernels that collect the complete expired interval,
  and prove that a direct re-ban recreates one exact closed interval without
  changing a neighbour.
- **Legacy dynamic-state quarantine:** During transactional reload, detect a
  non-singleton legacy dynamic interval ending at the address-family maximum in
  string, prefix or range JSON form. Quarantine the affected family across inet
  and netdev instead of preserving an ambiguous suffix. The packaged install
  path performs the same exact volatile-set quarantine before its own
  network-dependent configuration, restarts the packaged core service when a
  repair was required and performs a final pass to close the restart race. Keep
  pre-commit and completed warnings distinct, and make rollback report that
  persistent policy was restored while quarantined dynamic family state
  remained omitted. Because the already-published v4.03.2 updater must reach
  GitHub before the candidate package runs, document a bounded producer-stop
  and exact dynamic-set bootstrap for an affected host whose DNS or GitHub
  return traffic is already blocked.
- **Bounded OSINT source filtering:** Keep 6to4, private and other non-public or
  special-use prefixes inadmissible. For the supported multi-origin OSINT path
  only, discard a syntactically valid inadmissible entry with a bounded
  origin-and-count warning, exclude it from consensus and publication, and
  apply the source minimum after filtering. Malformed syntax and every custom
  or digest-bound feed remain fail closed.
- **Installation regression coverage:** Reproduce the upstream `2002::/16`
  6to4 case, prove that the entry is absent from the canonical IPv6 output and
  retain failures for malformed entries or an insufficient post-filter source.
- **Data-Shield availability boundary:** Keep the two-independent-origin quorum
  mandatory for every newly published Data-Shield candidate. During package
  installation only, tolerate a validly configured external mirror outage,
  rejected remote candidates or content disagreement by preserving an exact
  validated last-known-good feed, or by omitting the optional Data-Shield
  contribution when no such file exists. Never publish one mirror alone, and
  keep invalid mirror configuration, caller cancellation, unsafe local state
  and publication failures fatal. Explicit and scheduled feed updates still
  return failure after safely reapplying the validated policy so monitoring
  remains truthful.
- **Observable command failures and typed configuration output:** Return a
  non-zero result when any requested `block` or `unblock` transaction fails,
  while continuing the bounded argument set and emitting an alert only for a
  committed ban. Render strings directly and all other validated
  `config-get` values as compact JSON so empty and non-empty GEO or ASN arrays
  remain distinguishable and honor `99-user.toml` priority.
- **RHEL dependency boundary:** Remove `qrencode` and the implicit EPEL enablement
  from the RPM, package lab, manual DNF or YUM dependency path and RHEL image
  recipe. WireGuard keeps its protected client configuration when terminal QR
  rendering is unavailable and reports that rendering as an optional feature.
- **Alpine scheduler activation boundary:** Account for apk-tools 3 behavior
  that can commit package payload after a failed pre-install script. A fresh
  online transaction without prepared Cronie now completes with an unbroken,
  payload-only SysWarden package while both package hooks exit before creating
  configuration, data, logs, runtime state, cron state, services, processes or
  firewall policy. The package-owned payload includes its immutable launchers.
  The package prints bounded activation steps that remove BusyBox `crond` from
  all runlevels, keep Cronie active only in `default` and run the packaged
  installer. Prepared fresh installs remain automatic,
  scheduler-mismatched upgrades stop before configuration and are reported as
  broken rather than falsely rolled back, and offline staging remains deferred.
- **Package-owned shell completion:** Install Bash completion as an immutable
  package payload under `/usr/share/bash-completion/completions/syswarden`.
  Stop package hooks from writing `/etc/bash_completion.d` or `/root/.bashrc`,
  and remove only the byte-exact historical v4.02.8 through v4.03.2 completion
  during migration or verified removal. Preserve every modified, linked or
  otherwise ambiguous operator path.
- **Attributed integration cleanup:** Remove only byte-exact SysWarden WAF and
  enabled SIEM rsyslog fragments while the installed binary and configuration
  can still attest their expected bytes. Record published identities in a
  private root-owned provenance registry so later configuration changes can
  remove an exact obsolete fragment without claiming an operator file. Pin
  root-controlled directories, publish and quarantine atomically, recover a
  bounded interrupted operation, reactivate rsyslog before commit and preserve
  every concurrent or ambiguous replacement together with its provenance.
- **Exact final-removal closure:** Remove the byte-exact rsyslog anti-forging
  fragment, the attributable priority-400 `syswarden_rsyslog` SELinux module and
  its private checksum provenance, and the exact unlocked root-owned runtime
  firewall lock. Preserve modified, unprovenanced, differently prioritized,
  busy or otherwise ambiguous operator state. Scan the normal core only after
  managed services are stopped so a healthy service can be stopped while a
  manually launched residual core still blocks deletion. The `semodule` CLI has
  no checksum-conditional removal primitive, so SysWarden double-reattests the
  module and provenance immediately before priority-400 removal and verifies
  the result, but does not claim atomicity against an external store replacement
  inside that final comparison-to-command boundary.
- **Explicit package purge semantics:** Keep Debian `remove` non-destructive for
  `/etc/syswarden`, `/var/lib/syswarden` and `/var/log/syswarden`. Treat Debian
  `purge`, final RPM erase and APK post-deinstall as destructive removal of
  those dedicated namespaces. Refuse mounted roots or descendants before
  changing removal state, preserve an exact deferred barrier across Debian
  remove, consume it only after a successful reinstall, and refuse any active
  or ambiguous barrier. Move the exact final barrier outside the state root
  before removing that root so a retry or a successful reinstall can recover
  every bounded crash window without crossing an external mount.

### RELEASE GATE

- A real Power Automate endpoint qualification remains required before Teams
  delivery is claimed as released. The published v4.03.2 assets remain
  immutable and unchanged.
- The isolated nftables laboratory must exercise host and CIDR add, timed
  renewal, permanent replacement, idempotent replay and removal against a real
  Linux kernel for both address families. It must also prove functional timed
  expiry, safe direct re-ban whether an exclusive-end residue remains or has
  already been collected, and conservative rejection both of a singleton that
  overlaps a CIDR with the same start and of a CIDR that spans separately owned
  internal intervals.
- A manual release-owner gate on a disposable Ubuntu 26.04 AMD64 host must
  complete package configuration while a deterministic local TLS fixture serves
  one supported OSINT source path containing a syntactically valid `2002::/16`
  entry. This gate is separate from protected CI and must bind the exact source
  SHA, workflow artifact identity and package SHA-256. Its evidence must show
  the bounded warning, absence of the entry from published lists, successful
  service health and no package left in `iF` state.
- Disposable Ubuntu 26.04, AlmaLinux 10 and Alpine 3.24 AMD64 hosts must bind
  the exact candidate source SHA, workflow run, artifact ID and package digest.
  Their native package-manager records must prove v4.03.2 to v4.03.3 upgrade,
  configuration preservation, service health, reload and the family-specific
  destructive removal contract. The Ubuntu host must additionally exercise
  isolated GEO, ASN and WAAP threshold policy without writing synthetic events
  to a real authentication log or leaving test bans behind.
- The pre-tag Ubuntu migration gate must cover the exact workflow artifact after
  the documented contained bootstrap for a v4.03.2 legacy interval that already
  blocks DNS or GitHub return traffic. The Alpine gate must prove that a fresh
  online transaction without prepared Cronie leaves only an unbroken,
  payload-only inactive package and no generated configuration, data, logs,
  runtime, cron, service, process or firewall state. It must then prove the
  documented activation path and the normal automatic path with Cronie prepared
  before installation.

### POST-PUBLICATION CHECK

- Keep one disposable host on the exact published v4.03.2 package until the
  v4.03.3 Release is public. Run `syswarden update` only after GitHub
  `releases/latest` resolves to v4.03.3, then attest the embedded Ed25519 trust
  root, signed manifest, selected AMD64 package digest, installed v4.03.3
  package record and service health. This smoke test cannot be fabricated or
  claimed before publication.
- The post-publication smoke must use a connected v4.03.2 state for the signed
  updater itself. If the retained snapshot contains the blocking legacy suffix,
  first execute and record the qualified contained bootstrap from the migration
  runbook; no unsigned fallback is permitted.

---

# Release v4.03.2

> Release status: v4.03.2 was published at 2026-08-25T14:15:49Z from the
> signed annotated `v4.03.2` tag, peeled to commit
> `2eae757bbdee510fdd1058ba7770f2c5564ecb23`. It superseded the technically
> qualified but unpublished v4.03.1 candidate. Requirements recorded in the
> historical v4.03.1 block describe that candidate's original gate and do not
> authorize changing the immutable v4.03.2 tag or assets.

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

- **Historical gate result:** The exact published v4.03.2 commit passed the
  protected main and qualification gates, the qualification environment owner
  review requirement and the byte-for-byte signed-tag rebuild comparison. This
  historical block records that completed gate and does not authorize moving
  the tag, replacing an asset or reusing its evidence for a later Patch.

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
