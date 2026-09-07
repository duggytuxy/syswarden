# Release v4.10.0

> Candidate status: v4.10.0 is the active Major development line. This block
> records implemented and verified changes only and does not authorize a tag
> or public Release.

### ADDED

- **Authenticated HA v2 replication:** Add a two-node writer and standby state
  model with explicit cluster, node, peer and epoch identities, TLS 1.3 mutual
  authentication, durable WAL and head journals, heartbeats, acknowledgements,
  tombstones, checkpoints, fencing, rejoin and deterministic resynchronization.
- **Threat-feed provenance and freshness:** Record source identity, retrieval
  time, license, size, checksums, normalization result and current, stale,
  unavailable or rejected state for accepted feed snapshots. Preserve an
  attested last-known-good snapshot through bounded atomic publication. Expose
  the resulting provenance and freshness state through `syswarden audit`.
- **Offline candidate qualification channel:** Add an explicit, no-fallback
  updater path for protected native labs. It binds the signed manifest,
  package bytes, embedded CLI, installed package record and activated CLI to
  the same candidate before any service activation.
- **Versioned TUI and GRC evidence:** Add stable KPI fields for admitted and
  rejected events, HITS, highest signature-backed severity, enforcement jail,
  policy action, evidence quality and time window. The TUI and exported
  dashboard data now consume the same evidence model.
- **Bounded multi-provider webhooks:** Add deterministic Teams, Slack and
  Discord delivery contracts with HTTPS-only targets, strict payload and
  response limits, idempotency keys, bounded retries, rate-limit handling,
  backoff with jitter and explicit delivery-state reporting.
- **Typed TCP and UDP operator policy:** Extend the closed operator-policy
  schema with one canonical destination port for bounded inbound TCP and UDP
  allow rules while preserving the existing ICMP and ICMPv6 contract.
- **Native package-signing foundation:** Add explicit non-publishing bootstrap
  and qualified-policy paths for RPM OpenPGP signatures, APK RSA256 signatures
  and detached DEB OpenPGP signatures. Seal the selected key identities into
  immutable bundle provenance and isolate each family's protected secrets and
  cleanup.
- **Package-owned RHEL 9+ profile:** Add a separate opt-in RPM profile where
  the package owns flat systemd assets, presets and scriptlets while Go remains
  runtime-only. The profile does not configure firewalld, change SELinux
  policy or assemble an image. Its distinct `1.rhelpo` RPM, sealed signing
  provenance and updater exclusion support explicit RHEL 9+ ISO integration
  through an offline `mock` or chroot transaction. Release qualification binds
  separate AlmaLinux 9 and AlmaLinux 10 package-owned campaigns, first real
  boot and two subsequent reboots to the exact signed candidate.
- **Native release evidence framework:** Add candidate-bound contracts and
  validators for AMD64 package lifecycle, product capabilities, HA v2,
  performance and NODE01 migration.
- **Real native performance producer:** Add a reviewed, configuration-bound
  adapter that measures package installation, service startup, CPU, RSS,
  admitted WAAP throughput, event-to-rule latency, nftables transactions and
  process disk I/O from real host observations. Final evidence is pinned to
  the checked-in probe and adapter, the protected configuration and the
  verified DEB lifecycle package identities.
- **Source-bound allocation qualification:** Add an independent Go heap-object
  and byte-allocation channel for the reviewed WAAP engine scan path. It binds
  the exact v4.04.3 baseline and v4.10.0 candidate source commits, requires 60
  fresh processes across three paired campaigns and has no allocation waiver.
- **Go 1.27 evaluation lane:** Add isolated workflow, protocol, JSON v2,
  goroutine, reproducibility, performance and byte-exact rollback probes. The
  release remains pinned to Go 1.26.6 until native evidence supports adoption.
- **Unified Plumber baseline:** Align the GitHub compliance and score lanes
  with Plumber v0.4.55 at its immutable action commit while retaining binary
  checksum and provenance-attestation verification. Bind the release report to
  the exact commit and byte-exact workflow inventory, reject degraded metadata
  or warnings and retain strict 768 KiB report and 1 MiB archive ceilings.

### CHANGED

- **HA configuration contract:** Add closed, validated settings for HA v2
  identity, role, peer certificates, state and transaction files, heartbeat
  timing and request deadlines without changing the legacy HA path by default.
- **Feed authority boundaries:** Keep enforcement sources explicit and
  checksum-bound, skip individually safe special-use entries with a recorded
  reason, and keep OSINT enrichment display-only so it cannot set severity or
  firewall action.
- **BunkerWeb compatibility contract:** Revalidate the out-of-band plugin
  schema at the pinned plugin commit and preserve strict source-IP, event and
  log-follower boundaries without introducing an inline proxy role. Because
  that plugin is not HA-role-aware, a two-endpoint BunkerWeb deployment now
  requires a complete active-drained fence manifest; otherwise operators must
  expose only the writer or disable ban push. The separately validated
  `integrations.bunkerweb.scheduler_ips` list remains independent of the one
  HA peer authority.
- **HA crash and scheduler convergence:** Recover an attested head journal
  before the firewall journal, reject simultaneous recovery journals and
  refuse writer startup when a non-expired active or pending BunkerWeb ledger
  record lacks its exact durable claim. Retained scheduler scopes must still
  resolve to the exact configured authority after restart or reconfiguration.
- **HA delivery and claim convergence:** Treat bounded HTTP 208 replay as an
  idempotent acknowledgement after a lost response, advance checkpoints only
  within the attested convergence window and namespace BunkerWeb claims by
  source and scheduler scope. Delete, expiry, restart and resynchronization no
  longer shorten or remove an independent local claim.
- **HA role-aware integration state:** Advertise BunkerWeb mutation capability
  only from a healthy writer, expose the complete `/ha/sync` state there and
  preserve explicit `opaque_v2` provenance on standby projections that cannot
  attest the originating scheduler claim.
- **Bounded dashboard projection:** Use one 1 MiB telemetry envelope across
  the producer, HA transport and TUI. Display payload projection is
  deterministic and explicitly reported, while an oversized essential state
  preserves the last valid snapshot and records a publication failure.
- **Persistent blocklist initialization:** Create and attest both IPv4 and
  IPv6 persistent list files during installation, including an initialization
  marker. A later disappearance fails closed instead of silently recreating a
  privileged security input.
- **Webhook cancellation outcomes:** Report cancellation before a POST as a
  discarded delivery and cancellation after a POST may have started as a
  transport-ambiguous degraded delivery.
- **Performance qualification model:** Bind three paired campaigns to the same
  candidate, artifacts, host, probe and adapter, with exact quotas for runtime,
  install and size samples and a separate source-bound Go allocation gate.
- **Release qualification sequencing:** Separate diagnostic pre-merge
  rehearsals from official post-merge evidence so signed packages and every
  native result identify the exact resulting main commit.

### SECURITY

- **HA split-brain refusal:** Fence ambiguous or concurrent writers, bind
  replication to authenticated peer and instance identities, and prevent stale
  peers from resurrecting removed, expired or tombstoned state.
- **Descriptor-bound update verification:** Reject symbolic links, hard links,
  ownership or mode drift, substituted package members, changed installed CLI
  bytes, unbounded package-manager children and unsigned or network-fallback
  qualification paths.
- **Fail-closed native trust policy:** Reject missing, wrong, expired, revoked
  or substituted RPM, APK and DEB signing identities. Production trust roots,
  protected secrets and native signature proof remain required before release.
- **Native signing identity separation:** Reject cross-family key ID and
  public-key digest reuse, reject a shared RPM and DEB OpenPGP fingerprint, and
  prevent bootstrap provenance from satisfying release qualification.
- **Webhook containment:** Bound attacker-controlled fields before encoding,
  forbid redirects and unsafe targets, redact credential-bearing endpoints and
  prevent recursive or unbounded delivery storms.
- **Terminal rendering containment:** Bound dashboard strings to 4096 bytes,
  reject control characters and escape untrusted values before dynamic TUI
  rendering so telemetry cannot inject formatting or terminal content.
- **WAAP log-source integrity:** Require the exact expected owner UID, reject
  group-writable or other-writable log files, and re-attest descriptor and
  path identity, ownership, mode and size boundaries during reads, rotations
  and truncations.
- **Deterministic transport policy:** Compile typed ICMP, ICMPv6, TCP and UDP
  rules in canonical order, reject protocol and family ambiguity and preserve
  the authoritative terminal product policy.
- **Native evidence integrity:** Require owner-controlled, single-link inputs,
  exact digests, immutable output creation and externally verifiable
  attestations for release-critical host observations.
- **Allocation evidence isolation:** Produce source allocation evidence only
  on a protected runner through canonical root-owned system executables, a
  read-only repository and host root, unshared network namespaces and
  read-only probe-visible persistent filesystems. The final performance result
  requires independent PASS verdicts from both native and allocation channels.

### TESTING

- **HA adversarial coverage:** Add deterministic tests for partitions,
  asymmetric reachability, stale epochs, split-brain fencing, WAL recovery,
  crash-before-claim recovery, simultaneous-journal refusal, exact scheduler
  scope re-attestation, tombstones, restart, rejoin, mixed-version behavior and
  authenticated outbound replication. Cover response-loss replay, bounded 208
  convergence, independent local and scheduler claims, writer-only mutation
  capability and standby provenance across delete, expiry and restart.
- **Feed and offline-update coverage:** Add current, stale, unavailable,
  malformed, substituted and recovery cases plus package-payload and installed
  CLI identity tests for DEB, RPM and APK.
- **TUI, KPI and webhook coverage:** Replay brute-force and exploit evidence,
  event-quality states, queue pressure, deduplication, rate limits, retry
  boundaries, cancellation ambiguity, bounded dashboard projection, malicious
  terminal strings, secret-safe failures and provider-specific wire payloads.
- **Package and release contracts:** Add fail-closed tests for native signing,
  bootstrap mode boundaries, cross-family key reuse, family-scoped secret
  cleanup, lifecycle evidence, NODE01 migration, protected workflows and final
  release aggregation. Require package-owned RHEL offline staging and first
  boot evidence on AlmaLinux 9 and AlmaLinux 10 without reusing standard RPM
  proofs. Native host execution and production-key verification remain release
  gates for every shipped package.
- **Performance evidence coverage:** Add real native adapter, source-bound
  campaign identities, aggregate sample quotas, median and p95 calculations,
  a 10 percent stable regression gate, rejection of missing or substituted
  native observations and rejection of duplicated, synthetic or proxy
  allocation measurements.

---

# Release v4.04.3

> Candidate status: v4.04.3 is the Patch candidate for the stable corrections
> listed below. This block does not authorize a tag or public Release.

### FIXED

- **Dynamic-ban transaction timing:** Verify preserved nftables timeouts
  against the bounded start and finish of the kernel observation. Legitimate
  timeout decay while nftables serializes the ruleset no longer causes
  `whitelist` or `unblock` to reject a valid transaction, while extensions,
  premature expiry and missing elements still fail closed.
- **Transactional whitelist and unblock convergence:** Remove an explicitly
  unblocked IPv4, IPv6 or CIDR range from both live dynamic-ban layers while
  preserving every remaining interval and its expiry metadata. Restore the
  exact prior list content through identity-bound compare-and-swap when a
  firewall apply fails, and keep port-scoped whitelist entries from removing
  global bans. If HA delivery fails after the verified local apply, report
  that the local firewall and list changes remain committed instead of
  implying a distributed rollback. If compatibility-wrapper reconciliation
  fails after the authoritative commit, preserve the committed list content
  and report only the incomplete wrapper instead of creating list drift. If a
  journal-phase or journal-cleanup error occurs after verified policy
  persistence, preserve the committed list content and expose the remaining
  recovery debt.
- **Declarative whitelist convergence:** Merge `network.whitelist_ips` into
  every nftables transaction and into the core daemon's protected-target
  checks. TOML-only whitelist entries now remain effective after reload and
  reboot, configuration changes invalidate the cache immediately, and unsafe
  or overly broad entries remain rejected.
- **IGMP control-plane classification:** Exclude only the exact
  `SRC=0.0.0.0 DST=224.0.0.1` tuple with either `PROTO=IGMP` or `PROTO=2`, as
  reported in issue #148, from the generic port-scan telemetry classifier.
  This does not whitelist `0.0.0.0`, change nftables or alter the
  authoritative firewall decision; every near-miss remains observable.
  Neutralize existing `0.0.0.0` and `0.0.0.0/32` entries in
  `network.whitelist_ips` for upgrade compatibility, with an explicit
  diagnostic across runtime, validation and migration paths, while all other
  unsafe entries remain rejected.
- **Quiet modular configuration loading:** Stop printing the routine modular
  TOML success message for every CLI command while retaining warnings for
  legacy configuration and migration paths.
- **Shared log-parent uninstall convergence:** Accept supported
  distribution-managed shared `/var/log` layouts without weakening the strict removal
  policy for `/opt`, `/etc`, `/usr/local/bin`, `/run` or `/var/lib`. Empty the
  exact root-owned `/var/log/syswarden` tree through pinned directory
  descriptors and remove only the attested empty directory entry, so
  `syswarden uninstall` completes without exposing operator data to a
  recursive path-substitution race. Preflight every fixed removal artifact
  before the first product-file deletion and remove the executable root last,
  preventing a deterministic late refusal from leaving a non-retryable
  partial uninstall.
- **Package homepage metadata:** Align locally built DEB and RPM homepage
  fields with the authoritative Package workflow and apply fail-closed
  validation to every package format. Serialize local artifact publication,
  invalidate stale checksum evidence before replacing a package, derive the
  exact manifest from the private build workspace and publish
  `SHA256SUMS.txt` last.
- **Attested WireGuard table recovery:** Reconcile only inactive, fully known
  stale-token or orphaned reserved WireGuard tables after revalidating their
  ownership marker, complete topology, stable kernel handle, service state and
  interface state. Active, unmarked, malformed, modified or replaced tables
  remain protected from automatic deletion.
- **WireGuard pre-mutation recovery:** Recover only fully attested pending
  publication, immediate-removal and forwarding-persistence transactions
  before install or reload can change SSH or firewall state. Publication
  recovery now holds the shared lifecycle guard, so it cannot roll back a live
  concurrent publication. Corrupt, ambiguous and external reload-debt states
  remain fail closed. New forwarding journals and stages are file-synced,
  reread by exact identity and content, then directory-synced before the next
  transition boundary.
- **WireGuard activation persistence rollback:** Arm restoration before
  publishing changed forwarding persistence so a failure after manifest
  exchange restores the prior neutral boot setting together with the service,
  interface and runtime forwarding rollback. A failed re-enable no longer
  leaves `net.ipv4.ip_forward = 1` persisted.
- **WireGuard lifecycle serialization:** Hold the shared firewall guard from
  pending forwarding recovery through ownership, service, table and
  persistence changes, final runtime attestation and any compensation for
  both setup and disable. Concurrent lifecycle operations cannot interleave.
  If guard release fails after a verified commit, retain the attested commit
  and report the uncertainty without a blind rollback.
- **WireGuard boot ordering:** Install one exact package-owned systemd drop-in
  that orders the firewall loader after an independently scheduled
  `wg-quick@wg-syswarden` job without pulling WireGuard in or creating a
  dependency cycle. Keep the main systemd and OpenRC firewall units
  byte-compatible with v4.04.2 so downgrade and rollback remain safe; Alpine
  receives no systemd-specific artifact.
- **Retry-safe systemd artifact removal:** Preflight every exact service file,
  enablement link and the package-owned ordering drop-in before removal, then
  remove the drop-in last. If an earlier attempt stopped after any monotonic
  deletion or a failed `daemon-reload`, use the durable removal tombstone and
  a stable exact disk inventory to refresh only the systemd cache before the
  normal service-state attestation resumes. Modified links, unsafe parents,
  orphaned enablements, identity drift and ambiguous manager states remain
  fail closed.
- **WireGuard disable and uninstall safety:** Stop and disable only the exact
  owned service and interface, remove only an attested reserved table, and
  neutralize the manifest-owned `ip_forward` boot setting transactionally.
  Preserve keys for reactivation and restore the runtime forwarding baseline
  only when it is attested. Before inspecting or removing owned state,
  uninstall recovers any interrupted forwarding-persistence transition.

### SECURITY

- **Exact binary source provenance:** Bind every release binary to the clean
  candidate commit even when the local builder runs from a linked Git worktree.
  Package builds now bind both the worktree-specific and common Git metadata,
  create only an empty controlled discovery sentinel, reject inherited Git
  redirection and dirty source state, materialize an isolated source tree from
  the exact commit, use private Go build, module and temporary caches, verify
  locked modules, and require matching revision, commit time, clean VCS state
  and an exact provenance field inventory in the binaries extracted from every
  package before upload.
- **Exact systemd package provenance:** Reject a managed DEB or RPM installation
  before any host mutation when the required ordering drop-in is absent or not
  owned by the exact current package. Permit only the bounded old-and-current
  or duplicate-current RPM ownership overlap observed during an authenticated
  upgrade or reinstall transaction, and require SHA-256 RPM file-digest
  metadata for every accepted owner.
- **Fail-closed recovery boundaries:** Recheck WireGuard service, interface,
  table, manifest, forwarding and list-file identities at their final mutation
  boundaries. Unknown or concurrently replaced state is never deleted or
  guessed.
- **Authoritative firewall preservation:** Keep the existing nftables policy
  authoritative while correcting list convergence and telemetry-only IGMP
  classification. No broad allow rule or automatic ownership claim is added.

### TESTING

- **Build provenance gates:** Bind repository snapshots to the exact Git HEAD
  and validate `vcs.revision`, `vcs.time`, `vcs.modified=false` and the baseline
  AMD64 feature level for every dynamic and static Go binary in local and
  GitHub package builds. Retain every opened payload descriptor, identity and
  digest through the final verdict, inspect static binaries through those
  retained descriptor targets, revalidate them after all inspections, and bind
  the validated pre-package SHA-256 inventory to the workflow step output.
  Compare the exact binaries and signature database extracted from DEB, RPM
  and APK payloads with both that immutable inventory and their staging sources.
- **Patch qualification baseline:** Bind the eight-cell AMD64 qualification
  matrix to candidate v4.04.3 and to the immutable public v4.04.2 package
  assets by release ID, asset ID, size and SHA-256. Add an exact
  v4.04.2-to-v4.04.3 upgrade and rollback selector while preserving every
  historical lifecycle transition.
- **Ordering artifact lifecycle coverage:** Verify exact bytes, SHA-256, mode,
  owner, package inventory, systemd `DropInPaths` and `After` semantics for DEB
  and RPM. Verify absence for APK and after v4.04.2 rollback, plus interrupted
  removal recovery at each of the five deletion boundaries and after a failed
  systemd reload.
- **Firewall regression coverage:** Add timeout-window, dynamic range removal,
  rollback, TOML whitelist, cache invalidation, port-scope and near-miss tests.
- **WireGuard recovery coverage:** Add interrupted transaction, stale and
  orphaned table, inactive and failed service, forwarding restoration,
  uninstall boundary, exact systemd ordering-overlay ownership, unchanged
  OpenRC payload, complete lifecycle
  serialization, compensation-before-unlock, release-uncertainty and
  directory-durability tests, including concurrent publication, recovery and
  v4.04.2 rollback.
- **IGMP regression coverage:** Verify both textual IGMP and protocol number 2
  for the exact all-hosts tuple while keeping different sources, destinations,
  protocols and incomplete records observable.
- **Native uninstall regression coverage:** Model a supported shared
  `/var/log` layout, preserve unrelated log siblings byte for
  byte, reject shared-parent and target substitution attempts, and exercise
  the successful CLI uninstall path that package-only purge matrices did not
  previously cover.

---

# Release v4.04.2

> Candidate status: v4.04.2 is the Patch candidate for the publisher CLI
> contract correction and includes the complete unpublished v4.04.0 and
> v4.04.1 candidate scope. This block does not authorize a tag or public
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

- **Complete publisher CLI binding:** Pass the frozen qualification matrix to
  both unprivileged and privileged release-manager adapter invocations so the
  exact pre-tag evidence can be revalidated before staging and publication.
- **Exact qualification schema consumption:** Align both release-manager
  validators with qualification context schema 2, require the
  `previous_commit_sha` field and bind it to the frozen baseline commit in the
  AMD64 qualification matrix.
- **Release-chain regression coverage:** Require both publisher stages to
  consume schema 2, the exact baseline commit binding and every mandatory
  adapter option so producer and consumer drift fails during pre-merge
  validation.

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
- **Immutable publication recovery:** Preserve the signed v4.04.0 and v4.04.1
  tags and their successful qualification evidence without moving either tag,
  rewriting evidence or bypassing tag-bound provenance. Require v4.04.2 to
  complete a new qualification, signed tag and protected publication sequence.

### TESTING

- **Shared CLI and daemon contract corpus:** Exercise the same raw TOML,
  semantic, environment, 64/65-rule and 256 KiB boundary cases in both config
  implementations without coupling their Go modules.
- **Real nftables and failure-path coverage:** Add deterministic golden
  fixtures, validate the generated topology and populated IPv4/IPv6 rules in
  isolated real-nftables namespaces, and add exact JSON mutation tests plus
  injected failures for apply, verification, persistence, rollback and restart
  recovery.
- **Executable publisher contract regression:** Extract both exact continued
  adapter commands from the release-manager workflow, derive every mandatory
  option from the live parser and reject missing, unknown, duplicate or
  valueless options before merge.

---

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
