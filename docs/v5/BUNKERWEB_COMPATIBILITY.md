# BunkerWeb compatibility during the v5 transition

Status: mandatory compatibility boundary for the v5 design, pending complete
candidate verification. Preserve both the authenticated synchronization API and
the independent log-ingestion path. A successful unit harness is not a claim
that a real BunkerWeb deployment has been exercised.

## Baseline and authority

The existing [plugin contract snapshot](../../src/core/syswarden-core/network/testdata/bunkerweb-plugin-contract-v1.11.json)
pins plugin 1.11 at upstream commit
`90fe786729cf6912203196aac4d17517ab2fa3cb` and API version 2. It is a historical
compatibility baseline, not a statement about the newest upstream plugin.
Record the exact partner version used for each real integration run. Do not
silently update the frozen snapshot or claim compatibility with untested
versions.

Existing [HA v2 prerequisites](../technical/HA_V2_OPERATOR_PREREQUISITES.md)
and [BunkerWeb log configuration](../../examples/bunkerweb/README.md) document
the current boundaries. Their historical candidate wording is not a v5 claim.

## Required invariants

| Boundary | Invariant retained by v5 |
| --- | --- |
| Feature gate | BunkerWeb synchronization remains explicitly enabled with valid HA authentication and source authorization. Installing a dashboard must not enable it automatically. |
| Wire contract | Preserve API version/capability semantics, `/ha/status`, `/ha/sync`, `/ha/telemetry`, methods, payload shapes, errors and bounded responses for supported clients. New internal schemas use adapters. |
| Authentication | Preserve bearer and allowed-source checks, verified TLS behavior and the distinction between schedulers and HA peer identities. Do not reuse credentials for dashboard access. |
| Temporary ownership | Preserve the authenticated source scope plus source identifier, IP, TTL, reason, expiry and durable claim state. The label `bunkerweb` alone is not proof of ownership. |
| Retry and deletion | Retries remain idempotent; deletion withdraws only the caller's eligible claim. Other schedulers, core-runtime claims, persistent lists and administrator entries retain their effective protection. |
| Bounds | Preserve the reviewed request limits and TTL range from the snapshot unless an explicit compatible change is accepted. Reject malformed or ambiguous input without partial mutation. |
| HA v2 | Preserve the healthy static writer requirement, recent authenticated peer state, active fence and recoverable mutation path. The standby cannot become a writer through the dashboard. Retained scheduler scopes cannot be silently narrowed or shadowed. |
| Existing plugin topology | The pinned plugin is not HA v2 role-aware. Preserve the documented complete-fence prerequisites for its multi-peer operation; do not imply automatic writer selection. |
| Log collection | Preserve automatic discovery of real BunkerWeb logs and explicit host-mounted path overrides. Keep source trust, rotation/replacement handling, anti-recursion markers and bounded ingestion. Missing logs remain visible; no empty placeholder files. |
| Shared services | Do not rewrite BunkerWeb/Nginx policy, reload it for a read-only dashboard view, loosen log permissions, or remove unrelated rsyslog configuration. |
| Migration and lifecycle | Verify retained claims, expiry, source scopes, log overrides and service permissions after upgrade, restart and rollback. Validate product removal without damaging the partner's configuration or unrelated protection. |

The operator's existing opt-in authorizes the established bounded automatic
integration workflow. A new dashboard approval screen must not interrupt every
plugin ban/withdrawal request. Human-initiated changes from the console still
need the reviewed response transaction path and exact scope authorization.

## Dedicated dashboard tab

Add a **BunkerWeb** tab to WP18 when at least one authorized server has the
integration configured or a previously established integration state. Decide
this from authoritative configuration/capability information, not from an
untrusted event label. In a server detail view, scope the tab to that server.

Distinguish log collection, scheduler synchronization and combined operation.
Verified BunkerWeb log collection can make the tab relevant even when the
optional synchronization feature is disabled. A log path or name alone is not
authenticated proof of a partner deployment. Do not enable synchronization
merely to display a log-only integration.

- Keep the tab visible with explicit stale, disconnected or unknown state when
  a known integration stops reporting. Disabling an integration may retain its
  authorized history with a clear disabled label. Do not display unauthorized
  servers or reveal their existence through aggregate values.
- Show participating servers, integration enablement, observed API/plugin
  version when attested, source health, last successful exchange, supported
  capabilities, synchronization errors and applicable HA role/fence state.
  Missing plugin-version evidence remains unknown.
- Provide associated alerts and temporary-claim details: source scope,
  creation/update time where available, expiry/remaining TTL, requested versus
  verified result, and current control evidence. An expired or withdrawn
  partner claim does not prove the IP is globally unblocked.
- Use rate-based integration coverage, freshness and verified-operation KPIs
  only when the eligible population and evidence exist. Reuse the shared rate
  catalog and `Not available` behavior; no invented success percentage.
- Keep investigation read-only. Any supported manual action goes through the
  same scoped approval, verification and audit contract as other console
  actions. No embedded BunkerWeb administrator session, general proxy or new
  secret exposure is implied by this tab.
- Reuse official SysWarden components and maintain scope, time window and
  selection between the tab, server inventory, alerts and evidence. This is
  visibility of the integration, not a replacement for BunkerWeb's own UI.

## Existing executable regression anchors

The following source suites already exercise important SysWarden-side
contracts. Keep them in the validation path when the related code changes:

- [Plugin snapshot and retry contract](../../src/core/syswarden-core/network/bunkerweb_compatibility_contract_test.go).
- [Authenticated scheduler, TTL, ownership and eleven-scenario evidence boundaries](../../src/core/syswarden-core/network/ha_api_contract_test.go).
- [Separate scheduler identity and HA v2 writer/fence behavior](../../src/core/syswarden-core/network/ha_bunkerweb_v2_contract_test.go).
- [Recoverable runtime replication](../../src/core/syswarden-core/network/ha_runtime_v2_adapter_test.go).
- [Real-file discovery and explicit WAAP paths](../../src/core/syswarden-core/network/waap_log_paths_linux_test.go).
- [Configuration feature-gate validation](../../src/core/syswarden-cli/config/validator_test.go).
- [Rsyslog bridge generation and anti-recursion](../../src/core/syswarden-cli/pkg/integration/rsyslog_linux_test.go).
- [Rsyslog ownership and recovery](../../src/core/syswarden-cli/pkg/integration/rsyslog_provenance_linux_test.go).

Extend fixtures for v4-to-v5 adapters and the new tab: enabled/disabled/unknown,
unreachable source, denied node, stale capability, failed operation, overlapping
claims, expiry, current protection retained by another owner, and HA standby.

## Real integration evidence still required

On existing authorized laboratory resources, pin the partner release and test
real request/log production, scheduler delivery, kernel enforcement, expiry,
multiple owners, protected sources, audit mode, restart, upgrade and removal.
Include the relevant HA configuration, TLS modes and degraded recovery. Verify
that optional read-only views and push-only cycles do not cause unintended
BunkerWeb/Nginx reloads.

The existing eleven-scenario matrix distinguishes SysWarden fixtures from
partner execution. Retain that distinction: skipped/unavailable partner cases
remain open, not a passing integration claim. Simulation complements these
tests and does not replace them.
