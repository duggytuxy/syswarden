# v5 initial threat model and acceptance map

Status: review draft for WP01. This maps requirements to future evidence;
rows are not passing-test claims. Refine it with the versioned schemas and
deployment matrix before freezing scope.

## Assets and actors

Protect administrator access, local enforcement, policy/configuration,
authenticated fleet identities, integration-owned claims, private logs,
geographic/IP inventory, approval records, signed evidence and release trust.

Model unauthenticated network clients, authenticated but unauthorized users,
malicious log input, a compromised fleet node, a stolen browser session, a
compromised plugin credential, a compromised console, local unprivileged users
and a host administrator. Treat the identity provider and package/build chain
as explicit trust dependencies. A valid identity is not authorization for
every node or action. Internal network location alone grants no authority.

Root compromise may subvert local observation and enforcement. Bounded journal
integrity and externally retained checkpoints can expose some inconsistencies,
but do not prove that a compromised host reported every event. Document this
limit in UI and evidence claims. Exfiltration or publication of private raw
evidence is outside the authorized development workflow.

## Trust boundaries and required verification

| ID | Threat and boundary | Required behavior | Evidence owner and completion test |
| --- | --- | --- | --- |
| V5-T01 | Log content crosses the sensor/parser boundary. | Validate source ownership, canonical paths, types, framing and limits. Reject control/injection input without stopping healthy sources. No recursive ingestion of SysWarden output. | WP02/WP03 and WAAP adapters: malformed, oversized, rotation, replacement, loop and partial-input fixtures; native bridge checks. |
| V5-T02 | An observation becomes a security verdict. | Preserve unknowns and provenance; core policy owns decisions. No invented layer, identity, causality or successful enforcement. | WP02/WP06/WP17: shared golden and migration vectors across core, CLI, TUI, alerts and dashboard. |
| V5-T03 | A node or browser crosses a fleet read boundary. | Explicit membership and epochs, verified credentials, deny-by-default scope, bounded replay and prompt revocation. | WP11/WP18: forged identity, stale epoch, replay, unauthorized object/aggregate/map/export and reconnect tests. |
| V5-T04 | A web session requests a privileged change. | CSRF/session protections and separate authority; bind exact immutable targets, policy and TTL to approval. No read credential or display state authorizes execution. | WP08/WP10/WP18: cross-role attempts, changed target groups, expired approval, tampered plan, retry and partial-failure tests. |
| V5-T05 | A BunkerWeb scheduler submits or withdraws a claim. | Preserve explicit opt-in, source scope, TTL, idempotence, protected-source rules and writer/fence restrictions. No cross-source or administrator-claim deletion. | BunkerWeb contract plus WP08/WP11: API, ledger, migration, expiry and HA tests; real plugin scenarios remain separate evidence. |
| V5-T06 | HA members or a console change state after a partition. | Reject stale epochs and unsafe writers; preserve the supported topology. No implicit writer election or dashboard-led promotion. | WP11 and retained HA contracts: partition, delayed message, recovery, key rotation and restart tests. |
| V5-T07 | Attackers exhaust queues, disk, memory or client rendering. | Bounded work and storage, visible loss/freshness, cancellation and recovery. Preserve local protection and mandatory action evidence. | WP03/WP12/WP17/WP18: frozen load profile, slow consumers, disk pressure, crash recovery and soak evidence. |
| V5-T08 | Shared ownership is changed during upgrade or removal. | Remove only proven product entries; preserve administrator and partner behavior. Identify unresolved ambiguity and bounded recovery. | WP13/WP14: separate uninstall, remove, purge, deferred purge, reinstall, reload and reboot paths. |
| V5-T09 | An export discloses data or becomes executable content. | Reauthorize current scope, redact secrets, prevent spreadsheet formulas/macros and remote resource fetches. Preserve formula and snapshot provenance. | WP10/WP18: CSV/spreadsheet injection, cross-user cache, expired download and signature verification tests. |
| V5-T10 | A backup restores revoked authority or pending actions. | Fence epochs, invalidate stale approvals/jobs and attest restored evidence. Never blindly replay a saved mutation queue. | WP03/WP08/WP11/WP18: interrupted commit, restore, revocation and idempotence tests. |
| V5-T11 | A release or dependency changes the trust chain. | Reviewed version transition, pinned inputs, signatures, SBOM, provenance and independently verified public assets. | WP13/WP14 and toolchain work: supply-chain gates and exact candidate IVVQ. |
| V5-T12 | Geographic or percentage summaries hide uncertainty. | Scope before aggregation; provenance/precision on location; explicit denominators, unknowns, freshness and coverage. | WP02/WP18: unmapped/private IPs, unequal groups, zero denominators, missing nodes and redacted map fixtures. |

## Identity and key separation

Release signing, evidence signing, fleet transport, existing integration
authentication, browser sessions and privileged action approval have different
purposes. Do not reuse a release key in a console or expose a fleet credential
to a browser. Pin issuance, storage, rotation, expiry, revocation and recovery
rules for each identity class. Test compromise effects and residual authority.

The new console's role model must not turn an existing BunkerWeb bearer token
into a console login, a fleet enrollment token or a general response credential.
Likewise, new node read identities must not inherit scheduler write scope.

The [fleet admission ADR](FLEET_ADMISSION_ADR.md) maps V5-T02/T03/T06/T07/T10
to proposed enrollment, revocation, source admission and replay decisions.
FA-01 through FA-07 identify the required implementation and evidence stages.
Those stages remain open; the ADR itself is not a passing security test.

## Failure behavior

Loss of the console, IdP or management connection must not stop autonomous local
protection. A missing report is not proof that protection is active or absent.
Display uncertainty while rejecting new privileged work that lacks valid
authorization or mandatory durable evidence.

Retain the existing integration and HA failure semantics until an explicit
compatible migration is accepted. Review freshness and authority independently:
an authenticated stale message still cannot attest current state.

## Review and closure

Record implementation PRs and evidence per row. A successful unit harness does
not establish a real partner stack, a native kernel effect, a reboot outcome
or a 500-machine deployment. The final WP01 acceptance map must identify the
exact evidence producer, scope, candidate binding and remaining limitations.
Keep unimplemented or untested controls open in their work-package issues.
