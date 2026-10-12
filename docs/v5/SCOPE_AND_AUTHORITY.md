# v5 scope and authority contract

Status: proposed WP01 foundation for review. Linked work: #222, #223, #224,
#230, #233, #234, #255 and #315. Issue references here refer to the SysWarden
repository. Acceptance is recorded through reviewed PRs and evidence.

## Baseline and release boundary

Use the reviewed main baseline following the published v4.10.4 release.
Historical v4.10.0 qualification and later Patch IVV evidence retain their
original scope. They do not qualify v5. The v5.00.0 `Upgrade` release requires
the full track in [Release validation policy](../maintainers/RELEASE_VALIDATION_POLICY.md).

Foundation work does not change the stable version, publish a tag, edit a
historical changelog section or enable unfinished features on existing hosts.
The initial implementation must retain local operation without a console,
identity provider or multi-node enrollment.

## Initial support boundary

Retain Linux AMD64/x86_64 and the DEB, RPM and APK package families as the
starting boundary. The reviewed v5 matrix must explicitly address Debian 13,
Ubuntu 24.04/26.04, Fedora 44, AlmaLinux 9/10 and Alpine 3.22/3.24, based on the
existing native profile inventory. A listed review target is not a v5 support
or passing-test claim. Do not silently remove an existing profile to make a
candidate pass. The optional console has its own explicit delivery matrix.

Preserve systemd/OpenRC behavior, SELinux enforcement, administrator access,
IPv4/IPv6 control-plane reachability, firewall ownership and independent
uninstall/remove/purge contracts. Register a deliberate compatibility change
with migration, rollback and targeted native evidence before accepting it.

## Components and authority

| Component | Authority and obligations | Must not gain implicitly |
| --- | --- | --- |
| Sensors and log adapters | Submit bounded observations with provenance, source health and timestamps. Preserve unsupported/unknown classifications. | Trust, identity, a causal link or a successful block inferred from arbitrary input text. |
| Core policy and incident processing | Produce authoritative versioned decisions and evidence quality from identified inputs and policy. nftables remains the enforcement authority. | Autonomous policy learning or arbitrary shell response. |
| Journal and evidence | Retain bounded observations, action outcomes, loss markers and authenticated checkpoints. Explain completeness and retention. | A claim that local root cannot tamper with a machine, or that a digest alone proves origin. |
| CLI, TUI and alert viewer | Present authoritative events and current state; carry stable selection and supported scope. Keep local operation usable. | Recomputed severity, a hidden mutation during browsing, or an unknown-IP-only filter. |
| Internal fleet console | Scope-authorized projections, percentage indicators, fleet map, BunkerWeb tab and reviewed action proposals. | Node credentials in the browser, general fleet root access or a second enforcement engine. |
| Response executor | Verify an exact authorized plan, preconditions, target scope, TTL, durable commit, outcome and supported rollback. | Permission inherited from read access, a displayed button or a mutable group name. |
| Existing BunkerWeb integration | Continue its explicit opt-in, authenticated, source-owned, TTL-bounded synchronization under the retained API/HA contract. | General console privileges, cross-source deletion or a dashboard availability dependency. |

## Shared data contract to implement in WP02

Define event, node, policy, incident, action and evidence schemas before wiring
new presentation surfaces. Each needs a schema identifier, version, canonical
encoding where signatures/digests apply, compatibility policy and golden
vectors. Pin collections, strings, payloads, nesting and processing costs.

- Separate stable event/node identity from IP addresses and display names.
- Carry event time, receipt time, source clock quality, observation scope and
  freshness without inventing a global order across unsynchronized nodes.
- Separate observation, severity, policy decision, historical action result
  and current verified control state. A requested action is not a success.
- Model reputation matches, trust policy, observation history and attribution
  independently. Preserve missing, unavailable, stale, partial, rejected and
  not-applicable information without coercing it to a safe result.
- Preserve non-IP L2 evidence. Map only telemetry actually supported by the
  producing sensor to L2-L7; no synthetic coverage claims.
- A consumer may aggregate declared populations but must not classify policy
  or enforcement independently. Rate formulas, denominator eligibility,
  rounding and snapshot identity belong to a shared versioned catalog.
- Unknown or malformed mutation schemas fail closed. Unknown read schemas may
  be reported as unsupported but must not become an interpreted security fact.
- An adapter from v4 must label unavailable identity or evidence explicitly.
  Never manufacture a node identity, action verification or complete history.

The existing BunkerWeb wire API and documented telemetry formats remain a
separate compatibility boundary. A new internal event schema does not permit
renaming their fields or requiring a simultaneous partner upgrade.

## Approved product choices

- TUI: operational overview and primary L4/L7 triage, with the shared all-layer
  viewer. `syswarden alerts`: standalone real-time supported L2-L7 events.
- Dashboard: optional, internal, self-hosted, official SysWarden logo/fonts/
  themes. Same-origin browser sessions, explicit enrollment and scoped roles.
- Dashboard indicators: rates, principally percentages. Missing/zero
  denominators yield `Not available`. No raw-count KPI cards or misleading
  averages of percentages over unequal populations.
- Map: local 2D basemap, approved site metadata preferred, optional local IP
  geolocation with provenance and precision. Apply permissions before sending
  IPs/coordinates or computing aggregates. No required external tile service.
- BunkerWeb: a dedicated contextual tab with integration health, associated
  alerts, temporary claims, expiry and HA state. Preserve existing automatic
  synchronization independently of browser sessions and console health.
- Validation: simulate 500 independent agents on existing capacity; perform
  real-agent IVV on existing machines. No additional spending. Simulation is
  not evidence of 500 real deployed hosts.

## Response compatibility

New human-initiated fleet actions use WP08/WP10 preview, approval, exact target
binding, TTL, verification and evidence. Existing automatic BunkerWeb bans
remain governed by their explicitly enabled integration authority and bounded
source ownership. Do not add an interactive approval to every existing plugin
request or route the plugin through the console.

Any future adaptation to a common transaction engine must preserve that
authorization distinction, wire responses, retries, expiry and recovery. Its
equivalence requires regression tests and native integration evidence before
changing the existing execution path.

## Sequence and remaining review decisions

1. Review WP01 scope, trust boundaries, BunkerWeb invariants and budgets.
2. Implement WP02 executable schemas and compatibility fixtures; then WP03
   bounded journal and recovery contracts.
3. Build read-only consumer slices against those fixtures. Keep UI mockups
   visibly synthetic and review complete screen/state matrices.
4. Introduce integrity, incidents and approved response incrementally, with
   negative tests at each trust boundary.
5. Integrate fleet reads and the optional console after identity/scope rules
   are tested. Add writes only through accepted response contracts.
6. Run native lifecycle, migration, partner integration and full Upgrade IVVQ
   on the exact reviewed signed candidate before release acceptance.

Before freezing WP01, review the exact supported matrix, numeric journal and
agent budgets, signature/canonicalization choices, key lifecycle, role/action
catalog, console recovery objectives and full acceptance evidence map.
