# Initial v5 validation plan

Status: proposed WP01 review inputs. Component checks can begin now; native
campaigns use their applicable authorization. The final v5 Upgrade release
requires full IVVQ under the existing release policy. No result is implied by
listing a test here.

## Evidence levels

| Level | What it can establish | What it cannot establish alone |
| --- | --- | --- |
| Contract and unit fixtures | Parser bounds, schema compatibility, deterministic semantics, authorization rejection and modeled recovery. | Real partner processes, kernel effects, reboot persistence or fleet capacity. |
| Local integration fixtures | Actual local sockets/TLS, process boundaries and adapter behavior with controlled dependencies. | A complete deployed BunkerWeb stack or native lifecycle acceptance. |
| Simulated fleet load | Console capacity under a declared model of independent agent identities, events, sessions and failures. | End-to-end operation on 500 physical hosts or real network diversity. |
| Native IVV | Real signed product, supported host behavior, integration, lifecycle, access preservation and actual reboots. | Other untested profiles or a release verdict without the required acceptance process. |
| Protected Upgrade IVVQ | The accepted complete plan on the exact candidate, with immutable evidence and independent publisher checks. | An unlimited performance or security guarantee. |

Record candidate identity, command, environment/toolchain, start/end, exit
status, skipped tests, scope and limitations. Keep raw operational evidence
private. Public examples use synthetic inputs; public reports must not reuse
confidential feedback or identify private infrastructure.

## Capacity and spending constraint

The dashboard's 500 servers are a capacity target exercised by 500 logical
agents on existing hardware. Use distinct authenticated identities and scopes,
not 500 copies of an identical unauthenticated response. Bound and measure the
generator independently from the console, and disclose shared-host contention.

Use existing laboratory machines for real-agent and BunkerWeb IVV. Do not rent
servers, buy hardware, subscribe to a paid service or incur extra license/test
resource costs. If a test cannot fit existing resources, document the limitation
and revise the test design without silently weakening its assertion. A listed
2-vCPU/2-GiB reference VM is an allocation, not a purchase requirement.

## Initial budgets for review

| Area | Proposed or inherited boundary | Evidence to freeze before implementation |
| --- | --- | --- |
| Development checks | Shared Go build/module caches, two CPU workers, heavy jobs sequentially; reuse generated inputs where valid. | Toolchain identity, elapsed time, peak resources and actual free-space changes when cleaning. |
| Core/agent regression | Retain the WP01 10 percent regression decision boundary against the accepted standalone baseline. | Define each metric, workload, absolute ceiling, repetitions and measurement uncertainty; zero/near-zero baselines require an absolute rule. No automatic waiver. |
| TUI input | p95 cached local input-to-frame <= 50 ms, with an eight-hour bounded-resource soak. | Separate cached rendering from ingestion and remote delay; include resizing, floods and partial-source failure. |
| Dashboard capacity | 500 logical agents on existing resources; no real 500-server requirement. | Freeze concurrent viewers, health cadence, event rate/bursts, payload size, retained history, map density, replay and exports. |
| Dashboard service | Proposed 2 vCPU/2 GiB profile, steady RSS <= 512 MiB, burst RSS <= 1 GiB. | Measure generator separately; freeze CPU/disk/network limits and retention under the declared workload. |
| Dashboard interaction | Proposed p95 cached read API <= 250 ms and receipt-to-visible alert <= 2 seconds; initial compressed JavaScript <= 200 KiB. | Separate polling cadence/network delay; measure deferred map loading, slow consumers and export contention. |
| Journal and recovery | Bounded disk/queue/work with visible loss and no silent mandatory-evidence discard. | WP03 must freeze byte ceilings, reserve policy, retention, durable commit, recovery times and loss markers. |
| BunkerWeb | Preserve protocol bounds, TTL/ownership and existing runtime behavior; no console dependency. | Run the compatibility anchors and real partner matrix on exact pinned versions. Record any latency or resource regression. |

These proposals are review inputs, not benchmark results. Do not label WP01
fully frozen while workload definitions, absolute agent/journal limits or
recovery objectives remain undecided. Resource budgets describe consumption,
not a financial allocation.

## Non-regression gates by work slice

- Shared schemas: golden, malformed, duplicate, unknown-version, compatibility
  and migration fixtures; preserve existing public protocol/telemetry fields.
- Journal framing: exact payload bytes, independently bound start/end cursors,
  every interrupted-write position, corruption without resynchronization,
  replay/reorder, scope substitution, byte/frame limits and sequence exhaustion.
  See [Event journal](EVENT_JOURNAL.md). These component checks do not prove
  durable commits, crash recovery on disk or authenticated checkpoints.
- Checkpoint authentication: canonical signed bytes, exact scoped public keys,
  sequence-bound authorization, replay/rollback against a protected prior anchor,
  explicit key rotation, empty segments and byte verification after signature
  verification. See [Journal checkpoints](JOURNAL_CHECKPOINT.md). Key lifecycle,
  durable anchor persistence and global equivocation remain separate work.
- UI changes: shared verdicts and evidence quality, stable selection, supported
  scope, inert rendering, empty versus unavailable states and read-only behavior.
- Linux segment storage: private ownership, descriptor-relative exclusive
  creation, independent process locks, synchronized append, cursor conflicts,
  uncertain writes, preserved partial tails, bounded reads and authenticated
  read-only reopen. See [Journal storage](JOURNAL_STORAGE.md). Temporary-file
  and process-interruption tests do not establish physical power-loss durability
  or native reboot acceptance. Persistent anchor coordination remains separate.
- Checkpoint publication: serialized freeze, exact authenticated byte binding,
  bounded candidate/signature files, no-replace publication, phase-by-phase
  storage failures, preserved interruption evidence and authenticated read-only
  reopen. See [Checkpoint publication](JOURNAL_PUBLICATION.md). A readable file
  is not a protected continuity commit; physical power-loss IVV remains separate.
- Local continuity: independent bootstrap and expected resume head, full bounded
  chain validation, stored publication authentication/synchronization before
  anchor append, concurrent stale requests, capacity and counter exhaustion,
  uncertain complete/partial tails, safe file metadata and fault injection.
  See [Protected continuity](JOURNAL_CONTINUITY.md). Authority provisioning,
  independent restart-head custody and partial/corrupt-tail recovery remain open.
- Reviewed complete-anchor recovery: one-record eligibility, read-only plans,
  exact approval binding to bytes/resources/trust/budgets, current scoped signature
  verification, ordered resynchronization, no byte mutation, stale/corrupt/extra
  tails and fault injection. See [Reviewed recovery](JOURNAL_RECOVERY.md). A plan
  digest is not an authenticated principal; external custody and native IVV remain.
- Local custody admission: signed canonical policy, independent exact current
  pins, scope/key-purpose separation, validity, kernel peer credentials, explicit
  operation grants and recovery-approval separation. See [Custody admission](CUSTODY_ADMISSION.md).
  Same-UID socket fixtures do not establish cross-UID service isolation, current
  policy persistence or production lease/lifetime enforcement.
- Policy storage and custody leases: signed history, serialized administrative
  compare-and-install, reserved disable capacity, process locks, expiry during
  durable transitions, zero results on errors, retained pending/completed state,
  independent recovery approval and no automatic retry. See
  [Policy storage](CUSTODY_POLICY_STORAGE.md). These component tests do not establish
  authenticated administration, service isolation, clock integrity or native IVV.
- Reviewed policy administration: separate inspection/apply decisions, exact
  signed before/after state and resource/peer binding, bounded approval validity,
  atomic transition/audit-reference persistence, stale/replayed plans, unavailable
  authorization, uncertain writes and old-format continuity. See
  [Reviewed administration](REVIEWED_POLICY_ADMINISTRATION.md). The actual identity
  and audit providers, isolated service and native acceptance remain separate.
- Fixed-resource authority composition: owned startup descriptors and roots,
  canonical bounded requests, all six existing operation routes, unchanged
  authority checks, no-write denials, cross-handle exclusion, fixed limits and
  concurrent/draining close. See [Local authority](LOCAL_AUTHORITY.md). Socket
  transport, isolated provisioning, identity/audit providers and native acceptance
  remain separate; no service is activated by these tests.
- Bounded local authority transport: exact framing and client EOF, pre-allocation
  length checks, absolute I/O deadlines, connection capacity, generic wire denials,
  ancillary descriptor rejection without leaks, partial replies and draining
  approved mutations. See [Local transport](LOCAL_AUTHORITY_TRANSPORT.md). Listener
  isolation, accept/rate policy, durable denial auditing and native acceptance
  remain separate; no production service is activated.
- BunkerWeb-related changes: the [compatibility contract](BUNKERWEB_COMPATIBILITY.md),
  including existing automatic synchronization and the contextual dashboard tab.
- Response changes: exact approved targets, preconditions, TTL, durable outcome,
  retries, partial failure and rollback, with administrator access preserved.
- Lifecycle changes: uninstall, native remove, native purge and deferred purge
  tested separately, followed by reload/reboot and unrelated-protection checks.
- Release preparation: complete mandatory local pre-push and protected gates
  under [Local release preflight](../maintainers/LOCAL_RELEASE_PREFLIGHT.md).

## First foundation slice

This slice changes design documentation only. Run documentation consistency,
link and language checks. Execute the existing focused BunkerWeb/HA/WAAP,
configuration, log-bridge and ownership suites to establish a current local
baseline, including the race detector for those paths. Capture skipped tests
and do not turn a skipped loopback/native test into a pass.

Runtime schemas, a new dashboard service and native server campaigns remain
subsequent work. Link this foundation PR with `Refs #223` and the dependent
work packages; leave their acceptance boxes open until their deliverables pass.
