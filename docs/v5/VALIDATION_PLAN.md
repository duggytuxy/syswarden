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

- Container firewall compatibility (#376): explicit independent API-interface zone
  selection with independent Docker zones, missing/duplicate bindings, zone
  changes before and after commit, scoped ownership and exact removal. Exercise
  forwarded IPv4/IPv6 allowed/denied clients, private-source spoofing at ingress,
  container-to-backend traffic and bidirectional bans. Namespace packet tests
  support the result; real Docker, NetworkManager, firewalld reload, host reboot
  and all independent native removal paths remain required before acceptance.
- Independent API ingress (#376): validated CLI/core configuration and legacy
  migration must preserve the separate firewalld scope. Exercise external
  protected ingress with local API ingress, reject unavailable frontend and
  multi-zone scopes, reattest bindings, and preserve unrelated permissions on
  replay and exact removal. An isolated production writer test must prove that
  the two settings do not select each other's policy. Native acceptance remains
  separate from synthetic fixtures.
- Interrupted firewalld compatibility ports (#376): retire only obsolete pending
  port records repeatedly proven absent from runtime and permanent state.
  Preserve present administrator permissions, changed receipts, unavailable
  frontends/zones and ambiguous observations. Exercise precommit refusal,
  pre-persistence rollback, postcommit failure, concurrent rule appearance and
  retry after an operator independently withdraws an unnecessary manual opening.
  Validate diagnostic configuration reads without historical normalization.
- Exposure inventory (#224/#315): complete authorized membership and exact selected
  report binding, disjoint External/Internal/Needs classification partitions,
  nonresponders, reclassification, revoked membership, epoch conflicts, stale
  provenance and unknown clocks. Verify deterministic deduplication, no rejected
  payload disclosure, immutable group copies, input limits and 500 synthetic
  identities. This component does not establish map permission, field RBAC,
  authenticated enrollment or native capacity. See [the inventory contract](NODE_EXPOSURE_INVENTORY.md).
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
  approved mutations. Explicit live-peer ceilings per kernel UID are tested before
  framing, under simultaneous registration and throughout operation drain, with
  reuse after completion and a real second UID served during incomplete input.
  Explicit fixed-window admission budgets now add bounded historical UID slots,
  unchanged spent quota after release, expiry without evicting unexpired history,
  concurrent registration and clock refusal. A real UID reconnecting after an
  admitted malformed request is refused before framing while another authorized
  UID resumes. No automatic request retry is introduced.
  See [Local transport](LOCAL_AUTHORITY_TRANSPORT.md). Deployed service isolation,
  deployment-specific rate policy, durable denial auditing and native acceptance
  remain separate; no production service is activated.
- Bounded listener/supervisor: provisioned endpoint ownership, socket and directory
  ACL refusal, preserved changed artifacts, descriptor-relative cleanup, fixed
  workers, paced admission, timeouts and approved-operation drain. See
  [Local server](LOCAL_AUTHORITY_SERVER.md). The cross-UID gate also verifies group
  reachability without authorization and refusal outside the selected group.
  The endpoint receipt adds exclusive private creation, synchronized write/readback
  before listen, preservation of uncertain or changed evidence, exact ordered
  socket/receipt removal, and startup refusal after a real process kill.
  Ordinary-user receipt reads and mutations are separately denied. The separate
  [endpoint recovery](ENDPOINT_RECOVERY.md) component tests independent receipt
  pins, exact inspect/apply approval, quiescence/audit provider boundaries, refused
  live/changed state, partial unlink/sync outcomes and non-root crash/recovery/resume.
  A separately locked private creator-written pin now supplies recovery trust
  across process death, with exact review binding, ordered retirement, fault
  preservation and additional ordinary-user file probes. Startup never adopts
  stale entries. Deterministic pending-operation fixtures now verify that stop
  closes admission while retaining both lifecycle leases and all evidence until
  drain, refusing either offline recovery mode before approval and preserving
  success/denial/expiry outcomes through concurrent close.
  Trusted provisioning, deployed recovery
  providers, service isolation and native evidence remain open.
- Protected-layout startup: five fixed private children opened relative to a
  trusted root descriptor, no-follow metadata/ACL checks, refused conflicts and
  unchanged failed-startup state, bounded descriptor cleanup and a root lease
  retained through drain. Child replacement is rejected before serving. The
  existing non-root process gate now exercises this actual startup path, including
  private-root attacks, commit, restart and reviewed stale-endpoint recovery.
  See [Protected authority layout](PROVISIONED_AUTHORITY.md). Trusted path discovery,
  account creation, installed OS isolation and native acceptance remain open.
- Explicit authority process: exact startup arguments and descriptor contract,
  nonblocking readiness, cancelled startup, worker and notification failures,
  joined shutdown errors and approved writes surviving cancellation. The existing
  separate-UID fixture uses the shared runner without extra child processes.
  Installed service and native signal/reboot evidence remain outstanding. See
  [Authority process](AUTHORITY_PROCESS.md).
- Protected launch configuration: canonical bounded public trust/enrollment,
  exact service identity and unchanged resource bounds, loaded from an independently
  pinned root-owned read-only descriptor. Mandatory metadata/type/digest and identity
  refusal cases supplement actual non-root startup, commit and restart. No automatic
  trust discovery or approval provider is introduced. See
  [Authority launch configuration](AUTHORITY_LAUNCH.md).
- Authenticated local client: pinned protected endpoint, kernel service UID/GID
  checked before sending, one nonqueued call, bounded canonical request/reply and
  EOF, operation/result binding, private plan shape/digest validation, cancellation
  and explicit uncertain outcomes without automatic replay. See
  [Local client](LOCAL_AUTHORITY_CLIENT.md). The mandatory 113-case cross-UID gate
  includes an impostor listener that receives zero bytes despite expected socket
  metadata. Service identity is not human authentication or independent approval;
  trusted discovery, deployed lifecycle and native evidence remain open.
- Unprivileged local attackers: a mandatory separate-UID component gate tests
  protected journal resources and all authority routes, verifies unchanged state
  and exercises authorized commit/reopen afterwards. Missing or skipped cases
  fail the dedicated gate. A distinct non-root service process owns the actual
  private stores while authorized and ungranted client processes exercise file
  access, all six routes, administrative denial, signal-zero permission, commit
  and clean restart/resume. These fixtures do not provide production provisioning
  or OS sandboxing. The [assurance plan](UNPRIVILEGED_ASSURANCE.md) tracks
  additional product surfaces and pending native distribution evidence; this first
  gate does not accept the installed product or replace independent review.
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

The [standalone executable assurance](AUTHORITY_EXECUTABLE_ASSURANCE.md) adds a
separate mandatory 296-case campaign against the actual built authority binary,
with exact-byte binding, kernel identity observations, separate client operations,
direct signal shutdown, crash preservation and stale restart refusal. The existing
132-case gate remains unchanged. This is component evidence, not installed-service
isolation or native acceptance. Stable remains v4.10.4 and BunkerWeb is independent.

The standalone command now rejects retained real/effective/saved privileges,
unexpected groups or capabilities and missing inherited no_new_privs before
private startup. It disables dumps, seals the four startup descriptors and sets
a restrictive umask. See the [startup contract](AUTHORITY_PROCESS.md). Four added
real-binary negative cases require unchanged private stores and no readiness.
Trusted privileged provisioning, complete OS confinement and native acceptance remain open.

The [sealed executable image](AUTHORITY_EXECUTABLE_IMAGE.md) now binds future launch
to an immutable copy of the approved bytes. The real-binary campaign executes that
image after replacing the source pathname. Native launch policy remains open.

The [non-root exec bootstrap](AUTHORITY_EXEC_BOOTSTRAP.md) now performs the actual
sealed-image transition, fixes the target environment and cwd, and isolates the
complete descriptor table before passing only the four startup handles. The
296-case executable campaign checks all three real programs and post-exec inheritance.
Privileged provisioning, loader/MAC policy, supervision and native acceptance
remain separate work. No native package is activated.

The [root-to-service launcher](AUTHORITY_CREDENTIAL_LAUNCH.md) now performs the
credential transition in the same PID and leaves no root supervisor resident.
Its mandatory lifecycle verifies empty active and bounding capabilities across
observed service threads. Provisioning, native MAC/loader policy and installed
service-manager integration remain open. No package is activated.

The [bounded native ELF profile](AUTHORITY_EXECUTABLE_FORMAT.md) now checks the
actual authenticated image before either exec transition. Its 296-case mandatory
campaign includes correctly hashed malformed images, with no readiness or private
state changes after refusal. Loader and dependency trust remain separate from
format admission; no installed service or stable release behavior is changed.

Protected launch-input acquisition adds mandatory file-resolution and metadata
refusals plus actual lifecycle coverage using the returned descriptors after
source replacement. Exact openat2 restrictions cannot fall back to weaker opens.
These component checks do not establish trusted deployment or native MAC policy.

The [immutable launch snapshot](AUTHORITY_LAUNCH_SNAPSHOT.md) now freezes the exact
approved record before descriptor handoff. Both real startup paths reject missing
seals with a correct digest; the normal lifecycle survives removal of the source
inode. The 296-case executable gate includes 21 snapshot cases and four actual
startup refusals. All 132 independent cross-UID cases remain mandatory. Kernel
support and native deployment policy still require distribution-level IVV.

[Protected runtime-directory acquisition](AUTHORITY_RUNTIME_INPUTS.md) now binds
fixed state and endpoint entries to the identities in the independently approved
launch record. Separate trusted parents preserve private storage and group-facing
endpoint traversal. Forty-one adversarial acquisition cases and real-program
lifecycle coverage contribute to the mandatory executable campaign. The existing
132 cross-UID controls remain separate. Trusted parent discovery, account creation,
installed service policy and native IVV remain open.

The [authority resource ceilings](AUTHORITY_RESOURCE_LIMITS.md) now require exact
soft/hard limits of 256 descriptors and zero ordinary core-file bytes in all three
real startup paths. Insufficient observed budgets or uncertain kernel transitions
fail before private startup. Live procfs checks and three refusal cases are mandatory
in the 296-case executable campaign, normally and under race. The separate 132-case
cross-UID gate remains unchanged. Native capacity and isolation acceptance remain open.

The [bounded readiness monitor](AUTHORITY_READINESS_MONITOR.md) now supplies the
production supervisor-side pipe and one-shot receiver used by actual lifecycle
tests. Its 30-second ceiling, cancellation, malformed/closed/full channel refusal
and explicit ownership are verified normally and under race. It does not launch
or kill processes or establish ongoing health. Installed supervision remains open.

The [pinned child supervisor](AUTHORITY_CHILD_SUPERVISION.md) now composes protected
input handoff, atomic pidfd creation, readiness observation, SIGTERM and bounded
exit/reap observation. Cancellation retains the child; cleanup cannot claim a
successful exit or erase retained evidence. It remains inactive and leaves native
service-manager integration and full v5 acceptance open.

[Complete supervisor input acquisition](AUTHORITY_SUPERVISOR_BUNDLE.md) adds the
independently approved launcher to the four-resource launch bundle. The five held
resources remain valid after caller-parent closure and source replacement; late
or partial acquisition failure releases all acquired handles. Its 25 acquisition
cases and actual handoff are mandatory within the 296-case executable campaign,
normally and under race. The independent 132-case cross-UID gate remains required.
This inactive component neither provisions nor starts an installed service and
preserves BunkerWeb's independent API and HA behavior.

[Protected child startup](AUTHORITY_CHILD_STARTUP.md) now composes complete input
acquisition and pinned process creation. Temporary resources close after handoff;
caller parents remain borrowed. A non-null child is always retained, and a later
handoff/cleanup error remains visible through readiness, exit observation and
final close. Its 17 startup cases remain mandatory within the 296-case real-program campaign,
normally and under race. The separate 132-case cross-UID gate remains unchanged.
This is inactive library composition, not installed supervision or fleet enrollment.

[Child lifecycle orchestration](AUTHORITY_CHILD_LIFECYCLE.md) now connects bounded
readiness, ongoing exit observation, one graceful stop request and bounded drain.
Its outcome keeps readiness, stop, reaped state and handle closure separate; a
lost exit observation leaves the child owned and unclosed. The mandatory campaign
requires 296 cases, including lifecycle fault decisions and actual child/client
operation, normally and under race. The independent 132-case separate-UID gate
remains required. This inactive library does not install a supervisor or establish
native acceptance; BunkerWeb remains independent.

The [LXC compatibility boundary](LXC_SERVICE_COMPATIBILITY.md) requires positive
provider and retirement fixtures plus changed-profile, unsafe-file, context and
stale-manager refusals. A controlled LXC campaign must separately prove actual
scheduling, guest reload/reboot, independent removal paths and preservation of
unrelated jobs. Component success does not establish container capability or
complete v5.00.0 IVVQ acceptance. Track the remaining native evidence in #384.
