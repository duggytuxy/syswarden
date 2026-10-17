# SysWarden v5 foundation

Status: initial reviewable foundation, started on October 12, 2026 at the
owner's request. These design documents do not implement v5 or establish its
release acceptance. The current published baseline remains v4.10.4.

The first work slice addresses [WP01 scope and threat model](https://github.com/duggytuxy/syswarden/issues/223)
and prepares [WP02 shared schemas](https://github.com/duggytuxy/syswarden/issues/224).
It includes the explicitly requested BunkerWeb compatibility boundary. No new
server campaign, paid resource or public v5 release is authorized by this text.

## Review order

1. [Scope, authority and sequencing](SCOPE_AND_AUTHORITY.md).
2. [Threat model and acceptance map](THREAT_MODEL.md).
3. [BunkerWeb compatibility and dashboard integration](BUNKERWEB_COMPATIBILITY.md).
4. [Validation profile and resource limits](VALIDATION_PLAN.md).
5. [Shared event envelope and conservative v4 projection](EVENT_ENVELOPE.md).
6. [Node identity and read snapshot](NODE_SNAPSHOT.md), with independent
   [fleet exposure classification](NODE_EXPOSURE.md).
7. [Policy decision records and exact input binding](POLICY_DECISION.md).
8. [Action history and scoped control reports](ACTION_AND_CONTROL.md).
9. [Evidence objects and explicit transformation lineage](EVIDENCE_DESCRIPTOR.md).
10. [Incident relationships without invented causality](INCIDENT_RELATION.md).
11. [Shared percentage catalog and bound rate reports](RATE_SNAPSHOT.md).
12. [Bounded event journal frames and recovery inspection](EVENT_JOURNAL.md).
13. [Authenticated journal segment checkpoints](JOURNAL_CHECKPOINT.md).
14. [Bounded Linux journal segment storage](JOURNAL_STORAGE.md).
15. [Frozen journal checkpoints and durable publication](JOURNAL_PUBLICATION.md).
16. [Protected local journal continuity](JOURNAL_CONTINUITY.md).
17. [Reviewed recovery of a complete journal anchor](JOURNAL_RECOVERY.md).
18. [Coordinating independent journal restart custody](JOURNAL_CUSTODY.md).
19. [Bounded local restart-custody storage](LOCAL_CUSTODY_STORAGE.md).
20. [Signed policy and local custody admission](CUSTODY_ADMISSION.md).
21. [Protected policy storage and custody leases](CUSTODY_POLICY_STORAGE.md).
22. [Reviewed custody policy administration](REVIEWED_POLICY_ADMINISTRATION.md).
23. [Fixed-resource local authority composition](LOCAL_AUTHORITY.md).
24. [Bounded local authority transport](LOCAL_AUTHORITY_TRANSPORT.md).
25. [Unprivileged local attack assurance](UNPRIVILEGED_ASSURANCE.md).
26. [Bounded local authority listener and supervisor](LOCAL_AUTHORITY_SERVER.md).
27. [Authenticated local authority client](LOCAL_AUTHORITY_CLIENT.md).
28. [Reviewed stale endpoint recovery](ENDPOINT_RECOVERY.md).
29. [Startup from protected authority directories](PROVISIONED_AUTHORITY.md).
30. [Protected local authority launch configuration](AUTHORITY_LAUNCH.md).
31. [Explicit local authority process and draining exit](AUTHORITY_PROCESS.md).

The [v5 roadmap](https://github.com/duggytuxy/syswarden/issues/222) remains the
work-package index. The accepted presentation work spans the
[TUI](https://github.com/duggytuxy/syswarden/issues/234),
[real-time alerts](https://github.com/duggytuxy/syswarden/issues/255) and
[optional internal dashboard](https://github.com/duggytuxy/syswarden/issues/315).
These consumers share authoritative semantics; none may invent an independent
security verdict or silently hide missing evidence.

## Ticket and PR completion rules

Every implementation PR must reference the affected work packages, describe the
delivered slice and identify completed, retained and outstanding validation.
Use `Refs #...` for partial delivery. Use a closing link only when the PR and
recorded evidence satisfy every remaining acceptance criterion of that issue.
Do not close a work package merely because an intermediate PR merged.

Record the merged commit and remaining work in the relevant issue. Keep
runtime implementation, local tests, native IVV and full v5 Upgrade IVVQ
acceptance distinct. Preserve the published v4 tags, evidence and change
records. Version transitions follow the existing reviewed release process.

This first slice leaves #223 open: numeric budgets, the final supported matrix
and the complete acceptance-to-evidence map still require review. It leaves
#224 open: the first executable event envelope and frozen v4 projection were
reviewed in PR #317; node identity and read snapshots were reviewed in PR #318.
Historical policy decisions and exact input binding were reviewed in PR #319.
Historical action outcomes and scoped control reports were reviewed in PR #320.
Evidence objects and transformation lineage were reviewed in PR #321.
Typed incident relationships and their declared support were reviewed in PR #322.
The shared percentage catalog and rate reports were reviewed in PR #323, with
explicit population partitions, uncertainty, sampling and deterministic rounding.
Bounded event journal frames and recovery inspection were reviewed in PR #324.
Authenticated segment checkpoints against independent scoped keys and continuity
anchors were reviewed in PR #325. Bounded Linux segment storage,
cooperating-process locking, synchronized append and authenticated read-only
reopen were reviewed in PR #326. Frozen checkpoint publication and historical
reopen were reviewed in PR #327. Bounded local continuity and exact expected
restart state were reviewed in PR #328. PR #329 adds read-only
inspection and exact-plan authorized resynchronization of one complete extra
anchor, after authenticating its actual publication. The custody follow-up
coordinates a trusted independent backend through prepared intents, verified
local commits, final state readback and separately authorized recovery, reviewed
in PR #330. The local backend follow-up adds explicit enrollment, a bounded
protected ledger, durable transitions and independently authorized audit bindings,
reviewed in PR #331. The admission follow-up verifies signed enrollment/access
policy against an independent current pin and binds high-level operations to
kernel-observed local peer identities, reviewed in PR #332. The policy-storage
follow-up adds bounded protected current-policy history, serialized updates and
per-operation admission/lifetime checks around the existing coordinator, reviewed
in PR #333. The administrative follow-up binds exact private plans to independent
inspection/apply authorization and stores the decision audit reference in the
same frame as the policy update, reviewed in PR #334. The composition follow-up
binds those existing operations to fixed startup resources and a bounded canonical
request dispatcher, with one active operation and draining shutdown, reviewed in
PR #335. The transport follow-up adds bounded framing and I/O deadlines on accepted
Unix peers, ancillary-input rejection, connection capacity and controlled shutdown.
It was reviewed in PR #336. The ordinary-user component gate was reviewed in
PR #338. The listener follow-up adds an explicitly provisioned pathname endpoint,
fixed paced workers, exact cleanup and further separate-UID checks, reviewed in
PR #339. The client follow-up pins the provisioned endpoint, verifies the kernel
service identity before sending and validates bounded request-bound replies, with
no automatic retry after an uncertain outcome, reviewed in PR #340. The process
follow-up exercises the actual service under a non-root identity with separate
authorized and ungranted clients, protected-file refusals and fresh-process
resume after a durable commit, reviewed in PR #341. The peer-quota follow-up adds explicit simultaneous
connection ceilings per kernel UID before framing, preserves charged slots through
shutdown drain and verifies service to another UID during incomplete input,
reviewed in PR #342. The endpoint-lifecycle follow-up persists a bounded private
ownership receipt before listening, preserves interrupted or changed evidence and
removes only the exact live creator's socket and receipt during clean shutdown.
This ownership evidence was reviewed in PR #343. A real process-kill test verifies
preservation and refusal on the next startup. The recovery follow-up adds
independently pinned, separately approved retirement of a complete stale endpoint
pair and verifies non-root restart/resume without changing journal resources,
reviewed in PR #344. The pin-custody follow-up creates independently protected
lifecycle evidence before listening, reads it in a fresh recovery process and
retires it only after synchronized endpoint cleanup. It preserves uncertain
state and rejects changes without creating a new recovery command. Its shutdown
follow-up separates stopped admission from completed work: both lifecycle leases
and all endpoint evidence remain held until workers and accepted operations drain,
preventing premature offline recovery without cancelling approved writes.
Admission-frequency limits now add explicit fixed windows per kernel UID before
framing, with bounded historical storage and no quota refund on disconnect.
A real separate-UID test verifies refusal after reconnection while another
authorized account still resumes.
Protected-layout startup now connects the actual server to five fixed private
directories, retains their root lease through drain and rejects replaced children.
The existing non-root service-process tests use this entry point through commit,
restart and reviewed endpoint recovery.
A bounded root-owned launch record now carries the independently pinned trust,
enrollment, service identity and explicit limits into the actual server. The
non-root process fixture uses its read-only descriptor; the mandatory gate includes
132 cases with protected-file and identity refusals.
An opt-in executable now consumes explicitly inherited startup descriptors and a
pinned launch digest. Its shared process runner provides nonblocking readiness and
context-driven draining exit, exercised by the existing non-root service fixture.
It is not installed or activated by packages and supplies no administrative approval.
Ambiguous or partial endpoint state and deployed recovery providers remain open.
These components and tests supply no identity
provider or installed OS-isolated service.
These components remain disconnected from production. Authenticated authority
provisioning, OS isolation, incomplete backend/intent recovery, key lifecycle and
retention remain future work.
The remaining schemas and shared consumer integration still follow the agreed
authority contract. No record alone grants response authority.

Detailed operator guidance belongs at https://syswarden.io/docs/ when the
corresponding feature exists. Keep the product README focused on the stable
release and canonical guidance. Public diagrams and fixtures must be synthetic.

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

The [protected launch-input acquisition](AUTHORITY_LAUNCH_INPUTS.md) now opens two
fixed files below an independently trusted private directory, verifies the launch
record and returns a sealed, native-layout-checked image. The actual executable
fixture uses those held handles after source-path replacement. Initial trust,
loader policy and installed supervision remain separate requirements.

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

[Complete protected launch acquisition](AUTHORITY_LAUNCH_BUNDLE.md) now composes
immutable configuration/image snapshots and runtime directories as one owned result.
A late failure releases all intermediate resources; caller parents are retained.
The actual root and non-root launch paths use this bundle after parent closure and
source replacement. The mandatory executable campaign has 296 cases; the independent
132 cross-UID controls remain required. Deployment approval, native isolation and
installed lifecycle acceptance remain open.

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

[Bounded LXC service compatibility](LXC_SERVICE_COMPATIBILITY.md) addresses the
shared runtime profile seen by cron and service retirement. Exact contents,
metadata, repeated LXC context and current manager metadata remain mandatory.
This development correction preserves package attribution and shared files;
native container and lifecycle acceptance remain open in issue #384.

[Authorized node rate populations](NODE_RATE_POPULATION.md) now provide an inactive
deterministic resolver for the three node percentage formulas. Exact membership
deduplication preserves missing/stale nodes, rejects scope or epoch mismatches and
retains conflicting assessments as unknown with their evidence. The immutable
private manifest binds the same scope, membership, policy and measurement instant.
Producer authentication, policy evaluation, consumer integration and native IVVQ
remain open; the 500-node fixture is simulation only. BunkerWeb stays independent.
