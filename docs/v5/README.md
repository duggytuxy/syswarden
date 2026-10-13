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
6. [Node identity and read snapshot](NODE_SNAPSHOT.md).
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
shutdown drain and verifies service to another UID during incomplete input.
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
