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
The next slice pins evidence objects and their explicit transformation lineage.
The remaining schemas and shared consumer integration still follow the agreed
authority contract. No record alone grants response authority.

Detailed operator guidance belongs at https://syswarden.io/docs/ when the
corresponding feature exists. Keep the product README focused on the stable
release and canonical guidance. Public diagrams and fixtures must be synthetic.
