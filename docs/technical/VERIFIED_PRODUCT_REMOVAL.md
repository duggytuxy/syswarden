# Verified product removal

Status: implementation under review for the v4.10.3 candidate. This document
describes code boundaries and review requirements. It does not establish release
acceptance or replace the operator guidance at <https://syswarden.io/docs/>.

## Removal contract

Standalone `syswarden uninstall`, native package removal and native package
purge are separate entry points. Each must retire proven product state while
preserving administrator configuration and effective unrelated protection.
Native package removal must finish runtime preparation before erasing the CLI.
A package-manager exit code alone does not establish that contract.

Removal first checks historical producers, administrator policy and persistent
firewall sources. It then publishes the durable removal barrier, stops exact
managed producers and repeats the checks before retiring their state. Ownership
is established from independent writer records, package authority or complete
supported historical generators. A product-looking path or table name is not
deletion authority.

An unresolved artifact keeps removal incomplete. The CLI and durable evidence
must remain available for recovery. Do not clear a barrier, discard a journal,
flush a shared ruleset or edit a package database to force completion.

## Review map

| Boundary | Implementation | Required observation |
| --- | --- | --- |
| Entry-point ordering | `cmd/removal_prepare.go`, `cmd/uninstall.go` | Refusal preserves the CLI; native payload erasure follows verified preparation. |
| Shared persistence | `pkg/firewall/nft_persistence_*` | Only proven entries change; includes, loader inputs, metadata and original backups remain bound to the plan. |
| Current product rules | `pkg/firewall/nft_removal_*`, `pkg/firewall/nft_policy_*` | Writer authority, runtime claims and kernel generation agree before deletion. |
| Historical Fail2ban | `pkg/firewall/legacy_fail2ban_*` | Exact historical targets disappear; unrelated jails, rules and the shared service remain effective. |
| Core runtime history | `pkg/runtimehistory`, `pkg/firewall/nft_removal_claims_*` | Active and retired claims match actual kernel state before private history archival. |
| Generated host artifacts | `pkg/system/removal_*`, `syswarden-core/fileorigin` | Original identity and bytes are retained where required; unknown directory contents are never recursively adopted. |
| Native finalization | `scripts/ci/package_removal_state.sh`, package scriptlets | No unretired product state is left behind; the documented administrator override survives. |

## Historical recovery boundaries

`recover-removal` separates inspection from an application authorized by the
exact lowercase SHA-256 digest of the reviewed plan. Inspection prints metadata
and declared effects, not private file contents. An apply attempt rechecks the
bound inputs; changed inputs require a new inspection.

The available inventories cover historical product logs, generated lists, UI
snapshots, exact historical root cron records and the former Fail2ban integration.
Legacy data retention also requires the operator to confirm that the listed
files have no other producer. Original bytes are moved to a private recovery
location and are distinguished from active configuration.

Fail2ban recovery binds the original configuration inventory separately from
the runtime or persistence plan. Persistent entries in a shared nftables source
are reviewed and retired before target jail and runtime retirement. The source
edit retains the original file privately and preserves administrator bytes.
It does not reload the firewall, mutate live rules or stop the shared Fail2ban
service. Applying the later runtime plan stops only the proven historical
targets and verifies that unrelated live protection remains present.

An interrupted unused-definition retirement has a separate resumption mode.
It requires the original file-plan digest and a fresh review of current
protection. It does not replace the original evidence with a new ownership claim.

The historical `syswarden_f2b` table may remain when it contains independently
verified administrator objects after exact product retirement. Completion then
requires the reviewed persistent edit, retired historical producers, original
private backups and matching live administrator state. The table's name alone
cannot justify deleting it or ignoring its contents.

## Explicit limits before acceptance

The following states remain refused and require additional bounded recovery
work. A refusal preserves evidence; it is not complete removal:

- Historical product persistence without an independent writer record, even
  when a pure historical template recognizer can identify its shape.
- Configured or live administrator policy embedded in product-owned tables
  until equivalent independently managed protection is established.
- Customized configuration outside the documented retained `99-user.toml`
  surface and other artifacts whose ownership is unresolved.
- An empty historical dedicated Fail2ban table without separately justified
  table-retirement authority.

The candidate must not be described as covering every historical removal state
while these limits remain. Accepted private recovery backups are inactive
evidence and must not recreate product state after service reload or reboot.

## IVV acceptance observations

For each of standalone uninstall, native remove and native purge, use an
independent installation and record all of the following:

1. The exact source, package and executed entry point.
2. Successful installation or a deliberately reproduced interrupted upgrade.
3. Active and retired core runtime claims, supported historical integration
   state and unrelated administrator protection before removal.
4. Successful bounded recovery, including an interrupted operation and retry.
5. Absence of active product files, services, generated entries and rules.
6. Preservation of administrator bytes, effective traffic policy and original
   private recovery backups.
7. The same absence and preservation after reload and a real host reboot.

An isolated container restart is useful integration evidence. It does not
replace the final hardened-host reboot. Component tests, native rehearsal and
protected Patch IVV must each retain their actual scope and candidate identity.
