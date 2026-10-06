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
| Administrator configuration | `pkg/system/removal_operator_retention_*`, `cmd/recover_operator_configuration.go` | An explicit retention decision preserves reviewed TOML files at their original paths, including later administrator edits. |
| Native finalization | `scripts/ci/package_removal_state.sh`, package scriptlets | No unretired product state is left behind; the documented administrator override and explicitly reviewed configuration survive. |

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

Complete dedicated-table retirement additionally requires original kernel
evidence containing the exact historical action output, with no administrator
objects or table annotations. A versioned plan binds that evidence before the
action is stopped. The final deletion uses a kernel generation fence, so an
intervening rule change causes refusal. An empty intermediate table is accepted
only with the original bound table identity. An already empty table without
that evidence does not acquire deletion authority. Existing version-one plans
keep their original meaning and cannot silently authorize whole-table removal.

## Administrator configuration retention

The documented `99-user.toml` override remains administrator-owned. Additional
customized modular configuration has an explicit recovery inventory:

```sh
sudo syswarden recover-removal --retain-operator-config
```

This route requires a removal already in progress with managed product services
stopped. It inventories the master `config.toml` and bounded, private TOML files
directly inside the `modules` directory. Exact pristine generated defaults are
excluded. Links, executable files, unknown entries and invalid TOML are refused.
The output contains paths, metadata and hashes, without configuration contents.

After confirming that every listed file is administrator configuration to keep,
apply the exact digest printed by inspection using the same flag with `--apply`
and `--plan-sha256`. Then repeat the original uninstall, remove or purge command.
The decision preserves bytes, permissions and inodes at the original paths. It
grants no deletion authority and does not classify neighboring files.

A private immutable record allows native finalization to honor this decision
after the CLI has been erased. Later administrator edits remain protected,
including edits made between native remove and a subsequent purge. New paths
require a separate review. Retained configuration and its private decision must
be distinguished from an active product installation; they do not load rules or
start services. Flat legacy configuration and arbitrary directory contents are
outside this modular retention route.

## Explicit limits before acceptance

The following states remain refused and require additional bounded recovery
work. A refusal preserves evidence; it is not complete removal:

- Historical product persistence without an independent writer record, even
  when a pure historical template recognizer can identify its shape.
- Configured or live administrator policy embedded in product-owned tables
  until equivalent independently managed protection is established.
- Customized configuration outside the documented retained `99-user.toml`
  surface or an explicit supported modular retention decision, and other
  artifacts whose ownership is unresolved.
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
