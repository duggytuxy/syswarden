# Verified product removal

Status: published in v4.10.3 after protected Patch IVV and independent public
asset verification. The [publication record](../releases/v4.10.3/README.md)
defines the accepted scope. This reference describes code boundaries; use the
[canonical recovery guide](https://syswarden.io/docs/historical-recovery/)
for operator steps.

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

The v4.10.4 candidate also recognizes the standard RHEL-family nftables loader
whose reload command contains a literal `flush ruleset; include` sequence.
Inspection records its exact absolute include path without executing the
command. It accepts `/sbin/nft` through a root-owned, stable `/sbin` link to
`/usr/sbin` and binds the link identity and resolved executable. Other link
targets, injected commands and changed evidence are refused. The shared
persistence reader still rejects symlinks, and retirement never stops or
reloads the shared nftables service.

The candidate also creates a missing `/var/backups` parent through an attested
`/var` directory descriptor when applying retirement. Existing shared backup
storage keeps its owner, mode and contents. Read-only inspection creates nothing;
unsafe metadata, links and concurrent replacement remain errors. The parent is
synchronized before publishing recovery journals or moving original files.

Candidate nftables retirement synchronizes its exact kernel intent before opening
the short-lived generation fence. It then repeats full live ownership inspection
and checks that its source and inputs match that intent. The final guard rechecks
producer quiescence, the original synchronized intent inode and bytes, and the
boot and network namespace. Concurrent kernel changes still invalidate the
single-use transaction. No timeout is extended and no ownership check is skipped.

After successful firewall cleanup and runtime-history retirement, the candidate
also removes the empty current compatibility-wrapper receipt. Its exact header,
private mode and single-link inode are checked through the existing quarantined
file-removal path. A receipt with owned or pending permissions, older syntax or
modified bytes remains a blocking recovery artifact. An empty receipt is not a
reason to modify shared firewalld or UFW configuration files or backend backups.

Native post-removal finalization checks and removes an empty `/opt/syswarden/bin`
before its parent. Package managers may leave this directory after erasing the
binaries. Both directories use nonrecursive `rmdir` after metadata and mount
checks. An extra file, child directory, link or mounted path still stops
finalization and keeps the removal barrier for recovery.

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

The bounded list inventory includes the optional SaaS monitor IPv4 and IPv6
cache files and `syswarden_saas_monitors.pair`. Historical installations may
have only one family or no pair manifest. These files require explicit
`--retain-legacy-lists` review and confirmation that no other producer uses
them. Neither their names nor their pair hashes establish product ownership.
Recovery retains their exact bytes and inodes, including incomplete cache
generations, without interpreting them as firewall input. Changed inputs,
unexpected creation markers and unrelated directory entries cause refusal.

For v4.10.4 candidate publications, the feed writer marks newly created threat
feed compatibility files, provenance commits and immutable snapshots with their
exact name, inode, creation time and content hash. Automatic refresh preserves
that origin only when replacing an already proven file. It never adopts an
existing unmarked file. Removal can privately archive these proven feed artifacts
together with the generated local lists. A modified or copied origin, unexpected
entry, unsafe metadata or changed content prevents automatic retirement.

Existing unmarked IPv4 and IPv6 threat feed artifacts have a bounded
`--retain-legacy-lists` route. This includes at most eight digest-named snapshots
per family, plus each compatibility file and provenance commit. The snapshot name
and the feed-validation provenance do not independently establish file ownership.
The operator must review the exact plan and confirm that every selected artifact
is legacy product data with no other producer before applying its SHA-256 digest.
Recovery keeps original bytes and inodes in a private backup; it does not delete
them or assign new ownership markers. Invalid present creation markers cannot be
bypassed through this route. Re-run the original removal command afterwards.
The feed reader uses the same 32 MiB per-file bound as the publisher, while
ordinary local lists retain their existing smaller read limit.

Snapshot pruning also retains old unmarked generations. Only a generation with
an exact writer-origin marker can be pruned automatically. The publisher's
bounded inventory remains enforced, so an unexpected accumulation requires
explicit recovery rather than unbounded scanning or deletion by filename.

Fail2ban recovery binds the original configuration inventory separately from
the runtime or persistence plan. Persistent entries in a shared nftables source
are reviewed and retired before target jail and runtime retirement. The source
edit retains the original file privately and preserves administrator bytes.
It does not reload the firewall, mutate live rules or stop the shared Fail2ban
service. Applying the later runtime plan stops only the proven historical
targets and verifies that unrelated live protection remains present.

Shared-source review also follows balanced administrator rule fragments inside
independent tables. It verifies the original and active include contexts before
each edit and after interruption. Fragments inside a selected Fail2ban table,
references to retired targets and changes to an administrator dependency cause
refusal. Literal administrator table replacement is preserved. One adjacent
`add table`, `flush table`, and literal include sequence per source is supported
only when the included file declares that complete independent table. Recovery
does not execute these loader commands or acquire ownership of their targets.

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

## Historical persistent-source recovery

A separate `recover-removal --retire-legacy-firewall-persistence` route accepts
an independently retained v4.02.8 generation-input capture supplied with
`--historical-inputs`. It recognizes only the complete supported historical
empty-set source. Every reserved product table must already be absent. This
route does not infer ownership of live set populations and never deletes live
rules or reloads the shared firewall.

The private capture binds the original configuration evidence and original
host-input evidence separately from the candidate source. Its description and
evidence files must be regular private files in a private directory under
`/root`. File hashes bind the reviewed bytes; they do not authenticate their
historical origin. Applying requires both the exact plan digest and
`--confirm-historical-inputs`, confirming that the supplied values describe
independently retained original inputs. Values reconstructed from the candidate
source or from an agreeing live ruleset do not satisfy this requirement.

The bounded include graph binds the actual loader, source identities and
metadata. Applying stops managed product producers, rechecks absent runtime,
retains original source and shared-file backups privately, and removes only
recognized product entries. Administrator bytes in shared files remain intact.
Modern ownership receipts, transaction journals or removal progress must use
their original recovery route; this procedure cannot replace those records or
broaden an earlier plan. Interrupted retirement can resume only with the same
input evidence, loader authority and reviewed digest. Completion of this route
covers persistent-source retirement only; repeat the original removal command
to handle the remaining product state.

## Historical iptables compatibility recovery

The v4.02.8 writer also prepended IPv4 compatibility permissions to `ip filter`
when the `iptables` executable was already available. These rules have a
separate recovery boundary. The shared `filter` table is not product ownership,
and a `SYSWARDEN_CORE` comment alone does not authorize a deletion. Removal
refuses recognizable unresolved historical state before erasing its payload,
then repeats that check under the firewall lock and after product cleanup.
Opaque comments are resolved through a separate read-only iptables observation,
including a remaining peer-port rule from a partial historical generation.
A uniquely matching, unmodified rule with committed wrapper-manifest ownership
keeps its existing cleanup route. Duplicate rules, pending ownership and
modified expressions remain unresolved. An unrelated administrator comment
does not become a product ownership marker. The legacy kernel backend is
inspected separately when present, even if the active alternative uses
`nf_tables`. Existing manifest-owned cleanup requires the exact matching active
backend; unowned legacy-backend rules require separate verified recovery.

`recover-removal --retire-legacy-iptables --historical-inputs /root/private-capture/review.json`
accepts independently retained original generation evidence. The description
uses schema `syswarden-historical-iptables-inputs-v1`, generation `v4.02.8`, the
original boot and network namespace identity, and original HA/subnet inputs.
Its evidence entries, in order, bind `configuration`, `nft-before`,
`nft-generated`, `iptables-generated`, and `iptables-before`. Every entry names
a separate private file by basename and SHA-256. The last capture may be omitted
only when the original nftables observation proves there were no compatibility
rules. The description and evidence must remain private regular files in a
private directory under `/root`.

This is an operator-reviewed origin claim, not a historical writer receipt.
Confirm that the captures are original, that SysWarden was the only writer in
the recorded generation interval, and that all retained rules belong to the
administrator or another application. Do not manufacture missing observations
from the current ruleset. Applying requires `--apply`, the exact
`--plan-sha256`, and `--confirm-historical-inputs`. Missing evidence, a different
boot or namespace, a partial generation, unsupported backend, or changed
container identity keeps recovery incomplete. This route currently supports
complete canonical IPv4 compatibility blocks on the `nf_tables` backend.

Planning checks the complete original ordered rule delta against the historical
generator and the independent iptables text capture. Only its added handles
can be selected. Identical rules already present, and independently reviewed
later administrator additions, remain untouched. The current shared ruleset,
retained remainder, source identities and producers are bound to the review.
The output contains hashes, handles, counts and declared effects without private
configuration or network addresses.

Applying first makes the product producers quiescent and publishes immutable
private intent under `/var/backups/syswarden-retired-v1/iptables-v1`. It then
uses a single kernel generation-bound rule transaction. A concurrent kernel
change rejects the transaction; a failed operation aborts the entire batch.
Neither the shared table nor its chains are flushed or deleted. An interrupted
attempt can resume only from the exact intent and the complete original or
complete resulting state, never from a partially matching rule list. An exact
private receipt also distinguishes the reviewed administrator remainder from
unresolved historical state during subsequent removal checks. That receipt
cannot authorize a new deletion or accept changed rules.

This route retires runtime compatibility rules only. Independently managed
iptables persistence and other administrator loaders are not edited or
reloaded. Review their original sources separately, retain unrelated behavior,
and verify that product rules do not return after service reload and reboot.
Complete standalone uninstall, package remove and package purge remain separate
native verification requirements.

## Administrator iptables preservation after a new review

An administrator rule can deliberately have the same comment as an older
product rule. A comment alone never proves ownership. A historical retirement
receipt preserves only the exact reviewed remainder in its original boot and
network namespace. After a reboot or a reload that changes rule handles, its
previous approval cannot be reused.

After independently verifying that historical product rules are absent, use
`recover-removal --preserve-operator-iptables` to inspect a new preservation
plan. This route requires no IPv4 compatibility ownership entries and retains
the existing historical host and integration preflights. Inspection is possible
before the removal barrier exists; the ordinary removal path still attests and
stops product producers independently. It supports the IPv4 `filter` table
on the `nf_tables` backend only. Legacy-backend ambiguity remains blocked.

Privately review the complete output of `sudo iptables-save -t filter` and
`sudo nft -a list table ip filter`, plus the administrator's persistent loaders.
Every remaining rule must belong to the administrator or another application.
If this cannot be established, preserve the rules and original evidence for
separate recovery. Do not use this decision to retain unresolved product rules.

Applying requires all three options: `--apply`, the exact `--plan-sha256` from
the dry run, and `--confirm-operator-iptables`. It creates only a private decision
under `/var/backups/syswarden-retired-v1/operator-iptables-v1`. No rule, service,
configuration, ownership manifest or removal barrier is changed by this action.
The private decision grants preservation, never ownership or deletion authority.
Then retry the original uninstall, remove or purge command.

The decision binds the complete table structure, rule order, handles, expressions,
iptables text, boot and network namespace. Packet and byte counters can advance
normally. Any policy or identity change requires another explicit review.
Existing manifest-bound rules must use their original cleanup path. This
preservation decision cannot bypass their ownership checks or the separate
persistent-source, integration and service removal checks.

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

## Inactive legacy configuration backups

This route is part of the unpublished v4.10.4 candidate. It requires fresh
signed-package IVV and is not available in the published v4.10.3 CLI.

A migrated flat configuration can leave a private `.bak` or `.migrated` file
under `/opt/syswarden`. A familiar name does not establish product ownership.
Removal preserves such a file and the recovery CLI until its retention is
reviewed. For a removal already in progress, inspect:

```sh
sudo syswarden recover-removal --retain-legacy-config
```

This bounded route selects one inactive backup at a time from
`syswarden-auto.conf.bak`, `syswarden-auto.conf.migrated` and
`syswarden-auto.conf.migration_backup.migrated`. It excludes the active flat
configuration and unfinished migration sources. Pending modular migration,
active product services, links, shared inodes, unsafe permissions and files
larger than 1 MiB prevent archival. Inspection prints metadata and an exact
plan digest without exposing configuration values.

Confirm independently that the selected file is an inactive legacy backup with
no other consumer or producer. Apply with the same flag, `--apply` and the exact
`--plan-sha256` from that dry run. The original inode and bytes move to a private
`legacy-config-<digest>` directory under `/var/backups/syswarden-retired-v1`.
The canonical plan is synchronized before the move. Recovery never overwrites
an existing backup or copies across filesystems. A repeated application verifies
the retained original; changed evidence or a recreated source stops recovery.

Retry the original uninstall, remove or purge command. Another backup needs its
own review. Active administrator configuration remains outside this archival
operation, and customized TOML still uses `--retain-operator-config` to remain
at its original path. The private archive is inactive recovery material, not a
remaining product installation. Preserve its confidentiality and do not restore
it automatically during a later installation.

## Independent administrator policy preservation

Typed administrator ingress accepts in `modules/99-user.toml` can have active
rules inside the product table. Retaining the TOML alone does not preserve their
runtime behavior. Removal refuses that state until a reviewed independent
receiver is present, persistent and reverified at each removal boundary.

Prepare a private export with `recover-removal --export-operator-policy`.
Standard output contains the exact receiver source, including private rule
predicates. Standard error identifies its required path. Save and review this
output privately. Exporting does not write an active file, change rules, approve
removal or establish ownership of any existing object.

The original administrator TOML may retain mode 0600 or 0640 with root ownership
and the root group. Its exact mode remains bound to the review and is never
changed by preservation or removal.

The administrator must install the reviewed source with root ownership and mode
0600 at the indicated path under `/etc/nftables.d`, include it exactly once from
the actual shared nftables loader, and verify the resulting traffic behavior.
The shared loader must be active and persistently enabled at boot. Recovery does
not enable, reload, restart or rewrite that shared service. Unexpected receiver
contents, namespace collisions, duplicate includes, unsafe files, opaque loader
commands and disabled or transient-only enablement are refused.

Reloads must also be idempotent. A bare declarative receiver include can append
duplicate rules on reload and is refused without a verified preceding reset.
For a loader that preserves other firewall owners, place these three statements
together, substituting the exact table name and path from the reviewed export:

```text
add table inet <exported_table_name>
flush table inet <exported_table_name>
include "<exported_receiver_path>"
```

The first statement permits a cold start; the second clears only the receiving
table's rules before loading the exact policy. Review namespace ownership before
installing this sequence. Recovery never executes it or changes the shared
loader. The receiving table must still match the independently compiled model.
An existing leading entry-point `flush ruleset` is recognized for compatibility;
adding a global flush is not required or recommended for this preparation.

Independent administrator tables may use a literal `destroy table` immediately
before their matching declaration. Balanced include fragments inside those
tables remain administrator-owned. Their complete literal include graph is
rechecked. Nested receivers, variables, table declarations inside fragments,
commands that escape the bounded reload forms and resets of reserved product
tables are refused. Verify cold-start and repeated-reload traffic behavior as
well as a real reboot before relying on the preservation result.

The receiver supports the same closed typed IPv4/IPv6 ICMP, TCP and UDP ingress
accept predicates. It has an independent input base chain with an accept policy.
It introduces no replacement default-deny policy. An accept verdict does not
override a drop in another base chain. Independently managed drops and unrelated
protections must still be verified before and after removal and reboot. Product
rules outside the administrator policy retain their existing ownership checks.

Once that independent configuration is active, inspect:

```sh
sudo syswarden recover-removal --preserve-operator-policy
```

Review the metadata and exact plan digest. Applying the same option with
`--apply --plan-sha256` records only a private preservation decision. It requires
the exact typed administrator source, the current writer receipt, the complete
recognized product source, matching original administrator runtime rules and
the exact independent receiver. The decision captures original counter
observations privately; it does not claim continuous counters across the two
chains. It grants no product ownership of the receiver or the administrator
configuration.

Then repeat the original uninstall, remove or purge command. Preflight, source
retirement, the kernel generation fence and final metadata retirement all
recheck the independent receiver. A changed or missing source, loader, decision
or runtime rule causes refusal. The receiver and original administrator TOML
remain outside product deletion targets. Unknown surrounding product-table
objects or populations still require their own recovery and cannot be adopted
through this decision.

The private decision can be reused after product source retirement because the
receiver remains independently reachable from the shared loader. Original review
evidence is not rewritten on retry. This route requires native validation of
uninstall, remove and purge separately, including shared reload and a real host
reboot, before it is accepted as release coverage.

## Explicit recovery limits

The following states remain refused and require additional bounded recovery
work. A refusal preserves evidence; it is not complete removal:

- Historical product persistence without independently retained original
  generation inputs, and historical live rules not covered by a separate
  ownership proof. A matching template alone is insufficient.
- Configured or live administrator policy embedded in product-owned tables
  without an exact reviewed preservation decision, or with changed configuration,
  loader or receiver evidence.
- Customized configuration outside the documented retained `99-user.toml`
  surface or an explicit supported modular retention decision, and other
  artifacts whose ownership is unresolved.
- An empty historical dedicated Fail2ban table without separately justified
  table-retirement authority.

The release must not be described as covering every historical removal state
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
