# Private SSH state recovery

Status: internal v5.00.0 development component. Refs #235 and #337.
This component does not publish SSH configuration, restart a service or expose
an apply command. Installation and CIS hardening do not invoke it yet. A
successful fixture test is not a completed migration or final IVVQ acceptance.

## Keep private state outside the SSH input graph

Before creating or recovering state, inspect the complete protected SSH
configuration graph. Refuse every Include that can reach `/var/lib/syswarden`
or its descendants, even when its target does not exist yet. Nested and
conditional Includes are included. Directory globbing and ambiguous path
aliases already fail the bounded inventory reader.

Reserve the whole state parent rather than checking one example staging name.
A different random name, future journal record or retained backup must not
later become SSH syntax. Recheck the same bytes, metadata, negative lookups and
directory membership before publishing ownership, before rename and after
completion. An external change stops the operation and preserves its evidence.
The read-only migration planner applies this constraint to a proposed
SysWarden-owned policy. External-owner observation stays read-only and does not
impose a write-storage requirement on an externally managed policy.

This deliberately refuses custom SSH configurations that include product state.
It neither removes those Includes nor changes an administrator's directory.
The adapter must rebuild the approved plan after provisioning, because state
creation can legitimately change ancestor directory metadata.

## An interrupted creation without ownership

A crash before the sibling ownership receipt is published can leave an empty
private staging directory, or a directory containing only its exact generated
marker. Neither its name nor the marker proves product ownership. Ordinary
provisioning continues to refuse it.

An internal inspection prepares a separate retention operation:

1. Acquire a nonblocking exclusive lock on the protected shared parent.
2. Require one exact staging instance, no active state directory or owner
   receipt, and no other unattributed creation stage.
3. Inspect a root-owned 0700 real directory. It may be empty or contain only
   the exact root-owned 0600 singly linked marker. Refuse additional children,
   links, unsafe metadata, malformed records and excessive directory listings.
4. Bind the parent and directory identities, attributes, original timestamps,
   optional marker inode and bytes, and complete SSH inventory into a digest.
5. Require explicit approval of precisely that digest before any mutation.

The future root-only adapter must present the concrete operation and private
backup location for review. Inspection alone, a prior installation and a
matching filename do not supply approval. There is currently no public
recovery subcommand.

## Retain the original inode

Apply rechecks the approved observation and writes an immutable private
`.ssh-policy-retirement-<instance>.json` receipt beside the directory. It uses
a synced unnamed inode and a nonreplacing link, then syncs the parent.
The receipt does not assert historical product ownership or authorize deletion.

Only after independently rechecking this receipt and its exact filesystem
identity does apply rename the original directory to
`.ssh-policy-retired-<instance>`, using a same-parent nonreplacing rename.
The inode, contents, ownership, mode, extended attributes and modification
time must remain unchanged. Rename necessarily changes directory change time.
No content is copied, deleted, chmodded or adopted as active state.

The parent is synced again and all evidence is reread. An ordinary user cannot
modify this protected state. The checks do not claim protection against
malicious root, the kernel, or an administrator bypassing cooperative locks.
A conflicting change stops the operation without deleting its evidence.

| Interruption or conflict | Result |
| --- | --- |
| Receipt publication or directory sync fails | Retain evidence and report uncertainty; never claim completion |
| Receipt exists, original stage remains unchanged | Reestablish receipt durability and finish the exact approved move |
| Exact retired directory exists, original stage is absent | Reverify it and sync the parent without rewriting the receipt |
| Destination already exists | Refuse without replacing its contents |
| SSH inventory, receipt, marker, directory or parent changed | Preserve evidence and refuse stale approval |
| Arbitrary children, multiple creation stages or active state coexist | Require separate reviewed recovery; do not select or delete them |

Retained recovery data is distinct from active configuration. A subsequent
fresh provisioning operation creates a new independent instance and inode.
It never activates the retained directory. Once new active state exists, the
old retention operation is no longer an active recovery candidate.

If configuration changes after an interrupted retention, the original receipt
cannot silently acquire a new inventory digest. That case requires separate
review; automatic rebinding or cleanup is not implemented. A filesystem restore
onto new inodes likewise cannot reuse historical custody merely because its
bytes match.

## Validation and remaining integration

Component tests cover actual pre-receipt creation failures, empty and marked
directories, repeated recovery, receipt and final directory-sync failures,
rename failure, concurrent operation locks, stale approvals, replaced inodes,
unsafe marker and receipt objects, changed retained content, nested Includes,
negative lookups, and preservation of external configuration. A bounded fuzz
target checks the canonical receipt decoder.

The internal [publisher](SSH_PUBLICATION.md) now implements durable configuration
phase transitions, checked intermediate graphs, ordered writes and read-only
interruption inspection. The [rollback protocol](SSH_ROLLBACK.md) handles
interrupted reversal, and the [shared transaction](SSH_TRANSACTION.md) composes
approval, target labels, publication and explicit recovery. Still required:
service activation checks, production installation/CIS opt-in wiring, and
separate uninstall/remove/purge handling. Retained private backups must be reported
separately and must not recreate product configuration.

The coherent migration package must then pass native AMD64 access, ProxyJump,
Ansible, SELinux, reload, reboot and lifecycle scenarios. BunkerWeb's independent
API, temporary-ban ownership and HA contract remain unchanged.

## Owned preparation-only journals

The [shared SSH transaction](SSH_TRANSACTION.md) has a separate internal path
for retiring verified aborted preparations. It requires independent storage
ownership, the original approved plan, installed-parser verification and a
complete preparation-only terminal record. It moves the original journal and
ownership receipt into private retention, with durable intent/completion and
restart-safe checks. Provisioning refuses unfinished or changed retirement
records. This does not broaden the pre-receipt orphan path described above,
claim ownership from names or permit deletion of administrator files.

## Restored configuration journals

The [shared transaction](SSH_TRANSACTION.md) also retires journals after verified
configuration rollback, including rollback of partial publication. It
independently checks the complete forward and inverse history, original plan,
parser and live restored inventory before moving the original directory and
receipt into retained custody. Durable intent and completion records support
explicit recovery of interrupted moves. Read-only history inspection cannot
reactivate an archived transaction.

The existing inactive candidates retain their original protected paths and
metadata on the SSH filesystem. Later provisioning verifies these exact
artifacts and their isolation from all Includes, while allowing separately
approved changes to active configuration. Changed, missing or included retained
candidates block provisioning. This does not delete recovery files or establish
complete uninstall, package remove or purge. Those independent native paths
remain required, along with activation and actual access verification.
