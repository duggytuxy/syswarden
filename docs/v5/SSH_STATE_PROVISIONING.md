# SSH transaction state ownership

Status: internal v5.00.0 development component. Refs #235 and #337.
The public SSH planner and parser verifier remain read-only. Installation,
CIS hardening and package removal do not invoke provisioning yet. This is not
a complete migration package or final IVVQ acceptance.

## Independent attribution

The fixed journal directory is `/var/lib/syswarden/ssh-policy-v1`. A separate
sibling receipt, `/var/lib/syswarden/ssh-policy-owner-v1.json`, attributes its
exact filesystem identity and the immutable private marker `ownership.json`
inside it. A matching path, matching content or mode 0700 alone is insufficient.
The marker includes a fresh cryptographically random 256-bit instance identity.
Its exact inode, timestamps, bytes, ownership, mode and extended attributes are
recorded in the sibling receipt. A copied marker cannot authorize a replacement
directory, even if its bytes match.

The shared `/var/lib/syswarden` parent must already exist beneath protected
real ancestors. This component neither creates nor claims the shared parent.
It binds the parent's identity, ownership, mode and extended attributes while
allowing its ordinary directory membership to change. The future installation
adapter must establish the shared parent's lifecycle separately.

Provisioning takes a nonblocking exclusive lock on the shared parent. Existing
journals retain their own transaction lock. Neither lock prevents an
administrator or an external manager from changing files. This protects
against unrelated local users; it is not protection from malicious root or
the kernel. Every journal operation rechecks the receipt, its protected parent,
the private directory and the exact marker. A persistent change poisons an
open handle instead of adopting a replacement.

## Durable creation and interruption

1. Refuse an existing unreceipted destination, malformed receipt or unclaimed
   staging name. Inspect at most the existing bounded directory-entry budget.
2. Exclusively create a randomly named private directory in the same parent.
   Set root:root 0700 on this new inode. Remove inherited access/default ACLs
   from it while retaining its kernel-assigned SELinux label. Do not alter the
   shared parent's ACL, label or mode.
3. Publish the private marker through a synced unnamed inode without replacing
   an existing entry. Sync its directory and then the parent. Capture the exact
   marker and directory identities.
4. Publish the canonical bounded sibling receipt through another synced
   unnamed inode, without replacement, and sync the parent. Private records
   are root:root 0600 and retain only their kernel-assigned SELinux label.
5. Recheck the receipt, parent and the staged directory, whose only child must
   be its exact marker. Rename the directory to its fixed destination with
   no replacement. Sync the parent and independently reread all ownership.

The receipt remains immutable across publication and ordinary reopening.
Directory entry timestamps are not a persistent identity because adding later
transaction records changes them. Directory identity is instead bound to its
device, inode, ownership, mode, attributes and the immutable marker identity.

| Interrupted boundary | Retry behavior |
| --- | --- |
| Before the sibling receipt exists | Preserve the unclaimed private staging directory and refuse automatic adoption. Internal [explicit retirement](SSH_STATE_RECOVERY.md) can retain an exact reviewed empty or marked stage without adopting it. |
| Receipt exists and its exact staged directory remains | Reestablish directory-entry durability and finish only that exact creation. Extra children or replacement identities refuse recovery. |
| Fixed directory exists and matches the receipt | Verify the marker and ownership, sync the parent, and finish without rewriting the receipt. |
| Missing or changed marker, foreign destination, unexpected stage, detached parent or unsafe metadata | Preserve evidence and fail without replacing administrator content. |

A directory-sync error is an uncertain result, not successful provisioning.
No error path deletes evidence or repairs unknown state. A rename that races
with a new destination fails without overwriting that destination. No weaker
filesystem fallback is provided.

A file-level restore onto new inodes also requires explicit recovery. Restored
bytes alone do not reestablish the original filesystem custody. This component
does not silently rewrite receipts to accept a copied directory or marker.

## Verification and remaining work

Disposable fixture tests exercise real filesystem publication and reopen,
idempotence, unique instances, inherited ACL stripping, concurrent provisioners,
all five sync boundaries, interrupted rename, copied/modified markers,
unreceipted names, foreign destinations, detached parents, unsafe record modes,
links and types, bounded canonical decoding, and journal invalidation after
ownership changes. SSH inputs remain unchanged during these tests.

No provisioning function is exported or connected to package hooks.
The internal [publisher](SSH_PUBLICATION.md) now uses phase records, checked
intermediate states, ordered writes and post-publication parser verification.
Remaining work includes the public recovery adapter, activation and rollback,
the shared installation/CIS adapter, and independent uninstall/remove/purge
retirement. Ownership of a directory does not establish ownership of arbitrary
children added later. Removal must inventory them and preserve administrator
data. Recovery bytes must remain distinct from active configuration.

Provisioning now inspects the complete SSH Include graph and refuses Includes
that can reach the shared product state parent, including unmatched and nested
patterns. It rechecks this isolation before mutations and after completion.
A location under `/var/lib` or a temporary-looking name alone is not that proof. Rebuild
the approved configuration inventory after provisioning, because creating state
legitimately changes ancestor directory timestamps and membership.

The future native campaign must cover direct SSH, ProxyJump, Ansible, SELinux,
reload/reboot, interruptions and each removal entry point. BunkerWeb's API,
temporary-ban ownership and independent HA contract remain unchanged.
