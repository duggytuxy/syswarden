# Shared SSH configuration transaction

Status: internal v5.00.0 development component. Refs #235, #337 and #422.
The public SSH commands remain read-only. Installation and CIS callers do not
invoke this engine yet. Configuration publication is not daemon activation,
proof of a successful login, a migration-ready package or final IVVQ acceptance.

## Explicit operator choice

The planned minimal native installation profile in #422 must not enable SSH,
CIS or general OS hardening. The shared SSH transaction belongs to the path
selected explicitly by an administrator through the configuration and reviewed
migration procedure. The [independent TOML choice](SSH_SELECTION.md) is now
checked by the internal transaction and bound into the plan inventory.
A selection cannot replace approval of the exact plan,
SSH ownership and role declarations, or the access checks.

The independent [port observation command](SSH_PORT_OBSERVATION.md) needs no
hardening intent and does not mutate SSH. Its configuration-only result is not
proof of runtime listeners and cannot authorize an SSH-specific firewall change.

The internal entry point requires root and the lowercase SHA-256 of the reviewed
plan. It independently reads the protected intent and inventory, pins the
installed AMD64 OpenSSH executable, and checks syntax and effective policy for
the live, sealed original, intermediate and final configuration graphs.
The global policy and every declared direct, ProxyJump and Ansible context must
preserve unrelated settings. External SSH ownership remains observation-only:
no transaction directory, target-label lookup or staged policy is created.

## Composition and storage

The engine combines the existing components in this order:

1. Recompute the plan, compare it with the explicit approval and require matching
   explicit SSH selection from the protected dedicated TOML module.
2. Verify the installed parser and all reviewed configuration graphs.
3. Resolve and recheck the new policy's target label.
4. Provision independently owned private state and acquire its exclusive lock.
5. Require a fresh journal containing only its attested marker.
6. Stage unnamed candidate inodes and write the immutable preparation.
7. Run the [publication protocol](SSH_PUBLICATION.md), including repeated
   dependency and inventory checks, durable phases and live parser verification.

The main-file candidate preserves the original mode, group and recorded extended
attributes. The new `/etc/ssh/sshd_config.d/00-syswarden-hardening.conf` has mode
`0600`, root ownership and no inherited discretionary ACL. The engine does not
copy a directory label onto the new regular file.

An existing journal is never adopted or overwritten by another apply attempt.
Its records might represent an interrupted or completed operation and require
their own inspected recovery or lifecycle transition. Replaying the original
approval over published files is refused.

## SELinux target policy

When SELinux is available, a descriptor-rooted lookup verifies the real
`selinuxfs` mount and reads its enforcement mode. Ordinary configuration-file
timestamp equality is not used for these virtual kernel objects.

The engine pins the installed `matchpathcon` executable through a protected
directory. It checks its inode, ownership, mode, link count, AMD64 ELF identity
and content digest. A fixed, bounded command requests the untranslated policy
context for the final regular-file target. Its output must be one bounded
context, with no extra lines, control characters or ambiguous result.

Before publication boundaries, the engine rechecks the executable identity,
enforcement observation and expected target label. A change stops publication
and retains any recovery evidence. It does not run a relabel operation, change
SELinux enforcement or replace the administrator's policy.

If the mount is unavailable while inventoried files have SELinux labels, the
operation refuses to guess the target policy. This includes a container that
hides host SELinux state. A system without SELinux labels or the mount can use
an empty target-label attribute set; mount appearance is still rechecked.

## Failure and recovery

Once preparation writing begins, a failure reports that inspection and recovery
are required. A visible file or successful parser check does not erase an
uncertain write or sync. There is no automatic adoption, deletion or blind retry.

Explicit recovery reopens the protected journal and requires both the original
approved plan digest and the original installed parser digest. The
[rollback protocol](SSH_ROLLBACK.md) verifies the exact history and restores the
original configuration identities. A changed parser or unrelated administrator
edit cannot silently acquire new approval. Recovery retains evidence and checks
the restored live configuration; it does not claim service or login success.

If no first publication intent exists, recovery can only abort the preparation.
It recomputes the complete protected plan and requires the original approved
digest, exact original main inode and metadata, unchanged explicit selection,
and absence of the reserved policy and both transaction staging paths. It
rejects unknown journal entries, partial publication, rollback records and
mixed histories. Recreating a lost unnamed inode from matching bytes is not an
authorized resume operation.

Before recording an abort, the installed parser must verify the live original
configuration against its sealed image, globally and for every declared access
context. Inventory, parser identity and journal contents are checked around
each parser call. The immutable `aborted-before-publication.json` record binds
the preparation digest and full unchanged inventory. An explicit retry verifies
the same record and repairs uncertain directory durability without replacing it.
No SSH file, daemon or listener is modified. Aborted evidence prevents later
publication and stays retained until a separately verified lifecycle retirement;
it does not make the journal reusable or establish operational access.

## Verified retirement of an aborted preparation

An internal retirement adapter now permits a new attempt after an explicitly
aborted preparation. It accepts the original approved plan, parser digest and
owned storage instance. It first verifies the unchanged complete SSH inventory,
original main inode, declared access contexts and absence of policy/staging
names with the installed parser. This path only accepts preparation-only aborts;
it refuses published, partially published, restored or ambiguous journals.

The original journal directory and its independent ownership receipt are moved
into private retention under `/var/lib/syswarden/`. Their inodes, file bytes,
permissions, extended attributes and single-link custody are retained. A bounded
canonical intent binds the exact three journal records before either rename.
Both moves prohibit replacement. A separate completion record and parent sync
are required before provisioning can accept this retired history. Interrupted
moves can resume only after the same inputs and custody are verified again.
Unknown files, changed records, conflicting destinations and incomplete
retirement block provisioning. No file is deleted and no SSH service is touched.

The retained directory, owner receipt, intent and completion record use the
`.ssh-policy-aborted-<instance>` prefix. They are private recovery evidence,
not active SSH configuration. They must remain isolated from all `Include`
patterns. A later transaction receives a new storage instance and transaction
identity; a retained journal never becomes active again. This adapter does not
retire already published policies or establish successful daemon activation.

## Verified retirement after configuration restoration

A second internal adapter handles journals whose configuration rollback has
finished. It verifies the entire recorded publication and inverse history,
including partial publication, against the original approved plan and pinned
parser. A terminal filename alone cannot establish restoration. The live
original policy must pass syntax and effective-policy comparison for every
declared access context, and its full inventory must match the recorded
restoration exactly.

The original journal directory and independent owner receipt move to the
`.ssh-policy-restored-<instance>` prefix under `/var/lib/syswarden/`. Separate
canonical intent and completion records bind every retained record's exact
inode, bytes, permissions, attributes and link count. The journal and parent
are synced. Both renames prohibit replacement; a failed or unacknowledged
rename can resume only with the original authorization and unchanged custody.
Incomplete or damaged retirement blocks fresh provisioning.

The inactive candidates remain at their original transaction-specific recovery
names in `/etc/ssh/` and `/etc/ssh/sshd_config.d/`. They retain their original
inodes and metadata, including the main candidate's original access mode and
the policy candidate's `0600` mode. There is no cross-filesystem copy or removal.
Every later provisioning verifies their custody and rejects Includes that could
activate either retained path. These are identified recovery artifacts, not a
completed uninstall, and must be accounted for by the future removal adapter.

History inspection uses a read-only journal capability: it cannot write
records, publish configuration or execute rollback. After retirement, a new
transaction needs a newly computed and explicitly approved plan, the matching
TOML choice, and new storage and transaction identities. The prior approval
cannot be replayed over the restored timestamps and retained directory entries.
No policy update, service activation or successful login is inferred from this
retirement.

## Revalidate an existing owned publication

The read-only [`verify-owned` command](SSH_OWNED_VERIFICATION.md) requires the
original independently approved plan digest and a completed publication.
It reopens the independent ownership receipt, reconstructs the original plan,
checks every phase transition and verifies the unchanged live configuration.
The installed parser must still match the original digest and pass the sealed
original, intermediate and final graphs plus all declared access contexts.

Exact journal membership and record identities are checked around each parser
call. Missing, mixed, restored or changed history is refused. The independent
TOML choice must still match. A successful observation does not repair uncertain
durability, activate SSH, prove a new login or permit another apply to reuse
the occupied journal. This supports later activation and owned update work
without treating a matching filename or generated comment as ownership.

## Observe service-manager topology before activation

The internal [systemd observer](SSH_SERVICE_OBSERVATION.md) pins the manager
helper and protected local endpoint, resolves fixed SSH service/socket aliases
and compares two bounded property samples. It refuses ambiguous active units,
instanced activation, pending jobs, unsupported states and observation drift.
An inactive vendor instanced socket is identified without selecting it.
The observer neither changes a unit nor establishes process, listener, policy
consumption or administrator-access proof. OpenRC and offline roots still need
separate adapters, and the production installer does not invoke this component.

## Validation and remaining work

Temporary-filesystem tests cover publication and explicit restoration, external
ownership, invalid prerequisites, existing journal contents, changed parser or
target-label observations, cancellation, repeated apply and stale recovery
approval. Preparation-abort tests cover lost anonymous inodes, repeated recovery,
uncertain sync, changed configuration and selection, mixed history, and changes
during parser checks. The installed OpenSSH oracle exercises the whole
transaction for forwarding, CIS and historical CIS migration, with direct,
ProxyJump and Ansible context declarations, including abort before publication,
verified private retirement, a new independently owned transaction, and its
restoration. Retirement tests also
interrupt every directory sync and both renames, exercise lost acknowledgements,
and reject replaced records, conflicting paths, changed input and busy locks.
Restored-journal tests additionally cover each partial publication boundary,
retained candidate tampering, incomplete rollback, read-only history mutation
attempts, stale authorization and a second independently approved publication
and restoration with the installed parser.
It runs parser modes only and never opens a listener.

The separate read-only label oracle checks the installed SELinux helper without
changing enforcement. These tests do not prove that root can apply the target
label on every supported native host.

Production opt-in wiring, already-owned updates, activation and independent
access checks, public recovery orchestration, and the lifecycle of successfully
activated policies remain required. Restored candidates still need explicit
handling in complete removal. Run native uninstall, package remove and purge
separately once the coherent adapter is available, including administrator edits,
reload and reboot.
Preserve BunkerWeb's independent API, temporary-ban ownership, expiry and HA.

## Process identity before activation

The internal [process observer](SSH_PROCESS_OBSERVATION.md) brackets a pinned
live process and protected executable with stable service-manager observations.
It does not authorize this transaction to activate a policy or establish that
the daemon consumed the published configuration. Configuration consumption,
listeners and fresh independent access remain separate integration gates.

The [listener observer](SSH_LISTENER_OBSERVATION.md) now binds sampled TCP
listeners to that process. Policy correspondence, configuration consumption and
independent access still need proof before an activation outcome can be accepted.

[Endpoint correspondence](SSH_ENDPOINT_CORRESPONDENCE.md) adds comparison with
the protected standard graph's parsed addresses and network namespace. Matching
endpoints alone still cannot establish loaded hardening policy or fresh access.
