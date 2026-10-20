# Shared SSH configuration transaction

Status: internal v5.00.0 development component. Refs #235, #337 and #422.
The public SSH commands remain read-only. Installation and CIS callers do not
invoke this engine yet. Configuration publication is not daemon activation,
proof of a successful login, a migration-ready package or final IVVQ acceptance.

## Explicit operator choice

The planned minimal native installation profile in #422 must not enable SSH,
CIS or general OS hardening. The shared SSH transaction belongs to the path
selected explicitly by an administrator through the configuration and reviewed
migration procedure. A TOML boolean cannot replace approval of the exact plan,
SSH ownership and role declarations, or the access checks.

The internal entry point requires root and the lowercase SHA-256 of the reviewed
plan. It independently reads the protected intent and inventory, pins the
installed AMD64 OpenSSH executable, and checks syntax and effective policy for
the live, sealed original, intermediate and final configuration graphs.
The global policy and every declared direct, ProxyJump and Ansible context must
preserve unrelated settings. External SSH ownership remains observation-only:
no transaction directory, target-label lookup or staged policy is created.

## Composition and storage

The engine combines the existing components in this order:

1. Recompute the plan and compare it with the explicit approval.
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

An interrupted preparation without the publication history needed for rollback
still requires separate inspected recovery. Recreating a lost unnamed inode from
matching bytes is not an authorized resume operation.

## Validation and remaining work

Temporary-filesystem tests cover publication and explicit restoration, external
ownership, invalid prerequisites, existing journal contents, changed parser or
target-label observations, cancellation, repeated apply and stale recovery
approval. The installed OpenSSH oracle exercises the whole transaction for
forwarding, CIS and historical CIS migration, with direct, ProxyJump and Ansible
context declarations. It runs parser modes only and never opens a listener.

The separate read-only label oracle checks the installed SELinux helper without
changing enforcement. These tests do not prove that root can apply the target
label on every supported native host.

Production opt-in wiring, already-owned updates, activation and independent
access checks, public recovery orchestration, and transaction retirement remain
required. Run native uninstall, package remove and purge separately once the
coherent adapter is available, including administrator edits, reload and reboot.
Preserve BunkerWeb's independent API, temporary-ban ownership, expiry and HA.
