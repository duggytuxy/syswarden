# Ordered SSH configuration publication

Status: internal v5.00.0 development component. Refs #235 and #337.
The installation and CIS entry points do not invoke this component yet.
There is no public apply command or complete migration package. Final IVVQ
acceptance remains open.

## Write sequence

The publisher requires an exact approved plan, the durable private preparation,
both retained anonymous candidate descriptors, and the same pinned installed
SSH parser. It verifies the original and candidate configurations again before
any named configuration write. All declared connection contexts are included.

Three steps follow:

1. Link the candidate main inode at its transaction-specific name in `/etc/ssh`.
   The complete Include inspection must exclude this name.
2. Link the policy inode at
   `/etc/ssh/sshd_config.d/00-syswarden-hardening.conf`, without replacing any
   existing destination.
3. Exchange the main configuration and its staged replacement. The original
   inode remains at the excluded transaction name for recovery.

The first two operations use nonreplacing
[linkat](https://man7.org/linux/man-pages/man2/link.2.html).
The third uses
[RENAME_EXCHANGE](https://man7.org/linux/man-pages/man2/rename.2.html).
The exchange is atomic for its two names; the entire sequence is not an atomic
two-file configuration update. The original-main-plus-new-policy state has
already passed the installed parser's syntax and effective-policy checks.

After publication, the installed parser checks the live configuration again.
Its complete effective output must match the sealed candidate for the global
defaults and each declared context. Configuration verification does not prove
a successful login or activate the daemon.

## Durable evidence and interruption

Each step has an immutable private intent record before the filesystem operation
and a separate completion record after it. Records bind the preparation digest,
transaction, step and complete configuration inventory. Only six fixed publication phase
filenames are accepted. The separate [rollback protocol](SSH_ROLLBACK.md) adds
its own fixed start and phase records. Individual records remain bounded to 8 MiB and protected
as root-owned mode 0600 files within the independently attested directory.

The target directory is synced after each operation, before completion evidence
is published. Journal publication independently syncs its directory and verifies
the linked inode. This follows the directory durability requirement documented
for [fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

A failed operation, changed input or uncertain synchronization poisons the
transaction handle. It preserves every existing artifact and refuses blind
retry. Read-only internal recovery inspection distinguishes a pending operation
whose before-state remains present from one whose intended after-state is
observed. It also validates completed phase continuity and detects missing or
contradictory records.

An observed after-state does not repair a failed sync or prove daemon activation.
The publication inspector never completes or reverses a write. A separate
[verified rollback helper](SSH_ROLLBACK.md) can reverse an inspected transaction
and explicitly resume its own interrupted operations. Anonymous candidates
lost before publication cannot be recreated or adopted without a separately
verified recovery operation.

## Administrator preservation

All unrelated configuration bytes, ownership, modes, labels, ACLs, vendor aliases,
negative observations and enumerated directory members remain exact. Only the
specific link/rename timestamp changes and changed parent directory metadata are
allowed during each operation. The observed metadata is then frozen and must
match exactly before the next step.

The product lock does not serialize an external configuration manager. If an
administrator races the final exchange, the displaced inode remains available;
the subsequent inventory check refuses success. No cleanup deletes that file and
no automatic compensating write guesses which content should win. Coordinating
external writers remains an operator requirement. This is not protection against
a hostile root administrator or kernel.

## Verification and remaining integration

Disposable filesystem fixtures exercise all twelve intent, mutation, target-sync
and completion failure boundaries. They also cover reserved-name collisions,
an administrator race at exchange, replaced inodes with identical bytes,
changed policy and access configuration, malformed phase evidence, hard links,
cancelled operations and post-publication parser disagreement.

An opt-in installed-OpenSSH oracle publishes real fixture files for forwarding,
CIS and reviewed historical CIS migration. It compares effective settings for
declared direct, ProxyJump and Ansible contexts without opening a listener.
These are component checks, not native access tests or final IVVQ acceptance.

Still required: target-policy SELinux label integration, the shared installation
and CIS adapter, service activation, public recovery orchestration,
and independent native SSH/ProxyJump/Ansible access and lifecycle verification.
Uninstall, native remove and purge must each preserve administrator changes and
handle retained private recovery data separately. BunkerWeb's independent API,
temporary-ban ownership and HA contract are unchanged.
