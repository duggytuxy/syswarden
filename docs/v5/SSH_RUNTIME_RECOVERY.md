# Restoring SSH configuration after an activation attempt

Development integration for v5.00.0. Refs #235, #337 and #422.
The coordinator restores the original retained configuration and issues one
separately recorded restoring reload. An explicit root-only
[operator recovery command](SSH_OPERATOR_RECOVERY.md) now connects it to fixed
live systemd paths. Forward migration activation, installer wiring, completed
recovery acceptance and migration-ready packages remain unavailable.

## Independent approval and live process

The original migration approval is insufficient to authorize a restoring
operation. Read-only preparation derives a separate `restore-original` digest
from the original plan/parser identity, complete protected history, current
configuration inventory and freshly retained daemon target. Applying recovery
must reproduce that digest. Inspection neither writes nor signals anything.

The original publication and activation records remain intact. An existing
access-evidence record is retained as opaque history, never used to approve
recovery or claim current access. Adding, removing or replacing any original
record invalidates approval. Current target identity is independently bound;
it need not equal the earlier activation target, whose listeners may have
changed since the original attempt.

The coordinator accepts the existing retained systemd process/pidfd adapter.
It holds the journal lock and process lease through restoration and dispatch,
with a bounded lifetime. Original, intermediate and final graphs must pass the
pinned installed parser. The supported profiles preserve endpoints and
authentication settings. Explicit SSH TOML selection is still required;
CIS/OS selection and historical generated defaults do not supply consent.

## File transitions and restart points

Before changing a file, the coordinator writes a private, immutable recovery
intent. Each inverse transition has its own intent and completion record:

1. Exchange the exact retained original main inode back into the active path.
2. Move the exact product drop-in into its nonincluded retained path.

No original inode, administrator content or previous evidence is deleted.
Every mutation rechecks the current inventory, parser, record identities and
retained process. The ordinary file-only rollback path keeps its original
activation fence; it cannot enter this recovery operation implicitly.

An interrupted inverse can resume after reopening and independently approving
the same recovery digest. The recorded before-state repeats only the missing
transition. An exact after-state repairs directory durability and completes its
record without repeating the rename. A completed transition is skipped. An
unexpected inode, extra record, changed target or changed configuration refuses
further mutation and retains all evidence.

After both transitions, the installed parser must confirm the live original
graph against its sealed baseline. A distinct restoring-reload intent is then
made durable before the one-shot request. Any presence of this record blocks
replay, including a failed directory sync, cancellation before dispatch, signal
error or lost response. Another attempt requires a separate future recovery
operation; deleting the marker is not a supported procedure.

## Meaning of the result

Configuration restoration and a returned reload request are separate facts.
Neither proves that the intended policy was consumed or that an administrator
can authenticate. `RecoveryRequired` remains true. The coordinator does not
retire the transaction, adopt historical access receipts or claim completed
migration. Fresh restored-policy access evidence and causal policy-consumption
qualification remain required before operational acceptance.

A separate [read-only restoration assessment](SSH_RESTORATION_ASSESSMENT.md)
reopens the complete inverse history after the restoring-reload intent. It
checks the original graph, parser and current endpoints without repairing or
replaying the request. A visible intent, including one left before a failed
directory sync or dispatch, never becomes a successful runtime acknowledgement.

## Validation boundary

Filesystem tests cover original inode and evidence preservation, independent
approval, all inverse rename and synchronization failures, explicit resume,
parser/target/input changes, final parser failure, request cancellation and
replay refusal. A composed test uses the actual serialized request target to
reject reentrant policy callbacks that could deadlock its ownership mutex.
Existing file-only activation fences remain tested.

The installed-parser oracle covers forwarding, CIS and attributed legacy CIS
with declared direct, bastion and Ansible contexts. A separate opt-in runtime
oracle calls the recovery coordinator with disposable OpenSSH daemons and the
actual serialized request target with fixture observation callbacks. It verifies
that the former forwarding restriction
survives disk restoration until the separate reload, then checks restored
forwarding and fresh direct/ProxyJump authentication. It does not exercise the
production systemd binder or establish an enrolled independent controller.

Complete production activation, post-reload recovery completion, owned policy
updates, native SSH lifecycle, minimal native package transitions and final
v5.00.0 IVVQ remain open. BunkerWeb independence and Linux AMD64 scope are
unchanged. All remaining #422 work stays in the consolidated implementation.

## Production recovery adapter oracle

The [isolated systemd oracle](SSH_SYSTEMD_ORACLE.md#integrated-recovery-scenarios)
connects the real parser/publication engine to the production activation binder
and fixed-path inspection, restoration and post-reload assessment adapters. It
checks forwarding, CIS and explicitly attributed legacy CIS profiles, exact
retained inodes, independent TOML selection, distinct recovery approval and a
no-op reload that preserves stale daemon policy despite fresh authentication.
The fixture prepares labels explicitly for recovery input; it does not qualify
production SELinux policy lookup. All success and failure scenarios retain the
recovery fence. These observations do not complete migration, independent access
authority or the native package lifecycle.
