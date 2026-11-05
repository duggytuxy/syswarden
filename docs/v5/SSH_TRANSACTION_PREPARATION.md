# SSH transaction storage and anonymous staging

Status: internal development component for v5.00.0. Refs #235 and #337.
The planning CLI remains read-only: `ssh-policy plan` and `ssh-policy verify`
do not create transaction state. Installation, CIS hardening and removal do not
call the new storage helpers yet. There is no public forward-application command
or complete migration package. Existing activation transactions can use the
separate [original-restoration command](SSH_OPERATOR_RECOVERY.md), which does not
provision state or accept complete recovery. Final IVVQ acceptance remains open.

## Exact metadata before publication

The protected inventory now retains bounded extended attributes for every
opened regular configuration file and directory, including the administrator
intent. The plan digest binds attribute names and values as well as the existing
bytes, inode identity, modes, ownership, timestamps and directory observations.
Previously printed development plan hashes must be inspected again; the digest
domain is now version 2. This does not change the intent JSON schema.

Attribute names and values are private. Public summaries still contain only
counts, operation metadata and hashes. An unreadable attribute or exceeded
32 KiB aggregate attribute budget per object refuses inspection. Attribute
mutation during capture or later reinspection invalidates the observation.

Replacement preparation uses an unnamed inode in the target filesystem. It
writes all bytes, sets the reviewed owner/group/mode, removes inherited
attributes absent from the source, restores the exact reviewed attributes,
syncs the file, and rereads the resulting bytes and metadata. This includes
access ACLs and SELinux labels. A host that refuses exact preservation fails
without changing its security policy or using a weaker staging method.

Content integrity signatures, executable capabilities and directory-only ACLs
cannot be transplanted to rewritten configuration. Reading such metadata in
an inventory is allowed; preparing a replacement with it is refused. A new
drop-in's target label still needs explicit integration with the host policy;
copying a directory label is not a substitute.

An unnamed inode cannot be found through an SSH Include pattern. Closing its
last descriptor discards it if it has never been linked. These properties use
Linux [O_TMPFILE semantics](https://man7.org/linux/man-pages/man2/open.2.html).
The staging helpers do not publish a temporary name or exchange a live file.
The separate internal [publisher](SSH_PUBLICATION.md) now implements those
ordered operations with durable phase evidence.

## Private durable preparation record

The internal journal expects the fixed protected directory
`/var/lib/syswarden/ssh-policy-v1`, owned by root:root with mode 0700, beneath
protected real ancestors. It does not create, repair or adopt an unsafe
directory. The internal [provisioner](SSH_STATE_PROVISIONING.md) now records
independent directory ownership; installation does not invoke it yet.
A nonblocking exclusive lock on the directory coordinates product processes.
It does not prevent an administrator or external configuration manager from
writing SSH configuration. Replaced or detached directories invalidate handles.

A prepared record contains a random transaction identity, the exact approved
plan and parser hashes, the original main configuration, and both unnamed
candidate inode identities, bytes and metadata. It is private recovery data,
not proof of publication, activation, a successful login or current ownership
of the reserved drop-in. The future orchestrator must reverify the installed
parser and complete live inventory while coordinating the transaction.

`prepared.json` is written through a synced unnamed file and linked without
replacement. It is root:root 0600 and inherits only its kernel-assigned SELinux
label, not a discretionary access ACL. The parent directory is then synced and
the complete record is reread. A file sync alone does not make the new directory
entry durable, as described by [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).
An existing record, including an invalid or unrelated one, is never overwritten.

Only the canonical bounded encoding is accepted on read. Duplicate/unknown
fields, case aliases, null images, invalid identity/metadata, excessive sizes,
symlinks, hard links and nonregular files are refused. A failed directory sync
retains the uncertain record and poisons the handle. No automatic deletion or
claim of successful preparation follows an uncertain write.

If a process dies before linking its candidates, those inodes disappear while
the private record retains their bytes. The record must not authorize a later
same-named or same-content file. The internal
[transaction recovery](SSH_TRANSACTION.md#failure-and-recovery) can now abort
an unpublished preparation after verifying the unchanged approved inventory and
original live policy. It records a terminal outcome and preserves all evidence;
it does not recreate those inodes or make the journal reusable.

## Publication preflight

The read-only verifier now checks the exact intermediate configuration with
the new drop-in and the original main file, in addition to the live baseline,
sealed baseline and final candidate. Every configuration passes syntax checks
and effective-policy comparison for the global defaults and all declared
connection contexts. A reviewed policy setting can retain its original value
or take its final value during the transition. Every unrelated setting must
remain identical. This includes an exact historical CIS block before removal,
administrator Match rules and explicitly declared access paths.

Before a preparation record can be returned, every captured Include directive
must also exclude the proposed same-directory main-file stage. Its fixed prefix
is `/etc/ssh/.syswarden-ssh-main-`, followed by the validated random transaction
identity. Inspection covers original and candidate main files, nested files,
conditional Includes and currently empty glob expansions. Both the candidate
and the displaced original could occupy this name during a future exchange;
neither may become a new SSH input. The nonincluded drop-in retention name used by
rollback must also be excluded by every captured Include pattern.

This check creates no named stage and performs no exchange. It does not replace
input revalidation, durable phase records, external-writer coordination or
post-publication verification. It establishes conditions for a future ordered
publication; it does not claim that two separate configuration writes are atomic.

## Tests and remaining integration

Component tests cover real unnamed files and access ACLs, inheritance removal,
attribute binding, concurrent product handles, directory replacement, immutable
records, reopening after candidate descriptors close, malformed storage,
stale approval, changed candidates and injected directory-sync failure. These
are temporary fixture tests; no installed configuration or server is changed.
Additional tests reject intermediate syntax errors, changes to access settings,
unreviewed policy values and Includes reaching the proposed stage. The optional
installed-OpenSSH oracle exercises all four configurations with temporary host
keys, including a legacy CIS migration and multiple connection contexts. It
does not start a listener or authenticate a user.

Internal state ownership is now implemented and rechecked by the journal.
Internal [pre-receipt retention](SSH_STATE_RECOVERY.md) preserves explicitly
reviewed orphan directories without adopting them. Include isolation prevents
private state from entering the SSH configuration graph.
The internal [publisher](SSH_PUBLICATION.md) adds durable phase transitions,
ordered configuration writes, read-only interrupted-state inspection and
post-publication parser verification. The internal [rollback helper](SSH_ROLLBACK.md)
adds inverse transitions and explicit interrupted recovery.
Still required: installation provisioning, a public recovery adapter,
service activation and a shared installation/CIS
adapter without an old-writer fallback. Follow with independent SSH, ProxyJump
and Ansible access, reload/reboot, and separate uninstall/remove/purge tests
that preserve administrator configuration and later edits. Prepared recovery
data must be handled separately from active product configuration on removal.
BunkerWeb's independent API, temporary-ban ownership and HA contract are unchanged.
