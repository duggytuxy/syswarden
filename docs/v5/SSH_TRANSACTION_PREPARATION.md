# SSH transaction storage and anonymous staging

Status: internal development component for v5.00.0. Refs #235 and #337.
The CLI remains read-only: `ssh-policy plan` and `ssh-policy verify` do not
create transaction state. Installation, CIS hardening and removal do not call
the new storage helpers yet. There is no public apply command or complete
migration package. Final IVVQ acceptance remains open.

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
The helpers do not publish a temporary name or exchange a live file.

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
same-named or same-content file. Recovery must independently reconcile exact
identities and record any replacement staging operation before publication.

## Tests and remaining integration

Component tests cover real unnamed files and access ACLs, inheritance removal,
attribute binding, concurrent product handles, directory replacement, immutable
records, reopening after candidate descriptors close, malformed storage,
stale approval, changed candidates and injected directory-sync failure. These
are temporary fixture tests; no installed configuration or server is changed.

Internal state ownership is now implemented and rechecked by the journal.
Internal [pre-receipt retention](SSH_STATE_RECOVERY.md) preserves explicitly
reviewed orphan directories without adopting them. Include isolation prevents
private state from entering the SSH configuration graph.
Still required: installation provisioning, a public recovery adapter, durable phase transitions,
intermediate-state parser checks, publication and interrupted recovery,
post-publication verification, activation/rollback and a shared installation/CIS
adapter without an old-writer fallback. Follow with independent SSH, ProxyJump
and Ansible access, reload/reboot, and separate uninstall/remove/purge tests
that preserve administrator configuration and later edits. Prepared recovery
data must be handled separately from active product configuration on removal.
BunkerWeb's independent API, temporary-ban ownership and HA contract are unchanged.
