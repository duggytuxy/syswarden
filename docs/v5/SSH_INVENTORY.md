# Protected SSH configuration inventory

Status: inactive SSH-02 inventory component for v5.00.0. Refs #235 and #337.
This is a read-only prerequisite for the [SSH policy preparer](SSH_DROPIN.md).
It does not change the installer, authorize a policy, migrate legacy edits or
establish native lifecycle or final IVVQ acceptance.

## Read boundary

`sshpolicy.OpenInventory` opens the fixed production root `/` and reads
`/etc/ssh/sshd_config`, the reachable Include graph and the reserved
`/etc/ssh/sshd_config.d/00-syswarden-hardening.conf` path. It takes no root path,
UID or environment override. The private test boundary uses an already-open
temporary root and the test user's UID; it is not a product configuration API.

Every path component is opened relative to a pinned directory descriptor, with
no-follow checks. Ancestors must be root-owned directories with owner search
permission. Files must be root-owned, singly linked regular files. Group/other
write permission and special mode bits are rejected; configuration files must
not be executable. Symlinks are refused except for the bounded vendor alias
described below. FIFOs, device files and directories used as files are refused.
File identity and metadata are compared before and after opening
and reading. No file, mode, owner, directory or service is changed.

The reader preserves exact configuration bytes. It observes device/inode,
ownership, mode, link count, size and modification/change timestamps, excluding
access time. Literal absent files and the first absent ancestor are retained.
For globs, it records all directory entry names, including unmatched names, so
a later addition cannot silently escape revalidation. Conditional includes are
collected conservatively; this does not decide which connection matches them.

The parser uses the preparer's restricted Include grammar. This first adapter
supports literal directory paths and `*`/`?` in the final filename component.
Directory-component wildcards, ambiguous paths and locale-sensitive directory
names are refused. Non-ASCII or control-character names in a glob directory are
rejected even when the Go matcher would consider them unmatched. Dotfiles may
be collected conservatively rather than relying on libc/locale glob behavior.
These restrictions can refuse valid OpenSSH layouts; they must never cause a
fallback through the old writer. Vendor configurations outside the explicit
alias adapter below remain unsupported; no generic symlink resolver is used.

## Crypto-policies vendor alias

The upstream [crypto-policies updater](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/blob/master/python/update-crypto-policies.py)
can publish a backend as a regular generated file or an absolute link to a
precomputed policy. The reader accepts exactly one terminal alias source:
`/etc/crypto-policies/back-ends/opensshserver.config`. Its target must be an
absolute canonical `/usr/share/crypto-policies/<label>/opensshserver.txt` path.
The single policy label has at most 128 uppercase ASCII letters, digits,
hyphens, underscores or colons, with no empty colon-delimited component.
Relative links, other paths, directory links and chained links are refused.

The alias must be root-owned and singly linked. Linux symlink permission bits
are not write authorization; the protected parent and link owner are checked.
The reader opens the link itself with `O_PATH|O_NOFOLLOW`, reads its text through
that descriptor and compares descriptor/named identity before and after reading
the target. All target ancestors independently pass the existing no-follow
directory checks; the target must be an existing trusted regular file.

Exact link text, alias and target metadata, and both logical input paths are
retained and rechecked. Both path/content entries count toward file/byte limits.
Retargeting, same-text link replacement, target replacement or an unsafe change
invalidates the handle. Includes inside the target remain subject to complete
graph collection, conflict detection, cycle checks and resource bounds.

A recognized path is not package provenance, policy ownership or cryptographic
compliance. The reader never selects a policy, rewrites either path, runs
`update-crypto-policies`, removes an Include or overrides crypto algorithms.
Regular generated backends remain supported by the original regular-file path.
The [upstream manual](https://gitlab.com/redhat-crypto/fedora-crypto-policies/-/blob/master/update-crypto-policies.8.txt)
describes the external policy manager. Preserving this input does not validate
the whole distribution, FIPS status or administrator access.

## Lifetime and revalidation

The returned `Inventory` owns a separate root descriptor and must be closed.
`Prepare`, `Recheck` and `Close` are serialized for concurrent callers; copying
the object is unsupported. No mutable source map is exposed. Opening performs
two complete collections and requires identical observations before returning.

`Inventory.Prepare` recollects the graph and all observations before calling the
pure preparer. `Recheck` performs the same comparison without preparing policy.
A changed file, ancestor, directory membership or previously absent entry
invalidates the handle. Subsequent calls fail even if earlier bytes reappear.
Close and capture a new inventory for a new review. A policy conflict such as
an administrator-owned bastion rule returns no candidate but does not corrupt
an otherwise unchanged inventory.

Existing reserved files are inspected, not adopted. Even matching bytes require
independent ownership before update or removal. Historical markers remain
evidence for migration review, not permission to rewrite the main file.

This is an observation boundary, not a filesystem transaction or external-writer
lock. It resists unrelated ordinary UIDs through ownership and permissions. It
does not defend against malicious root, a compromised kernel or a cooperating
configuration writer. A later publication step must independently serialize
changes, bind approval to observations, revalidate immediately before its CAS
and verify activation/rollback. `Candidate.SourceDigest` still binds only source
path/content pairs; it is not a durable inventory receipt or an approval token.

## Resource limits

The inherited limits are 128 files, 1 MiB total configuration bytes, 16 KiB per
line, 16 Include levels and 512 graph visits/patterns. This adapter additionally
limits observations to 512 nodes and enumeration to 4,096 entries across all
glob directories. Reads and enumeration are bounded; files are opened without
blocking special-file semantics and temporary descriptors are closed as the
walk progresses. A failed capture returns no partial handle or candidate.

## Evidence and remaining integration

Temporary-root tests cover nested vendor and administrator files, missing files
and directories, unmatched membership, independent descriptor lifetime, unsafe
owners/modes/types, symlinks and hard links. Mutation tests cover identical-byte
inode replacement, new includes, parent replacement, permission changes and
permanent handle invalidation. Further cases exercise cycles, malformed syntax,
locale-sensitive names, resource ceilings and concurrent close/recheck/prepare.
The real OpenSSH parser oracle also checks a temporary linked crypto policy
with the prepared candidate, preserving its cipher/MAC values. This remains
separate from native distribution evidence; neither test starts a listener or
proves an administrator connection. Alias cases cover invalid targets, unsafe
storage, policy changes, nested Includes and unchanged input bytes.

Protected role and policy-owner declarations are still required by the
[environment compatibility contract](SSH_ENVIRONMENT_COMPATIBILITY.md),
including bastion and Ansible workflows. Legacy migration, reviewed publication,
external-manager coordination, new connections, reload/reboot and independent
uninstall/remove/purge tests remain open. No runtime caller uses this reader yet.
BunkerWeb remains independent, and supported architecture remains Linux AMD64.
