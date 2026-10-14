# Immutable authority launch configuration

Status: inactive Linux v5 component. Refs #224, #225 and #337, all partial.
Stable remains v4.10.4. No package, account or installed service is activated.

## Exact approved bytes across startup

`SnapshotAuthorityLaunch` reads an independently approved launch record through
its existing protected descriptor. The existing 8,192-byte limit, lowercase
SHA-256, root UID/GID 0, 0400 mode, no-ACL, read-only access and canonical format
checks run before creating a snapshot. The copy preserves exact bytes, not a new
semantic encoding. Positional reads preserve the caller's offset and ownership
of the source descriptor. Invalid input exposes no output handle.

The copy is an anonymous memory file with close-on-exec and `MFD_NOEXEC_SEAL`.
Its final mode is 0400. The helper requires all of `F_SEAL_WRITE`, `F_SEAL_GROW`,
`F_SEAL_SHRINK`, `F_SEAL_SEAL` and `F_SEAL_EXEC`, then reads those seals back.
The data cannot be written, resized or shared through a writable mapping. The
seal policy cannot be extended and executable permission bits cannot be added.
These claims follow the [Linux non-executable memfd contract](https://docs.kernel.org/userspace-api/mfd_noexec.html)
and [memfd and sealing interface](https://man7.org/linux/man-pages/man2/memfd_create.2.html).

The writable construction descriptor closes before return. A trusted procfs
reopens only that exact kernel-created descriptor as read-only and close-on-exec;
the helper compares identities and revalidates metadata, seals, digest and bytes.
No pathname comes from the record. There is no discovery, source-path reopening,
retry, legacy fallback or relaxation of the namespace's memfd policy. Unsupported
`MFD_NOEXEC_SEAL`, policy denial or uncertain inspection fails closed.

`F_SEAL_EXEC` protects executable file-mode bits. It is not a claim of whole-process
W^X, a ban on every executable memory mapping, or a replacement for MAC/seccomp.
A privileged identity can still alter ownership or non-executable permission bits;
the loader checks these again and refuses a changed profile. Trusted procfs,
initial namespace and root integrity remain provisioning assumptions.

## Integration and compatibility

[Protected input acquisition](AUTHORITY_LAUNCH_INPUTS.md) now returns two immutable
snapshots. It retains all pre-open checks, exact constrained resolution and
name-to-inode rechecks before freezing the launch bytes. It closes both source
handles and returns neither output after any failure. The caller owns both
returned descriptors and keeps its directory descriptor.

`LoadAuthorityLaunch` continues accepting the existing protected named one-link
source for independent embedded callers. A zero-link descriptor is accepted only
when its complete seals, root ownership, exact mode, read-only access, no ACL,
bounded bytes and independent digest pass. Ordinary unlinked files, incompletely
sealed memory files and writable descriptors remain rejected.

The root launcher, independent non-root bootstrap and authority consume the same
launch descriptor contract. Subsequent replacement, editing or deletion of the
source inode cannot change a successful snapshot. Every startup still validates
the inherited record. Existing configuration schema and command-line arguments
remain unchanged. Clients receive no launch descriptor.

A snapshot is not an approval, deployment transaction, freshness guarantee,
revocation mechanism or rollback registry. The trusted provisioner must approve
the configuration/image digest pair, protect initial descriptor delivery and
serialize deployment changes. A running service is not automatically reconfigured
by editing its source record. Native loader policy and installed supervision
remain separate work.

## Mandatory verification

The executable gate now requires 276 cases, normally and under the race detector.
Its 21 snapshot cases cover exact output and offsets, source replacement/edit/unlink,
invalid handles and digests, malformed canonical records, every missing seal,
unsafe anonymous metadata and writable descriptors. The positive assertion probes
actual write, resize, shared-mapping, seal-policy and executable-mode refusal
through a separately writable descriptor inside the disposable root fixture, so
read-only access cannot mask a missing seal.

Four additional real-program cases supply correctly hashed anonymous records
without complete seals to both startup paths. They must fail without readiness or
private state changes. The existing commit, restart, drain and crash lifecycle
runs after the acquired source record is unlinked. Mandatory evidence cannot be
skipped. The separate 132-case cross-UID campaign is unchanged.

Creation-policy unit tests require one attempt with exact non-executable flags,
including kernel and policy errors. Linux 386 tests and ARM64 builds check portable
metadata conversion; they do not substitute for native supported-platform IVV.
The active v4 release, BunkerWeb's independent authenticated API, source-owned
temporary bans, expiry, retries and HA remain unchanged.
