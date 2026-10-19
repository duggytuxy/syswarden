# v5 protected registry snapshot reader

Status: inactive FA-02 persistence prerequisite. Refs #224, #233 and #315.
This adds a bounded storage format and Linux reader after the
[continuity contract](NODE_REGISTRY_CONTINUITY.md). It does not install a service,
provision trust or implement a registry writer. Stable remains v4.10.4 and final
v5.00.0 IVVQ remains open.

## One complete object and independent expected state

The [snapshot codec](../../src/core/syswarden-core/fleetregistry/snapshot.go)
encodes one complete object with these sections, in this order:

1. Literal ASCII header `SYSWARDEN-NODE-REGISTRY-V1` followed by one LF byte.
2. A four-byte big-endian length and canonical generation document, at most 4 KiB.
3. A four-byte big-endian length and canonical checkpoint document, at most 4 KiB.
4. A four-byte big-endian length and complete canonical registry manifest, at
   most 16 MiB.

Empty sections, unsupported headers, excessive lengths, truncation and trailing
bytes reject the whole object. No compression, path, arbitrary extension or
executable content is accepted. A synthetic independently generated
[binary golden vector](../../src/core/syswarden-core/fleetregistry/testdata/registry-v1.hex)
pins the exact framing. The length limits are object-size limits, not a measured
heap budget or the combined registry/receipt/audit budget.

The caller supplies the independently expected authority, lineage, generation
reference and checkpoint reference. The reader checks the small canonical
generation/checkpoint before parsing the larger registry. The checkpoint binds
the complete snapshot digest. Values contained in the file do not supply their
own expected authority, and a higher sequence is not automatically adopted.

The [registry decoder](../../src/core/syswarden-core/contracts/v5/node_registry_decode.go)
checks the expected complete digest and size, then bounds member and slot arrays
while decoding them. It never first unmarshals an arbitrarily large member/slot
array and checks its count afterward. Each fixed record is validated, followed
by the complete builder's scope, uniqueness, rotation and aggregate checks.
Exact canonical re-encoding rejects aliases, duplicates, reordering, null arrays,
extra fields and noncanonical strings. Any late fault returns no valid prefix.

`CheckNodeRegistryContinuity` is now an exported administrative check so the
reader can also verify disabled records for recovery. It grants no admission.
`NodeRegistryReadContext` still requires an active checkpoint and a trusted time;
the subsequent member, slot and grant checks remain mandatory.

## Protected descriptor boundary

The [Linux store](../../src/core/syswarden-core/fleetregistry/store_linux.go)
accepts an already-open directory descriptor from trusted startup provisioning.
It does not discover a directory from a node request, browser input or uploaded
path. Only the fixed filename `registry-v1.swr` is opened.

- The directory must be owned by the effective service UID, exactly mode 0700,
  and still linked. The file must be owned by the same UID, exactly mode 0600,
  regular, have exactly one link and fit the complete object limit.
- The reader acquires its own directory descriptor and exclusive nonblocking
  advisory `flock`. It does not duplicate the caller's open description, which
  would share lock ownership. Competing cooperating handles are refused.
- The file is opened read-only, without following a symlink, with close-on-exec,
  nonblocking and no-controlling-terminal flags. Type checks before and after
  opening reject special files, FIFO substitutions and multiple links.
- Directory, opened file and named entry are compared before and after every
  complete read. Device/inode, ownership, permissions, link count, size and
  modification/change timestamps must remain consistent. Access time is not an
  integrity signal. Even unrelated directory mutation invalidates this dedicated
  storage lease; this is not a shared administrator directory.
- An I/O error, changed metadata, replaced entry, malformed body or unexpected
  continuity returns no snapshot and poisons that handle. Restoring an older
  expected reference does not revive it. Close and independently reviewed reopen
  are required; the reader does not fall back to previously accepted bytes.

Closing releases only owned descriptors and the lease. The caller may close its
original directory descriptor after opening the store without invalidating the
store's ownership. Calls on one handle serialize with reads and close. The store
never writes, creates, truncates, repairs, changes permissions or removes a file.
An encoder produces provisioning bytes only; it is not a storage commit API.

This boundary protects against other ordinary UIDs under the provisioned OS
permissions. It does not isolate a process sharing the service UID, protect
against root or establish that the supplied directory came from a trusted
ancestor path. Those are startup provisioning and deployment responsibilities.
The component tests exercise real files and metadata checks. The mandatory
cross-UID gate also starts an ordinary attacker with dropped capabilities and a
positive canary, verifies denial of file reads, writes and replacement, and checks
that a subsequent authorized read still succeeds. The evidence gate rejects
missing or skipped cases. This is not native acceptance across all distributions.

## Reading is not an admission lease or durable acknowledgement

The returned snapshot owns its metadata and exposes an immutable registry.
It is administrative state. A disabled snapshot is readable but fails operational
admission. No file read proves key possession, source truth or current TLS identity.

Expected continuity must be refreshed independently at each use. Reading a valid
historical file with a correspondingly rolled-back expected context cannot detect
a common rollback. Reopen also cannot prove that a previous writer synchronized
the file or its directory. The future writer must establish that durability and
serialize current admission with revocation and publication.

This reader holds an exclusive lease for its lifetime and deliberately rejects
external replacement. It is not an online refresh mechanism. A future writer
must define explicit handover and current-custody publication instead of swapping
the file behind an active reader and hoping it adopts the change.

## Evidence and next gate

Component tests cover strict framing, independent golden bytes, late malformed
records, streaming count ceilings, empty and 500/4,096-member populations,
wrong expected state, disabled administrative reads, symlinks, hard links, FIFOs,
wrong permissions, truncation, lease conflicts, owned descriptors, changed files
during read, short/error reads, poisoned handles and concurrent read/close.
Bounded fuzz targets exercise the registry and complete snapshot decoders. The
existing mandatory cross-UID gate includes 12 file/directory attacks and a
verified read after those attacks; it cannot pass by skipping this scenario.

FA-02 still needs authenticated provisioning/approval, one durable writer,
independent current anchors, publication ordering and crash recovery, explicit
retention with denial history, and aggregate resource accounting. Native
ordinary-user attacks, process death and restored snapshots remain separate
requirements. No server, listener, enrollment or installed service is activated.
BunkerWeb retains its independent API, source ownership, TTL, retry, withdrawal,
cache and HA behavior; it never consults this optional fleet storage component.
