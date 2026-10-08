# Persistent WireGuard filesystem identity

Status: published in v4.10.3 after protected Patch IVV and independent public
asset verification. The earlier signed candidate
`1920f2065d6280d41211007895f969ea1f4fce36` failed a native reboot test; that
failure remains recorded. The final signed product passed a fresh native
campaign including actual device renumbering and verified restoration. See the
[publication record](../releases/v4.10.3/README.md) for exact identities and limits.

## Defect and ownership boundary

Linux can assign a different device number to the same filesystem after boot.
The original ownership record combined that number with the inode, content
digest, owner, permissions and link count. A legitimate device renumbering
therefore caused a refusal even when the filesystem and every owned file were
unchanged. The failed native result and its original evidence are retained.

The correction captures the filesystem UUID through the already pinned file
descriptor using the read-only `FS_IOC_GETFSUUID` interface. Its fixed response
is defined by the [Linux v6.12 filesystem UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/fs.h)
and [ioctl implementation](https://github.com/torvalds/linux/blob/v6.12/fs/ioctl.c).
Owned OpenRC links use the pinned parent directory on the same filesystem.

An optional `filesystem_uuid` field extends the existing canonical ownership
format. A recorded UUID must exactly match the current nonzero, canonical
16-byte UUID. Only the device number may then differ. Path, inode, SHA-256,
owner, permissions and hard-link count remain mandatory. Descriptor/path
identity checks during each read still require the current device number.
An unsupported ioctl retains strict device matching; it never removes an
existing UUID requirement. Malformed responses and unexpected errors refuse.

## Existing ownership and interruption

UUID-free records are readable without changing their original bytes. They
must first pass the original device, inode, metadata and digest checks before
the mutation phase may add UUID evidence. An old record whose device has
already changed cannot be rebound automatically. Keep its evidence for
separate verified recovery rather than editing the manifest by hand.

The binding operation changes only manifest UUID fields, with all generated
files and keys preserved. It publishes a private journal containing the exact
old manifest identity, old bytes and verified target bytes before staging or
exchanging the manifest. The journal is
`/etc/wireguard/.syswarden-filesystem-binding-v1.json`; its bounded stage is
`.syswarden-ownership-v1.json.filesystem-stage` in the same private directory.

Read-only preflight refuses pending binding state. Install, reload, setup and
native removal recover it under the existing activation guard before ordinary
ownership checks. Recovery verifies the target's filesystem-bound artifacts,
finishes the exact manifest exchange and removes only the attested prior
manifest and journal. Corrupt journals, foreign stages, substituted manifests
and changed generated files are retained with a refusal. A completed binding
is idempotent, including after device renumbering.

The same identity comparison applies to publication/removal journals,
historical migration archives and forwarding persistence. Forwarding recovery
checks the recorded forwarding artifact against the pinned file before
comparing every other target manifest byte. It does not reconstruct durable
manifest bytes from a newly assigned device number.

## Required validation

Regression tests cover positive and negative file identities, unsupported
UUID queries, OpenRC links, exact removal, every binding boundary, interrupted
historical migration, and forwarding rollback/commit after simulated device
renumbering. They also preserve refusal for UUID-free device drift and altered
content, inode or filesystem evidence.

These tests supplement the completed signed native campaign. Protected IVV
accepted actual historical first-hop upgrades, half-configured recovery,
unchanged clients, encrypted bidirectional traffic and NAT, repeated reboots,
native purge and same-version reinstall within the reviewed scope. A production
installation still requires its own verification.
