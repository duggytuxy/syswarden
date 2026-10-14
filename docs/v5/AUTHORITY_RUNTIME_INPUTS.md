# Acquiring protected authority runtime directories

Status: inactive Linux v5 provisioning component. Refs #224, #225 and #337,
all partial. Stable remains v4.10.4. Native packages and installed services remain
unchanged. This helper opens existing provisioning, not a new authority instance.

## Explicit parents and independently approved identity

`OpenAuthorityRuntimeDirectories` receives two already open parent descriptors,
a protected launch descriptor and its independently approved lowercase SHA-256.
It validates the launch record before opening either child. The record determines
the exact nonzero service UID, service GID and endpoint client GID. No request,
filename, account lookup or discovered configuration selects these identities.

| Resource | Required metadata | Purpose |
| --- | --- | --- |
| State parent | Root UID/GID 0, exactly 0700, readable directory, no access/default ACL. | Keep the storage discovery path private. |
| Fixed `state` child | Launch service UID/GID, exactly 0700, no access/default ACL. | Existing five-child protected authority layout. |
| Endpoint parent | Root UID/GID 0, exactly 0755, readable directory, no access/default ACL. | Permit traversal toward the group-restricted endpoint. |
| Fixed `endpoint` child | Launch service UID and endpoint GID, exactly 0750, no access/default ACL. | Existing authenticated local socket endpoint. |

All modes exclude special bits. O_PATH descriptors, missing or unlinked resources,
wrong types, incorrect ownership and extra permissions are refused. The two parents
and the two children must be distinct objects. Each child remains beneath its own
parent and cannot cross a mount during acquisition; the two independent parents
may reside on different filesystems, including persistent state and volatile
runtime storage. Provision each anchor on the intended filesystem.

The caller must independently trust parent ancestry, namespace and descriptor
origin and ensure endpoint ancestors are client-traversable. Root ownership inside
an untrusted user namespace is not host-root provenance. The helper cannot infer
that a human approved the account, directory or digest. These are deliberate
private/public provisioning anchors, not a requirement to chmod shared OS paths.

## Bounded acquisition and lifetime

Each fixed child is checked as a directory before opening. `openat2` requires
beneath-directory, no-symlink, no-magic-link and no-mount-crossing resolution. Opens
are read-only, directory-only, close-on-exec, nonblocking and cannot acquire a
controlling terminal. No other basename is accepted. Unsupported kernels, denied
mount crossings and uncertain resolution fail without retry or weaker fallback,
following the [Linux openat2 contract](https://man7.org/linux/man-pages/man2/openat2.2.html).

Acquired metadata must match the pre-open entry. Before success, both parent
profiles and timestamps, exact child-to-entry identities and ACLs are checked again.
The launch digest and record are also revalidated. A malformed second resource
releases the first: failure returns neither descriptor. The caller retains every
input and owns the two new handles on success. Closing the parent inputs does not
close those independently opened child references.

No directory scan, recursive read, account creation, permission repair, lease,
socket, receipt or state write occurs. The helper does not inspect or remove
unknown sibling entries. The existing [provisioned startup](PROVISIONED_AUTHORITY.md)
subsequently validates its five distinct children, obtains its leases and verifies
signed state before ordinary readiness. Pre-existing ambiguous runtime still uses
separately reviewed recovery; acquisition alone cannot approve cleanup or restart.

Directories remain mutable resources. An acquired descriptor retains the original
object after rename and does not follow a replacement. This is not a continuous
parent-path watcher, atomic deployment transaction or defense against hostile root
or service-identity compromise. The server's existing runtime metadata and storage
checks remain mandatory. Endpoint reachability and mount/MAC policy require native
validation in the final installed layout.

## Verification and integration

The separate mandatory real-program gate now contains 276 cases. Forty-one new
acquisition scenarios cover both valid lifetime and entry replacement, missing,
closed and O_PATH parents, swapped/aliased parents, invalid launch input, wrong
owner/group/mode, access/default ACLs, symlinks, FIFOs, regular files and missing
children. Rejections compare before/after parent state and check for leaked child
descriptors. Kernel-resolution unit tests require exact flags and no fallback on
unsupported, denied or uncertain opens.

The actual executable fixture provisions separate private and group-facing anchors,
uses this helper to acquire both directories, closes the parent handles, and passes
the acquired references through the root launcher and independent non-root bootstrap.
Real client resume, commit, denied access, clean drain, restart and crash retention
continue on that layout. All 132 independent cross-UID cases remain mandatory.
Normal and race campaigns are distinct and cannot skip required evidence.

Trusted initial discovery, account and directory provisioning, release approval,
loader/dependency policy, native MAC/seccomp, installed supervision, human MFA/audit
and full v5 acceptance remain open. BunkerWeb retains its independent authenticated
API, source-owned temporary bans, expiry, retries and HA without a dashboard,
journal, launcher or identity-provider dependency.

The [complete acquisition helper](AUTHORITY_LAUNCH_BUNDLE.md) combines these runtime
handles with the immutable launch record and image. A late runtime failure releases
the earlier snapshots and returns no partial bundle.
