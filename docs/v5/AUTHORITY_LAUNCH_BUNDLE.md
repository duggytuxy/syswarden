# Complete protected authority launch acquisition

Status: inactive Linux v5 provisioning component. Refs #224, #225 and #337,
all partial. Stable remains v4.10.4. No native package or installed service changes.

## Complete acquisition and explicit ownership

`OpenAuthorityLaunchBundle` accepts three caller-owned parent descriptors and two
independently approved SHA-256 digests. It composes the existing
[launch-input acquisition](AUTHORITY_LAUNCH_INPUTS.md) and
[runtime-directory acquisition](AUTHORITY_RUNTIME_INPUTS.md). The result owns four
independent close-on-exec handles:

| Handle | Contract |
| --- | --- |
| `Launch` | Immutable, read-only, root-owned canonical launch snapshot. |
| `Image` | Immutable, root-owned executable image with a validated native ELF layout. |
| `State` | Existing private state directory bound to the approved service identity. |
| `Endpoint` | Existing group-facing directory bound to the approved service and client identities. |

The source directory contains the two fixed names required by the launch-input
contract. Other entries are neither interpreted nor removed. The private state and
public endpoint parents retain their distinct exact metadata profiles. Every existing
ownership, mode, ACL, digest, constrained-resolution and repeated-binding check
remains mandatory. The service and client identities come from the frozen approved
record, never a name lookup or a request.

A failure returns no bundle. If runtime acquisition fails after image/configuration
preparation, both snapshots and any acquired children close. Caller parents remain
open. No files, permissions, accounts, storage records, sockets or recovery receipts
are created, repaired or retired. Resource acquisition alone takes no storage lease
and starts no process.

The owner serializes use and `Close`, does not copy the bundle or replace its fields,
and retains the handles until descriptor handoff finishes. `Close` consumes all four
fields and attempts every close even if one fails. A second call and a nil receiver
are harmless. Callers may close their parent descriptors immediately after successful
acquisition; the returned handles retain independent lifetimes. Closing the bundle
does not stop a process that already inherited its resources and does not perform
product removal or endpoint recovery.

## Startup and trust boundaries

The actual root launcher and independent non-root bootstrap fixture now receive
all four resources from this complete acquisition. Its parent handles and earlier
individual acquisitions are closed before startup. Source files are removed and
replaced with unapproved bytes before the real service starts. The held immutable
snapshots remain authoritative. Startup still repeats its own launch, executable,
identity and protected-storage checks, acquires lifecycle leases and verifies signed
state before readiness. The caller supplies a separately verified readiness channel.

This API is not an atomic deployment transaction. Mutable directories may change
after acquisition; storage and runtime checks remain necessary. It does not discover
trusted parent paths, authenticate namespaces or procfs, approve a digest pair,
prevent rollback, or validate a dynamic loader and its dependencies. Human approval,
account provisioning, native MAC/seccomp and service supervision remain separate
requirements. Root or service-identity compromise is outside the ordinary-user claim.

## Verification

Sixteen composition cases cover valid parent-independent lifetime, missing and closed
parents, wrong digests, a correctly hashed invalid image, invalid runtime identities,
missing children and swapped parents. Repeated refusal at the final runtime resource
must preserve all source/runtime metadata and bytes and leave the exact descriptor
inventory unchanged, including anonymous snapshots. Closure tests require all other
handles to close when one is already closed, and repeated closure to be harmless.

The complete real-program campaign now requires 212 cases, including this composition
and actual handoff. Existing client commit/resume, ordinary-user refusals, thread
credentials, clean drain, restart and crash preservation remain mandatory. All 132
independent cross-UID cases remain separate. Both campaigns run normally and with the
race detector; incomplete or skipped required evidence fails their CI gates.

This is component integration, not native deployment acceptance. BunkerWeb retains
its independent authenticated API, source-owned temporary bans, expiry, retries and
HA, with no new dashboard, journal, launcher or identity-provider dependency.
