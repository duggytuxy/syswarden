# Complete protected supervisor input acquisition

Status: inactive Linux v5 library component. Refs #224, #225 and #337 remain
open. Stable remains v4.10.4. No installed entry point, package, service or
BunkerWeb integration calls this API.

## Ownership and independent approvals

`OpenAuthoritySupervisorBundle` receives three independently trusted parent
handles and three approved lowercase SHA-256 digests. It acquires the existing
four-resource `AuthorityLaunchBundle` and a separately approved sealed launcher
image. A successful result owns exactly five close-on-exec descriptors:

| Resource | Fixed source or derived entry | Held result |
| --- | --- | --- |
| Launch record | `launch.json` in the input parent | Immutable non-executable snapshot |
| Authority image | `syswarden-authority` in the input parent | Immutable native ELF snapshot |
| Launcher image | `syswarden-authority-launch` in the input parent | Independently approved immutable native ELF snapshot |
| Private state | Existing `state` under the private parent | Verified directory handle |
| Public endpoint | Existing `endpoint` under the public parent | Verified directory handle |

The three digests have distinct roles and must come from the caller's trusted
approval process. A digest calculated from whatever file happens to be present
is not approval. The caller retains every parent handle on success and failure.
It must serialize their use and closure and must not copy or replace bundle fields.
The API does not discover trusted ancestry, select accounts, create directories,
install keys, approve a release or acquire an active service lease.

The input directory remains root-owned `0700`, with no access or default ACL.
Each executable source remains root-owned `0555`, a bounded regular file with
one link, no file capability and no ACL. Existing launch and runtime directory
profiles are unchanged. Fixed-name resolution requires `openat2` restrictions
against symlinks, magic links, mount crossings and escape. Unsupported kernels or
policy denials fail without an alternate pathname or weaker fallback.
Trusted ancestry, mount namespace and host-root provenance remain prerequisites;
root ownership observed inside an arbitrary user namespace is not that provenance.

## Acquisition, failure and handoff

The implementation first opens and snapshots the launcher, verifies its digest
and ELF profile, then acquires the complete launch bundle. Before returning it
rechecks the input parent and the original launcher inode and pathname binding.
Replacement, metadata changes and in-place changes during this interval cause a
refusal. These checks establish bounded coherence, not an atomic filesystem
transaction or protection from a compromised root or kernel. Native ELF admission
does not approve a dynamic interpreter or its dependencies.

Every failure returns no bundle and closes resources acquired by this layer,
including a launch bundle returned alongside an error. Source-close and cleanup
errors from this composition are retained. There is no source-file mutation,
implicit recovery, process creation or fallback acquisition.

After successful acquisition, callers may close the parents. Replacing source
paths cannot change held snapshots. A later acquisition still has to pass its own
metadata, digest and coherence checks. Runtime directory handles retain their
inodes; they do not replace the authority's startup revalidation.

`StartAuthorityChild` borrows `result.Bundle` and `result.Launcher`, together with
the three approved digests and a separately trusted read/write null-device handle.
It duplicates the resources before process creation. Keep the input bundle alive
until handoff returns. A non-null returned child remains caller-owned even when
an error accompanies it. Readiness, exit, drain and cleanup are separate verdicts.

`Close` consumes the bundle and launcher fields and attempts every owned close,
even after an error. Repeated or nil closure is harmless. Closing acquired inputs
never signals a child, deletes source files, releases a service lease or retires
runtime evidence. The child supervisor has its own lifecycle and close contract.

## Verification and remaining scope

The mandatory real-program campaign requires 276 named cases, normally and with
race instrumentation. This slice adds 25 acquisition cases plus the enclosing
composition and actual-program handoff cases. Tests cover independent approvals,
unsafe source metadata and types, late and partial acquisition failure, repeated
refusal without descriptor leaks, deterministic changes during acquisition,
caller-parent ownership, sealed images after source replacement and full closure.
All actual supervisor and executable lifecycle cases use the acquired resources
after their caller parents are closed and all three source names are replaced.
The independent 132-case cross-UID campaign remains mandatory and unchanged.

Synthetic root fixtures and user namespaces do not establish native OS acceptance.
Trusted provisioning, dynamic dependencies, service-manager policy, MAC/seccomp,
operational shutdown policy, native IVV and full v5 Upgrade IVVQ remain open.
BunkerWeb's independent API, source-owned temporary bans, expiry, retries and HA
contract acquire no dependency on this acquisition component or the dashboard.

## Related contracts

- [Complete launch bundle](AUTHORITY_LAUNCH_BUNDLE.md).
- [Protected launch input resolution](AUTHORITY_LAUNCH_INPUTS.md).
- [Pinned child creation and supervision](AUTHORITY_CHILD_SUPERVISION.md).
- [Actual executable assurance](AUTHORITY_EXECUTABLE_ASSURANCE.md).

[Protected startup composition](AUTHORITY_CHILD_STARTUP.md) connects acquisition
and process creation while preserving borrowed inputs and post-start failure evidence.
