# Protected authority startup composition

Status: inactive Linux v5 library component. Refs #224, #225 and #337 remain
open. Stable remains v4.10.4. No installed service, native package or existing
integration activates this API.

## Explicit inputs and ownership

`StartAuthorityChildFromInputs` takes an `AuthorityChildInputs` value containing
three independently trusted parent descriptors, one read/write Linux null-device
descriptor and three independently approved SHA-256 digests. It requires all real,
effective and saved user/group identities to be root before acquiring resources.
The caller retains every input and must serialize handoff against modification
or closure. It provides trusted provenance, not arbitrary paths or browser data.

The operation composes the existing
[complete acquisition](AUTHORITY_SUPERVISOR_BUNDLE.md) and
[pinned child supervisor](AUTHORITY_CHILD_SUPERVISION.md):

1. Acquire the fixed launch record, authority executable and root launcher,
   verify independent approved digests and seal immutable snapshots. Acquire
   the existing protected private-state and public-endpoint directories.
2. Reuse exact child admission and handoff: duplicate borrowed resources, check
   the null device, use a fixed environment and descriptor layout, create a new
   session and obtain an atomic pidfd. No shell, alternate path or retry.
3. Release all five temporary acquired resources after creation returns,
   including on partial or failed acquisition. The child keeps its own lifetime
   and process handle. Caller parents and null descriptor remain borrowed.

The composition creates no provisioning resources, account, key, approval or
trust root. It does not alter parent credentials or resource limits. Source
configuration and executable files remain unchanged. The child itself follows
its existing startup contract for verified runtime socket and evidence creation.
A successful return establishes process creation only; it is not readiness,
ongoing health, successful shutdown or installed service acceptance.

## Failures after creation must retain the child

| Outcome | Return and caller duty |
| --- | --- |
| Input or acquisition refused | No child. Acquired temporary resources close; borrowed inputs remain owned by the caller. |
| Kernel creation refused | No child. The exact error remains visible and there is no automatic retry. |
| Child created with a later handoff or close error | Return both child and error. Retain the child, inspect the uncertainty, request a permitted stop and observe/reap its exit. Never discard a non-null child because an error also exists. |
| Creation succeeds, service later refuses startup | Readiness fails and the exit verdict remains unsuccessful. Do not substitute successful process creation for service startup. |
| Clean creation and later clean drain | Readiness, exact signal request, exit/reap and close must each satisfy their own contract. |

Errors from this composition remain attached to the child before it is exposed
to the caller. An uncertain handoff cannot later report public readiness; exit
observation and final close retain the earlier error even if the child exits
with status zero. An additional close error does not replace an earlier error.
Temporary acquisition cleanup does not signal or abandon a created process.

There is no automatic wait, kill escalation, endpoint recovery or background
reaper. The caller remains the sole owner and reaper of a non-null child. Context
cancellation in later observation does not revoke that ownership. A supervisor
crash and service-manager/cgroup lifecycle require separate policy and acceptance.

## Verification and scope

The mandatory actual-program campaign now requires 296 named cases, normally
and under race instrumentation. Seventeen new startup cases verify rejection of
incorrect digests, closed/missing inputs and unsafe null descriptors; runtime and
repeated kernel creation refusal; partial acquisition; a missing creation result;
post-start error and cleanup uncertainty; private startup failure; and complete
real lifecycle after borrowed inputs close and all source names are replaced.

Tests assert no descriptor leaks after refusal or completed shutdown, unchanged
source/private-store inventories where no mutation is authorized, retained parent
identity/limits/flags, real kernel service identity, authorized client reads,
SIGTERM, exact exit status and preserved error evidence. Fault seams remain
private test mechanisms; production exposes no alternate factory or bypass.
The independent 132-case cross-UID campaign remains mandatory and unchanged.

The composed API does not discover trusted parents or the null device, create an
installed supervisor entry point, approve dynamic-loader dependencies, implement
fleet enrollment or replace human MFA/approval. Trusted provisioning, native
service-manager isolation/IVV and full v5 Upgrade IVVQ remain open. BunkerWeb's
independent API, temporary-ban source ownership, expiry, retries and HA acquire
no dependency on this component, the dashboard or its identity provider.

[Child lifecycle orchestration](AUTHORITY_CHILD_LIFECYCLE.md) now connects bounded
readiness, ongoing exit observation, one graceful stop request and bounded drain.
Its outcome keeps readiness, stop, reaped state and handle closure separate; a
lost exit observation leaves the child owned and unclosed. The mandatory campaign
requires 296 cases, including lifecycle fault decisions and actual child/client
operation, normally and under race. The independent 132-case separate-UID gate
remains required. This inactive library does not install a supervisor or establish
native acceptance; BunkerWeb remains independent.
