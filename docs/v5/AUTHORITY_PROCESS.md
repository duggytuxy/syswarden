# Explicit local authority process

Status: opt-in Linux v5 process implementation. Stable remains v4.10.4. Refs #224,
#225 and #337, all partial. Native packages neither install this executable nor
start a service. The existing v4 core and BunkerWeb integration do not call it.

## Startup contract

`cmd/syswarden-authority` is a separately buildable executable. A trusted launcher
must provision and validate the existing [launch record](AUTHORITY_LAUNCH.md),
[private layout](PROVISIONED_AUTHORITY.md), service identity and endpoint first.
The process accepts exactly `--launch-sha256` followed by one lowercase SHA-256.
There is no environment fallback, configuration discovery, executable path in the
record, test clock switch, automatic enrollment or default approval.

The launcher supplies these descriptors in the new process:

| Descriptor | Purpose | Required source |
| --- | --- | --- |
| 3 | Launch record | Independently pinned root-owned `0400`, read-only, single-link regular file without ACL. |
| 4 | State directory | Existing service-owned `0700` layout with the five fixed private children. |
| 5 | Endpoint directory | Existing separate service-owned `0750` directory with the reviewed client group. |
| 6 | Readiness | Write-only nonblocking pipe/FIFO delivered only to the service and its trusted supervisor. |

No pathname or identity lookup occurs in this executable. The numeric identity in
the record must match the effective process UID/GID. The launcher remains responsible
for trusted ancestry, mount/user namespace provenance, independently protected
digest delivery, account lifecycle, complete privilege drop and descriptor hygiene.
Do not retain root real/saved identities, capabilities or unrelated descriptors.
This code does not implement that privileged launcher or an installed sandbox.

The command uses the system clock and supplies no recovery or administrative
approval provider. Their independent authorization continues to deny those
operations. Signed ordinary operation grants still apply. A launcher or dashboard
must not turn this explicit absence into automatic approval. Missing authentication,
human MFA, durable decision/denial audit and recovery integration remain open work.

`RunAuthorityProcess` is the shared implementation used by the executable and the
non-root process fixture. It accepts explicit Go clock and approval providers for
trusted embedding. These are not selectable by a client request or CLI flag. The
caller retains all input descriptors; owned internal leases survive until drain.

## Readiness and exit

Readiness metadata is checked before protected startup and again before writing.
Only a write-only nonblocking pipe/FIFO is admitted. A raw descriptor-held write
emits exactly one ASCII `R`; no poller wait, flag mutation, unbounded buffering or
retry is allowed. A full or disconnected channel causes startup failure and exact
owned cleanup. No readiness byte is emitted after a failed startup. After receipt,
the supervisor must continue observing process exit; this is a startup snapshot,
not a health guarantee, operation grant or durable event. Cancellation can race
with notification, and a ready process may fail immediately afterwards.

SIGTERM or SIGINT cancels the process context. Cancellation stops new admission,
accepts and ordinary I/O, while approved durable operations retain their existing
non-cancellable semantics. Endpoint and pin evidence and locks remain held until
workers finish. The cancellation watcher is joined before final cleanup. Repeated
signals do not bypass drain. An external forced kill can leave stale or incomplete
evidence that requires separate verified recovery.

A fixed set of workers and one cancellation watcher bound concurrency. There is no
hard shutdown deadline: a blocked trusted provider or storage operation may delay
exit. Imposing a timeout and claiming complete cleanup would contradict the custody
contract. Future service-manager policy must distinguish clean drain from forced
termination and preserve the corresponding evidence.

The executable returns 0 only after clean drain and cleanup, 2 for invalid command
arguments and 1 for startup or shutdown failure. Error output contains a fixed
English diagnostic, without paths, roots, digests or operation details. Joined
shutdown errors remain failures even when accompanied by expected draining/busy
sentinels. There is no automatic retry, repair, stale takeover or uncertain reply.

```mermaid
flowchart TD
    L[Trusted external provisioning and privilege drop] --> F[Four inherited descriptors and pinned digest]
    F --> V[Readiness channel and protected launch validation]
    V --> S[Existing local authority and private leases]
    S --> R[One nonblocking readiness byte]
    S --> W[Fixed paced workers and signed peer grants]
    T[SIGTERM or SIGINT] --> C[Stop new admission and ordinary I/O]
    C --> D[Wait for approved operations and workers]
    W --> D
    D --> E[Exact endpoint and pin cleanup]
    E --> X[Exit status after joined shutdown]
```

## Verification and remaining deployment work

Unit tests cover exact command arguments, missing/closed/unsafe readiness handles,
full and disconnected pipes, startup failure without readiness, cancellation,
deadlines, readiness failure, concurrent cancellation, worker failure, retained
changed evidence and approved policy completion through drain. They preserve
unrelated journal state and reject lost shutdown errors.

The existing 132-case mandatory separate-UID campaign now uses the shared process
runner for actual non-root commit, restart, crash preservation and reviewed restart.
Its existing readiness and stop fixture supplies synthetic provisioning and clock;
it is not the standalone executable's installed systemd path. No child process,
assertion relaxation, skipped mandatory case or timeout extension is introduced.
Command parsing and builds are checked separately. Tests do not establish deployed
signal forwarding, native reboot, every supported MAC profile or human MFA.

Next work must integrate reviewed privileged provisioning, real process launch and
signal supervision, account and descriptor lifecycle, installed OS isolation and
independent approval/audit providers. Package activation requires its own tests and
native IVV. Keep BunkerWeb's authenticated API, source ownership, temporary-ban
lifetime, retry and HA independent of this optional local process and dashboard.
