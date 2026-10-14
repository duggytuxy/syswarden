# Bounded authority process resources

Status: inactive Linux v5 executable policy. Refs #224, #225 and #337, all partial.
Stable remains v4.10.4. No native service, package or embedding-library behavior changes.

## Explicit kernel ceilings

The root launcher, independent non-root bootstrap and direct authority command
share a startup guard. After verifying the approved service identity and disabling
dumpability, it constrains two process-wide resources before private storage opens:

| Resource | Soft limit | Hard limit | Purpose |
| --- | --- | --- | --- |
| `RLIMIT_CORE` | 0 bytes | 0 bytes | Disable ordinary core-file output alongside the existing non-dumpable policy. |
| `RLIMIT_NOFILE` | 256 | 256 | Bound new file-descriptor allocation in the dedicated authority process. |

The descriptor ceiling is a component budget for the existing fixed storage layout,
runtime handles and at most eight simultaneous transport peers. It is not a fleet
size limit and does not require additional machines or paid resources. Native IVV
must still validate distribution/runtime overhead and peak installed workloads.
Memory, CPU, task count and filesystem growth need their separate deployment limits;
this change does not claim to bound them through a file-descriptor ceiling.

Both current resource pairs are read before either is changed. An invalid pair,
read failure, or observed descriptor soft/hard budget below 256 causes refusal.
The guard never raises an observed limit or silently repairs insufficient
provisioning. It lowers each soft and hard value to the exact profile, then verifies
the kernel readback. Any set failure, mismatch or uncertain readback aborts startup.
A partial application is irreversible in this process; the command exits instead
of continuing, retrying or attempting restoration. No readiness byte is sent.

Linux resource limits are shared by threads and inherited across exec. The
[Linux resource-limit contract](https://man7.org/linux/man-pages/man2/getrlimit.2.html)
explains soft limits, hard ceilings and privileged changes. Lowering `RLIMIT_NOFILE`
does not close already open descriptors; the existing complete descriptor-table
isolation remains necessary. An ordinary service cannot raise its hard ceiling;
external privileged administration is outside that claim.

Go can raise an inherited descriptor soft limit toward its hard limit during runtime
startup. Both limits must therefore be bounded. The guard uses Go's `syscall.Setrlimit`
wrapper to clear its saved original-limit state before subsequent exec, as described
in the [Go resource-limit implementation](https://go.dev/src/syscall/rlimit.go).
The policy compares limits visible after runtime initialization; it cannot attest
an earlier pre-runtime soft limit. It runs again inside the actual service after exec.

A zero core-file ceiling is not a complete dump policy: Linux core handlers that
receive piped dumps have [separate semantics](https://man7.org/linux/man-pages/man5/core.5.html). The existing verified non-dumpable
setting remains mandatory, and native dump/MAC policy needs separate validation.
No host-global kernel or coredump configuration is changed.

## Verification and boundaries

Unit fault injection covers both initial reads, both writes and both readbacks,
including silent non-application, inconsistent results and kernel denials. Refusal
must stop immediately; no weaker limit, retry, restoration or fallback is permitted.
Already exact or larger budgets succeed; insufficient budgets trigger no writes.

The mandatory actual-program campaign now requires 258 cases. Three negative cases
start the real root launcher, non-root bootstrap and direct authority with a verified
128-descriptor hard ceiling. Each must refuse with no readiness or private-state
change. A live-process assertion reads exact soft/hard limits from procfs. Normal
startup, bootstrap startup and restart all enforce the same profile. Existing real
client operations, credential checks, clean drain and crash preservation remain
required normally and with the race detector. All 132 independent cross-UID cases
remain separately required. These tests change only disposable child processes.

The reusable journal library does not change its caller's resource limits. The
standalone guard is not a concurrent runtime monitor or complete sandbox. Trusted
provisioning, dynamic loader policy, native MAC/seccomp and cgroup budgets, installed
supervision, human MFA/audit and full v5 acceptance remain open. BunkerWeb keeps its
independent authenticated API, source-owned temporary bans, expiry, retries and HA,
without a dependency on this optional authority or the dashboard.
