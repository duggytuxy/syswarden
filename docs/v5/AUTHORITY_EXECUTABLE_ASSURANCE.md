# Standalone authority executable assurance

Status: mandatory Linux component evidence for the opt-in v5 executable. Stable
remains v4.10.4. Refs #224, #225 and #337, all partial. No native package, service
unit, deployment account or production integration is activated.

## Exact program under test

The dedicated CI step builds `cmd/syswarden-authority` from the checked-out source
with `CGO_ENABLED=0`. It passes the absolute executable path and its SHA-256 to a
separately compiled journal test harness. The harness bounds its read to 64 MiB,
verifies the exact bytes and copies only those bytes into a root-controlled,
read-only executable fixture before launching it. Reads and writes use opened
directory roots; execution uses the fixed `./syswarden-authority` name from that
protected fixture directory, with no PATH lookup. A missing prerequisite fails the
mandatory gate. This digest binds the build under test; it is not release signing
or an independent source attestation.

The service is the actual program, not a test function selected through an
internal environment flag. It receives only the four inherited descriptors from
the [process contract](AUTHORITY_PROCESS.md), its explicit launch digest, standard
I/O and the fixture's bounded Go worker setting. Policy validity is signed around
the current system time. The service has no test clock or approval bypass.

The parent fixture drops real, effective and saved service identity through the
OS process-launch API. Startup checks inspect each enumerated live thread through
procfs: all four UID/GID fields must identify the separate service account,
supplementary groups must contain only the fixture's client group, and effective,
permitted, inheritable and ambient capabilities must be zero. A disappearing or
unreadable thread fails this assertion. This is an observed identity snapshot,
not enforcement against future changes or a complete OS sandbox policy.

## Required cases

The separate verifier requires all 21 named cases and the enclosing successful
suite. It rejects missing, duplicate, skipped, failed, truncated, oversized or
unexpected results. A successful executable exit alone is insufficient.

| Boundary | Required observation |
| --- | --- |
| Build identity | Explicit exact executable bytes verified and used. |
| Startup rejection | Missing descriptors, wrong digest, wrong service identity, swapped directory handles and a read-only readiness handle fail with exit 1, no readiness, one fixed diagnostic and unchanged protected stores. |
| Live service | Exact readiness, observed kernel identities and zero active capabilities across enumerated threads. |
| Authorized operation | A separate signed-grant client resumes and commits the actual durable state. The commit changes protected bytes; duplicate commit is denied without further mutation. |
| Client separation | Direct private-file access and signal-zero interference fail for the expected permission reason; ordinary operation grants do not grant policy administration. A reachable ungranted UID cannot resume. |
| SIGTERM | The actual program receives the signal, exits 0 after cleanup and closes readiness. Protected committed bytes remain unchanged. |
| Restart and SIGINT | A fresh executable resumes the exact committed anchor and exits 0 after SIGINT with no socket, receipt or pin left active. |
| SIGKILL | The process is confirmed killed by that exact signal. Socket identity, receipt, pin and private stores retain their exact bytes and metadata. |
| Stale restart | A fresh executable refuses retained crash evidence with exit 1 and no readiness. It does not silently repair, delete, retry or claim a trusted result. |

Test subprocesses have bounded readiness and exit waits. Cleanup targets only the
fixture's children and temporary resources. The new gate has its own unchanged
style of two-minute process budget. The existing 132-case cross-UID gate keeps
its inventory, assertions and two-minute limit. Local normal and race execution
are recorded independently; the hosted mandatory step builds the ordinary binary.
A normal component run skips this explicit privileged fixture, while the dedicated
job requires it and rejects any skip.

```mermaid
flowchart LR
    B[Build real authority executable] --> H[Verify exact bytes in test fixture]
    H --> P[Drop fixture service identity and pass four descriptors]
    P --> R[Readiness and kernel identity assertions]
    R --> C[Separate client resume and durable commit]
    C --> T[SIGTERM and exact cleanup]
    T --> I[Fresh process resume then SIGINT]
    I --> K[Fresh process then SIGKILL]
    K --> F[Retain evidence and refuse stale restart]
    F --> G[Require complete named evidence inventory]
```

## Explicit limits and next work

The test launcher is synthetic and privileged inside its test environment. Local
runs use a rootless mapped namespace; hosted CI uses a disposable runner. Neither
changes a real service account or deployed server. The fixture is not the product's
privileged launcher and does not supply `no_new_privs`, capability bounding,
namespace isolation, seccomp or a native SELinux/AppArmor policy. Descriptor and
parent-ancestry trust remain provisioning responsibilities. These controls require
implementation and matching acceptance evidence before deployment.

The direct signal cases establish program handling, not systemd/OpenRC signal
forwarding, native reboot or forced-power-loss semantics. In-flight approved-write
drain retains the separate deterministic tests of the shared runner; this campaign
does not inject a blocked storage write into the standalone program. Independent
human authentication, MFA, decision/denial audit, endpoint recovery approval and
key lifecycle remain open. No complete WP19 or v5 acceptance is claimed.

The [BunkerWeb contract](BUNKERWEB_COMPATIBILITY.md) remains independent of the
journal, dashboard and identity provider. Its source-owned bans, expiry, retries
and HA behavior are unchanged. Existing regression tests continue to apply.
