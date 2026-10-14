# Standalone authority executable assurance

Status: mandatory Linux component evidence for the opt-in v5 executable. Stable
remains v4.10.4. Refs #224, #225 and #337, all partial. No native package, service
unit, deployment account or production integration is activated.

## Exact program under test

The dedicated CI step builds `cmd/syswarden-authority` and
`cmd/syswarden-authority-exec`, plus `cmd/syswarden-authority-launch`, from the checked-out source
with `CGO_ENABLED=0`. It passes all three absolute executable paths and their SHA-256 values to a
separately compiled journal test harness. The harness bounds its read to 64 MiB,
verifies the exact bytes and copies only those bytes into a root-controlled,
read-only executable fixture. The production [image primitive](AUTHORITY_EXECUTABLE_IMAGE.md)
then snapshots it into sealed anonymous storage. The original pathname is replaced
before launch; execution uses the fixed inherited `/proc/self/fd/7`, with no PATH
lookup. Reads and writes of the source fixture use opened directory roots. A
missing prerequisite fails the mandatory gate. This digest binds the build under test; it is not release signing
or an independent source attestation.

The service is the actual program, not a test function selected through an
internal environment flag. It receives only the four inherited descriptors from
the [process contract](AUTHORITY_PROCESS.md), its explicit launch digest, standard
I/O and the fixture's bounded Go worker setting. Policy validity is signed around
the current system time. The service has no test clock or approval bypass.

The normal lifecycle starts the actual [root-to-service launcher](AUTHORITY_CREDENTIAL_LAUNCH.md).
It receives unrelated inherited groups and an ambient/inheritable capability,
then performs the real credential transition. No fixture credential drop supplies
the normal service identity. A separate successful start/drain still exercises
the non-root bootstrap after the fixture selects its service credentials. Four
negative guard probes retain their test-only direct helper. All programs keep
the same PID through exec and expose no test mode.
Startup checks inspect each enumerated live thread through
procfs: all four UID/GID fields must identify the separate service account,
supplementary groups must contain only the fixture's client group, and effective,
permitted, inheritable and ambient capabilities must be zero. Each observed
thread must also have no_new_privs set and umask `0077`. A disappearing or
unreadable thread fails this assertion. This is an observed identity snapshot,
not enforcement against future changes or a complete OS sandbox policy.

## Required cases

The separate verifier requires all 258 named cases and the enclosing successful
suite. It rejects missing, duplicate, skipped, failed, truncated, oversized or
unexpected results. A successful executable exit alone is insufficient.

| Boundary | Required observation |
| --- | --- |
| Build identity | All three exact executable images verified, copied to kernel-sealed storage and used after replacement of the original pathname. |
| Image preparation | All 21 snapshot cases must pass: exact protected source, immutable output, original-file replacement and modification, rejected unsafe metadata, descriptors, types, size and digests. |
| Launch-input acquisition | The fixed protected pair is acquired through restricted resolution, covers 26 input cases, and drives the real lifecycle after source replacement. |
| Startup rejection | Missing descriptors, wrong digest, wrong service identity, swapped directory handles and a read-only readiness handle fail with exit 1, no readiness, one fixed diagnostic and unchanged protected stores. |
| Privilege rejection | A launcher without no_new_privs, retained real UID 0, an unexpected supplementary group and an inherited ambient capability each fail before readiness with unchanged stores. The fixture verifies that the negative no_new_privs, root-identity and ambient-capability conditions actually exist. |
| Bootstrap rejection | Wrong image digest, unsealed or missing image, and retained root identity fail without readiness or changed private stores. |
| Inheritance | The actual service has only the fixed environment and root cwd; neither image nor the unrelated canary descriptor survives. |
| Root launcher | Verified launcher bytes; wrong initial identity, digests and missing/unsealed image are rejected without readiness or changed private stores. |
| Non-root bootstrap | Independent successful start, identity check and clean SIGTERM drain remain required. |
| Live service | Exact readiness, observed kernel identities, no_new_privs, restrictive umask and zero active capabilities across enumerated threads; the root-launch path also requires an empty bounding set. |
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
    B[Build real authority executable] --> H[Verify and seal exact bytes in memory]
    H --> P[Drop service identity and pass image plus four startup handles]
    P --> N[Set no_new_privs on the exec thread]
    N --> E[Exec product and enforce startup privilege guard]
    E --> R[Readiness and kernel identity assertions]
    R --> C[Separate client resume and durable commit]
    C --> T[SIGTERM and exact cleanup]
    T --> I[Fresh process resume then SIGINT]
    I --> K[Fresh process then SIGKILL]
    K --> F[Retain evidence and refuse stale restart]
    F --> G[Require complete named evidence inventory]
```

## Explicit limits and next work

The surrounding provisioner is synthetic and privileged inside its test environment. Local
runs use a rootless mapped namespace; hosted CI uses a disposable runner. Neither
changes a real service account or deployed server. The fixture is not the product's
complete provisioner. The product supplies root-to-service and non-root exec
transitions, including an empty exec-thread capability bounding set on the root path.
Native namespace isolation, seccomp and SELinux/AppArmor policy remain separate work. Initial descriptor delivery and
parent-ancestry trust remain provisioning responsibilities. These controls require
implementation and matching acceptance evidence before deployment. The new
negative cases do not weaken or replace the existing identity, lifecycle or
independent-client checks. Saved-root identities are covered by the command
predicate tests: normal exec copies effective IDs to saved IDs, so retaining a
saved root ID across that exec would not be a valid integration fixture.

The direct signal cases establish program handling, not systemd/OpenRC signal
forwarding, native reboot or forced-power-loss semantics. In-flight approved-write
drain retains the separate deterministic tests of the shared runner; this campaign
does not inject a blocked storage write into the standalone program. Independent
human authentication, MFA, decision/denial audit, endpoint recovery approval and
key lifecycle remain open. No complete WP19 or v5 acceptance is claimed.

The [BunkerWeb contract](BUNKERWEB_COMPATIBILITY.md) remains independent of the
journal, dashboard and identity provider. Its source-owned bans, expiry, retries
and HA behavior are unchanged. Existing regression tests continue to apply.

The [sealed executable image](AUTHORITY_EXECUTABLE_IMAGE.md) now binds future launch
to an immutable copy of the approved bytes. The real-binary campaign executes that
image after replacing the source pathname. Native launch policy remains open.

The [bounded native ELF profile](AUTHORITY_EXECUTABLE_FORMAT.md) now checks the
actual authenticated image before either exec transition. Its 258-case mandatory
campaign includes correctly hashed malformed images, with no readiness or private
state changes after refusal. Loader and dependency trust remain separate from
format admission; no installed service or stable release behavior is changed.

The [bounded readiness monitor](AUTHORITY_READINESS_MONITOR.md) now supplies the
production supervisor-side pipe and one-shot receiver used by actual lifecycle
tests. Its 30-second ceiling, cancellation, malformed/closed/full channel refusal
and explicit ownership are verified normally and under race. It does not launch
or kill processes or establish ongoing health. Installed supervision remains open.

The [pinned child supervisor](AUTHORITY_CHILD_SUPERVISION.md) now composes protected
input handoff, atomic pidfd creation, readiness observation, SIGTERM and bounded
exit/reap observation. Cancellation retains the child; cleanup cannot claim a
successful exit or erase retained evidence. It remains inactive and leaves native
service-manager integration and full v5 acceptance open.

[Complete supervisor input acquisition](AUTHORITY_SUPERVISOR_BUNDLE.md) adds the
independently approved launcher to the four-resource launch bundle. The five held
resources remain valid after caller-parent closure and source replacement; late
or partial acquisition failure releases all acquired handles. Its 25 acquisition
cases and actual handoff are mandatory within the 258-case executable campaign,
normally and under race. The independent 132-case cross-UID gate remains required.
This inactive component neither provisions nor starts an installed service and
preserves BunkerWeb's independent API and HA behavior.
