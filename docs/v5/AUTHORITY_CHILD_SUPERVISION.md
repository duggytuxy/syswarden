# Pinned authority child creation and supervision

Status: inactive Linux v5 library component. Refs #224, #225 and #337 remain
open. No installed service, native package or current v4 integration calls this API.

## Trusted inputs and process creation

`StartAuthorityChild` consumes a borrowed `AuthorityLaunchBundle`, a separately
approved sealed launcher image and three independently approved SHA-256 digests.
The [complete supervisor acquisition API](AUTHORITY_SUPERVISOR_BUNDLE.md) can
supply the bundle and launcher together. The caller also holds a read/write Linux null-device descriptor for standard input,
output and error. It must serialize handoff against input modification or closure.
The API discovers no trusted path, account, dependency, signer or human approval.

All real, effective and saved user/group identities must be root. Six close-on-exec
duplicates hold the inputs while the implementation verifies the sealed anonymous
launch record, both native ELF images, the distinct protected runtime directories
and the null device. The original input handles remain the caller's property.

Creation uses the held launcher at fixed `/proc/self/fd/8`, a fixed argument layout,
a new session, working directory `/`, only `GOMAXPROCS=2` in the environment,
null standard streams,
launch/state/endpoint/readiness/authority/launcher at descriptors 3 through 8, and
empty supplementary groups. A trusted procfs and kernel remain prerequisites.
The launcher performs the existing credential, capability and resource-limit
transition. This parent API does not apply those changes to its own process.

Go's Linux process creation requests `CLONE_PIDFD` atomically. The supervisor keeps
that kernel process handle, so signaling never resolves a potentially reused numeric
PID. There is no shell, alternate launcher, inherited environment or automatic retry.
A creation failure releases temporary resources. If a post-creation operation fails,
the API returns both the child and an error: the caller MUST retain any non-null child,
observe its exit and record the uncertainty. Never discard it because an error exists.

## Separate readiness, exit and cleanup verdicts

1. `AwaitReady` uses the bounded, single-use readiness receiver. Success is one
   startup observation, not continuing health or proof that the process is still
   running after the call. The caller must also observe exit.
2. `RequestStop` sends only SIGTERM through the retained pidfd. It does not wait,
   force termination, prove drain, or authorize endpoint recovery.
3. `Wait` polls one pidfd without blocking, paced at 25 milliseconds and capped at
   30 seconds per call. After kernel exit it reaps the directly created child and
   retains the exit status. Nonzero and signaled exits remain failures on later
   calls. Only one waiter is admitted; signal requests can run concurrently.
4. Cancellation or timeout stops observation, not the child. The caller retains
   ownership and can wait again. There is no background reaper, process abandonment,
   force-kill escalation or alternate numeric-PID path.
5. `Close` refuses running or unreaped children and concurrent readiness/wait calls.
   After reaping, it releases owned handles, including after a failed child exit.
   Handle release is not proof of successful service drain or private-state cleanup.

The supervisor must remain the sole reaper and retain the object until exit is
observed. It must not modify its private handles or copy the object. A parent crash,
competing reaper, missing kernel support or uncertain exit is an explicit failure,
not permission to repair retained state. Service-manager/cgroup policy, supervisor
shutdown policy and endpoint recovery authorization remain separate work.

## Verification and remaining scope

The mandatory actual-program campaign requires 258 cases, normally and with race
instrumentation. New cases cover invalid input admission, repeated failed creation
without descriptor leaks, retained ownership after a post-creation failure,
actual launch/readiness/client access/SIGTERM/reap,
independent input closure after handoff, concurrent wait and stop, and missing
private state with unsuccessful startup. They compare private-store inventories,
parent credentials, resource limits and borrowed descriptor flags. Unit checks
exercise bounded poll failures and actual nonzero child exit accounting. The
independent 132-case cross-UID campaign remains mandatory.

Synthetic provisioning and local user namespaces do not establish installed OS
acceptance. Dynamic-loader dependency trust, account and key provisioning, MAC and
seccomp policy, service-manager lifecycle, human MFA/audit, native IVV and full v5
Upgrade IVVQ remain open. BunkerWeb's independent API, source-owned temporary bans,
expiry, retries and HA contract acquire no dependency on this component or dashboard.

## References

- [Go process creation API](https://pkg.go.dev/os#StartProcess).
- [Linux pidfd lifetime and polling](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
- [Linux pidfd signaling](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
- [Bounded readiness monitor](AUTHORITY_READINESS_MONITOR.md).
- [Protected complete launch inputs](AUTHORITY_LAUNCH_BUNDLE.md).
