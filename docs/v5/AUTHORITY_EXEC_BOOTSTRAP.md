# Non-root authority exec bootstrap

Status: inactive Linux v5 command. Refs #224, #225 and #337, all partial.
Stable remains v4.10.4. No package installs this command or enables a service.

## Purpose and exact inputs

`cmd/syswarden-authority-exec` replaces itself with an independently approved,
sealed authority image. It does not fork, supervise, select accounts, acquire
privileges or discover files. A trusted external provisioner must first verify
both programs, prepare the protected layout and launch record, drop credentials
and deliver the following inherited descriptors. It must protect its own ancestry,
namespace, bootstrap environment, stdio and digest delivery. Root inside a user
namespace is not host-root provenance. Neither digest constitutes release signature
verification, deployment approval, freshness or rollback protection.

| Descriptor | Input |
| --- | --- |
| 3 | Root-owned read-only launch record with its independently pinned digest. |
| 4 | Protected state directory. |
| 5 | Protected endpoint directory. |
| 6 | Nonblocking write-only readiness pipe. |
| 7 | Root-owned anonymous executable image with all four immutable-image seals. |

The command accepts exactly `--launch-sha256 <digest> --image-sha256 <digest>`,
in that order, with two lowercase 64-character SHA-256 values. There is no path,
shell, environment override, repair, clock or authentication-provider option.
Invalid arguments exit 2. Startup failure exits 1 with the same fixed private-safe
diagnostic as the authority. Readiness is written only by the actual authority
after its complete protected startup. A successful exec retains the PID.

## Transition into the actual service

The bootstrap locks its goroutine to the exec thread and loads the bounded,
protected launch record. `VerifyAuthorityExecutableImage` requires an anonymous
regular file owned by root UID/GID 0, mode 0555, no links, positive size no greater
than 64 MiB, all write/grow/shrink/seal-change seals, and the exact independently
approved digest. It hashes positional bounded chunks without changing offsets.
An ordinary named executable, missing image, unsealed handle or hash mismatch
fails before private state is opened. The supervisor prepares the image with
[SnapshotAuthorityExecutable](AUTHORITY_EXECUTABLE_IMAGE.md).

Before exec, the bootstrap sets no_new_privs on the locked thread and uses the
same startup guard as the actual authority: exact non-root real/effective/saved
UID/GID, only the expected endpoint group, no effective/permitted/inheritable
capabilities, and observed no_new_privs. Linux's capability subset rule excludes
ambient capabilities. It disables dumpability with readback, seals the four
startup handles, sets umask 0077 and changes the working directory to `/`.
It never repairs a wrong identity or drops root opportunistically.

A single `close_range` with `CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC` isolates
the calling thread's descriptor table and marks everything from descriptor 3
through the full 32-bit descriptor range close-on-exec. Only 3 through 6 are then
made inheritable, with flag readback; descriptor 7 must remain close-on-exec.
No live Go runtime descriptor is closed before exec. Unsupported kernels, policy
denials or flag errors terminate startup, without a guessed ceiling or racy
procfs-enumeration fallback. The isolated thread is never returned to the runtime
pool: errors require immediate process exit.

The kernel executes the fixed `/proc/self/fd/7` with the authority's exact launch
arguments and only `GOMAXPROCS=2` in its environment. The image and all unrelated
descriptors close during exec. Other bootstrap threads disappear, and all new
service threads inherit no_new_privs. The actual authority repeats its own
startup checks. Its existing readiness, durable operations, drain and crash
retention behavior remain unchanged. Stdio is deliberately retained from trusted
provisioning; this is not permission to pass arbitrary privileged standard streams.

These choices follow Linux's [descriptor isolation contract](https://man7.org/linux/man-pages/man2/close_range.2.html),
[no_new_privs inheritance](https://docs.kernel.org/userspace-api/no_new_privs.html)
and [exec semantics](https://man7.org/linux/man-pages/man2/execve.2.html).
The inherited bootstrap environment must itself be trusted: sanitizing the target
environment cannot undo a malicious dynamic loader configuration used to start
the bootstrap. Trusted procfs and executable/loader policy remain prerequisites.

## Evidence and remaining deployment work

The mandatory [actual executable campaign](AUTHORITY_EXECUTABLE_ASSURANCE.md)
builds and verifies both programs, seals them and replaces both original paths.
Ordinary lifecycle cases execute the product bootstrap after the fixture drops
credentials. Four negative controls retain a test-only direct launcher to prove
the authority independently rejects missing no_new_privs, retained root identity,
unexpected groups and ambient capability. Neither product has a test mode.

Six added required cases verify the bootstrap bytes, wrong/missing/unsealed image
rejection, root-bootstrap rejection and actual post-exec inheritance. The latter
reads the live process environment and cwd and checks that neither executable
image nor an unrelated canary descriptor survived. Existing checks still inspect
all enumerated service threads, perform authorized commits, reject strangers,
and verify SIGTERM/SIGINT drain, SIGKILL retention and stale restart denial.
All 70 executable cases are mandatory; the 132-case cross-UID gate is unchanged.
Fault-injection units reject every descriptor-isolation/flag failure and prohibit
partial continuation. Normal and race evidence are recorded separately.

The fixture remains the privileged provisioner. The new command implements only
the non-root transition. Production provisioning, trusted ELF/loader policy,
capability bounding, seccomp, native SELinux/AppArmor/IMA execution acceptance,
service-manager supervision, native reboot and installation still require review.
no_new_privs can affect MAC transitions; no policy is weakened to force success.
The sealed bytes may be a dynamically linked image: this command does not attest
its loader or libraries. Human MFA, durable approval/denial audit and key lifecycle
also remain open. No complete v5 or supported-distribution acceptance is claimed.

BunkerWeb preserves its independent authenticated API, source-owned temporary
bans, expiry, retries and HA without depending on this bootstrap, journal,
dashboard or new identity provider.

The separate [root-to-service launcher](AUTHORITY_CREDENTIAL_LAUNCH.md) now shares
this exec path after an explicit credential drop. It adds no root-drop flag to
the non-root command. The mandatory campaign retains a successful non-root start
and drain independently of the root launcher's lifecycle.

The [bounded native ELF profile](AUTHORITY_EXECUTABLE_FORMAT.md) now checks the
actual authenticated image before either exec transition. Its 70-case mandatory
campaign includes correctly hashed malformed images, with no readiness or private
state changes after refusal. Loader and dependency trust remain separate from
format admission; no installed service or stable release behavior is changed.
