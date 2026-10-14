# Acquiring protected authority launch inputs

Status: inactive Linux v5 provisioning component. Refs #224, #225 and #337,
all partial. Stable remains v4.10.4. No installed service or package is changed.

## Independently trusted inputs

`OpenAuthorityLaunchInputs` receives an already open directory and two separately
approved lowercase SHA-256 digests. It acquires exactly `launch.json` and
`syswarden-authority`. There are no configurable filenames, directory scans,
trust discovery, download, account selection or automatic repair. Its caller
retains the directory and owns the two returned close-on-exec handles: the
immutable read-only launch snapshot and an immutable executable image. Any error returns
neither handle and closes every intermediate acquisition.

The directory must be root UID/GID 0, exactly 0700, have no POSIX access or default
ACL, and be held through a readable non-O_PATH descriptor. This is a deliberately
private staging layout, not a requirement to change a distribution's shared bin
directory. Its ancestry, initial descriptor delivery, mount namespace and digest
source remain trusted provisioning inputs. A root identity inside an untrusted
user namespace does not prove host-root origin. Root compromise is outside the
ordinary-user threat model.

Each fixed entry is checked as a regular file before opening and rechecked through
its acquired descriptor. Resolution uses `openat2` with beneath-directory,
no-symbolic-link, no-magic-link and no-mount-crossing restrictions. The read-only
open is nonblocking, close-on-exec and cannot acquire a controlling terminal.
Unsupported kernels, bind mounts, policy denials and uncertain resolution fail
without an openat fallback or retry. This follows the
[Linux openat2 resolution contract](https://man7.org/linux/man-pages/man2/openat2.2.html).
A pre-open check avoids opening known devices or FIFOs; the trusted directory
prevents ordinary-user substitution, not concurrent hostile root mutation.

## Validation and ownership

The launch record must satisfy the existing root-owned 0400, one-link, bounded
canonical [launch contract](AUTHORITY_LAUNCH.md). The executable must satisfy the
root-owned 0555, one-link, no-ACL/no-file-capability and executable-mount
[image contract](AUTHORITY_EXECUTABLE_IMAGE.md). The image is copied in bounded
positional chunks, hash-checked, sealed and authenticated again. Its actual native
[ELF layout](AUTHORITY_EXECUTABLE_FORMAT.md) must pass before either handle is
returned. Correct digests cannot turn a script into an admitted ELF image.

After image acquisition, the helper rechecks directory metadata and exact
name-to-inode bindings, then authenticates and freezes the exact launch bytes in a sealed anonymous file. These checks detect
observed incomplete or changed preparation. They do not establish an atomic
cross-file deployment transaction, freshness or rollback protection. The caller
must independently approve the pair of digests and serialize privileged updates.
No state/endpoint directory, readiness channel, credentials or running service is
created here. Existing resource and execution guards still apply at startup.

A later source replacement, edit or unlink cannot alter either snapshot. The
[launch snapshot contract](AUTHORITY_LAUNCH_SNAPSHOT.md) preserves the exact
approved bytes with immutable data and executable-mode seals. The original disk
handles close after acquisition. Actual launch and authority startup still repeat
the descriptor, ownership, mode, seals, digest and canonical-byte checks.
Successful acquisition is not permission to skip subsequent checks.

The returned layout may describe a dynamic image. This helper does not open or
approve its interpreter, shared libraries or loader configuration. Those require
a separate deployment policy. It also does not authenticate the launcher itself,
provide human MFA, install MAC/seccomp policy or supply service-manager supervision.

## Verification

The mandatory real-program campaign contains 212 cases. Twenty-six input cases
exercise held handles, malformed or missing records, metadata/ACL failures,
symlinks, hardlinks, FIFOs, wrong digests, malformed ELF and changed names.
The fixture prepares the real image and launch record with this API, replaces
both source names and unlinks the original launch inode, then uses the returned handles in the actual root launcher
and independent non-root bootstrap through lifecycle, commit, drain and crash
checks. Kernel client identities and existing admission checks remain unchanged.

The resolution unit checks exact kernel flags and refuses weaker fallback for
unsupported, denied or uncertain opens. Normal and race campaigns remain separate;
all 132 existing cross-UID cases remain required. This is component evidence,
not deployed distribution acceptance. Native mount/MAC policy, trusted initial
provisioning and installed lifecycle validation remain open.

BunkerWeb retains its independent authenticated API, source-owned temporary bans,
expiry, retries and HA. No dashboard, journal or identity-provider dependency is
added to that integration.
