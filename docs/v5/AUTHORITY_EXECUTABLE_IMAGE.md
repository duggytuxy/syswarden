# Sealed authority executable snapshot

Status: inactive Linux launcher primitive. Refs #224, #225 and #337, all partial.
Stable remains v4.10.4. No package, service, account or deployed server is changed.

## Byte identity through launch

Checking a pathname and executing it later leaves a replacement window. Holding
an open file removes pathname substitution, but its contents could still change.
`SnapshotAuthorityExecutable` instead produces an anonymous, sealed copy of one
independently approved executable. The future trusted launcher must execute this
held image rather than resolve the original pathname again.

The caller supplies an already-open source and an independently protected lowercase
SHA-256. The API discovers no path, downloads nothing and grants no authority. A
matching hash is not a release signature, independent approval, freshness policy or
proof of trusted provisioning. Root ownership inside a user namespace is not
host-root provenance. Initial path resolution, namespace ancestry, package signature
verification, expected digest delivery and deployment authorization remain external.

The source must be a root UID/GID 0 regular file, exactly `0555`, with one link,
no access/default ACL and no file capability attribute. Its descriptor must be
read-only, not `O_PATH`, and its size must be between 1 byte and 64 MiB. This exact
mode describes the provisioned image, not a new permission rule for stable packages.
The source mount must permit execution, with `fstatfs` checked before and after
copying; `noexec` or an inspection error is refused. This snapshot is not a later
policy-revocation monitor. The API reads positional chunks of at most 64 KiB and leaves the source offset
unchanged. It checks source identity, metadata and timestamps again after copying.
Short reads, short writes, changed metadata, digest mismatch and any I/O uncertainty
reject the candidate without returning a partial handle or changing source files.

## Immutable output and kernel policy

The anonymous image is created close-on-exec and supports sealing. After the source
stream matches the independent digest, the image receives mode `0555` and all four
seals: write, grow, shrink and seal-set changes. Their presence is read back from
the kernel. The resulting mode, length and close-on-exec flag are checked, then the
actual sealed output is hashed again before its descriptor is returned. Replacing
or modifying the original source afterwards cannot change these copied bytes.

The returned descriptor is technically opened read/write by `memfd_create`; kernel
seals prohibit writes, truncation, growth and shared writable mappings. The caller
owns and must close it. No named recovery file, executable cache or disk fallback
is created. Anonymous storage is bounded by 64 MiB per image, plus a fixed chunk
buffer. The caller must bound concurrent preparations and lifetime. This slice
does not claim to enforce a global memory quota across independent callers.

`MFD_EXEC` explicitly requests executable memory. Only `EINVAL`, indicating that
an older kernel does not recognize this flag for the fixed valid name and other
flags, permits one attempt using the legacy API. Permission or policy denials,
resource exhaustion and unavailable syscalls never cause that fallback. Failure
to obtain executable mode or the complete seal set remains failure. No sysctl,
SELinux/AppArmor policy, mount flag or administrator protection is changed.

These semantics follow the Linux documentation for [anonymous files](https://man7.org/linux/man-pages/man2/memfd_create.2.html),
[file seals](https://man7.org/linux/man-pages/man2/F_ADD_SEALS.2const.html) and
[executable-memory policy](https://docs.kernel.org/userspace-api/mfd_noexec.html).
Source mount flags follow the [Linux fstatfs contract](https://man7.org/linux/man-pages/man2/statfs.2.html).
The noexec/error decisions have unit coverage; full native mount-policy validation
remains required. Native validation must establish whether anonymous execution is permitted and
whether the required MAC execution transitions remain correct. No distribution
support or installed sandbox acceptance is inferred from local component tests.

## Actual executable evidence

The [mandatory executable campaign](AUTHORITY_EXECUTABLE_ASSURANCE.md) uses this
production primitive on the exact built binary. It replaces the original pathname
with unrelated bytes before launching any service. The real non-root
[exec bootstrap](AUTHORITY_EXEC_BOOTSTRAP.md) receives the sealed image as descriptor
7, authenticates its inherited metadata, complete seals and exact digest, isolates
the descriptor table and executes the fixed `/proc/self/fd/7`. The kernel resolves
the image before closing it. The product keeps its original four startup handles.
Four direct guard-negative cases retain a test-only helper. Trusted procfs and
provisioner ancestry remain assumptions, not a completed deployment policy.

All existing real-binary identity, readiness, operation, signal, crash and restart
checks still apply. Twenty-one added snapshot cases cover source replacement and
in-place edits, write/truncate/grow/shared-map/seal rejection, unsafe ownership,
permissions, links, ACLs, file capabilities, descriptors, types, size and hashes.
The separate verifier requires the wrapper and every named case, bringing the
image-stage campaign to 47 cases; the bootstrap and credential-launch follow-ups
brought it to 61. The bounded ELF follow-up brought it to 70, and protected
launch-input acquisition brought it to 98 and immutable launch configuration to
124. Protected runtime-directory acquisition raised this to 167; complete launch acquisition now requires 185 executable cases.
The existing 132-case cross-UID gate is unchanged. Missing
kernel or filesystem prerequisites fail the dedicated gate rather than skip it.
Unit tests also exercise bounded streaming failures and precise feature fallback.

## Remaining deployment work

This snapshot API does not spawn or supervise a process. The separate
[ELF inspector](AUTHORITY_EXECUTABLE_FORMAT.md) now checks native layout after
image authentication. Trusted dynamic-loader dependencies remain outside that
format check. The snapshot does not close unrelated descriptors, provision an
account, choose native MAC policy or authenticate a human. A trusted launcher must
combine its reviewed image with the [process startup contract](AUTHORITY_PROCESS.md),
protected configuration/state handles, privilege drop and complete signal/drain
supervision. Installed packaging and native IVV require separate reviewed work.

BunkerWeb keeps its independent authenticated API, source-owned temporary bans,
expiry, retries and HA. It acquires no dependency on this launcher, journal,
dashboard or new identity provider.
