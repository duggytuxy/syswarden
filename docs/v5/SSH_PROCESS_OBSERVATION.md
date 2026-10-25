# Observe the running SSH process

Status: internal read-only v5.00.0 development component. Refs #235, #337
and #422. This extends [service-manager observation](SSH_SERVICE_OBSERVATION.md)
without wiring activation into installation or adding an operator command.

## Identity before activation

`ObserveSystemdProcess` requires an active supported SSH service. It brackets
a process observation with two independently stable manager snapshots. The
snapshots must agree on aliases, service/socket state, invocation, main PID,
start observation and service cgroup. A socket waiting for its first connection
does not provide a running service process and is refused by this adapter.

The adapter holds a Linux pidfd and the numeric process directory on verified
procfs. It checks that procfs uses the caller's PID namespace. Process start
ticks, thread-group identity, all four UID fields, absence of a tracer and
exact membership in the manager's cgroup are checked. The process must remain
alive before and after bounded reads. Missing visibility or unsupported pidfd
access is an error, with no weaker fallback.

The kernel executable reference must have the exact inode, device, metadata
and SHA-256 of the independently pinned, protected installed AMD64 `sshd`.
A renamed or deleted older executable does not match its replacement merely
because both have the same name. The installed executable and systemctl are
rechecked around manager queries. No process name, command-line text, environment
variable or PID file supplies executable identity or configuration authority.

PID, user and network namespaces must match the observer. Target namespace
descriptors remain held throughout observation so their identities cannot be
recycled during that lease. A different stable mount namespace is recorded:
service hardening can legitimately create one. Its root must identify the same
filesystem root, but this does not establish that every submount exposes the
same configuration. The mount namespace and root must remain unchanged. The
separate [activation/restoration binder](SSH_ACTIVATION_BOUNDARY.md) therefore
requires the same mount namespace as its inventory/parser verifier and refuses
private views before dispatch. A successful read-only observation does not
satisfy that additional mutation boundary.

The process's system-manager cgroup must match exactly. Unified cgroup v2 and a
single v1 `name=systemd` hierarchy are recognized. Missing, duplicate, ambiguous
hybrid, changing or unexpected memberships are refused. The observer does not
move a process or alter any cgroup. Custom units and instanced active SSH
services still require separate adapters.

## Result and authority limits

The result exposes manager and identity digests and the narrow booleans
`process_observed` and `executable_verified`. Raw PIDs, start ticks, cgroup paths,
namespace identifiers and procfs contents are not exposed in the summary.
`configuration_verified`, `listeners_verified`, `runtime_activated` and
`access_verified` remain false. The embedded manager summary retains its own
original limits. Any failed read, drift or lease-close error returns no summary.

The separate [listener observer](SSH_LISTENER_OBSERVATION.md) adds kernel socket
observations within this process lifetime boundary. It retains the distinction
between observed listening sockets, approved configuration and verified access.

These observations are not an atomic kernel snapshot. They cannot detect every
transient change or a same-process re-exec of identical code between samples.
They do not attest shared libraries, loaded code, configuration consumption,
submount contents, active listening sockets or a fresh administrator login.
The digest is an observation, not reusable activation authorization. A later
activation adapter must re-establish its live evidence and independently prove
configuration and access outcomes. This protects the ordinary-user substitution
boundary; it is not a defense against a compromised kernel or root account.

No signal, reload, restart, namespace transition, configuration write or login
occurs. Only the fixed protected manager queries and bounded procfs reads are
used. procfs links are followed only for fixed kernel objects under the pinned
process directory, never for configuration-supplied paths.

## Installation and qualification

The [minimal native installation contract](https://github.com/duggytuxy/syswarden/issues/422)
requires fresh packages to select no list and defer activation until explicit
configuration through `syswarden config`, with independent explicit TOML choices
for SSH/CIS/OS hardening and optional modules and preservation of
administrator configuration and existing protection on upgrade. An installed
or running SSH service is not consent to apply a policy. BunkerWeb remains
independent, including source-owned temporary bans, expiry and HA.

Parser and coordinator fixtures test malformed identities, changing manager
and process state, lifecycle errors and absence of stronger proof. Native
process tests use only the test process and a short-lived test child. They
exercise pidfd lifetime and executable substitution without touching an SSH
service; environments without a non-root service cgroup are explicitly skipped.
Actual root SSH transport, namespace variants, configuration consumption,
activation and direct/ProxyJump/Ansible access remain native qualification work.
Independent uninstall, package remove and purge remain required. This component
does not establish a migration-ready package or final v5.00.0 IVVQ acceptance.

## Primary references

- [Linux procfs lifetime and process observations](https://www.kernel.org/doc/html/latest/filesystems/proc.html).
- [Linux pidfd process lifetime](https://man7.org/linux/man-pages/man2/pidfd_open.2.html).
- [Kernel executable reference](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html).
- [Process start ticks and state](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html).
