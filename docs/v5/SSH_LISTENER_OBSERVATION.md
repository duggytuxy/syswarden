# Observe SSH listening sockets

Status: internal v5.00.0 development component. Refs #235, #337 and #422.
This extends [process observation](SSH_PROCESS_OBSERVATION.md). It does not
activate a policy, change native installation or add an operator command.

## Bind sockets to the observed process

`ObserveSystemdListeners` retains the existing protected executable, manager,
process identity and namespace checks. It observes sockets twice between stable
manager snapshots. Each socket observation is itself bracketed by unchanged
process observations. Any drift, missing visibility or failed close prevents
a success summary.

The adapter enumerates the pinned process's descriptor directory on verified
procfs. It bounds the directory at 4,096 entries, socket descriptors at 256 and
each collection at five seconds. Only numeric descriptor names and canonical
kernel socket links are accepted. Non-socket links are never followed or opened.

For each socket entry, `pidfd_getfd` obtains a descriptor from the already pinned
process. The inode must match the enumerated kernel link. Socket type, family,
TCP protocol and listening state come from kernel queries. The local endpoint,
IPv6-only mode, interface binding, socket cookie and network-namespace cookie
are recorded. Inconsistent address-family metadata is refused. Unbound sockets,
datagrams, connected sockets and non-TCP protocols are not TCP listeners.

The complete socket descriptor map must remain stable before and after each
collection. Both collections must agree, including descriptor numbers, socket
identities and endpoints. Multiple descriptors for the same kernel socket count
as one listener; conflicting observations of that object are refused. A busy
daemon whose descriptors change may require a later fresh observation. The
adapter does not retry indefinitely or accept partial visibility.

The socket duplicate is closed immediately after its metadata is read, before
any manager query. No socket I/O is performed, no traffic is sent and no socket
flags are changed. The adapter never accepts connections, binds, listens,
shuts down a socket or signals SSH. Obtaining a duplicate can briefly retain
an existing socket if its original descriptor closes concurrently; it is not
held across the overall manager-observation interval.

## Results and limits

The summary exposes an identity digest, a count of distinct TCP listening
sockets and `tcp_listeners_observed`. Raw addresses, ports, descriptor numbers,
cookies, namespace identifiers and interface names stay out of the summary.
The embedded process summary retains its own narrower claims.

The observation establishes possession of the sampled descriptors, not sole
ownership or the process that created a socket. A socket inherited from systemd
can be observed when the active SSH process holds it. An inactive socket-only
service still has no supported running SSH process. A socket passed from a
different network namespace retains that socket's namespace cookie; the adapter
records this identity without claiming correspondence to the process namespace
or reachability from an administrator's network.

Repeated samples are not an atomic kernel snapshot and cannot detect every
transient change. They do not establish that the observed addresses match the
approved policy, that the daemon consumed a particular configuration, or that
a fresh SSH login works. Configuration, runtime activation and access flags
remain false. This digest must not authorize a later mutation without fresh
live evidence and the independent configuration/access checks.

`pidfd_getfd` requires the applicable ptrace access permission. An unavailable
syscall, denied permission, missing socket option or incomplete procfs view
causes refusal. The adapter never weakens ptrace, SELinux, capabilities or
container isolation to gain visibility. Native qualification must exercise
these boundaries for each claimed service and container profile.

## Installation and validation

Issue422 remains unchanged: fresh native packages use the standard list only;
SSH/CIS/OS hardening and optional modules require independent explicit TOML
choices. Upgrades preserve administrator settings and existing protection.
Neither an active process nor a listening socket supplies hardening consent.
BunkerWeb remains independent, including source-owned temporary bans, expiry
and HA. Linux AMD64 is the supported architecture.

Tests cover descriptor replacement, partial reads, cancellation, socket/process
drift, duplicate descriptor counting, metadata inconsistencies and absence of
stronger proof. Native oracles create and close their own ephemeral loopback
listeners and inspect their own process. They do not contact a real SSH service.
Missing IPv6 or kernel permission is explicitly skipped only in the relevant
native oracle; the production adapter still refuses unsupported visibility.

Configuration consumption, activation, independent access, production wiring,
minimal package defaults and the separate native uninstall/remove/purge paths
remain qualification gates. This component is not a migration-ready package
or final v5.00.0 IVVQ acceptance.

The separate [endpoint comparison](SSH_ENDPOINT_CORRESPONDENCE.md) binds
these private observations to the protected standard graph's expected addresses
and the process network namespace. It preserves the independent configuration
consumption and access gates.

## Primary references

- [Kernel descriptor duplication and permission checks](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html).
- [Process descriptor directory and socket inode links](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).
- [Socket metadata queries](https://man7.org/linux/man-pages/man7/socket.7.html).
