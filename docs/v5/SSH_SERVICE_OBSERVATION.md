# Observe the SSH service manager

Status: internal read-only v5.00.0 development component. Refs #235, #337
and #422. This is a prerequisite for the dedicated SSH policy's activation
adapter, not completed migration support or a new operator command.

## Purpose

A verified configuration publication does not establish which daemon is
running or how it starts. The system manager may run `ssh.service` or
`sshd.service`, resolve one name as an alias, or activate a service through
a socket. Selecting the first installed unit would not establish this topology.

`ObserveSystemdRuntime` reads all four fixed service/socket names twice and
requires equivalent normalized observations. It never starts, stops, enables,
reloads or restarts a unit, reloads the manager, changes configuration, opens
a listener or authenticates an SSH connection. Existing installation and
hardening callers are unchanged by this component.

## Observation boundary

The root adapter pins the protected AMD64 `/usr/bin/systemctl` executable
by descriptor, identity and SHA-256. It refuses scripts, links, writable
executables and unsafe ancestors. Its environment is fixed, so caller-provided
bus addresses, pager commands, PATH entries and remote-manager hints cannot
choose its target. Only bounded `systemctl --system show` queries are allowed.

The adapter verifies the protected root-only `/run/systemd/private` socket
and its ancestors before and after each query, including a failed query.
The executable is rechecked at the same boundaries. It refuses unavailable
systemd state rather than guessing an offline or OpenRC configuration.
These boundaries resist ordinary-user substitution; they do not protect
against a compromised root account or a malicious system manager.

Each query has a five-second deadline and separate 64 KiB stdout/stderr limits;
the complete observation has a one-minute deadline. Unexpected stderr, missing
or duplicate properties, invalid framing, masked or failed units, pending jobs,
control processes, a required daemon reload and unsupported states are refused.
Raw output is not returned with errors.

Loaded aliases must independently resolve to one identical canonical service
and at most one identical canonical socket. Service process identifiers and
invocation identities must be internally consistent. An active service also
requires a bounded canonical cgroup path; inactive services must have none.
A non-instanced socket must target that service and have a reciprocal
relationship. Two distinct
services or sockets are ambiguous and refused.

An inactive vendor `Accept=yes` socket is recorded as instanced without making
it an activation target. An active instanced socket is unsupported and refused.
This preserves the distinction between a shipped inactive unit and the active
SSH access path. Unrecognized custom units and instance templates need a
separate adapter; their names are never guessed or executed.

## Result and limits

The summary contains executable and normalized-unit digests, fixed unit names,
observed active states and a mode: `absent`, `inactive`, `service` or `socket`.
`socket_instanced` explicitly identifies the inactive vendor case. The result
contains no unit text, drop-in paths, environment values or addresses.
There is no partial success result on refusal.

`manager_observed` describes two stable samples, not an atomic manager snapshot.
`process_verified`, `listeners_verified`, `runtime_activated` and
`access_verified` remain false. A reported PID or listening state does not prove
the executable/configuration consumed by that process, actual listening
addresses, namespace identity or a fresh administrator login. Unit fragment
and drop-in path strings are bound into the digest, not read or trusted as
file ownership evidence. Later activation must revalidate these observations
and independently verify the process, configuration and access path. The
separate [process observer](SSH_PROCESS_OBSERVATION.md) now binds a live process
and executable; loaded configuration, listeners and access remain unverified.

The [minimal native installation contract](https://github.com/duggytuxy/syswarden/issues/422)
is unchanged: fresh packages select the standard list only, and SSH/CIS/OS
hardening requires explicit independent TOML choices. This component neither
implements that package wiring nor turns an installed service into consent.
The [shared transaction](SSH_TRANSACTION.md), owned updates, activation,
public recovery and independent native removal paths still need integration.
BunkerWeb's API, source ownership, expiry and HA remain independent.

## Validation and primary references

Fixture tests cover aliases, service/socket combinations, inactive instanced
vendor sockets, malformed output, ambiguity, cancellation, changing samples,
unsafe executables/endpoints and output bounds through the actual copy path.
An opt-in installed-manager oracle executes only the fixed read-only queries.
When run without root it validates the real property format via the system
bus, not the root adapter's private-bus transport. Native root validation is
still required before acceptance under the v5.00.0 IVVQ contract.

The systemd references describe the
[`show` property interface](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)
and [socket activation and `Accept`](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html).
Their supported behaviors inform this deliberately bounded adapter; they do
not establish product support for every service-manager configuration.
