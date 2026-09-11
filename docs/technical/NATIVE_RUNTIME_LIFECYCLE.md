# Native runtime lifecycle

SysWarden records verified native enforcement independently of the attack
journal. Standalone and legacy HA operation use a local durable history. HA v2
continues to use its replicated model, writer fence, and peer checkpoints.
Local history never supplies invented HA identities or peer acknowledgements.

## State and evidence

- `active`: the native entry is present with consistent lifetime metadata in
  every expected IPv4 or IPv6 enforcement layer.
- `deleted`: a requested native removal has been verified and durably recorded.
  The cause is `verified-deletion`; this does not identify which subsystem
  originally requested the removal.
- `expired`: the previously verified native expiry has elapsed and a fresh
  native read confirms absence. Early disappearance is an error.
- `tombstoned`: a separate native read confirms continued absence at least
  30 seconds after the recorded deletion or expiry. The original cause remains
  attached to the claim.

The history retains the latest generation for each exact address or prefix.
A subsequent verified ban advances that generation. Administrative claims do
not create attack events, physical hits, severity scores, or selected jails.
The retained attack journal remains the source of those measurements.

Snapshots contain at most 1,024 claims, with counters for the full inventory.
Truncation prevents a complete GRC declaration. The durable inventory is bounded
at 16,384 entries. Missing layers, inconsistent lifetimes, untracked native
entries, unexpected disappearance, or an unresolved transaction also prevent
complete native evidence. A missing entry alone is never a deletion receipt.

The TUI opens the current snapshot's runtime history with `h`. Its text output
includes the same validated history. Terminal claims stay out of the active
ban registry and remain visible in this separate history.

## Operator commands

`syswarden unblock <IP>` removes the persistent policy entry, preserves native
claims while applying the policy, and asks the core to perform the native
removal with its durable transaction. Global whitelisting uses the same native
control path. The core must be available before either operation starts.

If native reconciliation fails after the persistent policy commits, the CLI
reports that partial result. It does not roll the persistent files back behind
the already committed firewall policy. A retained independent HA ban can keep
the address blocked; the command reports this instead of claiming full removal.

`syswarden runtime-unblock <IP>` removes the local runtime claim only. Persistent
blocklists and independent source claims remain effective. Under HA v2 the
authenticated core requires the healthy static writer and uses its replicated
transaction. The legacy `unblock` route remains refused under HA v2.

The control endpoint is `/run/syswarden-control.sock`, a separate stream socket
with mode `0600`. Both peers verify Unix credentials. Requests and responses
are bounded and reject unknown fields, duplicate fields, and trailing messages.
The rsyslog datagram input at `/run/syswarden.sock` cannot submit these commands.
Package removal cleans up both exact owned sockets after stopping the core.

Standard DEB and RPM packages keep the generated core service byte-compatible
with v4.04.3. The package owns a separate systemd policy at
`/usr/lib/systemd/system/syswarden-core.service.d/10-syswarden-socket-ownership.conf`
that adds `CAP_CHOWN` for the private rsyslog socket. The CLI verifies its exact
content, metadata and stable package ownership before selecting that layout.
Native downgrade removes the policy with the newer package. Source installs
and the RHEL package-owned profile retain their existing self-contained units
with the same effective capabilities. Modified or unowned policies are refused.

For legacy HA, the CLI and core hold compatible read leases on the existing
writer fence during the coordinated unblock. Fence transitions require an
exclusive lease and cannot overtake either participant. The ordinary legacy
HTTP writer retains its existing exclusive serialization.

## Persistence and restart

The private directory `/var/lib/syswarden/runtime-lifecycle` contains the
canonical state, its identity and digest anchor, and any pending write-ahead
journal. The directory requires mode `0700`; records require owner-only regular
files with a single link. A process lease prevents concurrent store instances.
Publication synchronizes files and directories before retiring the journal.

Native mutation observations, journal preparation, verified enforcement, and
durable publication run under the shared host firewall lock. A completed
witnessed candidate can finish publication after an interrupted process. An
intent whose native result was never witnessed remains fenced and requires
explicit recovery; it is not promoted to a successful ban or deletion.

On a normal restart, still-live verified desired claims are restored before
workers start. Timed claims use the remaining lifetime rounded upward to the
native backend's whole-second precision. Expired claims require a fresh absence
read before their state advances. This conservative restoration can reapply a
retained claim that an older binary or an external tool removed without updating
the durable history.

An existing empty directory, a missing state or anchor, a digest disagreement,
an unsafe link, or an unexplained pending mutation is a recovery condition.
Stop competing writers, preserve the complete state and native evidence, and
restore the verified host recovery point when the result cannot be established.
Do not delete an anchor or journal to make startup appear successful. Normal
package purge removes the product's runtime history with its other retained
state; export needed evidence before purging.

Native release qualification must still prove the required real enforcement,
deletion, expiry, history, reboot, restoration, HA, and performance behavior on
the exact signed candidate. Unit fixtures and source replays are not native
qualification evidence.

Overlapping native IP/CIDR claims require an exact operation on the retained
active claim first. A point inside a retained prefix cannot be reported as
unblocked. CLI preflight refuses such a target before persistent policy changes.
Runtime enforcement projection includes active covering prefixes, even when a
previous point claim has a terminal history record.
