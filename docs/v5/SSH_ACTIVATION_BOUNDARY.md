# Durable boundary for an SSH activation attempt

Status: internal v5.00.0 component. Refs #235, #337 and #422.
No production activation adapter, CLI command or installer call is enabled.

## Why publication recovery needs a separate boundary

Restoring configuration files does not restore the configuration held by a
running SSH daemon. OpenSSH documents its configuration reread on `SIGHUP`,
while systemd warns that sending a reload signal alone is asynchronous. See
the [OpenSSH daemon manual](https://man.openbsd.org/sshd.8) and
[systemd service documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html). A reload request can have reached that daemon even if its
caller subsequently times out, loses the response or crashes. Retrying a request
or declaring recovery successful solely because files were restored would hide
that uncertainty.

The internal dispatcher therefore records an immutable `activation-intent.json`
inside the existing protected journal before invoking its private request lease.
The journal lock remains held from publication verification through dispatch and
lease closure. A repeated attempt, including one after reopening the journal,
is refused. No result from this component claims policy consumption, operational
recovery or a newly authenticated connection.

## Ordering and ownership

The dispatcher first reconstructs the original independently approved plan and
verifies the exact publication history, recovery inode, installed parser and
explicit TOML selection. Parser checks cover the original, intermediate and
final graphs and all declared access contexts. The runtime binder is reached
only after these checks. It receives the original bounded context and a fresh
configuration guard, not a serialized authority.

A future production binder must retain the verified manager/process resources,
qualify the exact operation, and recheck its target immediately before dispatch.
Its identity is a digest of that bound target. This component supplies only the
private lease interface and fixture implementations for testing. It does not
supply a signal sender or service-manager mutation command.

The intent binds the transaction, original approval, parser, preparation record,
complete published inventory, original record identities and target digest.
It contains no configuration contents, accounts, endpoints or authentication
material. Existing protected storage writes the intent without replacement and
synchronizes it before the request becomes eligible. Configuration, parser,
journal membership, original records and the new intent inode remain guarded.
The request must honor that guard and the shared deadline. Production binding
and deadline enforcement still need qualification when their adapter is added.

An error during persistence prevents dispatch. From the write attempt onward,
the result requires recovery because a failed write may still have left visible
intent. Failure, cancellation, target drift and record replacement after
persistence also prevent dispatch. A request error retains uncertainty because
it may occur after the action was sent. Even a successful request return retains
the fence. No completion marker, retry or automatic evidence deletion is added.

## Recovery boundary

Any activation intent, including malformed, unreadable or unexpected filesystem
objects at that name, prevents the existing file-only recovery path from claiming
success. Rollback checks the fence at entry and around subsequent mutations.
Restored-history retirement explicitly excludes activation records. Existing
read-only owned verification still requires its exact publication-only history;
adding an activation record does not silently broaden that proof.

A newly opened, runtime-aware recovery path must eventually establish the actual
service state, safely select the approved policy, perform bounded activation and
verify independent authenticated access before accepting recovery. That path is
not implemented by this component. Deleting the intent to bypass it is not a
supported recovery procedure. Administrator changes and all recovery evidence
must be preserved when state is ambiguous.

## Validation and remaining integration

Isolated filesystem tests verify ordering, journal locking, bounded context,
explicit consent, target and parser drift, uncertain directory synchronization,
late cancellation, request and close errors, byte-identical record replacement,
replay refusal and reopening. They verify that configuration files remain intact
and that publication recovery, rollback and retirement reject the activation
fence. Request leases are test doubles; these checks do not reload a real SSH
daemon or establish native migration acceptance.

Production activation, configuration consumption, independent fresh access,
already-owned updates and the three separate uninstall/remove/purge paths still
require integration and native evidence. A migration-ready package is not yet
available. These component checks are intermediate evidence for v5.00.0 IVVQ.

Issue422 still requires standard-list-only fresh APK/DEB/RPM installation,
independent explicit TOML choices for SSH/CIS/OS and optional modules, and
preservation of administrator settings and existing protection on upgrade.
This change does not wire those production defaults. BunkerWeb's independent
API, source ownership, expiry and HA remain unchanged. Linux AMD64 only.
