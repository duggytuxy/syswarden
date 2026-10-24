# Durable boundary for an SSH activation attempt

Status: internal v5.00.0 component. Refs #235, #337 and #422.
A private systemd target adapter exists. No forward-activation CLI command or
installer call is enabled, and no complete activation or migration is accepted
by this component. Separately approved original-configuration restoration has
its own [operator boundary](SSH_OPERATOR_RECOVERY.md).

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

The private systemd binder retains the protected root, parser, systemctl and
busctl executable descriptors, endpoint identities, and original live process
lease. The existing read-only observers reuse the resource owner and still close
all resources before returning a summary. An observation summary cannot authorize
activation. Only a root-only binder selecting fixed live paths constructs the
systemd activation target; it does not accept a serialized target or caller PID.

That target qualifies the exact operation as a single `SIGHUP` sent through the
original pidfd. It rechecks the stable manager invocation, qualified typed startup
declaration, executable, process identity, namespaces, root and control group.
Activation and original restoration additionally require the daemon to share the
verifier's mount namespace. A stable private mount namespace may expose a
different configuration through `BindReadOnlyPaths` even when the root inode,
executable, endpoints and login behavior match. Such a service is refused before
an activation lease, durable dispatch intent or signal can be produced. Both the
target namespace and the verifier's held procfs namespace reference are rechecked
throughout the lease. This does not remove or weaken administrator unit hardening;
qualification of alternate daemon-visible graphs remains separate work. Read-only
process/listener observations may still describe those services without granting
activation authority.

Active socket configurations, unqualified startup options and changing state
remain refused. Its identity digest binds the operation and those observations.

The [Linux pidfd signal interface](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)
keeps an exited process's handle from addressing a recycled numeric PID. There
is no numeric-PID fallback, shell command, process-group signal, service-manager
mutation or automatic retry. A mutex serializes dispatch with closure so the
local pidfd cannot be closed and recycled during that request. The lease is
consumed even when dispatch fails. This protects the selected process identity;
it does not protect against hostile root or prove what OpenSSH subsequently read.

The intent binds the transaction, original approval, parser, preparation record,
complete published inventory, original record identities and target digest.
It contains no configuration contents, accounts, endpoints or authentication
material. Existing protected storage writes the intent without replacement and
synchronizes it before the request becomes eligible. Configuration, parser,
journal membership, original records and the new intent inode remain guarded.
The private adapter replaces the pre-intent policy guard with the request's
post-intent guard. Its retained runtime checks do not invoke the obsolete guard.
The original bounded lifetime and request cancellation both apply. Partial
acquisition releases resources; closure attempts every owned descriptor and
propagates errors. Native end-to-end activation still needs qualification.

## Listener replacement after the request

The private adapter now parses expected endpoints from the guarded current SSH
graph using the pinned installed parser. Before dispatch, it requires two stable
observations of all expected listening sockets in the held network namespace.
The target digest binds that baseline and the expected endpoints. A change
before dispatch refuses the request.

After the one signal, a bounded observer requires two consecutive identical
samples in which every expected listener has a new kernel socket cookie.
Descriptor numbers and inode numbers alone are not generation evidence.
Duplicate descriptors for one socket do not count as multiple listeners. A
cookie reused with conflicting metadata, an unexpected endpoint, a namespace
change or an unreadable observation is refused. The same retained process,
manager invocation, startup selection, executable and configuration guard apply
around the observations. There is no signal retry.

A stable empty interval and an otherwise valid sample still containing old
sockets remain pending. Neither establishes readiness. The observer waits at
most 15 seconds and 150 samples, with cancellation inherited from the original
request. Two new samples must be separated by a cancellable delay. Every
duplicated socket descriptor is closed inside its observation, before a delay,
manager query or signal; retaining it could prevent the daemon from rebinding.
The existing public read-only listener observer continues to refuse empty sets.

This detects an unchanged listener generation after a reported successful
signal. It is not an acknowledgement that OpenSSH consumed the entire intended
policy, and it does not prove authenticated access. The
[OpenSSH listener implementation](https://github.com/openssh/openssh-portable/blob/master/sshd.c)
closes listeners during its reload path, but a replacement observation alone
cannot establish why that change occurred. The durable activation intent and
recovery requirement remain in force even after this observation succeeds.

## Address-space retirement after the request

Listener replacement is now accompanied by a separate Linux address-space
observation. Before dispatch the adapter opens the fixed `mem` entry beneath
its retained process directory, read-only, with `openat2` restrictions against
symlinks, escapes and mount crossings. Unsupported lookup or access is a refusal;
there is no fallback or capability change. The descriptor must identify a
root-owned procfs regular file with the expected mode, link count and size.

One byte is requested only at address zero and immediately cleared. No memory
contents, configurable address, dump or process attachment is exposed. An initial
zero-byte `EIO` establishes a live referenced address space with an inaccessible
probe address. After listener replacement, that same descriptor must return EOF.
The still-held pidfd, executable, startup, manager and policy guards must continue
to pass. An exited process therefore cannot establish a successful reload.
A newly opened descriptor must again produce the initial result, and both
observations are checked before return and when releasing the activation lease.
Any failure retains the recovery requirement.

The [Linux procfs implementation](https://github.com/torvalds/linux/blob/v6.12/fs/proc/base.c)
retains the opened address space across an exec; it does not retarget that file
to the process's next address space. This supports retirement evidence on the
surviving, independently bound process. It is not an exact exec counter or proof
of the current address-space identity: another `CLONE_VM` user can keep a space
alive. Such sharing can delay retirement and cause refusal; a live replacement
handle alone does not exclude another exec with a surviving sharer. There is no
claim of protection against a hostile kernel, privileged writer or modified
cooperating daemon. OpenSSH's documented
[SIGHUP behavior](https://man.openbsd.org/sshd.8) and its qualified binary remain
part of the supported startup contract.

The byte count and operation sequence are bounded. Synchronous procfs open/read
calls can wait for kernel execution or mapping locks, so the surrounding context
deadline is not a hard preemption guarantee during a kernel stall. A cancelled
request is refused at the next check. No background goroutine abandons a live
memory handle, and no timeout success is synthesized.

This observation strengthens the runtime evidence without acknowledging every
policy directive or fresh administrator access. The durable activation fence
remains. Future consumption acceptance must also qualify the daemon build's
configuration semantics: a startup without explicit `-f` uses its compiled
configuration path, while the verifier selects `/etc/ssh/sshd_config` explicitly.
An executable hash establishes continuity, not that compiled default. A separate
qualification must bind that path and the supported OpenSSH parsing/reload
semantics. A concurrent legitimate reload can also overlap with this request;
any eventual consumption claim must describe the guarded interval, not exclusive
causation by this particular signal. Isolated tests exercise a real same-PID exec, no-op and early-exec
refusals, cancellation, guard/access failures, process exit and descriptor
closure. They do not qualify arbitrary shared-address-space daemons.

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
not implemented by this component. A separate read-only
[activation assessment](SSH_ACTIVATION_ASSESSMENT.md) now validates the complete
recorded intent and publication before observing current systemd endpoints. It
always retains the recovery requirement and does not dispatch or resolve the
attempt. Deleting the intent to bypass the fence is not a
supported recovery procedure. A separate
[runtime recovery coordinator](SSH_RUNTIME_RECOVERY.md) now performs explicitly
approved original-inode restoration and one restoring reload, including resume
before dispatch. It retains recovery-required status until the remaining runtime
and access acceptance is integrated. Administrator changes and all recovery evidence
must be preserved when state is ambiguous.

## Validation and remaining integration

Isolated filesystem tests verify ordering, journal locking, bounded context,
explicit consent, target and parser drift, uncertain directory synchronization,
late cancellation, request and close errors, byte-identical record replacement,
replay refusal and reopening. They verify that configuration files remain intact
and that publication recovery, rollback and retirement reject the activation
fence. Retained-resource tests cover partial acquisition, changed or prematurely
closed helpers, stale manager/startup/process state, cancellation, concurrent
requests and closure, and one-shot dispatch. A native syscall test sends SIGHUP
only to a disposable copy of the test binary and verifies refusal after its exit
and closure. It does not signal an installed SSH service. Higher-level dispatch
tests use controlled target callbacks. Listener replacement tests cover stale,
partial and changing generations, gaps, identity conflicts, endpoint drift,
observation failures, cancellation and the retained recovery fence. A native
TCP socket test closes and rebinds an isolated loopback listener and checks its
kernel cookie; it does not reload an installed daemon. These checks do not reload
a real SSH daemon or establish native migration acceptance.

Production activation, configuration consumption, independent fresh access,
already-owned updates and the three separate uninstall/remove/purge paths still
require integration and native evidence. A migration-ready package is not yet
available. These component checks are intermediate evidence for v5.00.0 IVVQ.

Issue422 still requires standard-list-only fresh APK/DEB/RPM installation,
independent explicit TOML choices for SSH/CIS/OS and optional modules, and
preservation of administrator settings and existing protection on upgrade.
This change does not wire those production defaults. BunkerWeb's independent
API, source ownership, expiry and HA remain unchanged. Linux AMD64 only.

## Disposable runtime evidence

The [native runtime and access oracle](SSH_RUNTIME_ACCESS_ORACLE.md) separately
checks real OpenSSH forwarding behavior and fresh direct/ProxyJump authentication
around fixture publication, reload and restoration. An existing authenticated
channel is retained as a negative control. This opt-in fixture does not invoke
the production binder or clear its durable recovery fence, and cannot establish
complete policy consumption, native migration or package readiness.
