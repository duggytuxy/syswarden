# Protected SSH access request and controller execution

Status: private v5.00.0 integration component. Refs #235, #337 and #422.
No CLI command, installer call or activation-completion path is enabled.

## Separate target and controller inputs

The target-side request preparer reuses the locked
[activation assessment](SSH_ACTIVATION_ASSESSMENT.md). It requires the original
independently approved migration plan, exact protected publication history,
activation intent, explicit TOML selection, current installed-parser checks and
qualified endpoint observations. A private continuation runs before that lock
and its inode guards are released. Any final recheck error discards the request.

The caller supplies only explicit public host and client keys for every declared
access context, plus public bastion identities where required. No private
credential is accepted by target-side preparation. Missing, extra, duplicated,
unknown or unsupported routes are refused. Input ordering cannot change the
protected context order. Target addresses and users must match the protected
plan. Keys and endpoints are copied, bounded and validated; certificates and
unsupported algorithms are refused consistently with the transport.

The result is a canonical versioned request binding the transaction, approved
plan, activation intent, historical retained target, current assessment digest,
every access context and all endpoint/key pins. Its maximum size is 256 KiB and
it contains at most 16 routes. **The request contains account names, addresses
and public keys. It is private operational data, not a public summary.** No
request file, record, receipt or durability repair is written automatically.

A controller receives those bytes separately and requires an independently
approved digest of the complete request. Approval of the migration plan alone
does not approve added host keys, credentials or controller execution. Computing
a hash from an untrusted request is not an approval procedure. Protected delivery,
controller enrollment and the operator approval interface remain to be wired.

## All-context controller preflight

The controller-side function accepts the exact request, its independent approval,
explicit private credentials indexed by context and a promptly returning trusted
authorization guard. It does not open the target journal or require private keys
to be copied onto the target host.

Before any connection, it verifies canonical encoding, schema, domain, every
digest, complete unique context coverage, route compatibility, pinned identities
and every private credential's correspondence to its declared public key. A bad
credential in the final route prevents connections on earlier routes. Empty,
extra or misplaced bastion credentials are refused. No ambient configuration,
agent, password prompt, route discovery or fallback identity is used.

Private encoded credentials are copied and the owned copies are cleared on every
exit, including partial preflight failures. This does not promise complete Go
runtime secret zeroization or alter caller-owned credential buffers.

The controller invokes the [fresh SSH transport](SSH_FRESH_ACCESS_PROBE.md) in
protected context order. Each challenge binds the complete approved request
in addition to the original transaction, plan, activation intent, target and
context. Every route requires new authenticated sessions. The batch inherits any
earlier caller deadline and has a two-minute ceiling; each transport retains its
15-second limit. Controller authorization is rechecked around operations and
at the final return. An error or cancellation returns no partial observations,
even if an earlier connection succeeded. Already executed network requests are
not undone by withholding a partial result.

## Meaning and limits of successful observations

Success returns the request digest and hash-only transport observations for all
requested contexts. Recovery remains required. The function does not persist a
receipt, consume a one-time grant, change the activation journal or authorize
another signal, rollback or retirement. Repeated diagnostics may establish new
sessions; their results are not reusable activation authorization.

The request describes the state observed during preparation. It does not prove
that target state remained unchanged during later controller execution, that
the controller is independently enrolled, or that the daemon consumed the
intended policy. The historical target digest is not a claim of current process
continuity. Acceptance of future durable receipts must independently validate
current target state, causality, controller authority and replay/expiry rules.
Server-reported connection tuples retain the transport's documented limitations.

## Verification and remaining work

Tests join protected fixture publication and activation history to actual SSH
protocol handshakes on direct and single-bastion routes. They verify no private
key in preparation, no network during preparation, journal-lock retention,
unchanged records/configuration and continued refusal of file-only rollback.
State drift, record replacement, disabled selection, missing context coverage,
malformed encoding, wrong approval, wrong final credentials, late controller
revocation and later-route network failure return no usable partial result.
Caller buffer mutation cannot alter the frozen approved execution.

The explicitly enabled [OpenSSH runtime oracle](SSH_RUNTIME_ACCESS_ORACLE.md)
executes approved request batches after candidate reloads for both forwarding
and CIS policies. Its bindings and approval are synthetic fixture inputs; this
is not independent host enrollment or native production migration acceptance.

Protected controller delivery/enrollment, causal consumed-policy acknowledgement,
durable receipt acceptance, runtime recovery, owned updates and separately
validated native uninstall, remove and purge remain open. There is no
migration-ready package or final v5.00.0 IVVQ acceptance.

Issue #422 is unchanged: fresh native installation must select the standard list
only, with independent explicit TOML choices for SSH, CIS, OS hardening and
optional modules. The source installer now uses that profile and preserves host
hardening; [native dependency transitions and package qualification](MINIMAL_NATIVE_INSTALL.md)
remain incomplete. Administrator
upgrade settings, BunkerWeb independence and Linux AMD64 scope are preserved.

## Signed controller continuation

The [controller receipt component](SSH_CONTROLLER_RECEIPTS.md) adds a separately
approved expiring challenge, an explicit controller signing key and strict
verification of complete signed observations. Target-side read-only appraisal
regenerates this request under the same protected assessment guards. Receipt
persistence, enrollment, single-use acceptance and causal policy-consumption
proof remain separate gates; successful appraisal retains recovery required.
