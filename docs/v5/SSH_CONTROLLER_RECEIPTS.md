# Signed SSH controller observations and protected appraisal

Status: private v5.00.0 component. Refs #235, #337 and #422.
No production CLI, installer or activation-completion path is enabled. Fixed-path
target enrollment and issuance are described in [the access exchange](SSH_ACCESS_ISSUANCE.md).

## Independent challenge and controller identity

The [protected request](SSH_PROTECTED_ACCESS_REQUEST.md) contains the exact
transaction, original plan, activation intent, current assessment and complete
public endpoint/key pins. A new challenge binds that request digest, an explicit
Ed25519 controller public-key digest, a random 32-byte nonce and a validity
window of one second through five minutes. Its canonical encoding is bounded
to 2 KiB. The original request remains private operational data.

The complete challenge requires independent approval. The expected challenge
and controller public key are supplied separately from the returned receipt.
A key embedded in received data cannot establish authority. Generating a nonce
or computing a digest does not enroll a controller or approve execution.
The [target enrollment reader](SSH_ACCESS_ISSUANCE.md) now supplies protected
plan-specific public keys and pins, with replacement, expiry and revocation
checks. Protected controller-side delivery and membership administration remain
open; the authorization guard must consult independently established authority.

Controller signing keys remain on the controller. An exact Ed25519 software
private key is copied and its seed/public halves must agree. Its owned encoded
copy is cleared on exit, without claiming complete Go runtime secret erasure.
The existing SSH authentication keys also remain controller-side.

## Execution and signed result

The controller validates the approved challenge, request and signing identity
before any connection. It then invokes the existing all-context fresh SSH
transport. The authorization guard and trusted local clock are checked around
that execution and after signing. Expiry is exclusive, and a clock moving
backward during a call is refused. Both elapsed-time ordering and wall-clock
ordering are checked, because receipt expiry is expressed as Unix time. A
monotonic reading cannot hide a wall-clock rollback. Cancellation, late
revocation, expiry or a failed final route returns no signed result. Cloned inputs cannot be changed by
later caller buffer mutations.

Only a successful batch produces a signed canonical payload. It binds the
challenge digest, start/completion seconds and every ordered route observation.
The signed JSON envelope is limited to 16 KiB. Signature verification uses only
the separately pinned controller key. Schema and purpose are fixed, and unknown,
duplicate, case-folded or noncanonical fields are refused.

The verifier reconstructs each transport binding from the exact approved request
and public key pins. All declared contexts must occur in protected order, every
challenge/session digest must be well formed and distinct, and a bastion session
is required only for a bastion route. Both batch and route observations must
retain recovery-required status. A valid signature cannot excuse an incomplete
batch, a different context, an expired window or an activation-complete claim.

The controller key remains a trust boundary: a signature authenticates its
statement, not the controller host or an independently attested execution.
Clocks must be trustworthy and sufficiently synchronized. The implementation
deliberately offers no clock-skew allowance that could extend expiry.

## Target-side protected appraisal

Before returning a useful summary, the target verifies the signature and window,
then regenerates the request from the original protected activation history.
The same journal lock, inode guards, explicit TOML selection, installed parser
checks and qualified endpoint observations apply. Exact byte equality with the
signed request is required. Policy, parser, record, endpoint or authority drift
returns an empty result. Expiry and authority are rechecked during the guarded
assessment, with protected file checks after the final authorization callback.
No private key is needed on the target and no network connection is opened there.

Success returns only digests, a context count and `RecoveryRequired`. It writes
no receipt, repairs no durability, consumes no replay token and changes no
activation or recovery fence. Repeated appraisal inside the validity window is
a read-only diagnostic. A receipt from a different challenge is refused, but
a separate [one-time evidence writer](SSH_ACCESS_EVIDENCE.md) can retain the
observation without granting activation acceptance.

The endpoint comparison describes current observations. It does not establish
continuous process identity throughout remote execution or prove that the daemon
consumed the intended policy. Even a signed fresh login and matching on-disk
configuration must not substitute for causal policy-consumption evidence.

## Validation and remaining integration

Adversarial tests cover wrong keys, malformed signatures and encodings, changed
request/challenge identities, reordered or partial context batches, session
reuse, exact expiry, clock rollback, late revocation/cancellation and mutable
caller buffers. Protected filesystem tests preserve records and configuration,
retain the journal lock and reject changed endpoints or policy. File-only
rollback remains refused after successful appraisal.

The explicitly enabled [OpenSSH runtime oracle](SSH_RUNTIME_ACCESS_ORACLE.md)
now signs and verifies observations after forwarding and CIS reloads on direct
and single-bastion routes. Controller keys and approvals in that fixture are
synthetic. Native oracle success is not independent production enrollment.

Protected controller-side delivery and enrollment, causal consumed-policy
acknowledgement, complete runtime recovery acceptance, owned updates
and separate native uninstall/remove/purge remain open. No migration-ready
package or final v5.00.0 IVVQ acceptance is claimed.

Issue #422 requires fresh native installation to select no list and defer
activation until explicit configuration through `syswarden config`, with
independent explicit TOML selection of SSH, CIS, OS hardening and optional modules.
The native hooks stage an unconfigured TOML profile; [native dependency transitions
and package qualification](MINIMAL_NATIVE_INSTALL.md) remain incomplete. Administrator
upgrade settings, BunkerWeb independence and Linux AMD64 scope are unchanged.
