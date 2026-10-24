# Read-only observation of retained SSH access evidence

Status: private v5.00.0 component. Refs #235, #337 and #422.
No production command or installer path is enabled by this observer. The
separate [target enrollment and issuance adapters](SSH_ACCESS_ISSUANCE.md) remain
subject to independent approvals.

## Independent authority and bounded history

The [one-time evidence writer](SSH_ACCESS_EVIDENCE.md) retains a complete private
request, challenge and signed controller receipt. A separate observer can inspect
that occupied history without clearing it. The original approved migration plan,
exact evidence digest, approved challenge digest and controller public key must
be supplied independently. The record cannot supply its own approval or trust.
Current controller authorization is checked throughout observation.

The record is limited to 512 KiB, including its encoded request and receipt.
The existing independent inner limits still apply. Canonical encoding, fixed
schema/purpose, complete identities and recovery-required status are mandatory.
Unknown, duplicate, case-folded and omitted fields, invalid signatures, changed
controller pins and inconsistent request/record identities are refused.

Historical verification uses the record's appraisal time, which must be inside
the signed challenge window, after receipt completion and no later than the
observer's current time. Expired evidence can remain inspectable. This proves
signature consistency at the recorded time, not that an observer witnessed that
past event or that its disk write was acknowledged. The clock and independently
authorized controller remain trust boundaries; backward movement during a call
is refused.

## Separate historical and current observations

Under the original journal lock, the observer accepts exactly the complete
publication history, activation intent and one pinned evidence image. Issued
evidence also requires the exact referenced issuance image, without treating
its historical presence as current authority. Original
record identities, the plan, parser, current configuration and independent TOML
selection are checked again. Retained routes must match every original protected
access context in order. A valid controller signature cannot replace that plan.
Evidence or original-record substitution during observation is refused, including
a replacement carrying identical bytes. The retained record also binds the
original publication-record fingerprints; this is not protection against a
privileged rollback of the complete storage state.

The observer obtains fresh local manager/process/listener correspondence and
regenerates the current request using independently supplied public key pins.
It reports whether these complete bytes match the retained request. A different
current endpoint or pin can yield a valid historical signature with
`CurrentRequestMatches=false`. Unsafe policy, parser or original-history changes
return no observation. This is a constrained observer of a still-qualified
configuration, not a general forensic reader for arbitrary changed systems.

The hash-only result separates `HistoricalSignatureVerified`,
`CurrentRequestMatches` and `WindowOpen`. The validity-window flag is sampled
after the final guard. Expiry during observation can change that flag to false
without invalidating the historical signature. Late revocation, cancellation,
clock rollback or protected-file drift returns an empty result. Caller-owned
public key buffers and route pins are frozen before any authorization callback.

## Uncertainty and unchanged recovery fences

`DurabilityUnknown` and `RecoveryRequired` are always true on success. Even a
complete visible record cannot reconstruct the original writer's acknowledgement
or establish that the daemon consumed a policy. No fresh network authentication,
SSH reload, file write, synchronization, repair or retirement occurs. A record
left by failed directory synchronization can be inspected under independent
approval without silently repairing that failure.

Ordinary request preparation, fresh receipt appraisal and the one-time writer
retain their original closed history. Inspection does not reopen those paths,
allow a second receipt or permit file-only rollback. No observed summary can
serve as authority for a later mutation. Original evidence is retained unchanged.
The controller's signature does not independently attest its host or physical
execution, and this observer cannot establish continued access availability.

## Verification and remaining work

Synthetic direct/bastion protocol fixtures cover current, expired and uncertain
records, changed current endpoints/pins, malformed encodings, independently
reviewed but inconsistent history, foreign signed contexts, final callback
revocation/cancellation/expiry, clock rollback and mutable caller buffers.
Tests assert unchanged record/configuration bytes, original lock retention,
no new network connections, no sync repair and continued replay/recovery fences.
A bounded fuzzer includes a valid signed canonical seed and invalid inputs.
The explicitly enabled native OpenSSH regression oracle remains separate from
production enrollment, physical crash durability and full migration acceptance.

Protected controller-side enrollment/delivery, causal policy-consumption
acknowledgement, complete runtime recovery acceptance, owned
updates and separate native uninstall/remove/purge remain open. There is no
migration-ready package or final v5.00.0 IVVQ acceptance. Issue #422 production
installer wiring remains open: standard-list-only fresh packages, independent
TOML selection of SSH/CIS/OS and optional modules, and preservation of
administrator upgrades. BunkerWeb independence and Linux AMD64 are unchanged.
