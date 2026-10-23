# Durable one-time SSH access observations

Status: private v5.00.0 component. Refs #235, #337 and #422.
No production command, installer or activation-completion path is enabled.

## Protected recording boundary

The [signed controller receipt](SSH_CONTROLLER_RECEIPTS.md) can now be recorded
once in the original protected activation transaction. The writer performs the
same bounded signature, independent challenge/key approval, expiry, monotonic
clock, explicit TOML selection, parser, policy and endpoint checks as read-only
appraisal. It regenerates the complete current request and requires exact byte
equality. The original journal lock remains held through final verification.
No target-side network authentication or daemon reload is performed.

A single fixed `access-evidence.json` record retains the exact request, challenge
and signed receipt bytes, with the controller public-key digest, original plan,
parser, transaction, activation intent, target and original publication-record
fingerprint. `assessed_at` records the successful appraisal time, not a claim of
write completion or policy consumption. No private key is stored. The request
contains private operational information; this root-owned record must remain
private and must not be uploaded to public reports or CI artifacts.

The existing journal writer creates a 0600 anonymous inode, synchronizes its
contents, publishes the fixed name without replacement and synchronizes the
protected directory. Readback binds the original inode as well as its exact
bytes, attributes, ownership and link count. Only that acknowledged image may
extend the in-flight assessment's closed record set. The final guard rechecks
authority, time, cancellation, parser, unchanged configuration and all original
records after the write. It does not adopt an independently replaced copy.

## Replay, interruption and uncertainty

Any existing evidence entry occupies the transaction's single recording slot.
This includes an empty, malformed, substituted or uncertain entry after an
interrupted write. Ordinary preparation, appraisal and recording still require
the original closed history, so another receipt, nonce or controller cannot
replace the entry. The write handle is unusable after every write attempt.
Closing and reopening the journal, including from a separate process, does not
clear the occupied slot. No retry, cleanup, overwrite or durability repair is
performed automatically.

`RecordDurable` means this invocation received the writer's synchronization and
original-inode acknowledgement. A later failed guard can return an error with
that flag still true. A directory-sync failure leaves the flag false even when
the file is visible. Both cases require recovery and retain evidence. Observing
an existing file after reopening does not reconstruct a lost acknowledgement.
If a crash loses an unacknowledged directory entry, no successful recording was
reported; the earlier activation intent still prevents file-only recovery.
The component does not promise resistance to privileged disk rollback or removal
of the entire protected history.

The stored observation is not activation acceptance. `RecoveryRequired` remains
true, and no loaded-policy, runtime-complete or reusable access authority is
returned. The existing activation fence continues to prohibit file-only
rollback. Recorded histories deliberately require a future explicit runtime-aware
recovery/inspection path; deleting the record to resume migration is unsupported.

## Verification and remaining work

Synthetic SSH protocol fixtures exercise direct and single-bastion authentication
before recording. Tests verify exact retained bytes, private modes, unchanged
configuration and original records, lock retention, occupied-slot refusal and
replay rejection after reopening in another process. Failure injection covers
sync uncertainty, same-byte inode replacement, hard links, unsafe modes, unknown
entries, policy/history drift, final-callback revocation, cancellation, expiry,
clock rollback and caller buffer changes. Invalid inputs never reach the write.
These checks do not simulate physical power loss or prove storage hardware
honors synchronization.

Protected enrollment/delivery and durable challenge issuance, causal policy
consumption, runtime-aware recovery, owned updates, separate native
uninstall/remove/purge and complete migration qualification remain open.
There is no migration-ready package or final v5.00.0 IVVQ acceptance.
Issue #422 still requires standard-list-only fresh native installation and
independent TOML choices for SSH, CIS, OS hardening and optional modules.
Production minimal-profile installer wiring remains incomplete. Preserve
administrator upgrades, BunkerWeb independence and Linux AMD64 scope.
