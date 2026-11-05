# Protected SSH controller enrollment and challenge issuance

Status: v5.00.0 development component in consolidated PR452. Refs #235, #337
and #422. Root-only target adapters are implemented and exposed through the private
[exchange commands](SSH_ACCESS_COMMANDS.md). No automatic installer activation or
migration-completion path is enabled by this component.

## Independent target enrollment

The target reads only `/etc/syswarden/ssh-access-controller-v1.json`. It never
creates, repairs or learns this enrollment from a request or returned receipt.
An independently supplied SHA-256 must approve its complete canonical bytes,
and its exact plan must match the separately approved migration plan. The file
must be a root-owned, root-group, single-link regular file with mode 0600.
Descriptor traversal refuses symlinks and unsafe ancestors. The bounded reader
pins its complete inode, bytes, timestamps, mode, ownership and attributes.
Ancestor identity, permissions and attributes remain pinned; unrelated sibling
directory activity does not revoke enrollment.

The canonical JSON document has schema 1, domain
`syswarden-ssh-access-controller-v1`, scope `activation-access`,
`plan_sha256`, a raw Ed25519 public key in `controller_public_key`, ordered
`routes`, and integer Unix `not_before` and `expires_at` values. JSON byte
arrays use base64. Each route has `context_id`, `target` and an optional `jump`;
each peer contains a literal address and port, user, SSH wire public host key
and SSH wire public authentication key. Request construction must match every
protected plan context, including direct or single-bastion route semantics.
No authentication private key or controller signing private key belongs on the
target. Enrollment cannot select another operation or enable SSH hardening.
The independent explicit SSH TOML choice remains mandatory.

Unknown, duplicate, case-folded, noncanonical and oversized encodings are
refused. The authority handle rechecks its exact file and ancestor identities
throughout an operation. Expiry, backward time, replacement or revocation poisons
that handle. Restoring old bytes does not revive it. Independently restoring or
rolling back the complete protected storage is outside this boundary's threat
model, as are compromised root and untrusted clocks.

## Preparation, issuance and recording

`PrepareSystemdAccessRequest` opens the fixed protected enrollment, journal and
installed daemon parser. It regenerates the private request from the current
configuration and systemd endpoint observations. It writes nothing and makes
no network connection. The returned request requires separate approval of its
complete SHA-256; plan or enrollment approval alone does not issue a challenge.

`IssueSystemdAccessChallenge` requires that exact request approval and a
whole-second lifetime from 1 through 300 seconds, within enrollment expiry.
Under the original journal lock it writes one fixed `access-issuance.json`
record. The record binds the original transaction, plan, parser, activation
intent, target and original publication history, the enrollment's bytes and
exact image fingerprints, and the complete request and random challenge.
Original records and their fingerprints are not rewritten.

The existing anonymous-file writer synchronizes the new 0600 file, publishes
without replacement, synchronizes the directory and pins the original inode.
Authority, expiry, cancellation and protected state are checked again after
storage latency. Delivery bytes are returned only if all final checks and resource
closure succeed. A late failure can retain `IssuanceDurable=true` and
`RecoveryRequired=true` while returning no deliverable request or challenge.
A visible file after reopening does not reconstruct a lost writer acknowledgement.

An occupied issuance slot, including malformed or uncertain interrupted data,
refuses another issuance. An expired challenge cannot be replaced by deleting
its record. These operations neither retry an activation nor retire recovery
history. Physical power-loss durability and privileged disk rollback are not
proved by filesystem failure injection.

`RecordSystemdAccessReceipt` requires both the issued record byte digest and
`IssuanceImageSHA256` returned by the original acknowledged writer. It refuses
a same-byte replacement made before reopening as well as substitutions during
verification. It then uses the exact request/challenge and the current protected
enrollment key. Neither approval is learned from the reopened file.
The received receipt cannot choose its own key, route, path or approval. The
existing signature and fresh-request checks precede one-time evidence publication.
The evidence additionally binds `issuance_image_sha256`; the field is omitted in
older component records, preserving their canonical bytes. Replaying a receipt
or replacing an issuance inode is refused. No target-side network authentication
or reload occurs in this adapter.

The [controller protocol](SSH_CONTROLLER_RECEIPTS.md) is exposed through the
private exchange commands. Controller-side credentials and delivery require
independent operator provisioning; independently administered native qualification
is still required. A local target adapter or a signed
receipt alone does not establish independent controller execution.

## Recovery and historical inspection

The [historical observer](SSH_RECORDED_ACCESS_OBSERVATION.md) can follow an exact
issuance-image reference without treating it as current authority or reconstructing
durability. Old non-issued evidence retains its previous closed history.
Ordinary activation/request paths still refuse the additional occupied slots.

[Original restoration](SSH_RUNTIME_RECOVERY.md) preserves issuance and receipt
records as opaque pinned history, even if enrollment is revoked or issuance is
malformed or expired. It does not require a working controller to restore the
independently approved original configuration. The maximum closed recovery
history now has 17 entries, including both optional access records and the six
inverse/reload records. Restoration does not delete those records or claim
loaded-policy consumption, fresh restored access or completed recovery.

## Validation boundaries

Synthetic tests cover protected storage, complete approvals, route/key changes,
expiry and clock reversal, same-byte replacement, late revocation, sync failure,
one-time recording and restoration with opaque issuance. A separate isolated
systemd/OpenSSH `access-exchange` scenario exercises fixed production target
paths, real pinned authentication, replay refusal, controller revocation and
original restoration. Its synthetic controller runs in the same disposable
container; it is not independent-host enrollment qualification.

Causal policy-consumption acknowledgement, independently operated controller
handoff, complete recovery acceptance, owned updates and the full separate
native uninstall/remove/purge and migration matrix remain open. There is no
migration-ready package or final v5.00.0 IVVQ acceptance. Fresh packages must
select no list and defer activation until explicit configuration through
`syswarden config`, with independent TOML opt-in for optional modules, preserved
administrator upgrades and mandatory Alpine prerequisites. BunkerWeb independence
and Linux AMD64-only scope remain unchanged.
