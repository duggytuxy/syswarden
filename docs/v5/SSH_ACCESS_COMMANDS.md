# Private SSH controller exchange commands

Status: development component in PR452, refs #235, #337 and #422. These commands
make the existing access exchange usable by separate target and controller
processes. They do not publish SSH policy, reload SSH, accept migration, or clear
`recovery_required`. Forward activation and terminal recovery acceptance remain
separate integration gates. Do not run this workflow against an unprepared host.

## Roles and private files

The target administrator provisions the public enrollment described in
[SSH_ACCESS_ISSUANCE.md](SSH_ACCESS_ISSUANCE.md) through an independently approved
channel. The controller administrator independently reviews the request's full
routes, host keys and authentication public keys. A digest copied from untrusted
input does not constitute that review. Keep the controller signing key and SSH
private keys on the separately administered controller. Never copy
`credentials.json` to a target or place it in logs, public artifacts or tickets.

Each command takes `--exchange-dir`, an existing absolute directory owned by the
invoking effective user with mode 0700. Inputs must be owner-only mode 0600,
single-link, bounded regular files. Directory and file symlinks are refused.
A root-owned sticky temporary ancestor is allowed, but the final directory must
be private. There are no environment path overrides, credential discovery, SSH
agents, passwords, shell commands supplied by the request, or fallback keys.

The commands reserve outputs with exclusive creation before issuance or probing.
They synchronize the file and directory, check identity and content, and print
only digests and durability/recovery facts. They never overwrite an earlier file.
A failed or interrupted operation can leave an empty or incomplete output. Keep
it with the journal; deleting it does not authorize a retry. In particular, a
lost challenge delivery does not free its durable one-time issuance slot.

## Target preparation and issuance

Run as root on a target with an existing protected activation transaction:

```sh
syswarden ssh-policy access-request \
  --exchange-dir /root/ssh-exchange \
  --plan-sha256 "$APPROVED_PLAN" \
  --enrollment-sha256 "$APPROVED_ENROLLMENT"
```

This writes the exact private request to `request.json`. Review its complete
contents independently before issuing a challenge. Do not normalize the JSON,
add a newline or change the transferred bytes.

```sh
syswarden ssh-policy access-issue \
  --exchange-dir /root/ssh-exchange \
  --plan-sha256 "$APPROVED_PLAN" \
  --enrollment-sha256 "$APPROVED_ENROLLMENT" \
  --request-sha256 "$APPROVED_REQUEST" \
  --lifetime-seconds 180
```

The lifetime is 1 through 300 seconds. `delivery.json` contains canonical schema-1
JSON with base64 `request` and `challenge` bytes, plus `issuance_sha256` and
`issuance_image_sha256`. Retain the original writer's issuance approvals from
stdout. Deliver only this private file and the independently approved request and
challenge digests to the controller using the administrator's trusted channel.
The challenge expiry includes transport and review time; do not issue until the
controller is ready. No command changes the firewall or loads general TOML files.
Target issuance and recording still obey the product removal barrier.

## Independent controller

Provision `credentials.json` locally as compact canonical JSON, with fields in
this order: `schema` (1), `signing_seed` (base64 of the 32-byte Ed25519 seed),
`routes` (ordered list). Each route contains `context_id`, `target` (base64 of
an unencrypted supported SSH private key file), and optional `jump` (the same
encoding for the explicitly declared bastion credential). The seed's public key
must equal the target's independently provisioned controller pin. Every context
must have exactly one credential entry. Unknown or duplicate fields, additional
credentials and mismatching public keys are refused before authentication.
The full credentials-file digest is approved locally, never learned from delivery.

Run under the controller account that owns its private exchange directory:

```sh
syswarden ssh-policy access-probe \
  --exchange-dir /home/operator/ssh-exchange \
  --request-sha256 "$APPROVED_REQUEST" \
  --challenge-sha256 "$APPROVED_CHALLENGE" \
  --credentials-sha256 "$APPROVED_LOCAL_CREDENTIALS"
```

This command bypasses target configuration loading, target removal inspection and
firewall recovery. It authenticates fresh pinned sessions for every declared
route and signs the complete observed batch into `receipt.json`. A replacement,
revocation, expiry, guard failure or partial route failure suppresses the receipt.
Private transport errors are not printed. It does not claim that controller
independence follows from a key or process identifier. That requires separate
administration, provisioning and operation.

Transfer only `receipt.json` back to the target's private exchange directory.

```sh
syswarden ssh-policy access-record \
  --exchange-dir /root/ssh-exchange \
  --plan-sha256 "$APPROVED_PLAN" \
  --enrollment-sha256 "$APPROVED_ENROLLMENT" \
  --issuance-sha256 "$ORIGINAL_ISSUANCE" \
  --issuance-image-sha256 "$ORIGINAL_ISSUANCE_IMAGE"
```

This records one receipt under the existing protected journal lock after current
state, enrollment and signature checks. It does not connect to SSH or select a
key from the receipt. Replay and changed enrollment are refused.

## Limits

A successful login proves fresh access for the declared routes. It does not prove
all server restrictions or exclusive causation by a particular reload signal.
Stock OpenSSH's parser, process and listener evidence must not be described as a
daemon-emitted acknowledgement. Runtime acceptance, restored-policy access,
owned lifecycle operations and native migration qualification remain incomplete.
These commands do not make the package ready for migration testing or establish
final v5.00.0 IVVQ acceptance. Fresh installation remains standard-list-only;
SSH hardening still requires its independent explicit TOML selection.
