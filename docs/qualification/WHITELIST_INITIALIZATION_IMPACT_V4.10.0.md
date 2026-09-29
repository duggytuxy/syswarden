# Whitelist initialization impact for v4.10.0

Status: qualification blocked; this correction does not qualify or publish a release.
Baseline candidate: `24c3c6e1548b8db0ccf64c37a33e05b351be5a18`.

## Preserved native failure

The RPM-A10-RHELPO image reached its real native boot with an operator IPv4
whitelist but no IPv6 whitelist file. Four authentic SSH failures reached the
catalogue threshold. The runtime refused the firewall mutation because a required
whitelist source was absent; no ban was present and the event remained DETECTED.
The error capture is retained privately with SHA-256
`631231d80ea790d9b214c0c4a66782922e7f94adcf425c63a3cff2c5998dd7e9`.
The failed final-state export is retained with SHA-256
`55ccb45387069b4bd1d02f4aa68eeee77ed60814c8ae8f3ccdd3972128051334`.
Neither this reproduction nor any previous verdict is replaced by the fix.

## Change boundary

The CLI policy reload initializes an explicit pair of whitelist files before
policy application, using the same rooted, locked and exclusive-creation path as
persistent blocklists. A fresh missing family is empty; seeded entries and file
metadata are preserved. Existing whitelist mode 0640 is accepted, while new files
and the separate whitelist marker use 0600. Ownership, regular-file, single-link,
size and writable-mode checks remain enforced. A missing file after initialization
fails before policy application. Initialization does not discover infrastructure,
add allowlist entries or weaken runtime handling of missing or unsafe sources.

The runtime, catalogue, native contracts and protected acceptance verifiers are
unchanged. The shared initialization implementation also serves blocklists, so
both families' existing blocklist regressions are part of the validation scope.

## Candidate and replay policy

A merged correction creates a new candidate. Before any native replay:

1. Record the exact merged commit and build all four package variants with their
   provenance, checksums, signatures and attestations. Compare the payloads and
   source scopes with the baseline. Do not relabel old artifacts as new ones.
2. Retain every old verdict under its original candidate and package hashes.
   No result is inherited merely because its feature code did not change.
3. Produce a gate-by-gate impact matrix for the new commit. Separate behavioral
   invalidation from candidate or package binding. Where the frozen gate supports
   reviewed evidence admission, require that explicit admission and its proofs.
   Otherwise replay the complete gate at the new candidate; never edit an old
   record's commit, timestamp, package digest or verdict to make it acceptable.

| Evidence or gate | Required disposition |
| --- | --- |
| RPM-A10-RHELPO capabilities | Replay fresh native activation and the full failed profile, including real SSH enforcement and verified restoration. Unit tests do not replace it. |
| RPM-A9-RHELPO capabilities | Validate the same image activation path on its native platform. |
| Other capabilities and lifecycle | Review the changed reload/list initialization and rebuilt CLI payload against each gate; replay affected installation, reload, reboot and persistence controls. Whole profiles are required where partial admission is unavailable. |
| Native HA campaigns | Keep both completed 30-minute baseline campaigns and their signature. Review activation and candidate/package binding before deciding admission or a fresh pair of full campaigns. Local concurrency tests do not substitute for native HA. |
| Feed and allocation evidence | Retain exact baseline results; assess unchanged algorithm inputs separately from changed binary bindings. No automatic pass on the new candidate. |
| Migrations, updater and native performance | Complete their still-missing candidate-bound evidence after rebuilding. |
| Global protected acceptance | Execute only after all prerequisites refer to the accepted exact candidate and required restorations are verified. |

The restored host is evidence of cleanup, not evidence that the failed profile
passed. No release publication is authorized by this document.
