# Explicit original SSH configuration restoration

Development candidate for v5.00.0. Refs #235, #337 and #422. This bounded
recovery command does not enable forward migration or qualify a migration-ready
package. It requires an existing, attributable SSH activation transaction.

## Inspect, review and apply

Run as root with the original independently approved migration plan digest:

```sh
syswarden ssh-policy restore-original --plan-sha256 ORIGINAL_SHA256
```

This reads fixed protected SSH configuration, journal and installed parser
paths. It observes and retains the qualified systemd SSH process but creates,
renames, synchronizes and signals nothing. It does not provision missing state.
Review the original plan and the resulting `recovery_sha256` before a second
explicit invocation:

```sh
syswarden ssh-policy restore-original --plan-sha256 ORIGINAL_SHA256 --apply --recovery-sha256 RECOVERY_SHA256
```

Both digests must be complete lowercase SHA-256 values. The recovery approval
binds the original history and retained configuration to the currently observed
target. Changed input requires inspection again, not forced application. A
missing recovery digest cannot turn an application request into a dry run.
Positional arguments, unknown options and `--config` are rejected; these commands
do not select an alternate configuration tree.

Application restores the exact original main inode, moves the product drop-in
to private retention, verifies the original graph, and records a separate
restoring-reload intent before one request to the retained process. It never
uses a service-manager restart, numeric PID fallback or automatic retry.

## Input isolation and outcomes

Both forms bypass global configuration loading and normalization, legacy config
fallback and automatic firewall recovery. They validate their own protected
inputs and explicit SSH selection. Inspection is allowed while removal is
pending; application refuses a present or unreadable removal barrier before
opening recovery resources. Neither form starts optional modules or changes
the default installation profile.

JSON output contains only operation/digest identifiers and bounded facts from
this invocation. It never contains configuration, private history, accounts,
network endpoints or process identifiers. `recovery_required` stays true, while
`runtime_activated` and `access_verified` stay false. A successful exit means
the requested inspection or bounded restoration/reload request returned; it
does not mean policy consumption, fresh access or complete recovery was accepted.

An operation error exits nonzero and emits no result JSON. If restoration
or request return was already observed, the error preserves those partial facts
and requires retaining the journal. A failure while closing resources cannot
erase the fact that a reload may already have been requested. Output delivery
failure also exits nonzero and preserves those facts in its error; partial or
lost output is not authority to repeat the command.

## Supported states and limits

Before the restoring-reload record exists, the same independently approved
recovery can resume exact interrupted inverse file transitions. Changed target
identity, ambiguous ownership, administrator drift or unsupported state refuses
further mutation. A missing or unsupported systemd SSH daemon cannot use this
path. OpenRC SSH recovery remains unavailable.

Any restoring-reload record blocks subsequent inspection and application,
including after an uncertain write or dispatch. Do not delete or alter it.
The older `assess-activation` command does not accept this expanded recovery
history and is not the next step after restoration. Post-reload recovery
assessment/completion, protected independent fresh access evidence, consumed
policy qualification and lifecycle retirement remain under integration.

The native service-manager, upgrade and removal matrix and final v5.00.0 IVVQ
remain open. Fresh APK/DEB/RPM packages retain standard Data-Shield list1 only;
SSH/CIS/OS and optional integrations require independent TOML selection.
Administrator configuration, existing protection on upgrades, required Alpine
dependencies and BunkerWeb independence remain mandatory. Linux AMD64 only.
