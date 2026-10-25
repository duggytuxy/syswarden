# SSH assessment after a restoring reload intent

Development integration for v5.00.0. Refs #235, #337 and #422. This read-only
assessment inspects an existing original-restoration transaction. It does not
complete recovery or qualify a migration-ready package.

## Operator entry point

After a separately approved `restore-original` operation has recorded its
restoring-reload intent, run as root:

```sh
syswarden ssh-policy assess-restoration --plan-sha256 ORIGINAL_SHA256 --recovery-sha256 RECOVERY_SHA256
```

Use the original independently approved migration digest and the separately
approved restoration digest. Both must be complete lowercase SHA-256 values.
The command reads only existing fixed protected paths. Positional arguments,
`--config`, application options and missing or malformed digests are rejected.
It creates no state, repairs no directory durability, repeats no signal, and
does not attempt authentication. It bypasses global configuration normalization
and automatic firewall recovery, including while a removal barrier is present.

## Verified observations and retained uncertainty

The assessment requires the complete original publication history, the exact
approved recovery intent, both inverse transition records and their completion,
and the canonical restoring-reload record. It rechecks record identity, the
restored original inode, retained product files, explicit TOML selection and
the installed parser. Missing records cannot be inferred from matching files.

The pinned parser checks the restored graph against its sealed original in all
declared contexts. Bounded systemd process, listener and configured endpoint
observations run while configuration and history remain guarded. Drift,
unsupported state, malformed history, cancellation or resource-close failure
produces a nonzero exit without result JSON. The two-minute assessment ceiling
does not extend an earlier caller deadline.

Successful output reports configuration restoration, parser verification and
observed intent separately. It contains bounded counts, digests and transaction
identifiers, not accounts, addresses, private configuration or process IDs.
`recovery_required` remains true, with `runtime_activated` and `access_verified`
false. The recorded target digest describes the approved historical target;
current endpoints are a new observation and do not prove that target consumed
the restored policy.

Record presence does not prove durability or signal delivery. The command may
successfully inspect a visible reload record left by a failed directory sync
before dispatch. It preserves that uncertainty and the prohibition on replay.
The journal is neither cleared nor reusable after inspection. Do not delete
records to retry activation or recovery.

## Validation and remaining work

Filesystem tests cover complete and uncertain reload histories, hostile or
replaced records, incomplete inverse phases, parser/configuration/selection
changes, cancellation and resource ownership. CLI tests exercise fixed inputs,
degraded global configuration and separation from mutation commands.

Installed OpenSSH parser tests cover forwarding, CIS and attributed legacy CIS
with direct, bastion and Ansible contexts. Disposable authenticated daemon
tests distinguish a dispatched restoring reload from a request that failed
before dispatch. Both can present restored files, current endpoints and fresh
authenticated transport while still enforcing different forwarding policies.
These fixture tests do not qualify the production systemd binder or establish
an enrolled independent controller.

Causal policy-consumption acknowledgement, independently authorized fresh
access, completed recovery, owned policy lifecycle, native package transitions
and final v5.00.0 IVVQ remain open. Fresh packages must select no list and defer
activation until explicit configuration through `syswarden config`. SSH/CIS/OS
and optional modules require independent TOML selection.
Administrator settings, existing upgrade protection, mandatory Alpine
dependencies and BunkerWeb independence remain preserved. Linux AMD64 only.
