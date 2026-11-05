# Explicit SSH hardening selection

Status: internal v5.00.0 integration under #235, #337 and #422. This contract
does not switch the existing package installation pipeline, expose a public
apply command or establish migration readiness. Native installation defaults
and the complete SSH lifecycle still require their own validation.

## Independent TOML choice

The SSH transaction reads one dedicated module:
`/etc/syswarden/config/modules/05-ssh.toml`.

```toml
[ssh]
hardening = "disabled"
```

The accepted values are:

| Value | Meaning |
| :---- | :------ |
| `disabled` | Do not authorize a new SSH hardening publication. |
| `forwarding` | Select the fixed forwarding restriction profile. |
| `cis` | Select the fixed SSH CIS profile. This does not enable OS/CIS hardening. |

Missing files, an empty module or an empty `[ssh]` table mean no declaration.
The plan reports effective selection `disabled` and
`ssh_selection_declared: false`. An explicitly written `disabled` remains
distinguishable from an absent declaration.

Historical `core.hardening_enabled`, `core.cis_l2_hardening` and flat
configuration flags do not provide SSH consent. Generated defaults and legacy
migration do not create a positive selection. Reading an existing configuration
does not rewrite those values or remove previously applied protection.

Only this module may declare `[ssh]`. Other modules, the master configuration,
unknown SSH keys, different casing, booleans, numeric values and unsupported
profiles are rejected. Environment overrides cannot grant or revoke consent.
General configuration validation and `config-get ssh.hardening` recognize the
choice, but the transaction independently reads its fixed protected source.
It does not use a cached global configuration value or a caller-selected root.

The module must be a root-owned regular file with root group, mode `0600`, one
link and at most 32 KiB. Protected real ancestor directories and bounded
descriptor-rooted reads are required. Symlinks, writable parents and ambiguous
metadata are refused. Keep this module limited to the SSH choice, without
credentials or unrelated configuration.

## Selection is not migration approval

The choice must agree with the profile in the independently reviewed
`/etc/syswarden/ssh-policy.json` intent. Publication requires all three:

1. Explicit TOML selection of the requested SSH profile.
2. Explicit SysWarden ownership, target role and access contexts.
3. Approval of the exact freshly inspected migration plan digest.

The [shared transaction](SSH_TRANSACTION.md) rejects missing, disabled or
mismatched consent before parser execution, label lookup, journal creation
or staging. External ownership permits observation only, with SSH hardening
undeclared or disabled. A positive selection conflicting with external
ownership is refused.

The module bytes, metadata, ancestors and negative lookups are part of the
plan's complete inventory. Replacing, removing, adding or editing this file
invalidates earlier approval, even if the effective profile stays the same.
Publication and rollback retain and compare the inventory at their existing
transaction boundaries. The TOML and JSON declarations are never passed to
OpenSSH as configuration files.

The new plan digest domain is `SYSWARDEN-SSH-MIGRATION-PLAN-V3`. Prior
development approvals are not reusable. Existing private records must be
preserved; this change does not convert or overwrite historical journals.

The independent [port observer](SSH_PORT_OBSERVATION.md) still requires no
hardening selection. Parser observations do not establish active listeners,
successful logins or authority to change firewall access.

## Disabled is not removal

Changing a selection to `disabled` does not retire an active drop-in, undo
historical main-file edits, delete a journal or restore daemon state. Those
operations require exact ownership and their separately reviewed lifecycle
or recovery procedure. Do not remove evidence to bypass a refusal.

Issue #422 native qualification remains open for fresh packages that select no
list and defer activation until explicit configuration through `syswarden config`,
independent OS/CIS opt-in, optional module inventory and preserved upgrade choices.
SSH integration also requires owned updates, service and socket
activation, independent access checks, public recovery, and separate native
uninstall, remove and purge trials. This intermediate component evidence does
not constitute final v5.00.0 IVVQ acceptance.
