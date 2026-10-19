# Protected SSH intent and migration planning

Status: read-only SSH integration step for v5.00.0. Refs #235 and #337.
`syswarden ssh-policy plan` and `syswarden ssh-policy verify` are available in
development source. Neither command will
activate the dedicated file, replace either existing installation writer,
restart SSH, establish a new connection or authorize publication. A package
containing these commands can test planning and parser verification, not a
completed SSH migration.
Stable v4.10.4 and final v5.00.0 IVVQ acceptance remain unchanged.

## Explicit administrator declaration

The planner reads only the fixed `/etc/syswarden/ssh-policy.json` declaration.
It must be a root-owned, root-group, singly linked regular file with mode 0600.
Every ancestor must be a protected root-owned real directory. A missing file,
symlink, unsafe permissions or invalid schema refuses planning. No environment
variable, peer address, package, management comment or process selects a role.
The global `--config` option does not redirect this authority source.

Example for a directly administered target, using documentation-only identities:

```json
{
  "schema": 1,
  "role": "target",
  "owner": "syswarden",
  "profile": "forwarding",
  "contexts": [
    {
      "id": "administrator",
      "route": "direct",
      "user": "administrator",
      "host": "controller.example",
      "address": "192.0.2.10",
      "local_address": "192.0.2.20",
      "local_port": 22
    }
  ]
}
```

An administrator must supply the real required connection contexts privately.
Do not copy the example as evidence that an access route works. The declaration
accepts 1 to 16 contexts with unique IDs, exact canonical addresses without
zones, validated usernames/hostnames and a port from 1 to 65535. Contexts can
describe `direct`, `proxyjump` or `ansible` routes. `bastion` requires the
`jump-host` role. These labels describe intent; the planner does not execute a
controller, resolve DNS, infer remote topology or prove a successful login.

The two independent decisions are:

| Owner and role | Profile | Planning behavior |
| --- | --- | --- |
| `syswarden`, `target` | `forwarding` or `cis` | Prepare the fixed policy after checking the complete configuration graph |
| `external`, `target` or `jump-host` | `observe` | Inventory only, with no generated policy or write capability |
| `syswarden`, `jump-host` | Any | Refuse: scoped bastion publication is not implemented |
| Missing or unknown role/owner | Any | Refuse without an inferred default |

External observation refuses an occupied reserved drop-in and unresolved
historical SysWarden markers. It does not adopt files, remove old contributions,
claim that an external manager enforces CIS, or claim a successful login. The
separate `verify` command checks effective daemon output without changing the
external policy.
The [environment contract](SSH_ENVIRONMENT_COMPATIBILITY.md) still requires
actual role-specific access, forwarding and controller tests before activation.

The JSON schema rejects unknown fields, case aliases, duplicate keys including
escaped equivalents, null, trailing values, invalid UTF-8 and oversized input.
Maximum declaration size is 32 KiB. There is no freeform command, output path,
replacement configuration, daemon flag or executable in this schema.

## Historical main-file attribution

The older forwarding and CIS functions changed `/etc/ssh/sshd_config` without
retaining a durable before-image proving ownership of every line. A recognizable
comment or matching directive is therefore insufficient for automatic removal.

An optional `legacy` object requires all of these fields:

- `attribution`: exactly `operator-reviewed`, supplied by the administrator who
  has reviewed the particular historical contribution.
- `main_sha256`: the complete current main file's lowercase SHA-256, not a hash
  of selected lines. Any changed byte invalidates the declaration.
- `edits`: 1 to 128 objects containing `line` and `action`. Line numbers refer
  to the original file, are one-based, unique and strictly increasing.

Only two actions exist:

- `remove`: select an exact historical hardening directive emitted by SysWarden.
  The known six-line CIS block can be removed only with every exact line selected
  together. Modified blocks and arbitrary administrator lines are refused.
- `restore`: remove exactly one historical `# SYSWARDEN OVERRIDE: ` prefix from
  a supported SSH hardening directive. Preserve the original indentation and
  value. No other setting, include, port, authentication or `Match` line can be
  restored through this operation.

The transformation preserves every unselected line, including its bytes and
position. It does not guess missing historical settings or recover content
that an old writer already discarded. Those cases need independent private
backups and a separate administrator decision. The complete resulting graph
must pass the existing preparer. For example, restoring `AllowTcpForwarding yes`
does not authorize silently replacing it with the fixed target policy: the
conflict is reported for review.

This declaration attributes selected historical lines only. It is not approval
to apply the resulting plan. Existing reserved drop-ins still need independent
lifecycle ownership; the planner refuses them rather than inferring ownership
from their bytes or filename. Missing or conditional global Includes are also
refused. No Include is inserted into an administrator file.

## Read-only command and binding

```sh
sudo syswarden ssh-policy plan
```

The command skips general configuration loading, normalization and firewall
recovery. It remains available during an incomplete removal. Those exemptions
apply only to the exact read-only `plan` and `verify` paths, not a future apply
subcommand.
The planner creates no lock, backup, receipt or directory and executes no daemon.
Errors return no partial plan. JSON output contains bounded counts, operation,
role/owner/profile and hashes, not usernames, addresses or configuration text.
`apply_available` is always `false` in this implementation.

`plan_sha256` binds exact intent/configuration bytes, the transformed main file,
the candidate drop-in, every observed file and ancestor identity/metadata,
negative lookups, directory membership and restricted vendor alias text. A
second complete capture must match the first before a result is returned.
The digest is deterministic for unchanged observations. It is not a signature,
an ownership receipt, concurrency protection or durable migration approval.

## Installed-daemon candidate verification

```sh
sudo syswarden ssh-policy verify
```

This root-only command first performs the same protected planning capture. It
pins and hashes the installed Linux AMD64 ELF `sshd` in the standard protected
`/usr/bin` or `/usr/sbin` layout. It does not search `PATH`, execute a shell,
follow an executable/directory alias or accept executable options from intent.
Missing, changed, writable, linked or non-executable daemon files are refused.
The package's trusted runtime libraries remain part of the operating-system
trust boundary; this is not a package-signature verification service.

The verifier retains every configuration file separately in sealed anonymous
memory. Only Include references are translated to those retained descriptors;
file boundaries, expansion ordering and Match scope remain intact. OpenSSH
closes inherited nonstandard descriptors, so the sealed files are accessed
through the retained parent process's procfs descriptors. A host policy that
denies this access causes verification to fail; no weaker filesystem fallback
or alteration of that policy is attempted.

It runs `sshd -t` and `sshd -T` on the live baseline, its sealed equivalent and
the candidate. It checks global defaults and every declared `-C` connection
context. The live and sealed baselines must agree on every effective directive,
including repeated values and ordering. The candidate must satisfy its fixed
profile while preserving every unrelated effective value. External observation
permits no effective changes. Inputs and the pinned daemon are rechecked before
and after each invocation, including failed invocations, and at completion.

Each parser invocation is limited to ten seconds, the complete verification to
two minutes, and each output stream to one MiB. The child receives a fixed
minimal environment. Raw parser output and configuration contents never appear
in the JSON result or diagnostic messages. Successful JSON contains the plan,
parser hash and declared-context count, with `parser_verified: true`,
`runtime_activated: false` and `apply_available: false`. Refusal returns no
partial successful result.

These checks do not publish a drop-in, modify the main configuration, load keys
into an agent, start a listener, reload a service, authenticate a user or run an
Ansible controller. A route label is not a tested connection. No configuration
lock or filesystem rollback mechanism is claimed by this read-only command.
The complete migration and lifecycle gates below are still required.

## Remaining activation and lifecycle work

Before a tester can validate an applied package migration, implement and review:

1. Exact plan approval, independently verified ownership and durable transaction
   state containing private recovery data, without an old-writer fallback.
2. Publication with input revalidation and external-writer coordination; complete
   reverification of the candidate immediately before and after publication,
   activation and rollback after failures or interruption.
3. A single shared install/CIS path, update and recovery handling, then separate
   uninstall, native remove and native purge behavior preserving administrator
   files and effective access.
4. Real independent SSH, ProxyJump and Ansible connection/transfer checks on the
   supported AMD64 laboratories, followed by reload, reboot and failure testing.

Component and parser tests do not satisfy these native checks or final IVVQ.
BunkerWeb's independent integration and HA contracts are unchanged.
