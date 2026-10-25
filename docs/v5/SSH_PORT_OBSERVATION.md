# Read-only SSH port observation

Status: v5.00.0 development command, related to #235, #337 and #422.
This separates configuration observation from hardening. It does not yet replace
the existing installer writer or implement the minimal package profile.

## Independent of hardening consent

```sh
sudo syswarden ssh-policy ports
```

The command reads the fixed standard SSH configuration graph and uses the
installed OpenSSH parser. It requires root but does not require or create
`/etc/syswarden/ssh-policy.json`. It does not load the general SysWarden
configuration, migrate TOML, recover firewall state, create transaction state,
write a drop-in or call a service manager. It remains available during product
removal for read-only diagnostics.

The JSON result contains:

| Field | Meaning |
| --- | --- |
| `schema` | Result schema, currently `1` |
| `configured_ports` | Sorted, distinct `Port` values reported by the parser |
| `listen_ports` | Sorted, distinct ports in the parser's `ListenAddress` results |
| `parser_sha256` | Identity of the pinned installed daemon executable |
| `parser_verified` | The live and sealed configuration graphs passed and agree |
| `runtime_verified` | Always `false`; actual service listeners were not inspected |
| `hardening_applied` | Always `false`; this operation cannot apply hardening |

No addresses, account names, hostnames, complete configuration or parser stderr
are included. An error returns no partial JSON result. Missing or unsupported
input is refused; it never invents port 22. The installed parser may itself
report its standard default when no explicit `Port` is present.

Explicit `ListenAddress` ports can differ from `Port`. For example, a fixture
with `Port 22` and `ListenAddress 127.0.0.1:2222` reports configured port `22`
and listen port `2222`. Combining those sets would incorrectly imply that both
ports listen. Multiple ports and IPv4/IPv6 expansions are preserved as separate
sets with duplicate port values removed.

## Trust and execution boundaries

The [protected inventory](SSH_INVENTORY.md) captures the standard main file,
Includes, permitted vendor aliases, file metadata, extended attributes, absent
paths and directory membership. Existing content at the reserved drop-in path
can be observed without adopting it or claiming its ownership.

The command pins the protected AMD64 daemon executable. It checks syntax and
effective configuration both against the live standard path and a sealed memory
image of the inventory. All effective directives must agree, not just the port.
File, Include and executable identities are rechecked around parser calls,
including failed calls. Changes, cancellation, malformed output and resource
limits refuse the observation.

Execution uses fixed `-t` and `-T` modes, a bounded timeout and output, no shell,
and a fixed environment. It does not start a listener. Numeric IPv4/IPv6
`ListenAddress` output is supported. Unsupported forms, including an unhandled
routing-domain suffix, are rejected without exposing their values.

This observes the standard graph only. A service can use another `-f`, `-p` or
`-o` option; a systemd socket can supply different listening sockets. A running
daemon may also retain an older configuration. Therefore this result is not a
firewall plan, an attestation of active listeners, proof of login or approval
to reload SSH. It cannot justify closing an administrator port.

## Minimal installation integration boundary

Issue #422 requires fresh native installation to select no list and defer
activation until explicit configuration through `syswarden config`. Mandatory
platform prerequisites remain installed. Reading SSH configuration must never
imply consent to change it.

The current production `system.ConfigureSSH` both writes SSH configuration and
sets the in-memory port used by the firewall. Production integration must remove
that coupling. Simply skipping the writer and guessing port 22 is insufficient;
using this configuration-only observation as proof of runtime state is also
insufficient.

Before switching the package path:

1. Select fresh minimal defaults independently of historical configuration and
   explicit administrator choices. Do not silently undo existing protections.
2. Keep SSH hardening, OS/CIS hardening and optional modules explicitly selected.
   An OS/CIS switch must not implicitly authorize an SSH rewrite.
3. Preserve declared service arguments, socket activation, multiple listeners
   and actual administrator access before any SSH-specific firewall decision.
   The minimal profile must not enable SSH cloaking as an incidental effect of
   discovering a port.
4. Send an opted-in SSH change through the single
   [reviewed transaction](SSH_TRANSACTION.md), with explicit intent, exact
   approval, activation checks and recovery. Never fall back to the old writer.
5. Validate fresh installation, upgrade, repair, reinstall and separate
   uninstall, native remove and purge paths, including reload and reboot.
   Switching a feature off does not prove that an older policy was retired.

The BunkerWeb API, temporary-ban lifetime, per-source ownership and HA contract
remain independent. This command neither enables nor reconfigures them.

## Validation scope

Tests cover nonstandard and multiple ports, distinct `ListenAddress` ports,
IPv4/IPv6 expansion, malformed or missing observations, protected Include
changes, cancellation, parser failures and unchanged administrator files.
Command tests verify the read-only preparation exemption, rejected mutation
flags, no partial output and no change to the in-memory configured SSH port.

The installed OpenSSH oracle uses temporary configurations and a disposable
fixture key. It preserves externally managed forwarding and authentication and
creates no SysWarden policy or state. It opens no network listener.

Native activation, independent direct/ProxyJump/Ansible access, the complete
minimal installation profile and final v5.00.0 IVVQ remain open. This component
alone does not make a package ready for SSH migration testing.
