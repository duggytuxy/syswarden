# Bind static SSH startup selection to the observed invocation

Status: internal v5.00.0 integration component. Refs #235, #337 and #422.

The production endpoint observer, including the owned-publication composition,
now checks the manager's typed startup declaration before binding a process.
It repeats that check while retaining the process lease and ownership guards.
A matching listener cannot compensate for an unsupported startup declaration.

## Exact arguments and invocation

The adapter reads `ExecStartEx` through the documented
[systemd D-Bus interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html).
It preserves each argument as a separate string. It does not parse the flattened
`systemctl show` display or a mutable process title. The strict decoder rejects
unknown fields, duplicate keys, extra commands, null values, trailing documents,
invalid types, excessive sizes and unsupported signatures.

The declaration must select exactly the pinned installed daemon path. The
supported static arguments are `-D`, optional `-e`, and an optional separate
`-f /etc/ssh/sshd_config` pair. Without `-f`, this is OpenSSH's documented default
configuration path. The check binds the command's recorded PID and monotonic
start to the current service observation and rejects a completed invocation.
The complete declaration must remain identical across the process observation.

This restriction matters because [OpenSSH command-line options](https://man.openbsd.org/sshd.8)
can override file settings, and a reload reuses the original startup options.
An alternate `-f`, `-o`, port/family override, wrapper, execution prefix, joined
or duplicate option, or unresolved variable such as `$OPTIONS` is refused.
Argument arrays are never flattened, expanded or executed by SysWarden.

Active socket activation, instanced sockets and executable path aliases not
independently qualified by this adapter are refused. The basic manager/process
observers remain available internally without this stronger declaration check.
These limits are not a claim that distribution service defaults are invalid.
They identify cases that still require explicit integration and native evidence.
The adapter never rewrites a vendor unit or clears an administrator option to
make the check pass.

## Protected read-only transport

The root adapter pins `/usr/bin/busctl` as a protected, single-link Linux AMD64
executable and verifies its identity and digest around queries. It uses only a
fixed `get-property` request for `ssh.service` or `sshd.service` over the protected
local system-bus endpoint. The broker must identify the manager as root PID 1
before and after each property read. The broker socket and its protected
ancestors are rechecked together with the manager private endpoint used by
the separate root `systemctl` observer. The executable is invoked through its retained
descriptor, with a fixed environment, bounded output and a five-second deadline.
No shell, caller-selected bus, auto-start or interactive authorization is used.
Failure, cancellation, drift and close errors invalidate the combined result.

The owned endpoint path retains the original journal lock, plan, explicit TOML
selection and inventory checks during these additional observations. The result
exposes only a command digest and declaration flags, not raw arguments, process
identifiers or timestamps. It is not reusable authorization.

## What remains before migration readiness

A verified declaration is still not proof of the daemon's loaded policy. It
does not attest the full execution environment, historical configuration bytes,
compiled defaults, authentication success or causally verified activation. The
configuration, activation and access proof flags therefore remain false.
Environment-derived options, supported socket startup, alias resolution and
OpenRC need their own qualified adapters before broader native support can be
claimed. No fallback silently weakens these requirements.

No new CLI, installer call, service action or dependency installation is added.
The complete activation/recovery path, fresh independent authenticated access,
already-owned updates and separate uninstall/remove/purge validation remain
open. Component tests do not establish native acceptance or final v5.00.0 IVVQ.

Issue422 still requires a standard-list-only fresh APK/DEB/RPM installation,
independent explicit TOML choices for SSH, CIS, OS and optional modules, and
preservation of administrator settings and existing protection during upgrades.
Its complete production wiring is not implemented by this component. BunkerWeb
remains independent, including source ownership, expiry and HA. Linux AMD64 only.

## Validation boundaries

Tests cover typed argument preservation, override refusal, invocation changes,
unsupported socket topology, cancellation, transport and binary replacement,
late errors and absence of partial success. The installed manager oracle reads
its real typed property and manager credentials over the same fixed system-bus
transport without changing a service. It does not qualify an activated SSH
daemon or prove a real authenticated SSH connection. Existing process/socket tests retain
their separate descriptor and namespace coverage.
