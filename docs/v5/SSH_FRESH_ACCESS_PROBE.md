# Fresh SSH access transport

Status: private development component for v5.00.0. Refs #235, #337 and #422.
This component is not exposed through the CLI or installer and does not make a
migration-ready package available.

## Input and authority boundary

The Linux transport accepts an explicit target, optional single forwarding
bastion, software authentication keys and exact pinned host public keys. It
binds its challenge to transaction, plan, activation-intent and retained-target
digests, the declared access context and both endpoint/key identities.

These supplied digests are bindings, not proof of approval. The future
independent controller must obtain them from verified protected state and
establish its authority separately. A local guard rechecks that caller's state
before network activity, around authentication and challenge execution, and
again after connection cleanup. The trusted guard must itself return promptly.
No return value from this component authorizes activation or recovery.

Endpoints must be canonical literal IP addresses with explicit nonzero ports;
no DNS resolution, ambient SSH configuration, agent, existing client connection,
password callback or automatic route discovery is used. Only `direct` and a
single `proxyjump` route are implemented. Ansible, general bastion orchestration,
multiple jumps, host certificates, interactive hardware keys and MFA require
separate adapters and qualification.

Host keys and unencrypted private-key inputs are limited to 16 KiB each. Keys
are parsed from copied bytes. Ed25519, ECDSA and RSA keys are accepted, with RSA
restricted to 2048 through 8192 bits and SHA-2 signatures. The temporary encoded
private-key copy is cleared after parsing; this is not a guarantee of complete
secret zeroization by the Go runtime. Credentials are neither written to disk
nor included in returned observations.

## Fresh authentication and response

Every invocation opens a new TCP connection and SSH handshake. The jump route
also authenticates the bastion and establishes a fresh target SSH handshake
through its forwarding channel. Host identities must exactly match the supplied
pins. Each peer must require exactly one signature by its selected client key.
A server accepting SSH `none` authentication is refused, even if the protocol
library reports an authenticated connection. There is no retry or alternate
credential fallback.

After authentication, 32 random bytes produce a challenge bound to the input
identity. A fixed remote command returns a versioned header, that challenge and
`SSH_CONNECTION`. Only fixed text and a lowercase digest enter the command.
There is no PTY, arbitrary command or client-supplied environment. Success
requires exit status zero, empty standard error, bounded output and exact
framing. Standard output is limited to 512 bytes and standard error to 256.
An earlier caller deadline takes precedence over the 15-second transport
ceiling. Cancellation closes the physical socket, including during a handshake
or a forwarded session; all opened connections are closed before return.

The response's destination address, port and source address must match the
explicit context. Direct access additionally matches the source address and
port to the local TCP socket. This deliberately does not qualify NAT-translated
direct routes. On a jump route the source tuple is server-reported; it is not
independent kernel attestation. The context host name is binding metadata, not
reverse-DNS proof. A pinned server or account remains trusted to execute and
report the fixed command honestly.

A successful observation contains only binding, challenge and fresh SSH session
hashes, including a separate bastion session hash where applicable. It always
reports `RecoveryRequired`. Errors return an empty observation. Neither result
clears the activation journal, writes a completion marker, proves consumption of
the full policy or attests fresh access from an independently enrolled host.

## Verification and integration gates

Adversarial protocol fixtures cover incorrect host/client keys, absent
signature authentication, refused forwarding and execution, stale responses,
wrong tuples, excess output, nonzero exit status, guard drift and stalled
handshakes or sessions. Repeated successful calls require different challenge
and session identities. Key-policy refusal and bounded-response fuzz tests
exercise the input boundary.

The [disposable OpenSSH oracle](SSH_RUNTIME_ACCESS_ORACLE.md) additionally calls
this transport directly and through its bastion after each candidate reload.
Both forwarding and CIS profiles must pass twice with distinct fresh session
identities. Its synthetic bindings are not production controller enrollment or
protected transaction proof. This native test is explicitly enabled and does
not run merely because ordinary hosted unit tests pass.

Production integration still needs protected independent controller authority,
causal policy-consumption acknowledgement, transaction-bound receipt handling,
runtime-aware recovery, owned updates and separate native uninstall, remove and
purge validation. Final v5.00.0 IVVQ acceptance remains open.

Issue #422 still requires standard-list-only fresh native installation, with
independent explicit TOML choices for SSH, CIS, OS hardening and optional
modules. Production minimal-profile installer wiring is incomplete. This
transport changes no installation defaults or administrator upgrade settings.
BunkerWeb independence is preserved; product scope remains Linux AMD64 only.
