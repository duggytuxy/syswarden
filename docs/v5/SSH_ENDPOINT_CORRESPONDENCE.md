# Compare configured SSH endpoints with observed listeners

Status: internal v5.00.0 development component. Refs #235, #337 and #422.
This extends [listener observation](SSH_LISTENER_OBSERVATION.md) without
publishing configuration, activating SSH or adding an operator command.

## Configuration and live evidence

`ObserveSystemdEndpoints` reads the protected standard SSH configuration graph
and invokes the pinned installed parser in syntax/effective modes. The live
graph and sealed-memory baseline must produce identical effective settings,
including unrelated directives. The existing inventory and executable guards
remain active around the parser and throughout live listener inspection.

The adapter derives expected endpoints from `AddressFamily` and the parser's
expanded numeric `ListenAddress` values. An explicit listen port may differ
from a `Port` directive. Missing values are refused; no default port or
hostname-to-address approximation is supplied by the comparison code.

The expected set must exactly match the distinct kernel listening sockets held
by the observed process. Addresses and ports are compared together. A wildcard
address does not equal a specific address, even when that interface is the only
one currently present. Missing or additional endpoints prevent correspondence.
Multiple descriptors for one socket are permitted; distinct socket objects for
the same endpoint require a separately qualified policy and are refused here.

The running executable must match the parser's SHA-256. Both socket samples
are checked within the existing stable process/manager observation boundary.
The configuration inventory is checked again after observation. One shared
deadline bounds parser and service observation; failures or close errors yield
no partial success summary.

## Network namespace and supported endpoint forms

An address string is meaningful only within a network namespace. The adapter
locks its OS thread briefly, verifies that thread's namespace against the held
process namespace, and queries the namespace cookie of a temporary unbound UDP
socket. It checks the thread namespace again and closes all temporary handles.
It never binds, connects, sends traffic, changes namespace or adjusts privileges.
Every observed listener must have that same kernel namespace cookie.

The initial comparison supports numeric IPv4 and unscoped IPv6 endpoints.
IPv6 sockets must be IPv6-only; a dual-stack wildcard must not silently replace
separate IPv4/IPv6 expectations. Mapped IPv4, scoped/link-local addresses,
multicast, interface-bound sockets, routing-domain suffixes, duplicate parser
endpoints and inconsistent address families are refused without fallback.
These restrictions describe this internal verifier, not a claim that those
OpenSSH configurations are invalid. Additional forms need explicit qualification.

No resolver is called by the comparison code. The protected installed parser
retains its own configuration processing semantics. No public address, port,
interface, namespace identifier or configuration value is included in the
summary. Digests identify file contents and canonical expected endpoints;
metadata remains protected by the live inventory checks.

## Proof and installation boundaries

The only new claim is `configured_endpoints_matched`. Agreement does not prove
that the daemon consumed this file graph, that authentication/forwarding policy
is active, that its service arguments use the standard configuration, or that
a new administrator connection succeeds. Socket-unit settings can also select
listeners. The configuration, activation and access flags remain false, as do
the narrower embedded observer claims. Repeated reads are not atomic snapshots.

This summary must not become permission to mutate SSH later. Activation needs
fresh configuration-consumption evidence and independent access verification,
with rollback and ownership preservation. Native migration and independent
uninstall/remove/purge paths remain open under the v5.00.0 IVVQ contract.

Issue #422 requires fresh native packages to select no list and defer activation
until explicit configuration through `syswarden config`, with independent explicit
TOML choices for SSH/CIS/OS hardening and optional modules and preservation of
administrator settings and existing protection during upgrades. This observer
changes no defaults or installation calls. BunkerWeb remains independent,
including source ownership, temporary-ban expiry and HA. Linux AMD64 only.

Tests cover expanded/narrowed exposure, missing/extra listeners, namespace and
parser drift, duplicated descriptors, unsupported endpoint forms and proof
limits. Native oracles use ephemeral loopback sockets, the installed parser
and their own process. They do not activate a real SSH service or establish a
migration-ready package or final acceptance.

## Primary references

- [OpenSSH address-family and listen-address semantics](https://man.openbsd.org/sshd_config).
- [Linux IPv6 socket and scope semantics](https://man7.org/linux/man-pages/man7/ipv6.7.html).
