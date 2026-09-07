# ADR-001: SNMP and metrics exporters

Status: deferred for v4.10.0 implementation

## Context

SNMP and metrics exporters could expose useful operational counters, but they
also add listeners, credentials, dependency lifecycles and a remotely
queryable schema. The current v4.10.0 work requires closed configuration
schemas, bounded inputs, explicit network policy and exact lifecycle evidence.

## Decision

Defer runtime SNMP and exporter integration. Include only a future design and
threat-model study. No listener, package dependency, default port, credential,
firewall exception or availability claim is introduced by this decision.

Any later proposal must define a versioned allowlisted metric schema, bounded
cardinality, local-only default binding, explicit authentication and encryption,
secret storage and rotation, package-owned service lifecycle, exact TCP or UDP
operator-policy rules, rate and resource limits, audit evidence, uninstall and
rollback behavior, and tests on every supported init system. Raw OID, command,
label, query or nftables expressions remain forbidden.

## Consequences

The v4.10.0 security boundary remains unchanged. GRC metric consumers may use
existing local evidence only until a separate reviewed implementation satisfies
the closed-schema and host-qualification requirements above.
