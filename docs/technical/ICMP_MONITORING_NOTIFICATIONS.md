# Ping monitoring and webhook notifications

Applies to: the v4.10.0 source candidate. This document does not establish
release qualification and must not be used as a v4.04.3 configuration guide.

The v4.10.0 candidate excludes valid IPv4 ICMP echo requests (type 8, code 0)
and IPv6 ICMP echo requests (type 128, code 0) from the catch-all port-scan
tracker. Ordinary ping probes therefore produce no port-scan strike, source ban
or webhook alert through that handler. Their original kernel drop records remain
available through the configured kernel log collection; firewall logging and
packet-filtering rules are unchanged.

This exception is specific to valid echo requests observed by the catch-all
handler. Other ICMP types, ambiguous records, TCP/UDP scans and dedicated attack
signals retain their existing handling. It is not a general per-rule allowlist.

A provider firewall permission does not override the host firewall. To make
monitoring pings succeed, an operator must explicitly permit echo requests in
SysWarden's typed operator policy. A dynamic monitoring IP can be handled with a
protocol-specific source CIDR rule, without globally trusting that source for
other traffic. Earlier mandatory protection rules continue to apply.

Changing alert classification alone does not open ICMP or remove an existing
ban. Review existing operator policy and any earlier ban before applying a
monitoring configuration. IPv4 and IPv6 require their corresponding rule types.
