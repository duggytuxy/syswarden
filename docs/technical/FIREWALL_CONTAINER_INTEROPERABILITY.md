# firewalld and container interoperability

Status: v5.00.0 development correction under [issue #376](https://github.com/duggytuxy/syswarden/issues/376).
This interface-scoped selection is not included in the published v4.10.4 package.
Component tests do not establish native boot, reload or release acceptance.

## Existing zone ownership

Docker can create a firewalld zone containing its bridge interfaces and a
forwarding policy allowing traffic into that zone. NetworkManager restores the
connection-to-zone bindings that it manages. These are expected behaviors.
SysWarden must preserve both, including unrelated administrator rules.

The compatibility layer reconciles only the product's bounded required ports
and trusted sources. It does not replace firewalld as the administrator's policy
manager. A plain zone port permission applies to all interfaces in that zone;
it is not an interface-specific rich rule.

The published implementation requires a unique interface-bound port zone.
The development correction also accepts an explicit protected-interface scope:

```toml
[network]
interfaces = "eth0"
```

The name above is illustrative. Select the actual protected interfaces through
the existing reviewed SysWarden configuration process. The legacy equivalent is
`SYSWARDEN_INTERFACES`. All selected interfaces must have an active binding to
one common existing firewalld zone. Unselected zones, including container zones,
remain untouched. The zone name and default annotation never establish its role.

When no explicit scope is supplied, the existing unique-zone requirement remains.
A missing interface, a duplicated binding, or selected interfaces in different
zones causes a refusal before the authoritative transaction. The selected scope
is copied into the plan and rechecked before commit and during reconciliation.
An interface moving to another zone invalidates the plan. Exact ownership records
continue to bind each managed permission to its zone.

Do not remove a NetworkManager-managed interface from its zone as a workaround.
Do not disable Docker's firewall integration, choose a zone by its name, or open
the product ports across every zone to suppress the refusal.

## Strict country selection and container traffic

GeoIP/ASN strict allow in SysWarden uses packet source addresses. It does not
interpret HTTP real-client-IP headers. An upstream proxy or CDN changes the
source visible to this layer; application-level real-IP configuration cannot
change a packet that the kernel has already rejected.

The existing strict-allow forward chain applies to new forwarded traffic as
well as client ingress. Private container sources are absent from public country
allocations. A container connection to an application backend, DNS resolver or
other external service can therefore fail independently of the client's country.
Established traffic, explicit trusted sources and reputation rules also affect
the final result.

The v5 correction applies the forwarded GeoIP/ASN strict-allow checks only to
the explicitly configured protected ingress interfaces. Configure every client
ingress path in `network.interfaces`; this selection is a security boundary.
Container-to-backend connections entering through a different interface no
longer need a public country allocation. This does not insert an accept rule,
disable Docker/firewalld policy, or authorize the backend in another firewall.
Dynamic source and destination bans and reputation blocks still precede
established-flow acceptance and country selection in both IP families, subject
to the existing explicit whitelist exceptions. Host-input filtering
and explicit denied-country/ASN rules retain their existing semantics.

Without explicit protected interfaces, the historical strict-allow forwarding
behavior remains. The correction never uses the inferred default route to
silently exclude other ingress paths, and never trusts a private address solely
because it is private. A private source arriving on a protected external
interface remains subject to strict country selection.

The generated ownership receipt records the scoped generation and its exact
interfaces. Postchecks verify both live rules. Removal validates the source and
live scope before recognizing the historical remainder; an edited selector,
unknown generation or unmarked source does not authorize deletion. Older
versions do not recognize this new receipt. A downgrade therefore needs a
reviewed restoration plan, rather than manually deleting ownership evidence.

Before changing policy, distinguish:

- Client-to-published-port ingress from container-to-backend and container egress.
- An IP-layer timeout from an HTTP denial or an unavailable upstream backend.
- IPv4 from IPv6, including the actual source visible on each path.
- SysWarden strict allow from BunkerWeb's own country and real-IP settings.

Do not use a broad private-range whitelist or a client-supplied HTTP header as
an automatic bypass. Preserve independent source-owned bans, expiry and HA
behavior. No BunkerWeb upstream defect is established by a multi-zone refusal
inside SysWarden.

## Verification boundaries

Local tests cover explicit and custom zones, an unrelated Docker zone, default
annotations, missing and duplicate bindings, selected interfaces in multiple
zones, caller-slice changes, rebinding before commit, unrelated zones appearing
through the final post-commit reinspection, runtime reconstruction and
exact scoped removal preserving unrelated permissions. Runtime reconstruction
uses a deterministic firewalld fixture, not a real daemon reload.

An isolated Linux user/network-namespace test sends actual forwarded IPv4/IPv6
frames through the historical and corrected rules. It checks allowed and denied
visitors, private-source spoofing at protected ingress, container-to-backend
traffic, source/destination bans and policy replay. Independent kernel JSON is
also checked against the exact removal model. These tests do not exercise a real
Docker daemon, BunkerWeb HTTP proxy, NetworkManager or host reboot.

Native verification must still cover boot ordering, NetworkManager reassignment,
firewalld reload, Docker container connectivity, allowed and rejected client
traffic in both IP families, backend connectivity and independent removal paths.
Keep private operational evidence out of public issues and CI artifacts.

## References

- [Docker packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [firewalld connection and interface assignments](https://firewalld.org/documentation/zone/connections-interfaces-and-sources)
- [Docker forwarding and DNAT](https://docs.docker.com/engine/network/firewall-iptables/)
- [BunkerWeb compatibility contract](../v5/BUNKERWEB_COMPATIBILITY.md)
