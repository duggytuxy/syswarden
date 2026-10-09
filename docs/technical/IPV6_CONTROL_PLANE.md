# IPv6 control-plane preservation

The v4.10.4 source candidate addresses issue #304. It is not a publication or
IVV acceptance statement. The latest published release remains v4.10.3 until
protected publication and independent public verification are complete.

## Policy boundary

An IPv6 host depends on traffic that is not necessarily associated with an
established conntrack entry. Neighbour discovery and router advertisements can
be untracked. Dropping them can leave existing connections working briefly
while the default route, neighbour cache or address lease expires.

The generated `ipv6-control-plane` chain runs first in SysWarden's netdev ingress
and inet host input chains. It admits these bounded protocol classes:

| Traffic | Conditions |
| --- | --- |
| ICMPv6 errors | Destination unreachable, packet too big, time exceeded and parameter problem |
| Router advertisement | Link-local source, hop limit 255, code zero |
| Neighbour solicitation and advertisement | Hop limit 255, code zero, including DAD's unspecified source |
| Router solicitation | Link-local or unspecified source, hop limit 255, code zero |
| MLD query | Link-local source, hop limit one, code zero |
| MLD reports and done | Link-local or unspecified source, hop limit one, code zero |
| DHCPv6 client delivery | IPv6 UDP destination 546, independent of listener discovery |

DHCPv6 source ports are not restricted to 547: the current DHCPv6 specification
permits other source ports. The exception does not open IPv4 UDP 546 or create
a DHCPv6 server permission on port 547.

These permissions precede source reputation and geographic restrictions because
those restrictions cannot establish whether essential infrastructure packets
belong to a permitted application. They do not permit arbitrary application
traffic from the router, DHCP server or neighbour. Redirects and unsolicited
echo do not receive this exception. The existing policy continues to control
them, and the kernel still validates received protocol messages.

An accept in this chain does not override a drop in another nftables base chain.
Administrator-owned firewalld or UFW policy remains authoritative for its own
rules. The patch does not change IPv6 forwarding, router acceptance sysctls,
NetworkManager profiles, router trust or upstream switch policy. Hop limits
constrain packets to the local link; they do not authenticate an on-link router.

## Persistence and removal

The normal policy generator includes the extension on every installation,
reload and feed-driven regeneration. No manual nftables insertion is needed.
Post-apply verification checks the complete rule expressions, regular-chain
shape and first dispatch position in both product chains.

Runtime preservation recognizes the exact generated chain name in each of the
two product tables. It replaces those chains while keeping compatible dynamic
ban sets in the kernel, so reload, rollback and interrupted recovery do not
restart their expiration timers. The name exception does not permit other
hyphenated objects, lookalike names or a set with the chain's name.

The private writer receipt records the exact extension generation. Retirement
checks its complete source and live topology before normalizing that extension
for the existing full ownership model. Historical templates remain unchanged.
A missing generation, unknown generation or modified rule is not adopted as
product ownership. The same proof is used by standalone uninstall, native
remove and native purge.

## Administrator access

OS hardening no longer removes members of sudo, wheel or adm. Package scripts
cannot reliably identify every authorized administrator from SUDO_USER, and
the invoking user is not necessarily the only administrator. Existing account,
group and sudo policy remain administrator-owned.

The patch does not reconstruct memberships removed by a previous installation.
That recovery requires an administrator's known access policy; inferring or
granting roles automatically would create a separate access-control risk.

## Verification

The regression suite exercises old and corrected policies with real packets in
new user and network namespaces. It checks router lifetime refresh, neighbour
discovery, DHCPv6 delivery, ICMPv6 errors without an existing connection, strict
source filtering, rejected malformed or out-of-scope discovery, and reloads.
An independently accepting input chain demonstrates the base-chain interaction.
Kernel tests cover eight existing generation-input combinations, apply two
complete policy transactions per combination and reject a modified live
extension. A separate integration test checks live ban-set handles and expiry
through reload, failed verification, rollback and interrupted recovery with
both IPv6 chains present. With nftables 1.0.9, the suite also verifies
IPv6 delivery and exact extension normalization, but complete retirement remains
refused: that userland omits ingress device identities from its JSON output.
The test establishes the same refusal with the unmodified baseline and does not
count it as successful removal. Complete native removal requires a userland
that exposes all ownership evidence.

Filesystem-isolated hardening tests preserve multiple administrators with and
without SUDO_USER.

Run the mandatory local kernel regression without touching the host firewall:

```sh
SYSWARDEN_REQUIRE_IPV6_KERNEL=1 go test ./pkg/firewall -run '^TestIPv6ControlPlaneKernel$' -count=1 -v
```

Run that command from `src/core/syswarden-cli`. It requires Linux, nftables,
iproute2 and support for unprivileged user and network namespaces. Failure to
provide the namespace is a test failure when the required flag is set. These
tests do not replace native package IVV, reboot checks or verification on the
target distribution and kernel.

Canonical operator documentation is maintained at [syswarden.io/docs](https://syswarden.io/docs/).

## Protocol references

- [RFC 4890: ICMPv6 filtering recommendations](https://www.rfc-editor.org/rfc/rfc4890.html), especially sections 4.3 and 4.4.
- [RFC 4861: Neighbour discovery](https://www.rfc-editor.org/rfc/rfc4861.html), including router advertisement and neighbour message validation.
- [RFC 9915: DHCPv6](https://www.rfc-editor.org/rfc/rfc9915.html), section 7.2 for client and server ports.
- [nftables base-chain verdict semantics](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).
