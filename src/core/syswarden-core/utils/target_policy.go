package utils

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// ErrProtectedFirewallTarget identifies a syntactically valid address that a
// trusted boundary must never pass to a firewall mutation.
var ErrProtectedFirewallTarget = errors.New("protected firewall target")

const (
	// MinimumFirewallIPv4PrefixBits is the conservative floor for externally
	// supplied IPv4 networks that can affect firewall policy.
	MinimumFirewallIPv4PrefixBits = 24
	// MinimumFirewallIPv6PrefixBits is the conservative floor for externally
	// supplied IPv6 networks that can affect firewall policy.
	MinimumFirewallIPv6PrefixBits = 64
)

// FirewallTargetPolicy describes the host-specific context needed to validate
// an address immediately before a firewall mutation. Mutation targets are
// intentionally limited to host addresses; network prefixes belong to policy
// and peer configuration boundaries, not event-driven ban paths.
type FirewallTargetPolicy struct {
	LocalAddresses    []netip.Addr
	ProtectedPrefixes []netip.Prefix
	IsWhitelisted     func(string) (bool, error)
}

// deniedFirewallTargetPrefixes tracks IANA special-purpose blocks that must
// not become dynamic DROP or downloaded ACCEPT policy. Generic loopback,
// private, multicast, and global-unicast checks remain in place as a second
// layer; explicit entries cover ranges those generic predicates classify as
// unicast. Sources: iana-ipv4-special-registry and iana-ipv6-special-registry.
var deniedFirewallTargetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("100:0:0:1::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// CanonicalFirewallMutationTarget returns one canonical public host address or
// rejects it. The caller supplies local/interface addresses, protected peers,
// and the authoritative whitelist so the final decision is made at the
// mutation boundary and remains deterministic in tests.
func CanonicalFirewallMutationTarget(value string, policy FirewallTargetPolicy) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.Contains(value, "/") {
		return "", fmt.Errorf("firewall mutation target must be one canonical host address")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.Is4In6() || address.Zone() != "" {
		return "", fmt.Errorf("invalid firewall mutation target")
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || deniedFirewallTarget(address) {
		return "", fmt.Errorf("%w: non-routable or special-use address", ErrProtectedFirewallTarget)
	}
	for _, local := range policy.LocalAddresses {
		if !local.IsValid() {
			return "", fmt.Errorf("invalid local interface address in firewall target policy")
		}
		if local.Unmap() == address {
			return "", fmt.Errorf("%w: local interface address", ErrProtectedFirewallTarget)
		}
	}
	for _, protected := range policy.ProtectedPrefixes {
		if !protected.IsValid() || protected.Addr().Is4In6() || protected.Addr().Zone() != "" || protected != protected.Masked() {
			return "", fmt.Errorf("invalid protected prefix in firewall target policy")
		}
		if protected.Contains(address) {
			return "", fmt.Errorf("%w: protected peer address", ErrProtectedFirewallTarget)
		}
	}
	if policy.IsWhitelisted == nil {
		return "", fmt.Errorf("firewall target whitelist policy is unavailable")
	}
	canonical := address.String()
	whitelisted, err := policy.IsWhitelisted(canonical)
	if err != nil {
		return "", fmt.Errorf("evaluate firewall target whitelist: %w", err)
	}
	if whitelisted {
		return "", fmt.Errorf("%w: whitelisted address", ErrProtectedFirewallTarget)
	}
	return canonical, nil
}

func deniedFirewallTarget(address netip.Addr) bool {
	for _, prefix := range deniedFirewallTargetPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// FirewallNetworkPolicy describes contextual protections for externally
// supplied IP/CIDR entries that become firewall policy. Prefix floors are
// fixed centrally to avoid a permissive caller-specific interpretation.
type FirewallNetworkPolicy struct {
	LocalAddresses    []netip.Addr
	ProtectedPrefixes []netip.Prefix
}

// CanonicalFirewallNetworkEntry validates one public IP or conservatively
// bounded CIDR before it can be published as firewall policy.
func CanonicalFirewallNetworkEntry(value string, policy FirewallNetworkPolicy) (string, bool, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", false, fmt.Errorf("firewall network entry must not contain surrounding whitespace")
	}
	var prefix netip.Prefix
	isAddress := false
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", false, fmt.Errorf("invalid firewall network address")
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
		isAddress = true
	} else {
		parsed, err := netip.ParsePrefix(value)
		if err != nil || !parsed.IsValid() || parsed.Addr().Is4In6() || parsed.Addr().Zone() != "" {
			return "", false, fmt.Errorf("invalid firewall network entry")
		}
		prefix = parsed.Masked()
	}
	minimumBits := MinimumFirewallIPv6PrefixBits
	if prefix.Addr().Is4() {
		minimumBits = MinimumFirewallIPv4PrefixBits
	}
	if prefix.Bits() < minimumBits {
		return "", false, fmt.Errorf("firewall network prefix is broader than the /%d minimum", minimumBits)
	}
	if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
		return "", false, fmt.Errorf("%w: non-routable or special-use network", ErrProtectedFirewallTarget)
	}
	for _, denied := range deniedFirewallTargetPrefixes {
		if networkPrefixesOverlap(prefix, denied) {
			return "", false, fmt.Errorf("%w: non-routable or special-use network", ErrProtectedFirewallTarget)
		}
	}
	for _, local := range policy.LocalAddresses {
		if !local.IsValid() {
			return "", false, fmt.Errorf("invalid local interface address in firewall network policy")
		}
		if prefix.Contains(local.Unmap()) {
			return "", false, fmt.Errorf("%w: network contains a local interface address", ErrProtectedFirewallTarget)
		}
	}
	for _, protected := range policy.ProtectedPrefixes {
		if !protected.IsValid() || protected.Addr().Is4In6() || protected.Addr().Zone() != "" || protected != protected.Masked() {
			return "", false, fmt.Errorf("invalid protected prefix in firewall network policy")
		}
		if networkPrefixesOverlap(prefix, protected) {
			return "", false, fmt.Errorf("%w: network overlaps a protected peer", ErrProtectedFirewallTarget)
		}
	}
	if isAddress {
		return prefix.Addr().String(), prefix.Addr().Is4(), nil
	}
	return prefix.String(), prefix.Addr().Is4(), nil
}

func networkPrefixesOverlap(first, second netip.Prefix) bool {
	if first.Addr().BitLen() != second.Addr().BitLen() {
		return false
	}
	return first.Contains(second.Addr()) || second.Contains(first.Addr())
}

// LocalInterfaceAddresses returns canonical host addresses currently assigned
// to local interfaces. An enumeration or parsing failure is returned so a
// privileged caller can fail closed rather than mutate with incomplete state.
func LocalInterfaceAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate local interfaces: %w", err)
	}
	seen := make(map[netip.Addr]struct{})
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("enumerate addresses for interface %q: %w", networkInterface.Name, err)
		}
		for _, raw := range addresses {
			address, err := interfaceAddress(raw)
			if err != nil {
				return nil, fmt.Errorf("parse address for interface %q: %w", networkInterface.Name, err)
			}
			seen[address] = struct{}{}
		}
	}
	result := make([]netip.Addr, 0, len(seen))
	for address := range seen {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result, nil
}

func interfaceAddress(raw net.Addr) (netip.Addr, error) {
	var ip net.IP
	switch value := raw.(type) {
	case *net.IPNet:
		ip = value.IP
	case *net.IPAddr:
		ip = value.IP
	default:
		return netip.Addr{}, fmt.Errorf("unsupported interface address type %T", raw)
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok || !address.IsValid() {
		return netip.Addr{}, fmt.Errorf("invalid interface address")
	}
	return address.Unmap(), nil
}
