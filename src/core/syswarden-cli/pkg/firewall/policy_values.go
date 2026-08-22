package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var interfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

const (
	minimumFirewallListIPv4PrefixBits = 24
	minimumFirewallListIPv6PrefixBits = 64
)

// deniedFirewallListPrefixes contains IANA special-purpose networks that must
// not be introduced into persistent firewall block, allow, or SSH bypass
// lists. RFC 1918, IPv6 unique-local, and documentation networks remain
// available for operator-managed LAN and deterministic fixture use, subject
// to the prefix floor below.
var deniedFirewallListPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
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
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2620:4f:8000::/48"),
	netip.MustParsePrefix("3ffe::/16"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// deniedSaaSMonitorPrefixes extends the persistent list policy with public
// documentation ranges. SaaS monitor data is an externally supplied ACCEPT
// authority and must never whitelist private or example space.
var deniedSaaSMonitorPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

// deniedLANPolicyPrefixes is intentionally narrower than the persistent list
// policy. LAN configuration may legitimately contain broad private networks
// and the historical loopback default, but it must never trust unspecified,
// link-local, multicast, or reserved destination space.
var deniedLANPolicyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func canonicalIPOrPrefix(value string) (string, bool, error) {
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Zone() != "" {
			return "", false, fmt.Errorf("scoped IP addresses are not supported: %q", value)
		}
		if address.Is4In6() {
			return "", false, fmt.Errorf("IPv4-mapped IPv6 addresses are not supported: %q", value)
		}
		return address.String(), address.Is4(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", false, fmt.Errorf("invalid IP address or CIDR %q", value)
	}
	if prefix.Addr().Is4In6() {
		return "", false, fmt.Errorf("IPv4-mapped IPv6 prefixes are not supported: %q", value)
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	return prefix.String(), address.Is4(), nil
}

func canonicalNetworkPrefix(value string) (netip.Prefix, bool, error) {
	canonical, _, err := canonicalIPOrPrefix(value)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	if address, parseErr := netip.ParseAddr(canonical); parseErr == nil {
		return netip.PrefixFrom(address, address.BitLen()), true, nil
	}
	prefix, err := netip.ParsePrefix(canonical)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("invalid canonical IP prefix %q", canonical)
	}
	return prefix.Masked(), false, nil
}

func networkPrefixesOverlap(left, right netip.Prefix) bool {
	if left.Addr().BitLen() != right.Addr().BitLen() {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func overlapsAnyNetwork(prefix netip.Prefix, denied []netip.Prefix) bool {
	for _, candidate := range denied {
		if networkPrefixesOverlap(prefix, candidate) {
			return true
		}
	}
	return false
}

func canonicalFirewallListNetwork(value string) (string, bool, error) {
	if parsed, err := netip.ParsePrefix(value); err == nil && parsed != parsed.Masked() {
		return "", false, fmt.Errorf("firewall list prefix %q has host bits set", value)
	}
	prefix, isHost, err := canonicalNetworkPrefix(value)
	if err != nil {
		return "", false, err
	}
	minimumBits := minimumFirewallListIPv6PrefixBits
	if prefix.Addr().Is4() {
		minimumBits = minimumFirewallListIPv4PrefixBits
	}
	if !isHost && prefix.Bits() < minimumBits {
		return "", false, fmt.Errorf("firewall list prefix %q is broader than /%d", value, minimumBits)
	}
	if !prefix.Addr().IsGlobalUnicast() || overlapsAnyNetwork(prefix, deniedFirewallListPrefixes) {
		return "", false, fmt.Errorf("firewall list entry %q is non-routable or special-use", value)
	}
	if isHost {
		return prefix.Addr().String(), prefix.Addr().Is4(), nil
	}
	return prefix.String(), prefix.Addr().Is4(), nil
}

func canonicalSaaSMonitorNetwork(value string) (string, bool, netip.Prefix, error) {
	canonical, isIPv4, err := canonicalFirewallListNetwork(value)
	if err != nil {
		return "", false, netip.Prefix{}, err
	}
	prefix, _, err := canonicalNetworkPrefix(canonical)
	if err != nil {
		return "", false, netip.Prefix{}, err
	}
	if prefix.Addr().IsPrivate() || overlapsAnyNetwork(prefix, deniedSaaSMonitorPrefixes) {
		return "", false, netip.Prefix{}, fmt.Errorf("SaaS monitor entry %q is private or special-use", value)
	}
	return canonical, isIPv4, prefix, nil
}

func canonicalLANPolicyNetwork(value string) (string, bool, error) {
	prefix, isHost, err := canonicalNetworkPrefix(value)
	if err != nil {
		return "", false, err
	}
	if prefix.Bits() == 0 || overlapsAnyNetwork(prefix, deniedLANPolicyPrefixes) {
		return "", false, fmt.Errorf("LAN subnet %q contains unsafe address space", value)
	}
	if isHost {
		return prefix.Addr().String(), prefix.Addr().Is4(), nil
	}
	return prefix.String(), prefix.Addr().Is4(), nil
}

func canonicalPolicyNetworks(defaults []string, configured string) ([]string, error) {
	values := append([]string(nil), defaults...)
	if configured != "" {
		values = append(values, strings.Fields(strings.ReplaceAll(configured, ",", " "))...)
	}
	canonical := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		network, _, err := canonicalLANPolicyNetwork(value)
		if err != nil {
			return nil, fmt.Errorf("invalid LAN subnet: %w", err)
		}
		if _, exists := seen[network]; exists {
			continue
		}
		seen[network] = struct{}{}
		canonical = append(canonical, network)
	}
	return canonical, nil
}

func splitPolicyNetworksByFamily(networks []string) ([]string, []string, error) {
	ipv4 := make([]string, 0, len(networks))
	ipv6 := make([]string, 0, len(networks))
	for _, value := range networks {
		canonical, isIPv4, err := canonicalIPOrPrefix(value)
		if err != nil {
			return nil, nil, err
		}
		if isIPv4 {
			ipv4 = append(ipv4, canonical)
		} else {
			ipv6 = append(ipv6, canonical)
		}
	}
	return ipv4, ipv6, nil
}

func canonicalIPv4Network(value, label string) (string, error) {
	canonical, isIPv4, err := canonicalLANPolicyNetwork(value)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", label, err)
	}
	if !isIPv4 {
		return "", fmt.Errorf("invalid %s: expected an IPv4 address or prefix", label)
	}
	return canonical, nil
}

func canonicalPort(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("port is empty")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return "", fmt.Errorf("port %q is not decimal", value)
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("port %q is outside 1..65535", value)
	}
	return strconv.Itoa(port), nil
}

func canonicalPorts(label string, values []string) ([]string, error) {
	canonical := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		port, err := canonicalPort(value)
		if err != nil {
			return nil, fmt.Errorf("invalid %s: %w", label, err)
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		canonical = append(canonical, port)
	}
	return canonical, nil
}

func canonicalInterfaceName(value string) (string, error) {
	if !interfaceNameRE.MatchString(value) {
		return "", fmt.Errorf("invalid network interface name %q", value)
	}
	return value, nil
}
