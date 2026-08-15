package firewall

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var interfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

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

func canonicalPolicyNetworks(defaults []string, configured string) ([]string, error) {
	values := append([]string(nil), defaults...)
	if configured != "" {
		values = append(values, strings.Fields(strings.ReplaceAll(configured, ",", " "))...)
	}
	canonical := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		network, _, err := canonicalIPOrPrefix(value)
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
	canonical, isIPv4, err := canonicalIPOrPrefix(value)
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
