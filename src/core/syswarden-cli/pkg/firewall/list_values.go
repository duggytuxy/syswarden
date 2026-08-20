package firewall

import (
	"fmt"
	"net"
	"strings"
)

type canonicalListEntry struct {
	network string
	port    string
	isIPv4  bool
}

func parseCanonicalListEntry(value string, allowPort bool) (canonicalListEntry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return canonicalListEntry{}, fmt.Errorf("list entry is empty")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return canonicalListEntry{}, fmt.Errorf("list entry contains a forbidden control character")
	}
	if canonical, isIPv4, err := canonicalIPOrPrefix(value); err == nil {
		return canonicalListEntry{network: canonical, isIPv4: isIPv4}, nil
	}
	if !allowPort {
		return canonicalListEntry{}, fmt.Errorf("invalid IP address or CIDR %q", value)
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return canonicalListEntry{}, fmt.Errorf("invalid address and port %q", value)
	}
	canonical, isIPv4, err := canonicalIPOrPrefix(host)
	if err != nil {
		return canonicalListEntry{}, err
	}
	port, err := canonicalPort(rawPort)
	if err != nil {
		return canonicalListEntry{}, err
	}
	return canonicalListEntry{network: canonical, port: port, isIPv4: isIPv4}, nil
}

func newCanonicalListEntry(network, port string) (canonicalListEntry, error) {
	entry, err := parseCanonicalListEntry(network, false)
	if err != nil {
		return canonicalListEntry{}, err
	}
	if port == "" {
		return entry, nil
	}
	entry.port, err = canonicalPort(port)
	if err != nil {
		return canonicalListEntry{}, err
	}
	return entry, nil
}

// ValidateWhitelistEntry applies the exact parser used by persistent whitelist
// writes without mutating the registry or the active firewall policy.
func ValidateWhitelistEntry(network, port string) error {
	_, err := newCanonicalListEntry(network, port)
	return err
}

func newCanonicalSSHBypassEntry(network, requestedPort, effectivePort string) (canonicalListEntry, error) {
	canonicalEffectivePort, err := canonicalPort(effectivePort)
	if err != nil {
		return canonicalListEntry{}, fmt.Errorf("invalid effective SSH port: %w", err)
	}
	entry, err := newCanonicalListEntry(network, requestedPort)
	if err != nil {
		return canonicalListEntry{}, err
	}
	if entry.port != "" && entry.port != canonicalEffectivePort {
		return canonicalListEntry{}, fmt.Errorf("SSH bypass port %s does not match the effective SSH port %s", entry.port, canonicalEffectivePort)
	}
	return entry, nil
}

func (entry canonicalListEntry) String() string {
	if entry.port == "" {
		return entry.network
	}
	return net.JoinHostPort(entry.network, entry.port)
}

func sameListNetwork(left, right canonicalListEntry) bool {
	return left.network == right.network && left.isIPv4 == right.isIPv4
}

func sameListEntry(left, right canonicalListEntry) bool {
	return sameListNetwork(left, right) && left.port == right.port
}

func listContentContainsNetwork(content []byte, target canonicalListEntry) bool {
	for _, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseCanonicalListEntry(line, true)
		if err == nil && sameListNetwork(entry, target) {
			return true
		}
	}
	return false
}

func nftRulesetContainsExactNetwork(content []byte, target canonicalListEntry) bool {
	fields := strings.FieldsFunc(string(content), func(character rune) bool {
		switch character {
		case ' ', '\t', '\r', '\n', '{', '}', ',', ';', '(', ')', '"', '\'':
			return true
		default:
			return false
		}
	})
	for _, field := range fields {
		entry, err := parseCanonicalListEntry(field, true)
		if err == nil && sameListNetwork(entry, target) {
			return true
		}
	}
	return false
}
