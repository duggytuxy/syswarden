package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

type canonicalListEntry struct {
	network string
	port    string
	isIPv4  bool
}

func parseCanonicalListEntry(value string, allowPort bool) (canonicalListEntry, error) {
	return parseCanonicalListEntryWith(value, allowPort, canonicalFirewallListNetwork)
}

// parseCanonicalRecoveryListEntry accepts syntactically valid legacy networks
// so an operator can inspect or remove policy that the strict mutation path
// now rejects. It must never be used to add or populate active firewall state.
func parseCanonicalRecoveryListEntry(value string, allowPort bool) (canonicalListEntry, error) {
	return parseCanonicalListEntryWith(value, allowPort, canonicalIPOrPrefix)
}

func parseCanonicalListEntryWith(
	value string,
	allowPort bool,
	canonicalize func(string) (string, bool, error),
) (canonicalListEntry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return canonicalListEntry{}, fmt.Errorf("list entry is empty")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return canonicalListEntry{}, fmt.Errorf("list entry contains a forbidden control character")
	}
	canonical, isIPv4, directErr := canonicalize(value)
	if directErr == nil {
		return canonicalListEntry{network: canonical, isIPv4: isIPv4}, nil
	}
	if !allowPort {
		return canonicalListEntry{}, directErr
	}
	if _, addressErr := netip.ParseAddr(value); addressErr == nil {
		return canonicalListEntry{}, directErr
	}
	if _, prefixErr := netip.ParsePrefix(value); prefixErr == nil {
		return canonicalListEntry{}, directErr
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return canonicalListEntry{}, fmt.Errorf("invalid address and port %q", value)
	}
	canonical, isIPv4, err = canonicalize(host)
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
		entry, err := parseCanonicalRecoveryListEntry(line, true)
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
		entry, err := parseCanonicalRecoveryListEntry(field, true)
		if err == nil && sameListNetwork(entry, target) {
			return true
		}
	}
	return false
}
