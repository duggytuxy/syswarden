package firewall

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// HealthState describes whether a firewall manager can enforce all, some, or
// none of its configured blocking layers.
type HealthState string

const (
	HealthHealthy     HealthState = "healthy"
	HealthDegraded    HealthState = "degraded"
	HealthUnavailable HealthState = "unavailable"
)

// HealthReporter is implemented by every built-in firewall manager without
// widening the historical Manager interface used by integrations.
type HealthReporter interface {
	Health() HealthState
}

const (
	MinimumBanTTL = time.Second
	MaximumBanTTL = 30 * 24 * time.Hour
)

// BanWithTTLManager is an additive capability for backends that can enforce
// expiration in the kernel. The historical Manager interface remains stable.
type BanWithTTLManager interface {
	BanWithTTL(entry string, ttl time.Duration) error
}

// BanPermanentManager is an additive capability for callers that require an
// entry with no kernel expiry. Manager.Ban keeps its historical bounded
// lifetime for compatibility.
type BanPermanentManager interface {
	BanPermanent(entry string) error
}

// BanTTLReconciler atomically replaces a native timed ban with the exact
// remaining lifetime selected by a multi-source ledger. Unlike BanWithTTL, it
// is allowed to shorten a longer kernel expiry when that longer source was
// removed.
type BanTTLReconciler interface {
	ReconcileBanTTL(entry string, ttl time.Duration) error
}

type BanExpiryMode string

const (
	BanExpiryNative   BanExpiryMode = "native"
	BanExpiryExternal BanExpiryMode = "external"
)

// BanExpiryReporter lets callers decide whether they must persist an expiry
// and call Unban themselves. A backend must not advertise native expiry unless
// BanWithTTL is enforced and verified in the kernel.
type BanExpiryReporter interface {
	BanExpiryMode() BanExpiryMode
}

func validateBanTTL(ttl time.Duration) error {
	if ttl < MinimumBanTTL || ttl > MaximumBanTTL {
		return fmt.Errorf("ban TTL %s is outside %s..%s", ttl, MinimumBanTTL, MaximumBanTTL)
	}
	if ttl%time.Second != 0 {
		return fmt.Errorf("ban TTL %s must use whole-second precision", ttl)
	}
	return nil
}

type firewallEntry struct {
	text   string
	key    []byte
	keyEnd []byte
}

func parseFirewallEntry(value string) (firewallEntry, error) {
	if ip := net.ParseIP(value); ip != nil {
		if strings.Contains(value, ":") && ip.To4() != nil {
			return firewallEntry{}, fmt.Errorf("IPv4-mapped IPv6 addresses are not supported: %s", value)
		}
		key := ip.To16()
		if ipv4 := ip.To4(); ipv4 != nil {
			key = ipv4
		}
		return firewallEntry{text: ip.String(), key: append([]byte(nil), key...)}, nil
	}

	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return firewallEntry{}, fmt.Errorf("invalid IP address or CIDR: %s", value)
	}
	if len(network.Mask) == net.IPv6len && network.IP.To4() != nil {
		return firewallEntry{}, fmt.Errorf("IPv4-mapped IPv6 prefixes are not supported: %s", value)
	}
	first := network.IP.To16()
	mask := network.Mask
	if ipv4 := network.IP.To4(); ipv4 != nil {
		first = ipv4
		if len(mask) != net.IPv4len {
			mask = mask[len(mask)-net.IPv4len:]
		}
	}
	last := make([]byte, len(first))
	for index := range first {
		last[index] = first[index] | ^mask[index]
	}
	ones, _ := network.Mask.Size()
	return firewallEntry{
		text:   fmt.Sprintf("%s/%d", net.IP(first).String(), ones),
		key:    append([]byte(nil), first...),
		keyEnd: last,
	}, nil
}
