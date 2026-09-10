package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// RecoverableMutation describes one exact desired firewall state. It is kept
// deliberately small so security subsystems can durably journal their own
// model before asking the authoritative firewall manager to mutate the host.
type RecoverableMutation struct {
	Entry     string
	Present   bool
	Permanent bool
	TTL       time.Duration
	// PreserveStronger keeps an existing permanent or longer timed ban.
	// The default remains exact reconciliation for HA v2 transactions.
	PreserveStronger bool
}

// RecoverableMutationHooks are executed while the shared inter-process
// firewall lock is held. Prepare must durably publish a WAL record, Persist
// must publish the caller's post-mutation model, and Commit must durably retire
// the WAL record. A failure leaves the WAL available for idempotent recovery.
type RecoverableMutationHooks struct {
	Prepare func() error
	Persist func() error
	Commit  func() error
	// Observation hooks run under the same lock, before Prepare and Persist.
	// A caller requiring native lifecycle evidence supplies both hooks.
	ObserveBefore func(NativeRuntimeEntrySnapshot) error
	ObserveAfter  func(NativeRuntimeEntrySnapshot) error
}

// NativeRuntimeEntrySnapshot attests exact element agreement in all expected
// native sets. ExpiresAt is a conservative upper bound on kernel expiration.
type NativeRuntimeEntrySnapshot struct {
	Entry      string
	CapturedAt time.Time
	Present    bool
	Permanent  bool
	ExpiresAt  time.Time
}

// NativeRuntimeStateReader holds the host firewall lock through the callback.
// A callback must not reenter the firewall manager. No snapshot is returned
// when any expected layer is missing, unreadable, or inconsistent.
type NativeRuntimeStateReader interface {
	WithNativeRuntimeSnapshot(context.Context, []string, func([]NativeRuntimeEntrySnapshot) error) error
}

type RuntimeLifecycleClaimSnapshot struct {
	Entry        string `json:"entry"`
	Generation   uint64 `json:"generation"`
	State        string `json:"state"`
	Cause        string `json:"cause"`
	CreatedAt    string `json:"created_at"`
	TransitionAt string `json:"transition_at"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	ConfirmedAt  string `json:"confirmed_at,omitempty"`
}

// RuntimeLifecycleSnapshot describes the local durable native history. Its
// identity is not an HA cluster and its sequence is not a peer checkpoint.
type RuntimeLifecycleSnapshot struct {
	SchemaVersion int                             `json:"schema_version"`
	Identity      string                          `json:"identity"`
	Sequence      uint64                          `json:"sequence"`
	ModelSHA256   string                          `json:"model_sha256"`
	UpdatedAt     string                          `json:"updated_at"`
	CapturedAt    string                          `json:"captured_at"`
	Active        int                             `json:"active"`
	Expired       int                             `json:"expired"`
	Deleted       int                             `json:"deleted"`
	Tombstoned    int                             `json:"tombstoned"`
	Truncated     bool                            `json:"truncated"`
	Claims        []RuntimeLifecycleClaimSnapshot `json:"claims"`
}

type RuntimeLifecycleStateReporter interface {
	RuntimeLifecycleStateSnapshot(limit int) (RuntimeLifecycleSnapshot, error)
}

// RecoverableMutationManager couples a caller-owned durable model to the
// authoritative firewall mutation under one shared host lock.
type RecoverableMutationManager interface {
	RunRecoverableMutation(context.Context, RecoverableMutation, RecoverableMutationHooks) error
}

// HAReplicationClaimSnapshot is a bounded, read-only view of one HA v2 claim.
// State is one of active, expired, deleted, or tombstoned.
type HAReplicationClaimSnapshot struct {
	Owner          string `json:"owner"`
	Source         string `json:"source"`
	IP             string `json:"ip"`
	State          string `json:"state"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	TombstoneUntil string `json:"tombstone_until,omitempty"`
}

type HAReplicationSnapshot struct {
	SchemaVersion        int                          `json:"schema_version"`
	ClusterID            string                       `json:"cluster_id"`
	Epoch                uint64                       `json:"epoch"`
	NodeID               string                       `json:"node_id"`
	Role                 string                       `json:"role"`
	Coordination         string                       `json:"coordination"`
	ModelSHA256          string                       `json:"model_sha256"`
	CheckpointSHA256     string                       `json:"checkpoint_sha256"`
	PeerCheckpointSHA256 string                       `json:"peer_checkpoint_sha256,omitempty"`
	CheckpointAt         string                       `json:"checkpoint_at"`
	CapturedAt           string                       `json:"captured_at"`
	Active               int                          `json:"active"`
	Expired              int                          `json:"expired"`
	Deleted              int                          `json:"deleted"`
	Tombstoned           int                          `json:"tombstoned"`
	Truncated            bool                         `json:"truncated"`
	Claims               []HAReplicationClaimSnapshot `json:"claims"`
}

// HAReplicationStateReporter exposes no mutator, key material, or transport
// metadata. Callers must select a bound from 1 through 1024 records.
type HAReplicationStateReporter interface {
	HAReplicationStateSnapshot(limit int) (HAReplicationSnapshot, error)
}

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
