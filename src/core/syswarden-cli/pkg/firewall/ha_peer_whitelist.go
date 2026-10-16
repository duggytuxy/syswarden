package firewall

import (
	"fmt"
	"strings"

	"syswarden-cli/config"
)

// AllowConfiguredHAPeer grants only the configured peer's TCP API access. Unlike
// the manual whitelist command, this automatic mutation retains exact generated
// origin, without adopting an unmarked or administrator-modified list.
func AllowConfiguredHAPeer(peer, port string) error {
	entry, err := configuredHAPeerWhitelistEntry(peer, port)
	if err != nil {
		return err
	}
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before HA peer access: %w", err)
	}
	if err := EnsurePersistentWhitelistPair(); err != nil {
		return err
	}
	path := WhitelistV6
	if entry.isIPv4 {
		path = WhitelistV4
	}
	target, err := approvedListFileForPath(path)
	if err != nil {
		return err
	}
	return allowHAPeerAt(entry, target, ApplyPolicies)
}

func configuredHAPeerWhitelistEntry(peer, port string) (canonicalListEntry, error) {
	value := config.GlobalConfig
	if value == nil || !value.HAEnabled || port == "" || port != value.HAPeerPort {
		return canonicalListEntry{}, fmt.Errorf("automatic HA peer access requires the enabled configured API port")
	}
	entry, err := newCanonicalListEntry(peer, port)
	if err != nil || entry.port != port {
		return canonicalListEntry{}, fmt.Errorf("automatic HA peer access requires a canonical address and TCP port")
	}
	canonical, err := config.CanonicalHAPeer(peer)
	if err != nil || canonical != peer {
		return canonicalListEntry{}, fmt.Errorf("automatic HA peer access requires a canonical configured peer")
	}
	found := false
	for _, candidate := range strings.Fields(strings.ReplaceAll(value.HAPeerIP, ",", " ")) {
		configured, err := config.CanonicalHAPeer(candidate)
		if err != nil {
			return canonicalListEntry{}, fmt.Errorf("validate automatic HA peer configuration: %w", err)
		}
		found = found || configured == peer
	}
	if !found {
		return canonicalListEntry{}, fmt.Errorf("automatic HA peer access is outside the configured peer plan")
	}
	return entry, nil
}

func allowHAPeerAt(entry canonicalListEntry, target approvedListFile, apply func() error) error {
	if entry.port == "" || (entry.isIPv4 && target.name != "syswarden_whitelist.ipv4") ||
		(!entry.isIPv4 && target.name != "syswarden_whitelist.ipv6") {
		return fmt.Errorf("automatic HA peer access requires a port-scoped whitelist of the correct family")
	}
	mutation, err := addToListFileTransactionallyWithOrigin(target, entry.String(), true)
	mutations := []transactionalListMutation{mutation}
	if err != nil {
		return failWithTransactionalListRollback(err, mutations)
	}
	if err := apply(); err != nil {
		return failWithTransactionalListRollback(err, mutations)
	}
	return nil
}
