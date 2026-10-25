//go:build linux

package wireguardstate

import "fmt"

// ScopedServerPostUp renders the v2 policy from already validated fields.
// Unrelated forwarding continues through the administrator's other chains.
// The terminal tunnel drops reject unsupported paths, including IPv6.
func ScopedServerPostUp(identity ServerConfigurationIdentity) string {
	return fmt.Sprintf(`%s 'create table inet syswarden_wg { comment "syswarden-wg-v2:%s"; }; add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }; add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }; add chain inet syswarden_wg forward { type filter hook forward priority 0; policy accept; }; add rule inet syswarden_wg postrouting iifname "wg-syswarden" oifname "%s" ip saddr %s masquerade; add rule inet syswarden_wg forward %s; add rule inet syswarden_wg forward %s; add rule inet syswarden_wg forward iifname "wg-syswarden" drop; add rule inet syswarden_wg forward oifname "wg-syswarden" drop'`,
		identity.NFTPath, identity.OwnershipToken, identity.ActiveInterface, identity.IPv4Subnet,
		ScopedForwardExpression(identity, false), ScopedForwardExpression(identity, true))
}

// ScopedForwardExpression renders an IPv4 tunnel permit from validated fields.
func ScopedForwardExpression(identity ServerConfigurationIdentity, reply bool) string {
	if reply {
		return fmt.Sprintf(`iifname "%s" oifname "wg-syswarden" ip daddr %s ct state { established, related } accept`, identity.ActiveInterface, identity.IPv4Subnet)
	}
	return fmt.Sprintf(`iifname "wg-syswarden" oifname "%s" ip saddr %s ct state { established, related, new } accept`, identity.ActiveInterface, identity.IPv4Subnet)
}

// ScopedSharedForwardPostUpSuffix replaces historical broad allowances only
// during the explicit legacy migration. The surrounding chain remains shared.
func ScopedSharedForwardPostUpSuffix(identity ServerConfigurationIdentity) string {
	return fmt.Sprintf(`; insert rule inet filter forward %s comment "syswarden-wg-forward-v2:%s"; insert rule inet filter forward %s comment "syswarden-wg-forward-v2:%s"`,
		ScopedForwardExpression(identity, false), identity.OwnershipToken,
		ScopedForwardExpression(identity, true), identity.OwnershipToken)
}
