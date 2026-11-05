//go:build linux

package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
)

func validateWireGuardPolicyIdentity(identity wireguardstate.ServerConfigurationIdentity) error {
	switch identity.PolicyVersion {
	case 0:
		if identity.IPv4Subnet != "" {
			return fmt.Errorf("legacy WireGuard identity cannot claim a scoped subnet")
		}
	case 2:
		prefix, _, _, err := wireGuardHostAddresses(identity.IPv4Subnet)
		if err != nil || prefix.String() != identity.IPv4Subnet || identity.ActiveInterface == "wg-syswarden" {
			return fmt.Errorf("scoped WireGuard identity has an invalid subnet or egress")
		}
	default:
		return fmt.Errorf("unsupported WireGuard policy version")
	}
	return nil
}

func wireGuardPolicyTableComment(identity wireguardstate.ServerConfigurationIdentity) string {
	if identity.PolicyVersion == 2 {
		return "syswarden-wg-v2:" + identity.OwnershipToken
	}
	return wireGuardNFTTableOwnershipCommentPrefix + identity.OwnershipToken
}

func wireGuardScopedForwardOrder(identity wireguardstate.ServerConfigurationIdentity) []string {
	return []string{
		"iifname=wg-syswarden:oifname=" + identity.ActiveInterface + ":ip.saddr=" + identity.IPv4Subnet + ":ct.state=established,new,related:accept",
		"iifname=" + identity.ActiveInterface + ":oifname=wg-syswarden:ip.daddr=" + identity.IPv4Subnet + ":ct.state=established,related:accept",
		"iifname=wg-syswarden:drop",
		"oifname=wg-syswarden:drop",
	}
}

func wireGuardScopedRuleInventory(identity wireguardstate.ServerConfigurationIdentity) map[string]int {
	rules := map[string]int{
		"postrouting:iifname=wg-syswarden:oifname=" + identity.ActiveInterface + ":ip.saddr=" + identity.IPv4Subnet + ":masquerade": 1,
	}
	for _, signature := range wireGuardScopedForwardOrder(identity) {
		rules["forward:"+signature] = 1
	}
	return rules
}

// Keep the v1 decoder unchanged. The v2 decoder accepts only the small set of
// expressions emitted by the scoped generator, retaining their exact order.
func wireGuardScopedNFTExpressionSignature(expressions []map[string]json.RawMessage) (string, error) {
	if len(expressions) < 2 || len(expressions) > 5 {
		return "", fmt.Errorf("scoped WireGuard rule has an unexpected expression count")
	}
	parts := make([]string, 0, len(expressions))
	for _, expression := range expressions[:len(expressions)-1] {
		if len(expression) != 1 {
			return "", fmt.Errorf("scoped WireGuard match is ambiguous")
		}
		var match struct {
			Op    string                     `json:"op"`
			Left  map[string]json.RawMessage `json:"left"`
			Right json.RawMessage            `json:"right"`
		}
		if err := decodeStrictWireGuardNFTObject(expression["match"], &match, "scoped match"); err != nil || len(match.Left) != 1 {
			return "", fmt.Errorf("scoped WireGuard rule has an invalid match")
		}
		for kind, raw := range match.Left {
			switch kind {
			case "meta":
				var meta struct {
					Key string `json:"key"`
				}
				var value string
				if decodeStrictWireGuardNFTObject(raw, &meta, "scoped meta") != nil ||
					(meta.Key != "iifname" && meta.Key != "oifname") || match.Op != "==" ||
					json.Unmarshal(match.Right, &value) != nil || !wireGuardInterfaceName.MatchString(value) {
					return "", fmt.Errorf("scoped WireGuard interface match is not exact")
				}
				parts = append(parts, meta.Key+"="+value)
			case "payload":
				var payload struct {
					Protocol string `json:"protocol"`
					Field    string `json:"field"`
				}
				var value struct {
					Prefix struct {
						Addr string `json:"addr"`
						Len  int    `json:"len"`
					} `json:"prefix"`
				}
				if decodeStrictWireGuardNFTObject(raw, &payload, "scoped payload") != nil || payload.Protocol != "ip" ||
					(payload.Field != "saddr" && payload.Field != "daddr") || match.Op != "==" ||
					decodeStrictWireGuardNFTObject(match.Right, &value, "scoped prefix") != nil {
					return "", fmt.Errorf("scoped WireGuard address match is not exact")
				}
				prefix, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", value.Prefix.Addr, value.Prefix.Len))
				if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 30 {
					return "", fmt.Errorf("scoped WireGuard subnet is not canonical")
				}
				parts = append(parts, "ip."+payload.Field+"="+prefix.String())
			case "ct":
				var ct struct {
					Key string `json:"key"`
				}
				var value struct {
					Set []string `json:"set"`
				}
				if decodeStrictWireGuardNFTObject(raw, &ct, "scoped conntrack") != nil || ct.Key != "state" ||
					(match.Op != "in" && match.Op != "==") || decodeStrictWireGuardNFTObject(match.Right, &value, "scoped states") != nil || len(value.Set) < 2 || len(value.Set) > 3 {
					return "", fmt.Errorf("scoped WireGuard conntrack match is not exact")
				}
				sort.Strings(value.Set)
				states := strings.Join(value.Set, ",")
				if states != "established,related" && states != "established,new,related" {
					return "", fmt.Errorf("scoped WireGuard conntrack states are not owned")
				}
				parts = append(parts, "ct.state="+states)
			default:
				return "", fmt.Errorf("scoped WireGuard rule has an unsupported match")
			}
		}
	}
	terminal := expressions[len(expressions)-1]
	if len(terminal) == 1 {
		for _, action := range []string{"accept", "drop", "masquerade"} {
			if raw, ok := terminal[action]; ok && (bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || bytes.Equal(bytes.TrimSpace(raw), []byte("{}"))) {
				return strings.Join(append(parts, action), ":"), nil
			}
		}
	}
	return "", fmt.Errorf("scoped WireGuard terminal expression is not owned")
}
