//go:build linux

package firewall

import (
	"syswarden-cli/config"
	"syswarden-cli/pkg/network"
)

func configuredThreatIntelSelection(c *config.Config) network.ThreatIntelSelection {
	return network.ThreatIntelSelection{ListChoice: c.ListChoice, CustomURL: c.CustomURL, CustomURLIPv6: c.CustomURLIPv6, CustomHash: c.CustomHash, CustomHashIPv6: c.CustomHashIPv6, OSINTEnabled: c.OSINTEnabled, LANMode: c.LANMode}
}
