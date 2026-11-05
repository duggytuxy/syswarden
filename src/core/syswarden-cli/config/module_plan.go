package config

import "fmt"

// ModulePlan contains selection flags only. It never includes endpoint names,
// addresses, credentials, tokens, source bytes or claims of runtime acceptance.
func ModulePlan(c *Config) []string {
	if c == nil {
		return nil
	}
	profile := c.InstallProfile
	if profile == "" {
		profile = "historical (preserved)"
	}
	lines := []string{"Installation profile: " + profile, "Firewall policy: " + c.FirewallPolicyMode, "Threat list choice: " + c.ListChoice, "Managed list sources: Data-Shield only; legacy OSINT selection is inactive."}
	for _, entry := range []struct {
		name    string
		enabled bool
	}{
		{"WAAP", c.WAAPEnabled}, {"WAF log bridge", c.LogBridgeEnabled},
		{"Local detection", c.DetectionEnabled}, {"GeoIP", c.EnableGeo}, {"ASN", c.EnableASN},
		{"Layer 2 detection", c.EnableL2}, {"ARP protection", c.ArpProtect}, {"WireGuard", c.EnableWG},
		{"HA", c.HAEnabled}, {"BunkerWeb integration", c.BunkerWebEnabled}, {"SaaS allowlists", c.AllowSaaSMonitors},
		{"SIEM", c.SiemEnabled}, {"Wazuh", c.EnableWazuh}, {"AbuseIPDB", c.EnableAbuse}, {"Webhooks", c.EnableWebhook},
	} {
		lines = append(lines, fmt.Sprintf("%s selected: %t", entry.name, entry.enabled))
	}
	return append(lines, "SSH, CIS and OS policy: preserved by install/reload; selection is not migration approval.")
}
