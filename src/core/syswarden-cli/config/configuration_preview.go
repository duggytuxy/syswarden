package config

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

// ConfigurationEffect describes an effect to review before activation. It is
// neither a runtime observation nor permission to execute an operation.
type ConfigurationEffect struct {
	Area   string
	Detail string
}

// ConfigurationPreview contains only fixed descriptions, validated selectors
// and counts. It never exports policy values, credentials or mutation authority.
type ConfigurationPreview struct {
	ModulePlan         []string
	Effects            []ConfigurationEffect
	InputCount         int
	UnknownKeyCount    int
	DeprecatedKeyCount int
}

// PreviewConfiguration reads the current complete TOML through the same bounded
// snapshot and merged validation as ordinary editing. It performs no host probes,
// environment overlay, normalization, recovery or process-global configuration load.
func PreviewConfiguration(ctx context.Context, root string) (ConfigurationPreview, error) {
	if ctx == nil {
		return ConfigurationPreview{}, errors.New("configuration preview requires a context")
	}
	if err := ctx.Err(); err != nil {
		return ConfigurationPreview{}, err
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return ConfigurationPreview{}, errors.New("configuration preview root must be absolute and canonical")
	}
	target := userTOMLTarget()
	before, content, err := captureModuleEdit(root, target)
	if err != nil {
		return ConfigurationPreview{}, err
	}
	validated, err := validateModuleCandidate(root, target, content, before.identity(target))
	if err != nil {
		return ConfigurationPreview{}, err
	}
	if !sameUserModuleBaseline(before, validated) {
		return ConfigurationPreview{}, errors.New("configuration changed during preview")
	}
	if err := before.revalidate(root, false, nil); err != nil {
		return ConfigurationPreview{}, err
	}
	if err := ctx.Err(); err != nil {
		return ConfigurationPreview{}, err
	}
	count := len(before.moduleNames)
	if before.master != nil {
		count++
	}
	return ConfigurationPreview{
		ModulePlan: append([]string(nil), validated.report.ModulePlan...),
		Effects:    append([]ConfigurationEffect(nil), validated.effects...), InputCount: count,
		UnknownKeyCount: len(validated.report.UnknownKeys), DeprecatedKeyCount: len(validated.report.DeprecatedKeys),
	}, nil
}

// Keep descriptions tied to actual install/reload boundaries. Disabled choices
// can reconcile previously owned artifacts; they are not a blanket no-op or a
// promise to undo historical administrator settings. No endpoint or secret is shown.
func configurationEffects(c *ModularConfig) []ConfigurationEffect {
	if c == nil {
		return nil
	}
	effects := []ConfigurationEffect{}
	add := func(area, detail string) { effects = append(effects, ConfigurationEffect{Area: area, Detail: detail}) }
	if c.Network.PolicyMode == "host" {
		add("Firewall", "Host policy can restrict inbound access and selected traffic. Verify administrator access and independent firewall protection before activation.")
	} else {
		add("Firewall", "List policy adds the selected list overlay while preserving independent firewall protection. It is not a complete host access policy.")
	}
	switch c.Core.FirewallBackend {
	case "nftables":
		add("Firewall backend", "nftables is selected. Compatibility, ownership and existing live rules still require inspection.")
	case "iptables":
		add("Firewall backend", "iptables is selected. Compatibility, ownership and existing live rules still require inspection.")
	case "keep":
		add("Firewall backend", "Keep mode preserves the selected host firewall authority; product overlays still require compatibility and ownership checks.")
	}
	switch c.Network.Blocklists.ListChoice {
	case "1":
		add("Threat lists", "Standard Data-Shield lists are selected. Activation or refresh can download data and change product block sets.")
	case "2":
		add("Threat lists", "Critical Data-Shield lists are selected. Activation or refresh can download data and change product block sets.")
	case "3":
		add("Threat lists", "Custom feeds are selected. Review both address families, HTTPS sources and expected hashes in TOML before activation.")
	default:
		add("Threat lists", "No managed threat list is selected. Existing owned feed state may need reconciliation; persistent administrator entries are a separate policy.")
	}
	if c.Network.Blocklists.UseSpamhaus {
		add("Additional feeds", "The additional Spamhaus feed is selected; it can add remote downloads and product block entries.")
	}
	add("Scheduling and services", "Install/reload can reconcile product feed scheduling and service state even with no threat list selected. Reload normally restarts the core; suppressing that restart does not suppress other host changes.")
	if c.Network.Geo.Enabled || c.Network.ASN.Enabled {
		add("GeoIP and ASN", "Selected geographic or ASN policy changes address-based filtering. Allow selections are restrictive and need nonempty validated IPv4 and IPv6 populations; this preview does not resolve those populations.")
	}
	if len(c.Network.WhitelistIPs) > 0 || len(c.Network.LanSubnets) > 0 || c.Network.WhitelistInfra || c.Network.Saas.AllowMonitors || len(c.OperatorPolicy.Rules) > 0 {
		add("Address exceptions", fmt.Sprintf("Review %d configured whitelist entries, %d LAN prefixes and %d explicit operator rules. Infrastructure and SaaS selections can add access exceptions. Independent protection and effective rule ordering need runtime verification.", len(c.Network.WhitelistIPs), len(c.Network.LanSubnets), len(c.OperatorPolicy.Rules)))
	}
	if c.Network.Wireguard.Enabled {
		add("WireGuard", "Selected VPN setup can create tunnel configuration, enable a service, change forwarding and add scoped firewall/NAT rules. Review tunnel routing and existing ownership before activation; older policy migration has separate recovery requirements.")
	} else {
		add("WireGuard", "VPN setup is not selected. Existing product-owned VPN state may require bounded reconciliation; disabling the selection does not authorize removal of administrator VPN state.")
	}
	if c.Security.DetectionEnabled || c.WAAP.Enabled || c.Security.L2.EnableL2 || c.Security.L2.ARPProtect {
		detail := "Selected detection consumes local events; authenticated producer authority, source ownership, expiry and runtime enforcement still require verification."
		if c.WAAP.EnforcementMode == "audit" {
			detail += " WAAP audit mode is selected; other firewall policy remains independent."
		}
		add("Detection", detail)
	}
	if c.WAAP.LogBridgeEnabled {
		add("WAF log bridge", "The selected bridge can change owned rsyslog configuration and service state to forward configured application logs. Review trusted producers and local log access.")
	} else {
		add("WAF log bridge", "The bridge is not selected. Activation can retire verified owned bridge configuration and reload rsyslog while preserving unrelated logging.")
	}
	if c.Integrations.SIEM.Enabled {
		add("SIEM", "Selected SIEM forwarding can send host logs to the configured receiver and reconcile rsyslog. Review transport, receiver authentication and disclosure of log contents.")
	} else {
		add("SIEM", "SIEM forwarding is not selected. Activation can retire verified owned forwarding configuration and reconcile rsyslog; unrelated forwarding must remain.")
	}
	if c.Integrations.Wazuh.Enabled {
		add("Wazuh", "Install can add product log inputs to an independently installed Wazuh agent and change its configuration/service state. Reload alone does not run this integration step. The agent must already be installed; preview does not install or enroll it.")
	}
	if c.Integrations.Webhooks.Enabled {
		add("Webhooks", "External notification endpoints are selected. Install can send a connectivity notification containing the host name; runtime events can disclose event data. Preview sends nothing.")
	}
	if c.Integrations.AbuseIPDB.Enabled && !c.Core.EnterpriseMode {
		add("AbuseIPDB", "External reporting is selected. The core reads its API key from TOML and authorized runtime events can be reported externally. Install/reload do not write a separate credential file. Preview does not validate remote credentials or send reports.")
	} else {
		add("AbuseIPDB", "Reporting is disabled by selection or enterprise mode. Install/reload preserve any historical credential file; its ownership and external consumers require separate review.")
	}
	if c.Integrations.HA.Enabled {
		add("HA synchronization", "Selected synchronization can add peer access rules and product scheduling, and transfer policy data. Peer identity, authentication and conflict handling require separate verification.")
	} else {
		add("HA synchronization", "Synchronization is not selected. Activation can remove the product synchronization schedule; independently managed peers and protection remain separate.")
	}
	if c.Integrations.BunkerWeb.Enabled {
		add("BunkerWeb", "The selected integration remains independent from native HA. Its settings, source ownership, expiry and synchronization need separate verification; selection does not transfer ownership of BunkerWeb policy to SysWarden.")
	}
	switch c.SSH.Hardening {
	case "forwarding":
		add("Dedicated SSH selection", "The forwarding profile is selected in the dedicated SSH module. It is not applied by preview, install or reload.")
	case "cis":
		add("Dedicated SSH selection", "The CIS profile is selected in the dedicated SSH module. It is not applied by preview, install or reload.")
	default:
		add("Dedicated SSH selection", "No forward SSH hardening is selected. This does not undo existing SSH policy.")
	}
	add("System hardening selection", fmt.Sprintf("OS hardening selected: %t. CIS level 2 selected: %t. Neither choice grants activation or rollback authority.", c.Core.Hardening, c.Core.CISL2Hardening))
	add("SSH and system hardening", "Install/reload preserve SSH, CIS and OS policy. TOML selection is not approval for migration or hardening. Dedicated SSH activation requires its protected review, authenticated access and recovery workflow.")
	add("Installation prerequisites", "Manual activation can require selected module dependencies and native service preparation. This preview does not install packages, attest prerequisites or determine whether existing service choices permit activation.")
	return effects
}
