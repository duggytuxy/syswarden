package config

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// loadOldConfig reads syswarden-auto.conf into an isolated candidate. The
// active configuration is replaced only after the complete file was read.
func loadOldConfig(path string) (loadErr error) {
	configLoadMu.Lock()
	defer configLoadMu.Unlock()
	defer func() {
		if loadErr != nil {
			recordConfigLoadFailure(path, loadErr)
		}
	}()

	content, identity, err := readSecureFileIdentityByPath(path)
	if err != nil {
		return fmt.Errorf("read legacy config file: %w", err)
	}

	candidate := NewFailSafeConfig()
	scanner := bufio.NewScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

		switch key {
		case "SYSWARDEN_ENTERPRISE_MODE":
			candidate.EnterpriseMode = parseBool(val)
		case "SYSWARDEN_ENFORCEMENT_MODE":
			candidate.EnforcementMode = val
		case "SYSWARDEN_SSH_PORT":
			candidate.SSHPort = val
		case "SYSWARDEN_FIREWALL_BACKEND":
			candidate.FirewallBackend = val
		case "SYSWARDEN_INTERFACES":
			candidate.Interfaces = val
		case "SYSWARDEN_WHITELIST_INFRA":
			candidate.WhitelistInfra = parseBool(val)
		case "SYSWARDEN_WHITELIST_IPS":
			candidate.WhitelistIPs = val
		case "SYSWARDEN_ENABLE_WG":
			candidate.EnableWG = parseBool(val)
		case "SYSWARDEN_WG_PORT":
			candidate.WGPort = val
		case "SYSWARDEN_WG_SUBNET":
			candidate.WGSubnet = val
		case "SYSWARDEN_MODSEC_LOGS":
			candidate.ModsecLogs = val
		case "SYSWARDEN_BRUTEFORCE_LOGS":
			candidate.BruteforceLogs = val
		case "SYSWARDEN_BRUTEFORCE_THRESHOLD":
			candidate.BruteforceThreshold = val
		case "SYSWARDEN_BRUTEFORCE_WINDOW":
			candidate.BruteforceWindow = val
		case "SYSWARDEN_HONEYPORTS":
			candidate.HoneyPorts = val
		case "SYSWARDEN_HARDENING":
			candidate.Hardening = parseBool(val)
		case "APPLY_CIS_L2_HARDENING", "SYSWARDEN_CIS_L2":
			candidate.CISL2Hardening = parseBool(val)
		case "SYSWARDEN_LIST_CHOICE":
			candidate.ListChoice = val
		case "SYSWARDEN_CUSTOM_URL":
			candidate.CustomURL = val
		case "SYSWARDEN_CUSTOM_URL_IPV6":
			candidate.CustomURLIPv6 = val
		case "SYSWARDEN_CUSTOM_HASH":
			candidate.CustomHash = val
		case "SYSWARDEN_CUSTOM_HASH_IPV6":
			candidate.CustomHashIPv6 = val
		case "SYSWARDEN_ENABLE_GEO":
			candidate.EnableGeo = parseBool(val)
		case "SYSWARDEN_GEO_CODES":
			candidate.GeoCodes = val
		case "SYSWARDEN_GEO_ALLOWED":
			candidate.GeoAllowed = val
		case "SYSWARDEN_ENABLE_ASN":
			candidate.EnableASN = parseBool(val)
		case "SYSWARDEN_ASN_LIST":
			candidate.ASNList = val
		case "SYSWARDEN_ASN_ALLOWED":
			candidate.ASNAllowed = val
		case "SYSWARDEN_USE_SPAMHAUS":
			candidate.UseSpamhaus = parseBool(val)
		case "SYSWARDEN_ALLOW_SAAS_MONITORS", "SYSWARDEN_ALLOW_MONITORS":
			candidate.AllowSaaSMonitors = parseBool(val)
		case "SYSWARDEN_HA_ENABLED":
			candidate.HAEnabled, err = parseLegacyBoolValue(key, val)
			if err != nil {
				return err
			}
		case "SYSWARDEN_HA_TOKEN":
			candidate.HAToken = val
		case "SYSWARDEN_HA_PEER_IP":
			candidate.HAPeerIP = val
		case "SYSWARDEN_HA_PEER_PORT":
			candidate.HAPeerPort = val
		case "SYSWARDEN_SIEM_ENABLED":
			candidate.SiemEnabled = parseBool(val)
		case "SYSWARDEN_SIEM_IP":
			candidate.SiemIP = val
		case "SYSWARDEN_SIEM_PORT":
			candidate.SiemPort = val
		case "SYSWARDEN_SIEM_PROTO":
			candidate.SiemProto = val
		case "SYSWARDEN_SIEM_TLS_CA":
			candidate.SiemTLSCA = val
		case "SYSWARDEN_ENABLE_ABUSE":
			candidate.EnableAbuse = parseBool(val)
		case "SYSWARDEN_ABUSE_API_KEY":
			candidate.AbuseAPIKey = val
		case "SYSWARDEN_ENABLE_WEBHOOK":
			candidate.EnableWebhook = parseBool(val)
		case "SYSWARDEN_WEBHOOK_URL_DISCORD":
			candidate.WebhookURLDiscord = val
		case "SYSWARDEN_WEBHOOK_URL_TEAMS":
			candidate.WebhookURLTeams = val
		case "SYSWARDEN_WEBHOOK_URL_SLACK":
			candidate.WebhookURLSlack = val
		case "SYSWARDEN_BUNKERWEB_ENABLED":
			candidate.BunkerWebEnabled, err = parseLegacyBoolValue(key, val)
			if err != nil {
				return err
			}
		case "SYSWARDEN_ENABLE_WAZUH":
			candidate.EnableWazuh = parseBool(val)
		case "SYSWARDEN_WAZUH_IP":
			candidate.WazuhIP = val
		case "SYSWARDEN_WAZUH_NAME":
			candidate.WazuhName = val
		case "SYSWARDEN_WAZUH_GROUP":
			candidate.WazuhGroup = val
		case "SYSWARDEN_WAZUH_COMM_PORT":
			candidate.WazuhCommPort = val
		case "SYSWARDEN_WAZUH_ENROLL_PORT":
			candidate.WazuhEnrollPort = val
		case "SYSWARDEN_SECURE_WIPE_CONF":
			candidate.SecureWipeConf = parseBool(val)
		case "SYSWARDEN_ENABLE_L2":
			candidate.EnableL2 = parseBool(val)

		case "SYSWARDEN_ARP_PROTECT":
			candidate.ArpProtect = parseBool(val)
		case "SYSWARDEN_LAN_MODE":
			candidate.LANMode = parseBool(val)
		case "SYSWARDEN_LAN_SUBNETS":
			candidate.LANSubnets = val
		case "SYSWARDEN_WEB_TOKEN":
			candidate.WebTUIPassword = val
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}
	normalized, err := normalizeHistoricalLegacyHA(candidate)
	if err != nil {
		return err
	}
	if err := validateLegacyConfig(candidate); err != nil {
		return err
	}
	if normalized {
		rewritten, rewriteErr := persistHistoricalLegacyHA(content)
		if rewriteErr != nil {
			return rewriteErr
		}
		if err := replaceSecureFileAtomicallyIfUnchanged(filepath.Dir(path), filepath.Base(path), rewritten, identity); err != nil {
			return fmt.Errorf("persist historical legacy HA compatibility normalization: %w", err)
		}
	}

	commitGlobalConfig(candidate, path)
	return nil
}

func validateLegacyConfig(candidate *Config) error {
	switch candidate.EnforcementMode {
	case "", "enforcing", "audit":
	default:
		return fmt.Errorf("invalid legacy enforcement mode %q", candidate.EnforcementMode)
	}
	switch candidate.FirewallBackend {
	case "nftables", "iptables", "keep":
	default:
		return fmt.Errorf("invalid legacy firewall backend %q", candidate.FirewallBackend)
	}

	ports := []struct {
		name  string
		value string
	}{
		{"SSH", candidate.SSHPort},
		{"WireGuard", candidate.WGPort},
		{"HA peer", candidate.HAPeerPort},
		{"SIEM", candidate.SiemPort},
		{"Wazuh comm", candidate.WazuhCommPort},
		{"Wazuh enroll", candidate.WazuhEnrollPort},
	}
	for _, item := range ports {
		if item.value == "" {
			continue
		}
		port, err := strconv.Atoi(item.value)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid legacy %s port %q", item.name, item.value)
		}
	}
	for _, raw := range strings.Fields(strings.ReplaceAll(candidate.HoneyPorts, ",", " ")) {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid legacy honeyport %q", raw)
		}
	}

	peerValues := strings.Fields(strings.ReplaceAll(candidate.HAPeerIP, ",", " "))
	for _, peer := range peerValues {
		if !validExactIPOrCanonicalCIDR(peer) {
			return fmt.Errorf("invalid legacy HA peer %q", peer)
		}
	}
	if candidate.HAEnabled {
		if candidate.HAToken == "" || strings.TrimSpace(candidate.HAToken) != candidate.HAToken {
			return fmt.Errorf("legacy HA requires a non-empty token without surrounding whitespace")
		}
		if len(peerValues) == 0 {
			return fmt.Errorf("legacy HA requires at least one exact IP or canonical CIDR peer")
		}
	}
	if candidate.BunkerWebEnabled {
		if !candidate.HAEnabled {
			return fmt.Errorf("legacy BunkerWeb integration requires HA to be enabled")
		}
		if candidate.HAToken == "" || strings.TrimSpace(candidate.HAToken) != candidate.HAToken || len(peerValues) == 0 {
			return fmt.Errorf("legacy BunkerWeb integration requires authenticated HA peers")
		}
	}

	threshold, err := strconv.Atoi(candidate.BruteforceThreshold)
	if err != nil || threshold < 1 {
		return fmt.Errorf("invalid legacy brute-force threshold %q", candidate.BruteforceThreshold)
	}
	if seconds, err := strconv.Atoi(candidate.BruteforceWindow); err == nil {
		if seconds < 1 {
			return fmt.Errorf("invalid legacy brute-force window %q", candidate.BruteforceWindow)
		}
	} else if duration, durationErr := time.ParseDuration(candidate.BruteforceWindow); durationErr != nil || duration <= 0 {
		return fmt.Errorf("invalid legacy brute-force window %q", candidate.BruteforceWindow)
	}
	return nil
}

// normalizeHistoricalLegacyHA preserves the exact v4.02.8 default contract:
// HA was advertised as enabled while both authentication inputs were empty.
// That one complete historical default state is safely normalized to disabled;
// partial or explicitly BunkerWeb-enabled states remain validation failures.
func normalizeHistoricalLegacyHA(candidate *Config) (bool, error) {
	if candidate == nil || !candidate.HAEnabled {
		return false, nil
	}
	tokenEmpty := candidate.HAToken == ""
	peersEmpty := len(strings.Fields(strings.ReplaceAll(candidate.HAPeerIP, ",", " "))) == 0
	if tokenEmpty && peersEmpty && !candidate.BunkerWebEnabled {
		candidate.HAEnabled = false
		candidate.BunkerWebEnabled = false
		return true, nil
	}
	if tokenEmpty != peersEmpty {
		return false, fmt.Errorf("legacy HA configuration is partial: token and peer_ips must be configured together")
	}
	return false, nil
}

func validExactIPOrCanonicalCIDR(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return !address.Is4In6() && address.Zone() == ""
	}
	prefix, err := netip.ParsePrefix(value)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Addr().Zone() == "" && prefix == prefix.Masked()
}

func parseBool(val string) bool {
	v := strings.ToLower(val)
	return v == "y" || v == "yes" || v == "true" || v == "1"
}
