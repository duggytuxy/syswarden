package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseConfig reads syswarden-auto.conf securely and populates GlobalConfig
func ParseConfig(filepath string) error {
	file, err := os.Open(filepath) // #nosec
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() { _ = file.Close() }()

	GlobalConfig = &Config{}
	scanner := bufio.NewScanner(file)

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
			GlobalConfig.EnterpriseMode = parseBool(val)
		case "SYSWARDEN_SSH_PORT":
			GlobalConfig.SSHPort = val
		case "SYSWARDEN_FIREWALL_BACKEND":
			GlobalConfig.FirewallBackend = val
		case "SYSWARDEN_WHITELIST_INFRA":
			GlobalConfig.WhitelistInfra = parseBool(val)
		case "SYSWARDEN_WHITELIST_IPS":
			GlobalConfig.WhitelistIPs = val
		case "SYSWARDEN_ENABLE_WG":
			GlobalConfig.EnableWG = parseBool(val)
		case "SYSWARDEN_WG_PORT":
			GlobalConfig.WGPort = val
		case "SYSWARDEN_WG_SUBNET":
			GlobalConfig.WGSubnet = val
		case "SYSWARDEN_MODSEC_LOGS":
			GlobalConfig.ModsecLogs = val
		case "SYSWARDEN_BRUTEFORCE_LOGS":
			GlobalConfig.BruteforceLogs = val
		case "SYSWARDEN_BRUTEFORCE_THRESHOLD":
			GlobalConfig.BruteforceThreshold = val
		case "SYSWARDEN_BRUTEFORCE_WINDOW":
			GlobalConfig.BruteforceWindow = val
		case "SYSWARDEN_HONEYPORTS":
			GlobalConfig.HoneyPorts = val
		case "SYSWARDEN_HARDENING":
			GlobalConfig.Hardening = parseBool(val)
		case "APPLY_CIS_L2_HARDENING":
			GlobalConfig.CISL2Hardening = parseBool(val)
		case "SYSWARDEN_LIST_CHOICE":
			GlobalConfig.ListChoice = val
		case "SYSWARDEN_CUSTOM_URL":
			GlobalConfig.CustomURL = val
		case "SYSWARDEN_CUSTOM_URL6":
			GlobalConfig.CustomURL6 = val
		case "SYSWARDEN_CUSTOM_HASH":
			GlobalConfig.CustomHash = val
		case "SYSWARDEN_ENABLE_GEO":
			GlobalConfig.EnableGeo = parseBool(val)
		case "SYSWARDEN_GEO_CODES":
			GlobalConfig.GeoCodes = val
		case "SYSWARDEN_GEO_ALLOWED":
			GlobalConfig.GeoAllowed = val
		case "SYSWARDEN_ENABLE_ASN":
			GlobalConfig.EnableASN = parseBool(val)
		case "SYSWARDEN_ASN_LIST":
			GlobalConfig.ASNList = val
		case "SYSWARDEN_ASN_ALLOWED":
			GlobalConfig.ASNAllowed = val
		case "SYSWARDEN_USE_SPAMHAUS":
			GlobalConfig.UseSpamhaus = parseBool(val)
		case "SYSWARDEN_HA_ENABLED":
			GlobalConfig.HAEnabled = parseBool(val)
		case "SYSWARDEN_HA_PEER_IP":
			GlobalConfig.HAPeerIP = val
		case "SYSWARDEN_HA_PEER_PORT":
			GlobalConfig.HAPeerPort = val
		case "SYSWARDEN_SIEM_ENABLED":
			GlobalConfig.SiemEnabled = parseBool(val)
		case "SYSWARDEN_SIEM_IP":
			GlobalConfig.SiemIP = val
		case "SYSWARDEN_SIEM_PORT":
			GlobalConfig.SiemPort = val
		case "SYSWARDEN_SIEM_PROTO":
			GlobalConfig.SiemProto = val
		case "SYSWARDEN_SIEM_TLS_CA":
			GlobalConfig.SiemTLSCA = val
		case "SYSWARDEN_ENABLE_ABUSE":
			GlobalConfig.EnableAbuse = parseBool(val)
		case "SYSWARDEN_ABUSE_API_KEY":
			GlobalConfig.AbuseAPIKey = val
		case "SYSWARDEN_ENABLE_WEBHOOK":
			GlobalConfig.EnableWebhook = parseBool(val)
		case "SYSWARDEN_WEBHOOK_URL_DISCORD":
			GlobalConfig.WebhookURLDiscord = val
		case "SYSWARDEN_WEBHOOK_URL_TEAMS":
			GlobalConfig.WebhookURLTeams = val
		case "SYSWARDEN_WEBHOOK_URL_SLACK":
			GlobalConfig.WebhookURLSlack = val
		case "SYSWARDEN_ENABLE_WAZUH":
			GlobalConfig.EnableWazuh = parseBool(val)
		case "SYSWARDEN_WAZUH_IP":
			GlobalConfig.WazuhIP = val
		case "SYSWARDEN_WAZUH_NAME":
			GlobalConfig.WazuhName = val
		case "SYSWARDEN_WAZUH_GROUP":
			GlobalConfig.WazuhGroup = val
		case "SYSWARDEN_WAZUH_COMM_PORT":
			GlobalConfig.WazuhCommPort = val
		case "SYSWARDEN_WAZUH_ENROLL_PORT":
			GlobalConfig.WazuhEnrollPort = val
		case "SYSWARDEN_SECURE_WIPE_CONF":
			GlobalConfig.SecureWipeConf = parseBool(val)
		case "SYSWARDEN_ENABLE_L2":
			GlobalConfig.EnableL2 = parseBool(val)

		case "SYSWARDEN_ARP_PROTECT":
			GlobalConfig.ArpProtect = parseBool(val)
		case "SYSWARDEN_LAN_MODE":
			GlobalConfig.LANMode = parseBool(val)
		case "SYSWARDEN_LAN_SUBNETS":
			GlobalConfig.LANSubnets = val
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	return nil
}

func parseBool(val string) bool {
	v := strings.ToLower(val)
	return v == "y" || v == "yes" || v == "true" || v == "1"
}
