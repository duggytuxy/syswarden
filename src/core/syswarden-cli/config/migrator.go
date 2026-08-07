package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Migrator struct {
	SourcePath string
	OutputDir  string
	DryRun     bool
}

func (m *Migrator) Run() error {
	if _, err := os.Stat(m.SourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source config file not found: %s", m.SourcePath)
	}

	if err := os.MkdirAll(filepath.Join(m.OutputDir, "modules"), 0750); err != nil {
		return err
	}

	oldConfig, err := m.parseOldConfig()
	if err != nil {
		return err
	}

	if err := m.generateAllModules(oldConfig); err != nil {
		return err
	}

	if err := m.generateMasterConfig(); err != nil {
		return err
	}

	return nil
}

func (m *Migrator) parseOldConfig() (map[string]string, error) {
	config := make(map[string]string)
	file, err := os.Open(m.SourcePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(strings.Trim(parts[1], `"'`))
		if idx := strings.Index(value, "#"); idx != -1 {
			value = strings.TrimSpace(value[:idx])
		}
		config[key] = value
	}
	return config, scanner.Err()
}

func (m *Migrator) generateAllModules(oldConfig map[string]string) error {
	generators := []struct {
		name      string
		generator func(map[string]string) string
	}{
		{"00-core.toml", m.generateCore},
		{"10-network.toml", m.generateNetwork},
		{"20-security.toml", m.generateSecurity},
		{"30-waap.toml", m.generateWAAP},
		{"40-integrations.toml", m.generateIntegrations},
		{"99-user.toml", m.generateUser},
	}

	for _, gen := range generators {
		content := gen.generator(oldConfig)
		outputPath := filepath.Join(m.OutputDir, "modules", gen.name)
		if m.DryRun {
			fmt.Printf("[DRY RUN] Would create: %s\n", outputPath)
		} else {
			if err := os.WriteFile(outputPath, []byte(content), 0640); err != nil {
				return err
			}
			fmt.Printf("Created: %s\n", outputPath)
		}
	}
	return nil
}

func (m *Migrator) generateMasterConfig() error {
	content := `# SYSWARDEN MODULAR CONFIGURATION
# Load order: 00-*.toml -> 99-*.toml
# Environment variables override: SYSWARDEN_<SECTION>_<KEY>

[core]
config_dir = "` + filepath.Join(m.OutputDir, "modules") + `"
enterprise_mode = true
log_level = "INFO"
`
	outputPath := filepath.Join(m.OutputDir, "config.toml")
	if m.DryRun {
		fmt.Printf("[DRY RUN] Would create: %s\n", outputPath)
	} else {
		if err := os.WriteFile(outputPath, []byte(content), 0640); err != nil {
			return err
		}
		fmt.Printf("Created: %s\n", outputPath)
	}
	return nil
}

func (m *Migrator) generateCore(oldConfig map[string]string) string {
	getBool := func(key, defaultValue string) string {
		val, ok := oldConfig[key]
		if !ok || val == "" {
			return defaultValue
		}
		if val == "y" || val == "yes" || val == "true" || val == "1" {
			return "true"
		}
		return "false"
	}
	get := func(key, defaultValue string) string {
		if val, ok := oldConfig[key]; ok && val != "" {
			return val
		}
		return defaultValue
	}
	return `# [00] CORE SYSTEM CONFIGURATION
# Priority: 00 (loaded first, lowest precedence)

[core]
# Supported backends: "nftables"
firewall_backend = "` + get("SYSWARDEN_FIREWALL_BACKEND", "keep") + `"

# Boolean values: true or false (no quotes)
hardening_enabled = ` + getBool("SYSWARDEN_HARDENING", "false") + `
cis_l2_hardening = ` + getBool("SYSWARDEN_CIS_L2", "false") + `
secure_wipe_conf = ` + getBool("SYSWARDEN_SECURE_WIPE", "false") + `

# SSH Port string (e.g. "2222")
ssh_port = "` + get("SYSWARDEN_SSH_PORT", "") + `"
`
}

func (m *Migrator) generateNetwork(oldConfig map[string]string) string {
	getBool := func(key, defaultValue string) string {
		val, ok := oldConfig[key]
		if !ok || val == "" {
			return defaultValue
		}
		if val == "y" || val == "yes" || val == "true" || val == "1" {
			return "true"
		}
		return "false"
	}
	get := func(key, defaultValue string) string {
		if val, ok := oldConfig[key]; ok && val != "" {
			return val
		}
		return defaultValue
	}
	parseSlice := func(val string) string {
		if val == "" || val == "false" || val == "none" || val == "0" {
			return ""
		}
		val = strings.ReplaceAll(val, ",", " ")
		items := strings.Fields(val)
		var valid []string
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" && item != "false" && item != "none" {
				valid = append(valid, `"`+item+`"`)
			}
		}
		return strings.Join(valid, ", ")
	}

	geoListStr := parseSlice(get("SYSWARDEN_GEO_CODES", ""))
	asnListStr := parseSlice(get("SYSWARDEN_ASN_LIST", ""))
	lanListStr := parseSlice(get("SYSWARDEN_LAN_SUBNETS", ""))
	whitelistIPsStr := parseSlice(get("SYSWARDEN_WHITELIST_IPS", ""))

	return `# [10] NETWORK & THREAT INTELLIGENCE
# Priority: 10

[network]
# Boolean values: true or false (no quotes)
whitelist_infra = ` + getBool("SYSWARDEN_WHITELIST_INFRA", "true") + `

# Arrays MUST be formatted with brackets, quotes, and commas.
# Example: ["10.0.0.0/8", "192.168.1.0/24"]
lan_subnets = [` + lanListStr + `]
whitelist_ips = [` + whitelistIPsStr + `]

# String (e.g. "eth0,ens33")
interfaces = "` + get("SYSWARDEN_INTERFACES", "") + `"

[network.geo]
enabled = ` + getBool("SYSWARDEN_ENABLE_GEO", "true") + `
# Format requires quotes (ISO 3166-1 alpha-2): ["ru", "cn", "fr"]
blocked_countries = [` + geoListStr + `]
allowed_countries = []

[network.asn]
enabled = ` + getBool("SYSWARDEN_ENABLE_ASN", "true") + `
# Format requires quotes: ["AS1234", "AS5678"]
blocked_asns = [` + asnListStr + `]
allowed_asns = []

[network.saas]
allow_monitors = ` + getBool("SYSWARDEN_ALLOW_MONITORS", "false") + `

[network.blocklists]
# Threat Intel Data-Shield lists configuration
# Choices: 1=standard, 2=critical, 3=custom, 4=none
list_choice = "` + get("SYSWARDEN_LIST_CHOICE", "1") + `"
custom_url = "` + get("SYSWARDEN_CUSTOM_URL", "") + `"
custom_url_ipv6 = "` + get("SYSWARDEN_CUSTOM_URL_IPV6", "") + `"
custom_hash = "` + get("SYSWARDEN_CUSTOM_HASH", "") + `"
custom_hash_ipv6 = "` + get("SYSWARDEN_CUSTOM_HASH_IPV6", "") + `"

[network.wireguard]
enabled = ` + getBool("SYSWARDEN_ENABLE_WG", "false") + `
port = "` + get("SYSWARDEN_WG_PORT", "") + `"
subnet = "` + get("SYSWARDEN_WG_SUBNET", "") + `"
`
}

func (m *Migrator) generateSecurity(oldConfig map[string]string) string {
	getBool := func(key, defaultValue string) string {
		val, ok := oldConfig[key]
		if !ok || val == "" {
			return defaultValue
		}
		if val == "y" || val == "yes" || val == "true" || val == "1" {
			return "true"
		}
		return "false"
	}
	get := func(key, defaultValue string) string {
		if val, ok := oldConfig[key]; ok && val != "" {
			return val
		}
		return defaultValue
	}
	parseSlice := func(val string) string {
		if val == "" || val == "false" || val == "none" || val == "0" {
			return ""
		}
		val = strings.ReplaceAll(val, ",", " ")
		items := strings.Fields(val)
		var valid []string
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" && item != "false" && item != "none" {
				valid = append(valid, `"`+item+`"`)
			}
		}
		return strings.Join(valid, ", ")
	}

	honeyPortsStr := parseSlice(get("SYSWARDEN_HONEYPORTS", ""))

	return `# [20] SECURITY & COMPLIANCE
# Priority: 20

[security]
# Format requires quotes: ["6379", "23"]
honeyports = [` + honeyPortsStr + `]

[security.l2]
enable_l2 = ` + getBool("SYSWARDEN_ENABLE_L2", "false") + `
arp_protect = ` + getBool("SYSWARDEN_ARP_PROTECT", "false") + `
lan_mode = ` + getBool("SYSWARDEN_LAN_MODE", "false") + `

[security.compliance]
enable_watchdog = true
check_interval = "24h"
`
}

func (m *Migrator) generateWAAP(oldConfig map[string]string) string {
	get := func(key, defaultValue string) string {
		if val, ok := oldConfig[key]; ok && val != "" {
			return val
		}
		return defaultValue
	}

	return `# [30] WAAP (Web Application & API Protection)
# Priority: 30

[waap]
# Modes: "enforcing", "permissive", "disabled"
enforcement_mode = "` + get("SYSWARDEN_ENFORCEMENT_MODE", "enforcing") + `"
bruteforce_logs = "` + get("SYSWARDEN_BRUTEFORCE_LOGS", "auto") + `"
bruteforce_threshold = ` + get("SYSWARDEN_BRUTEFORCE_THRESHOLD", "5") + `
bruteforce_window_seconds = ` + strings.TrimSuffix(get("SYSWARDEN_BRUTEFORCE_WINDOW", "60s"), "s") + `
modsec_logs = "` + get("SYSWARDEN_MODSEC_LOGS", "") + `"
`
}

func (m *Migrator) generateIntegrations(oldConfig map[string]string) string {
	getBool := func(key, defaultValue string) string {
		val, ok := oldConfig[key]
		if !ok || val == "" {
			return defaultValue
		}
		if val == "y" || val == "yes" || val == "true" || val == "1" {
			return "true"
		}
		return "false"
	}
	get := func(key, defaultValue string) string {
		if val, ok := oldConfig[key]; ok && val != "" {
			return val
		}
		return defaultValue
	}

	parseSlice := func(val string) string {
		if val == "" || val == "false" || val == "none" || val == "0" {
			return ""
		}
		val = strings.ReplaceAll(val, ",", " ")
		items := strings.Fields(val)
		var valid []string
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" && item != "false" && item != "none" {
				valid = append(valid, `"`+item+`"`)
			}
		}
		return strings.Join(valid, ", ")
	}

	peerIPsStr := parseSlice(get("SYSWARDEN_HA_PEER_IP", ""))

	return `# [40] INTEGRATIONS & NOTIFICATIONS
# Priority: 40

[integrations.ha]
enabled = ` + getBool("SYSWARDEN_HA_ENABLED", "false") + `
# Format requires quotes: ["10.0.0.1", "10.0.0.2"]
peer_ips = [` + peerIPsStr + `]
peer_port = ` + get("SYSWARDEN_HA_PEER_PORT", "62026") + `

# HA Shared Secret Token for API Authentication (Must be identical on all nodes)
# Generate a secure token using: openssl rand -hex 32
token = "` + get("SYSWARDEN_HA_TOKEN", "") + `"
`
}

func (m *Migrator) generateUser(oldConfig map[string]string) string {
	return `# [99] USER CUSTOM OVERRIDES
# Priority: 99 (highest - overrides all other modules)
# 
# This configuration file (99-user.toml) has absolute priority.
# Any value defined here will override defaults or values defined in other
# modules (00-core.toml to 40-integrations.toml).
# Use this file to customize your SysWarden environment without modifying
# the other files, which might be updated by the application.
#
# NOTE: Everything below is commented out by default. Remove the '#' to activate an override.
# Arrays MUST be formatted with brackets, quotes, and commas. Example: ["value1", "value2"]
# 
# [network.geo]
# blocked_countries = ["ru", "cn"]
#
# [waap]
# bruteforce_threshold = 3
`
}
