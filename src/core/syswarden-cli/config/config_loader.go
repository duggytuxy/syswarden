package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// ParseConfig is the entrypoint for loading configuration.
// It first tries to load the new modular TOML config. If the config directory doesn't exist,
// it falls back to the deprecated flat syswarden-auto.conf parser.
func ParseConfig(configPath string) error {
	configDir := "/etc/syswarden/config"
	if _, err := os.Stat(filepath.Join(configDir, "modules")); err == nil {
		log.Println("[INFO] Using new modular TOML configuration format")
		return loadModularConfig(configDir)
	}

	log.Println("[WARNING] Using old flat configuration format (deprecated)")
	log.Println("Please run 'syswarden migrate-config' to migrate to the new modular TOML format.")
	return loadOldConfig(configPath)
}

func loadModularConfig(configDir string) error {
	v := viper.New()
	v.SetConfigType("toml")
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	setDefaults(v)

	// Load master config
	masterConfig := filepath.Join(configDir, "config.toml")
	if _, err := os.Stat(masterConfig); err == nil {
		v.SetConfigFile(masterConfig)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("failed to load master config: %w", err)
		}
	}

	// Load modules in priority order
	modulesDir := filepath.Join(configDir, "modules")
	if _, err := os.Stat(modulesDir); err == nil {
		files, err := filepath.Glob(filepath.Join(modulesDir, "*.toml"))
		if err != nil {
			return err
		}
		sort.Slice(files, func(i, j int) bool {
			return filepath.Base(files[i]) < filepath.Base(files[j])
		})
		for _, file := range files {
			v.SetConfigFile(file)
			if err := v.MergeInConfig(); err != nil {
				return fmt.Errorf("failed to load module %s: %w", file, err)
			}
		}
	}

	var modConfig ModularConfig
	if err := v.Unmarshal(&modConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := validateConfig(&modConfig); err != nil {
		return err
	}

	mapToGlobalConfig(&modConfig)
	return nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("core.enterprise_mode", true)
	v.SetDefault("core.log_level", "INFO")
	v.SetDefault("core.firewall_backend", "keep")
	v.SetDefault("network.whitelist_infra", true)
	v.SetDefault("network.geo.enabled", true)
	v.SetDefault("network.asn.enabled", true)
	v.SetDefault("waap.bruteforce_logs", "auto")
	v.SetDefault("waap.bruteforce_threshold", 5)
	v.SetDefault("waap.bruteforce_window_seconds", 60)
}

// mapToGlobalConfig maps the new modular struct back to the legacy flat struct
// to ensure zero-breakage across the CLI commands.
func mapToGlobalConfig(m *ModularConfig) {
	GlobalConfig = &Config{}

	GlobalConfig.EnterpriseMode = m.Core.EnterpriseMode
	GlobalConfig.SSHPort = m.Core.SSHPort
	GlobalConfig.FirewallBackend = m.Core.FirewallBackend
	GlobalConfig.Interfaces = m.Network.Interfaces
	GlobalConfig.WhitelistInfra = m.Network.WhitelistInfra
	GlobalConfig.WhitelistIPs = strings.Join(m.Network.WhitelistIPs, " ")
	GlobalConfig.EnableWG = m.Network.Wireguard.Enabled
	GlobalConfig.WGPort = m.Network.Wireguard.Port
	GlobalConfig.WGSubnet = m.Network.Wireguard.Subnet
	GlobalConfig.ModsecLogs = m.WAAP.ModsecLogs
	GlobalConfig.BruteforceLogs = m.WAAP.BruteforceLogs
	GlobalConfig.BruteforceThreshold = strconv.Itoa(m.WAAP.BruteforceThreshold)
	GlobalConfig.BruteforceWindow = strconv.Itoa(m.WAAP.BruteforceWindowSeconds) + "s"
	GlobalConfig.HoneyPorts = strings.Join(m.Security.Honeyports, " ")
	GlobalConfig.Hardening = m.Core.Hardening
	GlobalConfig.CISL2Hardening = m.Core.CISL2Hardening
	GlobalConfig.ListChoice = m.Network.Blocklists.ListChoice
	GlobalConfig.CustomURL = m.Network.Blocklists.CustomURL
	GlobalConfig.CustomURLIPv6 = m.Network.Blocklists.CustomURL6
	GlobalConfig.CustomHash = m.Network.Blocklists.CustomHash
	GlobalConfig.CustomHashIPv6 = m.Network.Blocklists.CustomHash6
	GlobalConfig.EnableGeo = m.Network.Geo.Enabled
	GlobalConfig.GeoCodes = strings.Join(m.Network.Geo.BlockedCountries, " ")
	GlobalConfig.GeoAllowed = strings.Join(m.Network.Geo.AllowedCountries, " ")
	GlobalConfig.EnableASN = m.Network.ASN.Enabled
	GlobalConfig.ASNList = strings.Join(m.Network.ASN.BlockedASNs, " ")
	GlobalConfig.ASNAllowed = strings.Join(m.Network.ASN.AllowedASNs, " ")

	// Map Integrations
	GlobalConfig.HAEnabled = m.Integrations.HA.Enabled
	GlobalConfig.HAToken = m.Integrations.HA.Token
	GlobalConfig.HAPeerIP = strings.Join(m.Integrations.HA.PeerIPs, " ")
	GlobalConfig.HAPeerPort = strconv.Itoa(m.Integrations.HA.PeerPort)

	GlobalConfig.SiemEnabled = m.Integrations.SIEM.Enabled
	GlobalConfig.SiemIP = m.Integrations.SIEM.IP
	GlobalConfig.SiemPort = m.Integrations.SIEM.Port
	GlobalConfig.SiemProto = m.Integrations.SIEM.Protocol
	GlobalConfig.SiemTLSCA = m.Integrations.SIEM.TLSCA

	GlobalConfig.EnableAbuse = m.Integrations.AbuseIPDB.Enabled
	GlobalConfig.AbuseAPIKey = m.Integrations.AbuseIPDB.APIKey

	GlobalConfig.EnableWebhook = m.Integrations.Webhooks.Enabled
	GlobalConfig.WebhookURLDiscord = m.Integrations.Webhooks.DiscordURL
	GlobalConfig.WebhookURLSlack = m.Integrations.Webhooks.SlackURL
	GlobalConfig.WebhookURLTeams = m.Integrations.Webhooks.TeamsURL

	GlobalConfig.SecureWipeConf = m.Core.SecureWipeConf
	GlobalConfig.EnableL2 = m.Security.L2.EnableL2
	GlobalConfig.ArpProtect = m.Security.L2.ARPProtect
	GlobalConfig.LANMode = m.Security.L2.LanMode
	GlobalConfig.WebTUIPassword = m.User.WebTUIPassword
	GlobalConfig.LANSubnets = strings.Join(m.Network.LanSubnets, " ")
}
