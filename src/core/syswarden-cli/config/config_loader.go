package config

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

type modularConfigSource struct {
	relative string
	path     string
	content  []byte
	identity *secureFileIdentity
}

// ParseConfig is the entrypoint for loading configuration. A real directory is
// treated as a modular TOML root, a symbolic link is rejected explicitly, and
// any other path is parsed as the deprecated flat syswarden-auto.conf format.
func ParseConfig(configPath string) error {
	if info, err := os.Lstat(configPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			err := fmt.Errorf("configuration path %s is a symbolic link", configPath)
			recordConfigLoadFailure(configPath, err)
			return err
		}
		if info.IsDir() {
			if err := loadModularConfig(configPath); err != nil {
				return err
			}
			log.Println("[INFO] Using new modular TOML configuration format")
			return nil
		}
	}

	if err := loadOldConfig(configPath); err != nil {
		return err
	}
	log.Println("[WARNING] Using old flat configuration format (deprecated)")
	log.Println("Please run 'syswarden migrate-config' to migrate to the new modular TOML format.")
	return nil
}

func loadModularConfig(configDir string) (loadErr error) {
	configLoadMu.Lock()
	defer configLoadMu.Unlock()
	defer func() {
		if loadErr != nil {
			recordConfigLoadFailure(configDir, loadErr)
		}
	}()

	configRoot, err := openConfigDirectory(configDir, false, 0)
	if err != nil {
		return fmt.Errorf("open modular config directory: %w", err)
	}
	defer func() { _ = configRoot.Close() }()
	if err := rejectMigrationInProgress(configDir); err != nil {
		return err
	}

	v := viper.New()
	v.SetConfigType("toml")
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	_ = v.BindEnv("network.saas.allow_monitors")
	_ = v.BindEnv("integrations.saas.enabled")

	setDefaults(v, configDir)
	var sources []modularConfigSource
	observed := make(map[string]struct{})

	// Load master config
	masterConfig := filepath.Join(configDir, "config.toml")
	if _, err := configRoot.Lstat("config.toml"); err == nil {
		content, identity, readErr := readSecureRegularFileIdentity(configRoot, "config.toml", masterConfig)
		if readErr != nil {
			return readErr
		}
		document, err := parseTOMLDocument(content, "config.toml")
		if err != nil {
			return err
		}
		flattenTOMLKeys("", document, observed)
		if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
			return fmt.Errorf("failed to load master config: %w", err)
		}
		sources = append(sources, modularConfigSource{relative: "config.toml", path: masterConfig, content: content, identity: identity})
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect master config: %w", err)
	}

	// Load modules in priority order
	modulesDir := filepath.Join(configDir, "modules")
	if info, err := configRoot.Lstat("modules"); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("modules path %s is not a real directory", modulesDir)
		}
		modulesRoot, err := openConfigDirectory(modulesDir, false, 0)
		if err != nil {
			return fmt.Errorf("open modules directory: %w", err)
		}
		defer func() { _ = modulesRoot.Close() }()
		directory, err := modulesRoot.Open(".")
		if err != nil {
			return fmt.Errorf("open modules directory for listing: %w", err)
		}
		entries, err := directory.ReadDir(-1)
		_ = directory.Close()
		if err != nil {
			return fmt.Errorf("list modules directory: %w", err)
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".toml" {
				continue
			}
			file := filepath.Join(modulesDir, entry.Name())
			content, identity, readErr := readSecureRegularFileIdentity(modulesRoot, entry.Name(), file)
			if readErr != nil {
				return readErr
			}
			document, err := parseTOMLDocument(content, filepath.ToSlash(filepath.Join("modules", entry.Name())))
			if err != nil {
				return err
			}
			flattenTOMLKeys("", document, observed)
			if err := v.MergeConfig(bytes.NewReader(content)); err != nil {
				return fmt.Errorf("failed to load module %s: %w", file, err)
			}
			sources = append(sources, modularConfigSource{
				relative: filepath.ToSlash(filepath.Join("modules", entry.Name())),
				path:     file,
				content:  content,
				identity: identity,
			})
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect modules directory: %w", err)
	}
	resolveModularSaaSAlias(v, observed)

	var modConfig ModularConfig
	if err := v.Unmarshal(&modConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := normalizeHistoricalModularHA(&modConfig, sources); err != nil {
		return err
	}

	if err := validateConfig(&modConfig); err != nil {
		return err
	}

	commitGlobalConfig(mapModularToLegacy(&modConfig), configDir)
	return nil
}

func setDefaults(v *viper.Viper, configDir string) {
	v.SetDefault("core.config_dir", filepath.Join(configDir, "modules"))
	v.SetDefault("core.enterprise_mode", true)
	v.SetDefault("core.log_level", "INFO")
	v.SetDefault("core.firewall_backend", "keep")
	v.SetDefault("network.whitelist_infra", true)
	v.SetDefault("network.blocklists.list_choice", "4")
	v.SetDefault("network.geo.enabled", true)
	v.SetDefault("network.asn.enabled", true)
	v.SetDefault("network.wireguard.port", "51820")
	v.SetDefault("waap.bruteforce_logs", "auto")
	v.SetDefault("waap.enforcement_mode", "enforcing")
	v.SetDefault("waap.bruteforce_threshold", 5)
	v.SetDefault("waap.bruteforce_window_seconds", 60)
	v.SetDefault("security.compliance.check_interval", "24h")
	v.SetDefault("integrations.ha.peer_port", 62026)
	v.SetDefault("integrations.bunkerweb.enabled", false)
}

func resolveModularSaaSAlias(v *viper.Viper, observed map[string]struct{}) {
	_, officialFile := observed["network.saas.allow_monitors"]
	_, legacyFile := observed["integrations.saas.enabled"]
	_, officialEnv := os.LookupEnv("SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS")
	_, legacyEnv := os.LookupEnv("SYSWARDEN_INTEGRATIONS_SAAS_ENABLED")
	if officialFile || officialEnv {
		v.Set("network.saas.allow_monitors", v.GetBool("network.saas.allow_monitors"))
		return
	}
	if legacyFile || legacyEnv {
		v.Set("network.saas.allow_monitors", v.GetBool("integrations.saas.enabled"))
		return
	}
	v.Set("network.saas.allow_monitors", false)
}

// mapToGlobalConfig maps the new modular struct back to the legacy flat struct
// to ensure zero-breakage across the CLI commands.
func mapToGlobalConfig(m *ModularConfig) {
	commitGlobalConfig(mapModularToLegacy(m), "in-memory modular configuration")
}

func mapModularToLegacy(m *ModularConfig) *Config {
	candidate := NewFailSafeConfig()

	candidate.EnterpriseMode = m.Core.EnterpriseMode
	candidate.EnforcementMode = m.WAAP.EnforcementMode
	candidate.SSHPort = m.Core.SSHPort
	candidate.FirewallBackend = m.Core.FirewallBackend
	candidate.Interfaces = m.Network.Interfaces
	candidate.WhitelistInfra = m.Network.WhitelistInfra
	candidate.WhitelistIPs = strings.Join(m.Network.WhitelistIPs, " ")
	candidate.EnableWG = m.Network.Wireguard.Enabled
	candidate.WGPort = m.Network.Wireguard.Port
	candidate.WGSubnet = m.Network.Wireguard.Subnet
	candidate.ModsecLogs = m.WAAP.ModsecLogs
	candidate.BruteforceLogs = m.WAAP.BruteforceLogs
	candidate.BruteforceThreshold = strconv.Itoa(m.WAAP.BruteforceThreshold)
	candidate.BruteforceWindow = strconv.Itoa(m.WAAP.BruteforceWindowSeconds) + "s"
	candidate.HoneyPorts = strings.Join(m.Security.Honeyports, " ")
	candidate.Hardening = m.Core.Hardening
	candidate.CISL2Hardening = m.Core.CISL2Hardening
	candidate.ListChoice = m.Network.Blocklists.ListChoice
	candidate.CustomURL = m.Network.Blocklists.CustomURL
	candidate.CustomURLIPv6 = m.Network.Blocklists.CustomURL6
	candidate.CustomHash = m.Network.Blocklists.CustomHash
	candidate.CustomHashIPv6 = m.Network.Blocklists.CustomHash6
	candidate.UseSpamhaus = m.Network.Blocklists.UseSpamhaus
	candidate.AllowSaaSMonitors = m.Network.Saas.AllowMonitors
	candidate.EnableGeo = m.Network.Geo.Enabled
	candidate.GeoCodes = strings.Join(m.Network.Geo.BlockedCountries, " ")
	candidate.GeoAllowed = strings.Join(m.Network.Geo.AllowedCountries, " ")
	candidate.EnableASN = m.Network.ASN.Enabled
	candidate.ASNList = strings.Join(m.Network.ASN.BlockedASNs, " ")
	candidate.ASNAllowed = strings.Join(m.Network.ASN.AllowedASNs, " ")

	// Map Integrations
	candidate.HAEnabled = m.Integrations.HA.Enabled
	candidate.HAToken = m.Integrations.HA.Token
	candidate.HAPeerIP = strings.Join(m.Integrations.HA.PeerIPs, " ")
	candidate.HAPeerPort = strconv.Itoa(m.Integrations.HA.PeerPort)

	candidate.SiemEnabled = m.Integrations.SIEM.Enabled
	candidate.SiemIP = m.Integrations.SIEM.IP
	candidate.SiemPort = m.Integrations.SIEM.Port
	candidate.SiemProto = m.Integrations.SIEM.Protocol
	candidate.SiemTLSCA = m.Integrations.SIEM.TLSCA

	candidate.EnableAbuse = m.Integrations.AbuseIPDB.Enabled
	candidate.AbuseAPIKey = m.Integrations.AbuseIPDB.APIKey

	candidate.EnableWebhook = m.Integrations.Webhooks.Enabled
	candidate.WebhookURLDiscord = m.Integrations.Webhooks.DiscordURL
	candidate.WebhookURLSlack = m.Integrations.Webhooks.SlackURL
	candidate.WebhookURLTeams = m.Integrations.Webhooks.TeamsURL
	candidate.BunkerWebEnabled = m.Integrations.BunkerWeb.Enabled

	candidate.EnableWazuh = m.Integrations.Wazuh.Enabled
	candidate.WazuhIP = m.Integrations.Wazuh.IP
	candidate.WazuhName = m.Integrations.Wazuh.Name
	candidate.WazuhGroup = m.Integrations.Wazuh.Group
	candidate.WazuhCommPort = m.Integrations.Wazuh.CommPort
	candidate.WazuhEnrollPort = m.Integrations.Wazuh.EnrollPort

	candidate.SecureWipeConf = m.Core.SecureWipeConf
	candidate.EnableL2 = m.Security.L2.EnableL2
	candidate.ArpProtect = m.Security.L2.ARPProtect
	candidate.LANMode = m.Security.L2.LanMode
	candidate.LANSubnets = strings.Join(m.Network.LanSubnets, " ")
	return candidate
}
