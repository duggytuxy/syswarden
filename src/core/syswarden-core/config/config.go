package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
)

const CurrentSchemaVersion = 1

var loadMu sync.Mutex

type Diagnostics struct {
	SchemaVersion  int
	Historical     bool
	UnknownKeys    []string
	DeprecatedKeys []string
}

type runtimeConfig struct {
	SchemaVersion int                `mapstructure:"schema_version"`
	Core          coreConfig         `mapstructure:"core"`
	Network       networkConfig      `mapstructure:"network"`
	Security      securityConfig     `mapstructure:"security"`
	WAAP          waapConfig         `mapstructure:"waap"`
	Integrations  integrationsConfig `mapstructure:"integrations"`
	User          userConfig         `mapstructure:"user"`
}

type coreConfig struct {
	ConfigDir       string `mapstructure:"config_dir"`
	EnterpriseMode  bool   `mapstructure:"enterprise_mode"`
	LogLevel        string `mapstructure:"log_level"`
	FirewallBackend string `mapstructure:"firewall_backend"`
	Hardening       bool   `mapstructure:"hardening_enabled"`
	CISL2Hardening  bool   `mapstructure:"cis_l2_hardening"`
	SecureWipeConf  bool   `mapstructure:"secure_wipe_conf"`
	SSHPort         string `mapstructure:"ssh_port"`
}

type networkConfig struct {
	WhitelistInfra bool             `mapstructure:"whitelist_infra"`
	LanSubnets     []string         `mapstructure:"lan_subnets"`
	WhitelistIPs   []string         `mapstructure:"whitelist_ips"`
	Interfaces     string           `mapstructure:"interfaces"`
	Geo            geoConfig        `mapstructure:"geo"`
	ASN            asnConfig        `mapstructure:"asn"`
	SaaS           saasConfig       `mapstructure:"saas"`
	WireGuard      wireGuardConfig  `mapstructure:"wireguard"`
	Blocklists     blocklistsConfig `mapstructure:"blocklists"`
}

type geoConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Blocked []string `mapstructure:"blocked_countries"`
	Allowed []string `mapstructure:"allowed_countries"`
}

type asnConfig struct {
	Enabled bool     `mapstructure:"enabled"`
	Blocked []string `mapstructure:"blocked_asns"`
	Allowed []string `mapstructure:"allowed_asns"`
}

type saasConfig struct {
	AllowMonitors bool `mapstructure:"allow_monitors"`
}

type wireGuardConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    string `mapstructure:"port"`
	Subnet  string `mapstructure:"subnet"`
}

type blocklistsConfig struct {
	ListChoice  string `mapstructure:"list_choice"`
	CustomURL   string `mapstructure:"custom_url"`
	CustomURL6  string `mapstructure:"custom_url_ipv6"`
	CustomHash  string `mapstructure:"custom_hash"`
	CustomHash6 string `mapstructure:"custom_hash_ipv6"`
	UseSpamhaus bool   `mapstructure:"use_spamhaus"`
}

type securityConfig struct {
	Honeyports []string         `mapstructure:"honeyports"`
	L2         l2Config         `mapstructure:"l2"`
	Compliance complianceConfig `mapstructure:"compliance"`
}

type l2Config struct {
	EnableL2   bool `mapstructure:"enable_l2"`
	ARPProtect bool `mapstructure:"arp_protect"`
	LanMode    bool `mapstructure:"lan_mode"`
}

type complianceConfig struct {
	EnableWatchdog bool   `mapstructure:"enable_watchdog"`
	CheckInterval  string `mapstructure:"check_interval"`
}

type waapConfig struct {
	EnforcementMode         string `mapstructure:"enforcement_mode"`
	BruteforceLogs          string `mapstructure:"bruteforce_logs"`
	BruteforceThreshold     int    `mapstructure:"bruteforce_threshold"`
	BruteforceWindowSeconds int    `mapstructure:"bruteforce_window_seconds"`
	ModsecLogs              string `mapstructure:"modsec_logs"`
}

type integrationsConfig struct {
	HA        haConfig        `mapstructure:"ha"`
	SIEM      siemConfig      `mapstructure:"siem"`
	AbuseIPDB abuseIPDBConfig `mapstructure:"abuseipdb"`
	Webhooks  webhooksConfig  `mapstructure:"webhooks"`
	BunkerWeb bunkerWebConfig `mapstructure:"bunkerweb"`
	Wazuh     wazuhConfig     `mapstructure:"wazuh"`
}

type haConfig struct {
	Enabled  bool     `mapstructure:"enabled"`
	PeerIPs  []string `mapstructure:"peer_ips"`
	PeerPort int      `mapstructure:"peer_port"`
	Token    string   `mapstructure:"token"`
}

type siemConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	IP       string `mapstructure:"ip"`
	Port     string `mapstructure:"port"`
	Protocol string `mapstructure:"protocol"`
	TLSCA    string `mapstructure:"tls_ca"`
}

type abuseIPDBConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"`
}

type webhooksConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	DiscordURL string `mapstructure:"discord_url"`
	TeamsURL   string `mapstructure:"teams_url"`
	SlackURL   string `mapstructure:"slack_url"`
}

type bunkerWebConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

type wazuhConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	IP         string `mapstructure:"ip"`
	Name       string `mapstructure:"name"`
	Group      string `mapstructure:"group"`
	CommPort   string `mapstructure:"comm_port"`
	EnrollPort string `mapstructure:"enroll_port"`
}

type userConfig struct {
	ProfileName string `mapstructure:"profile_name"`
}

var deprecatedKeys = map[string]string{ // #nosec G101 -- keys name retired credential settings but contain no credential values
	"integrations.saas.enabled": "network.saas.allow_monitors",
	"user.webtui_password":      "removed Web-TUI credential",
}

func LoadConfig() error {
	diagnostics, err := LoadConfigDirectory("/etc/syswarden/config")
	if err != nil {
		return err
	}
	for _, key := range diagnostics.DeprecatedKeys {
		log.Printf("[WARNING] Deprecated configuration key: %s", key)
	}
	for _, key := range diagnostics.UnknownKeys {
		log.Printf("[WARNING] Unknown configuration key: %s", key)
	}
	return nil
}

// FirewallBackendForMutation returns the validated runtime backend only when
// the core daemon may safely initialize its nftables mutation paths. The
// iptables value remains parseable for compatibility but is not operational.
func FirewallBackendForMutation() (string, error) {
	backend := strings.TrimSpace(viper.GetString("core.firewall_backend"))
	switch backend {
	case "keep", "nftables":
		return backend, nil
	case "iptables":
		return "", fmt.Errorf("iptables is accepted for configuration compatibility but refused for core firewall mutations")
	case "":
		return "", fmt.Errorf("core.firewall_backend is unavailable")
	default:
		return "", fmt.Errorf("unsupported core.firewall_backend %q", backend)
	}
}

// LoadConfigDirectory validates an isolated candidate and publishes it only
// after every file and policy value succeeds.
func LoadConfigDirectory(configPath string) (Diagnostics, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	candidate, diagnostics, err := loadCandidate(configPath)
	if err != nil {
		return diagnostics, err
	}
	viper.Reset()
	target := viper.GetViper()
	configureEnvironment(target)
	if err := target.MergeConfigMap(candidate.AllSettings()); err != nil {
		return diagnostics, fmt.Errorf("publish validated runtime configuration: %w", err)
	}
	return diagnostics, nil
}

func loadCandidate(configPath string) (*viper.Viper, Diagnostics, error) {
	diagnostics := Diagnostics{}
	root, err := openSecureDirectory(configPath)
	if err != nil {
		return nil, diagnostics, fmt.Errorf("open configuration root: %w", err)
	}
	defer func() { _ = root.Close() }()
	candidate := viper.New()
	candidate.SetConfigType("toml")
	configureEnvironment(candidate)
	setDefaults(candidate, configPath)
	observed := make(map[string]struct{})
	merge := func(relative string, content []byte) error {
		document, err := parseDocument(content, relative)
		if err != nil {
			return err
		}
		flattenKeys("", document, observed)
		if err := candidate.MergeConfig(bytes.NewReader(content)); err != nil {
			return fmt.Errorf("merge %s: %w", relative, err)
		}
		return nil
	}
	if _, err := root.Lstat("config.toml"); err == nil {
		content, readErr := readSecureRegularFile(root, "config.toml", filepath.Join(configPath, "config.toml"))
		if readErr != nil {
			return nil, diagnostics, readErr
		}
		if err := merge("config.toml", content); err != nil {
			return nil, diagnostics, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, diagnostics, fmt.Errorf("inspect master configuration: %w", err)
	}
	modulesPath := filepath.Join(configPath, "modules")
	if info, err := root.Lstat("modules"); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, diagnostics, fmt.Errorf("modules path %s is not a secure real directory", modulesPath)
		}
		modules, openErr := openSecureDirectory(modulesPath)
		if openErr != nil {
			return nil, diagnostics, openErr
		}
		defer func() { _ = modules.Close() }()
		directory, openErr := modules.Open(".")
		if openErr != nil {
			return nil, diagnostics, openErr
		}
		entries, readErr := directory.ReadDir(-1)
		_ = directory.Close()
		if readErr != nil {
			return nil, diagnostics, readErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".toml" {
				continue
			}
			content, readErr := readSecureRegularFile(modules, entry.Name(), filepath.Join(modulesPath, entry.Name()))
			if readErr != nil {
				return nil, diagnostics, readErr
			}
			if err := merge(filepath.ToSlash(filepath.Join("modules", entry.Name())), content); err != nil {
				return nil, diagnostics, err
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, diagnostics, fmt.Errorf("inspect modules directory: %w", err)
	}

	known := make(map[string]struct{})
	collectKnownKeys(reflect.TypeOf(runtimeConfig{}), "", known)
	for key := range observed {
		if replacement, deprecated := deprecatedKeys[key]; deprecated {
			diagnostics.DeprecatedKeys = append(diagnostics.DeprecatedKeys, key+" (use "+replacement+")")
			continue
		}
		if _, exists := known[key]; !exists {
			diagnostics.UnknownKeys = append(diagnostics.UnknownKeys, key)
		}
	}
	sort.Strings(diagnostics.UnknownKeys)
	sort.Strings(diagnostics.DeprecatedKeys)

	resolveSaaSAlias(candidate, observed)
	var typed runtimeConfig
	if err := candidate.Unmarshal(&typed); err != nil {
		return nil, diagnostics, fmt.Errorf("decode runtime configuration: %w", err)
	}
	diagnostics.SchemaVersion = typed.SchemaVersion
	diagnostics.Historical = typed.SchemaVersion == 0
	if historicalHAState(&typed) {
		typed.Integrations.HA.Enabled = false
		typed.Integrations.BunkerWeb.Enabled = false
		candidate.Set("integrations.ha.enabled", false)
		candidate.Set("integrations.bunkerweb.enabled", false)
	}
	if err := validateRuntimeConfig(&typed); err != nil {
		return nil, diagnostics, err
	}
	return candidate, diagnostics, nil
}

func configureEnvironment(v *viper.Viper) {
	v.AutomaticEnv()
	v.SetEnvPrefix("SYSWARDEN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	known := make(map[string]struct{})
	collectKnownKeys(reflect.TypeOf(runtimeConfig{}), "", known)
	for key := range known {
		_ = v.BindEnv(key)
	}
	_ = v.BindEnv("integrations.saas.enabled")
}

func setDefaults(v *viper.Viper, configPath string) {
	v.SetDefault("core.config_dir", filepath.Join(configPath, "modules"))
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

func resolveSaaSAlias(v *viper.Viper, observed map[string]struct{}) {
	_, canonicalFile := observed["network.saas.allow_monitors"]
	_, legacyFile := observed["integrations.saas.enabled"]
	_, canonicalEnv := os.LookupEnv("SYSWARDEN_NETWORK_SAAS_ALLOW_MONITORS")
	_, legacyEnv := os.LookupEnv("SYSWARDEN_INTEGRATIONS_SAAS_ENABLED")
	if canonicalFile || canonicalEnv {
		v.Set("integrations.saas.enabled", v.GetBool("network.saas.allow_monitors"))
		return
	}
	if legacyFile || legacyEnv {
		value := v.GetBool("integrations.saas.enabled")
		v.Set("network.saas.allow_monitors", value)
		v.Set("integrations.saas.enabled", value)
	}
}

func parseDocument(content []byte, relative string) (map[string]any, error) {
	var document map[string]any
	if err := toml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parse %s: %w", relative, err)
	}
	if raw, present := document["schema_version"]; present {
		version, ok := raw.(int64)
		if !ok {
			return nil, fmt.Errorf("%s schema_version must be an integer", relative)
		}
		if version < 0 || version > CurrentSchemaVersion {
			return nil, fmt.Errorf("%s has unsupported schema_version %d", relative, version)
		}
	}
	return document, nil
}

func openSecureDirectory(path string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("%s is not a secure real directory", path)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	openedInfo, statErr := opened.Stat()
	_ = opened.Close()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		_ = root.Close()
		return nil, fmt.Errorf("directory %s changed while opening", path)
	}
	return root, nil
}

func readSecureRegularFile(root *os.Root, name, display string) ([]byte, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid configuration filename %q", name)
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0037 != 0 {
		return nil, fmt.Errorf("configuration file %s is not a secure regular file", display)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("configuration file %s changed while opening", display)
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(opened, after) || opened.Mode() != after.Mode() {
		return nil, fmt.Errorf("configuration file %s changed while reading", display)
	}
	return content, nil
}

func validateRuntimeConfig(value *runtimeConfig) error {
	if value.SchemaVersion < 0 || value.SchemaVersion > CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", value.SchemaVersion)
	}
	if !validAbsolutePath(value.Core.ConfigDir, false) {
		return fmt.Errorf("core.config_dir must be an absolute clean path")
	}
	if value.Core.LogLevel != "DEBUG" && value.Core.LogLevel != "INFO" && value.Core.LogLevel != "WARN" && value.Core.LogLevel != "ERROR" {
		return fmt.Errorf("invalid core.log_level %q", value.Core.LogLevel)
	}
	if value.Core.FirewallBackend != "nftables" && value.Core.FirewallBackend != "iptables" && value.Core.FirewallBackend != "keep" {
		return fmt.Errorf("invalid core.firewall_backend %q", value.Core.FirewallBackend)
	}
	if !validOptionalPort(value.Core.SSHPort) || !validOptionalPort(value.Network.WireGuard.Port) {
		return fmt.Errorf("invalid core or WireGuard port")
	}
	for _, prefix := range value.Network.LanSubnets {
		if !validCanonicalPrefix(prefix) {
			return fmt.Errorf("invalid LAN subnet %q", prefix)
		}
	}
	for _, entry := range value.Network.WhitelistIPs {
		if !validIPOrPrefix(entry) {
			return fmt.Errorf("invalid whitelist entry %q", entry)
		}
	}
	countryPattern := regexp.MustCompile(`^[A-Za-z]{2}$`)
	for _, code := range append(append([]string{}, value.Network.Geo.Blocked...), value.Network.Geo.Allowed...) {
		if !countryPattern.MatchString(code) {
			return fmt.Errorf("invalid country code %q", code)
		}
	}
	for _, asn := range append(append([]string{}, value.Network.ASN.Blocked...), value.Network.ASN.Allowed...) {
		if !validASN(asn) {
			return fmt.Errorf("invalid ASN %q", asn)
		}
	}
	if !validInterfaces(value.Network.Interfaces) {
		return fmt.Errorf("invalid network.interfaces")
	}
	if value.Network.WireGuard.Subnet != "" && !validCanonicalIPv4Prefix(value.Network.WireGuard.Subnet) {
		return fmt.Errorf("WireGuard subnet must be a canonical IPv4 prefix")
	}
	if value.Network.WireGuard.Enabled && (value.Network.WireGuard.Subnet == "" || value.Network.WireGuard.Port == "") {
		return fmt.Errorf("enabled WireGuard requires a subnet and port")
	}
	if value.Network.WireGuard.Enabled && value.Core.FirewallBackend != "nftables" {
		return fmt.Errorf("network.wireguard.enabled requires core.firewall_backend=nftables")
	}
	switch value.Network.Blocklists.ListChoice {
	case "", "1", "2", "3", "4":
	default:
		return fmt.Errorf("invalid blocklist choice")
	}
	for _, address := range []string{value.Network.Blocklists.CustomURL, value.Network.Blocklists.CustomURL6} {
		if address != "" && !validHTTPSURL(address) {
			return fmt.Errorf("invalid custom blocklist URL")
		}
	}
	for _, digest := range []string{value.Network.Blocklists.CustomHash, value.Network.Blocklists.CustomHash6} {
		if digest != "" && !validSHA256(digest) {
			return fmt.Errorf("invalid custom blocklist SHA-256")
		}
	}
	if value.Network.Blocklists.ListChoice == "3" && value.Network.Blocklists.CustomURL == "" && value.Network.Blocklists.CustomURL6 == "" {
		return fmt.Errorf("network.blocklists.list_choice=3 requires at least one custom HTTPS URL")
	}
	if value.Network.Blocklists.CustomHash != "" && value.Network.Blocklists.CustomURL == "" ||
		value.Network.Blocklists.CustomHash6 != "" && value.Network.Blocklists.CustomURL6 == "" {
		return fmt.Errorf("network.blocklists SHA-256 values require their matching custom URL")
	}
	seenPorts := make(map[string]struct{}, len(value.Security.Honeyports))
	for _, port := range value.Security.Honeyports {
		if port == "" || !validOptionalPort(port) {
			return fmt.Errorf("invalid honeyport %q", port)
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return fmt.Errorf("duplicate honeyport %q", port)
		}
		seenPorts[port] = struct{}{}
	}
	if value.Security.Compliance.CheckInterval != "" {
		if _, err := time.ParseDuration(value.Security.Compliance.CheckInterval); err != nil {
			return fmt.Errorf("invalid security.compliance.check_interval")
		}
	}
	if value.WAAP.EnforcementMode != "enforcing" && value.WAAP.EnforcementMode != "audit" {
		return fmt.Errorf("invalid WAAP enforcement mode")
	}
	if value.WAAP.BruteforceThreshold < 1 || value.WAAP.BruteforceWindowSeconds < 1 {
		return fmt.Errorf("invalid WAAP threshold or window")
	}
	if !validLogSetting(value.WAAP.BruteforceLogs, true) || !validLogSetting(value.WAAP.ModsecLogs, false) {
		return fmt.Errorf("invalid WAAP log path")
	}
	if value.Integrations.HA.PeerPort < 1 || value.Integrations.HA.PeerPort > 65535 {
		return fmt.Errorf("invalid HA peer port")
	}
	if value.Network.WireGuard.Enabled && value.Integrations.HA.Enabled && value.Core.SSHPort != "" {
		sshPort, _ := strconv.Atoi(value.Core.SSHPort)
		if sshPort == value.Integrations.HA.PeerPort {
			return fmt.Errorf("integrations.ha.peer_port must not equal core.ssh_port while WireGuard is enabled")
		}
	}
	for _, peer := range value.Integrations.HA.PeerIPs {
		if !validIPOrPrefix(peer) {
			return fmt.Errorf("invalid HA peer %q", peer)
		}
	}
	if value.Integrations.HA.Enabled && (!validToken(value.Integrations.HA.Token) || len(value.Integrations.HA.PeerIPs) == 0) {
		return fmt.Errorf("enabled HA requires authenticated canonical peers")
	}
	if value.Integrations.BunkerWeb.Enabled && !value.Integrations.HA.Enabled {
		return fmt.Errorf("BunkerWeb integration requires HA")
	}
	if value.Integrations.Wazuh.IP != "" {
		address, err := netip.ParseAddr(value.Integrations.Wazuh.IP)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return fmt.Errorf("invalid Wazuh IP")
		}
	}
	if !validOptionalPort(value.Integrations.Wazuh.CommPort) || !validOptionalPort(value.Integrations.Wazuh.EnrollPort) {
		return fmt.Errorf("invalid Wazuh port")
	}
	if value.Integrations.Wazuh.Enabled && (value.Integrations.Wazuh.IP == "" || value.Integrations.Wazuh.CommPort == "" || value.Integrations.Wazuh.EnrollPort == "") {
		return fmt.Errorf("enabled Wazuh configuration is incomplete")
	}
	if value.Integrations.SIEM.IP != "" {
		address, err := netip.ParseAddr(value.Integrations.SIEM.IP)
		if err != nil || address.Zone() != "" || address.Is4In6() {
			return fmt.Errorf("invalid SIEM IP")
		}
	}
	if !validOptionalPort(value.Integrations.SIEM.Port) ||
		value.Integrations.SIEM.Protocol != "" && value.Integrations.SIEM.Protocol != "tls" && value.Integrations.SIEM.Protocol != "tcp" && value.Integrations.SIEM.Protocol != "udp" {
		return fmt.Errorf("invalid SIEM port or protocol")
	}
	if value.Integrations.SIEM.TLSCA != "" && !validAbsolutePath(value.Integrations.SIEM.TLSCA, false) {
		return fmt.Errorf("invalid SIEM CA path")
	}
	if value.Integrations.SIEM.Enabled && (value.Integrations.SIEM.IP == "" || value.Integrations.SIEM.Port == "" || value.Integrations.SIEM.Protocol == "" ||
		value.Integrations.SIEM.Protocol == "tls" && value.Integrations.SIEM.TLSCA == "") {
		return fmt.Errorf("enabled SIEM configuration is incomplete")
	}
	webhooks := []string{value.Integrations.Webhooks.DiscordURL, value.Integrations.Webhooks.TeamsURL, value.Integrations.Webhooks.SlackURL}
	hasWebhook := false
	for _, address := range webhooks {
		if address == "" {
			continue
		}
		hasWebhook = true
		if !validHTTPSURL(address) {
			return fmt.Errorf("invalid webhook URL")
		}
	}
	if value.Integrations.Webhooks.Enabled && !hasWebhook {
		return fmt.Errorf("enabled webhooks require an HTTPS URL")
	}
	return nil
}

func historicalHAState(value *runtimeConfig) bool {
	return value.Integrations.HA.Enabled && value.Integrations.HA.Token == "" &&
		len(value.Integrations.HA.PeerIPs) == 0 && !value.Integrations.BunkerWeb.Enabled
}

func validOptionalPort(value string) bool {
	if value == "" {
		return true
	}
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}

func validCanonicalPrefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix == prefix.Masked() && prefix.Addr().Zone() == "" && !prefix.Addr().Is4In6()
}

func validCanonicalIPv4Prefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix == prefix.Masked() && prefix.Addr().Is4() && !prefix.Addr().Is4In6()
}

func validIPOrPrefix(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6()
	}
	return validCanonicalPrefix(value)
}

func validASN(value string) bool {
	if strings.HasPrefix(value, "AS") || strings.HasPrefix(value, "as") {
		value = value[2:]
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return value != "" && err == nil
}

func validInterfaces(value string) bool {
	if value == "" {
		return true
	}
	pattern := regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	seen := make(map[string]struct{})
	for _, name := range strings.Split(value, ",") {
		if strings.TrimSpace(name) != name || !pattern.MatchString(name) {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
	}
	return true
}

func validHTTPSURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func validSHA256(value string) bool {
	if strings.HasPrefix(value, "sha256:") {
		value = value[7:]
		if value == "" {
			return false
		}
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validLogSetting(value string, allowAuto bool) bool {
	if value == "" || allowAuto && value == "auto" {
		return true
	}
	patterns := strings.Fields(value)
	if len(patterns) == 0 || strings.Join(patterns, " ") != value {
		return false
	}
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if !validAbsolutePath(pattern, true) {
			return false
		}
		if _, err := filepath.Match(pattern, pattern); err != nil {
			return false
		}
		if _, duplicate := seen[pattern]; duplicate {
			return false
		}
		seen[pattern] = struct{}{}
	}
	return true
}

func validAbsolutePath(value string, allowGlob bool) bool {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	for _, component := range strings.Split(filepath.ToSlash(value), "/") {
		if component == ".." {
			return false
		}
	}
	return allowGlob || !strings.ContainsAny(value, "*?[")
}

func validToken(value string) bool {
	return value != "" && len(value) <= 4096 && strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) < 0
}

func flattenKeys(prefix string, document map[string]any, keys map[string]struct{}) {
	for name, value := range document {
		key := strings.ToLower(name)
		if prefix != "" {
			key = prefix + "." + key
		}
		if nested, ok := value.(map[string]any); ok {
			flattenKeys(key, nested, keys)
		} else {
			keys[key] = struct{}{}
		}
	}
}

func collectKnownKeys(value reflect.Type, prefix string, keys map[string]struct{}) {
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name := strings.Split(field.Tag.Get("mapstructure"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		if field.Type.Kind() == reflect.Struct {
			collectKnownKeys(field.Type, key, keys)
		} else {
			keys[strings.ToLower(key)] = struct{}{}
		}
	}
}
