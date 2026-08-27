package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate
var countryCodeRegex = regexp.MustCompile("^[a-zA-Z]{2}$")
var interfaceNameRegex = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

func init() {
	validate = validator.New()
	_ = validate.RegisterValidation("cidr", validateCIDR)
	_ = validate.RegisterValidation("canonical_cidr", validateCanonicalCIDR)
	_ = validate.RegisterValidation("cidr_slice", validateCIDRSlice)
	_ = validate.RegisterValidation("canonical_cidr_slice", validateCanonicalCIDRSlice)
	_ = validate.RegisterValidation("ip", validateIP)
	_ = validate.RegisterValidation("ip_slice", validateIPSlice)
	_ = validate.RegisterValidation("ip_or_cidr_slice", validateIPOrCIDRSlice)
	_ = validate.RegisterValidation("ha_peer_slice", validateHAPeerSlice)
	_ = validate.RegisterValidation("port", validatePort)
	_ = validate.RegisterValidation("port_slice", validatePortSlice)
	_ = validate.RegisterValidation("asn", validateASN)
	_ = validate.RegisterValidation("asn_slice", validateASNSlice)
	_ = validate.RegisterValidation("country_code", validateCountryCode)
	_ = validate.RegisterValidation("country_code_slice", validateCountryCodeSlice)
	_ = validate.RegisterValidation("duration", validateDuration)
	_ = validate.RegisterValidation("interface_list", validateInterfaceList)
	_ = validate.RegisterValidation("https_url_optional", validateHTTPSURLOptional)
	_ = validate.RegisterValidation("sha256_optional", validateSHA256Optional)
	_ = validate.RegisterValidation("absolute_path", validateAbsolutePath)
	_ = validate.RegisterValidation("absolute_path_optional", validateAbsolutePathOptional)
	_ = validate.RegisterValidation("log_path_or_auto", validateLogPathOrAuto)
	_ = validate.RegisterValidation("log_path_optional", validateLogPathOptional)
}

func validateConfig(config *ModularConfig) error {
	if config == nil {
		return fmt.Errorf("configuration must not be nil")
	}
	if config.SchemaVersion < 0 || config.SchemaVersion > CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", config.SchemaVersion)
	}
	if err := validate.Struct(config); err != nil {
		return err
	}
	if err := ValidateOperatorPolicy(config.OperatorPolicy); err != nil {
		return err
	}
	if hasDuplicateStrings(config.Security.Honeyports) {
		return fmt.Errorf("security.honeyports must not contain duplicate ports")
	}
	if config.Network.Wireguard.Enabled && (config.Network.Wireguard.Port == "" || config.Network.Wireguard.Subnet == "") {
		return fmt.Errorf("network.wireguard.enabled requires a valid port and canonical subnet")
	}
	if config.Network.Wireguard.Enabled && config.Core.FirewallBackend != "nftables" {
		return fmt.Errorf("network.wireguard.enabled requires core.firewall_backend=nftables")
	}
	if config.Network.Wireguard.Subnet != "" && !validCanonicalIPv4Prefix(config.Network.Wireguard.Subnet) {
		return fmt.Errorf("network.wireguard.subnet must be a canonical IPv4 prefix")
	}
	blocklists := config.Network.Blocklists
	if blocklists.ListChoice == "3" && blocklists.CustomURL == "" && blocklists.CustomURL6 == "" {
		return fmt.Errorf("network.blocklists.list_choice=3 requires at least one custom HTTPS URL")
	}
	if (blocklists.CustomURL == "") != (blocklists.CustomHash == "") ||
		(blocklists.CustomURL6 == "") != (blocklists.CustomHash6 == "") {
		return fmt.Errorf("network.blocklists custom HTTPS URLs and SHA-256 values must be configured in matching pairs")
	}
	if config.Integrations.BunkerWeb.Enabled {
		if !config.Integrations.HA.Enabled {
			return fmt.Errorf("integrations.bunkerweb.enabled requires integrations.ha.enabled=true")
		}
		if config.Integrations.HA.Token == "" || strings.TrimSpace(config.Integrations.HA.Token) != config.Integrations.HA.Token {
			return fmt.Errorf("integrations.bunkerweb.enabled requires a non-empty integrations.ha.token without surrounding whitespace")
		}
		if len(config.Integrations.HA.PeerIPs) == 0 {
			return fmt.Errorf("integrations.bunkerweb.enabled requires at least one exact IP or canonical CIDR in integrations.ha.peer_ips")
		}
	}
	if config.Integrations.HA.Enabled {
		if !validBearerToken(config.Integrations.HA.Token) {
			return fmt.Errorf("integrations.ha.token must be a non-empty bearer token without whitespace or control characters when HA is enabled")
		}
		if len(config.Integrations.HA.PeerIPs) == 0 {
			return fmt.Errorf("integrations.ha.peer_ips must contain at least one IP address or CIDR when HA is enabled")
		}
		if config.Network.Wireguard.Enabled && config.Core.SSHPort != "" {
			sshPort, _ := strconv.Atoi(config.Core.SSHPort)
			if sshPort == config.Integrations.HA.PeerPort {
				return fmt.Errorf("integrations.ha.peer_port must not equal core.ssh_port while WireGuard is enabled")
			}
		}
	}
	if config.Integrations.SIEM.Enabled {
		if config.Integrations.SIEM.IP == "" || config.Integrations.SIEM.Port == "" || config.Integrations.SIEM.Protocol == "" {
			return fmt.Errorf("integrations.siem.enabled requires a valid IP, port, and protocol")
		}
		if config.Integrations.SIEM.Protocol == "tls" && config.Integrations.SIEM.TLSCA == "" {
			return fmt.Errorf("integrations.siem.protocol=tls requires an absolute integrations.siem.tls_ca path")
		}
	}
	if config.Integrations.Webhooks.Enabled && config.Integrations.Webhooks.DiscordURL == "" &&
		config.Integrations.Webhooks.TeamsURL == "" && config.Integrations.Webhooks.SlackURL == "" {
		return fmt.Errorf("integrations.webhooks.enabled requires at least one HTTPS webhook URL")
	}
	if config.Integrations.Wazuh.Enabled &&
		(config.Integrations.Wazuh.IP == "" || config.Integrations.Wazuh.CommPort == "" || config.Integrations.Wazuh.EnrollPort == "") {
		return fmt.Errorf("enabled Wazuh configuration requires an IP, communication port, and enrollment port")
	}
	return nil
}

func validateCIDR(fl validator.FieldLevel) bool {
	cidr := fl.Field().String()
	if cidr == "" {
		return true
	}
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func validateCanonicalCIDR(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return value == "" || validCanonicalPrefix(value)
}

func validateCIDRSlice(fl validator.FieldLevel) bool {
	for _, cidr := range fl.Field().Interface().([]string) {
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return false
		}
	}
	return true
}

func validateCanonicalCIDRSlice(fl validator.FieldLevel) bool {
	values, ok := fl.Field().Interface().([]string)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == "" || !validCanonicalPrefix(value) {
			return false
		}
	}
	return true
}

func validateIP(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == "" && !address.Is4In6()
}

func validateIPSlice(fl validator.FieldLevel) bool {
	for _, ip := range fl.Field().Interface().([]string) {
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return false
		}
	}
	return true
}

func validateIPOrCIDRSlice(fl validator.FieldLevel) bool {
	values, ok := fl.Field().Interface().([]string)
	if !ok {
		return false
	}
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return false
		}
		if address, err := netip.ParseAddr(value); err == nil {
			if address.Is4In6() || address.Zone() != "" {
				return false
			}
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix != prefix.Masked() {
			return false
		}
	}
	return true
}

func validateHAPeerSlice(fl validator.FieldLevel) bool {
	values, ok := fl.Field().Interface().([]string)
	if !ok {
		return false
	}
	for _, value := range values {
		if _, err := CanonicalHAPeer(value); err != nil {
			return false
		}
	}
	return true
}

// CanonicalHAPeer validates and canonicalizes one exact HA peer address or
// inbound peer network. Network scopes are deliberately limited so a bypassed
// configuration loader cannot turn HA trust into a broad network allowlist.
func CanonicalHAPeer(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("HA peer must not be empty or whitespace padded")
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", fmt.Errorf("HA peer must be an unmapped and unzoned address")
		}
		return address.String(), nil
	}

	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return "", fmt.Errorf("HA peer must be an exact IP address or canonical CIDR")
	}
	if prefix != prefix.Masked() {
		return "", fmt.Errorf("HA peer CIDR must not contain host bits")
	}
	minimumBits := 64
	if prefix.Addr().Is4() {
		minimumBits = 24
	}
	if prefix.Bits() < minimumBits {
		return "", fmt.Errorf("HA peer CIDR is broader than /%d", minimumBits)
	}
	return prefix.String(), nil
}

func validatePort(fl validator.FieldLevel) bool {
	port := fl.Field().String()
	if port == "" {
		return true
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return p > 0 && p <= 65535
}

func validatePortSlice(fl validator.FieldLevel) bool {
	for _, port := range fl.Field().Interface().([]string) {
		if port == "" {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return false
		}
	}
	return true
}

func validateASN(fl validator.FieldLevel) bool {
	asn := trimASNPrefix(fl.Field().String())
	if asn == "" {
		return true
	}
	value, err := strconv.ParseUint(asn, 10, 32)
	return err == nil && value <= 4294967295
}

func validateASNSlice(fl validator.FieldLevel) bool {
	for _, asn := range fl.Field().Interface().([]string) {
		asnTrim := trimASNPrefix(asn)
		if asnTrim == "" {
			return false
		}
		if value, err := strconv.ParseUint(asnTrim, 10, 32); err != nil || value > 4294967295 {
			return false
		}
	}
	return true
}

func trimASNPrefix(value string) string {
	if strings.HasPrefix(value, "AS") || strings.HasPrefix(value, "as") {
		return value[2:]
	}
	return value
}

func validateCountryCode(fl validator.FieldLevel) bool {
	code := fl.Field().String()
	if code == "" {
		return true
	}
	return countryCodeRegex.MatchString(code)
}

func validateCountryCodeSlice(fl validator.FieldLevel) bool {
	for _, code := range fl.Field().Interface().([]string) {
		if code == "" {
			return false
		}
		if !countryCodeRegex.MatchString(code) {
			return false
		}
	}
	return true
}

func validateDuration(fl validator.FieldLevel) bool {
	duration := fl.Field().String()
	if duration == "" {
		return true
	}
	_, err := time.ParseDuration(duration)
	return err == nil
}

func validCanonicalPrefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Zone() == "" && !prefix.Addr().Is4In6() && prefix == prefix.Masked()
}

func validCanonicalIPv4Prefix(value string) bool {
	prefix, err := netip.ParsePrefix(value)
	return err == nil && prefix.Addr().Is4() && !prefix.Addr().Is4In6() && prefix == prefix.Masked()
}

func validateInterfaceList(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true
	}
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if part == "" || strings.TrimSpace(part) != part || !interfaceNameRegex.MatchString(part) {
			return false
		}
		if _, exists := seen[part]; exists {
			return false
		}
		seen[part] = struct{}{}
	}
	return true
}

func validateHTTPSURLOptional(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func validateSHA256Optional(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "sha256:") {
		value = strings.TrimPrefix(value, "sha256:")
		if value == "" {
			return false
		}
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateAbsolutePath(fl validator.FieldLevel) bool {
	return validAbsolutePath(fl.Field().String(), false)
}

func validateAbsolutePathOptional(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	return value == "" || validAbsolutePath(value, false)
}

func validateLogPathOrAuto(fl validator.FieldLevel) bool {
	return validLogPatternList(fl.Field().String(), true)
}

func validateLogPathOptional(fl validator.FieldLevel) bool {
	return validLogPatternList(fl.Field().String(), false)
}

func validLogPatternList(value string, allowAuto bool) bool {
	if value == "" {
		return true
	}
	if allowAuto && value == "auto" {
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
	if value == "" || !filepath.IsAbs(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		if part == ".." {
			return false
		}
	}
	if !allowGlob && strings.ContainsAny(value, "*?[") {
		return false
	}
	return filepath.Clean(value) == value
}

func validBearerToken(value string) bool {
	return value != "" && len(value) <= 4096 && strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) < 0
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
