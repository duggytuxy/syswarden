package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// StandardInstallProfile retains the existing list-1 profile's missing-key
// semantics. Neither profile authorizes host mutation or retires protection.
const StandardInstallProfile = "standard-v1"

// UnconfiguredInstallProfile is the fresh package template: no threat list or
// optional module is selected until the administrator configures TOML.
const UnconfiguredInstallProfile = "unconfigured-v1"

var optionalModuleKeys = []string{
	"network.blocklists.osint_enabled", "waap.enabled", "waap.log_bridge_enabled", "security.detection_enabled",
}

// Historical module switches retain their old defaults on upgrade. A fresh
// profile requires an actual TOML value for every optional activation.
var freshModuleKeys = []string{
	"core.hardening_enabled", "core.cis_l2_hardening",
	"network.geo.enabled", "network.asn.enabled", "network.wireguard.enabled",
	"network.blocklists.use_spamhaus", "network.saas.allow_monitors",
	"security.l2.enable_l2", "security.l2.arp_protect", "security.l2.lan_mode",
	"security.compliance.enable_watchdog", "integrations.ha.enabled", "integrations.ha.v2_enabled",
	"integrations.siem.enabled", "integrations.abuseipdb.enabled", "integrations.webhooks.enabled",
	"integrations.bunkerweb.enabled", "integrations.wazuh.enabled", "integrations.saas.enabled",
}

// Resolve only the newly introduced switches. Missing switches in historical
// installations preserve their old behavior; missing switches in this profile
// remain disabled. Environment variables cannot grant module consent.
func resolveOptionalModules(v *viper.Viper) error {
	keys := append([]string{"core.install_profile", "network.policy_mode"}, optionalModuleKeys...)
	for _, key := range keys {
		env := "SYSWARDEN_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		if _, present := os.LookupEnv(env); present {
			return fmt.Errorf("%s is unsupported; select modules in TOML", env)
		}
	}
	profile := v.GetString("core.install_profile")
	if profile != "" && profile != StandardInstallProfile && profile != UnconfiguredInstallProfile {
		return fmt.Errorf("unsupported core.install_profile %q", profile)
	}
	v.Set("core.install_profile", profile)
	if profile == StandardInstallProfile || profile == UnconfiguredInstallProfile {
		for _, key := range freshModuleKeys {
			env := "SYSWARDEN_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
			if _, present := os.LookupEnv(env); present {
				return fmt.Errorf("%s is unsupported for the fresh profile; select modules in TOML", env)
			}
			selected := false
			if v.InConfig(key) {
				selected = v.GetBool(key)
			}
			v.Set(key, selected)
		}
		listChoice := "1"
		if profile == UnconfiguredInstallProfile {
			listChoice = "4"
			if _, present := os.LookupEnv("SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE"); present {
				return fmt.Errorf("SYSWARDEN_NETWORK_BLOCKLISTS_LIST_CHOICE is unsupported for the unconfigured profile; select a list in TOML")
			}
		}
		for key, value := range map[string]string{"network.blocklists.list_choice": listChoice, "waap.bruteforce_logs": "", "waap.modsec_logs": ""} {
			if !v.InConfig(key) {
				v.SetDefault(key, value)
			}
		}
	}
	mode := "host"
	if profile == StandardInstallProfile || profile == UnconfiguredInstallProfile {
		mode = "lists"
	}
	if v.IsSet("network.policy_mode") {
		mode = v.GetString("network.policy_mode")
	}
	if mode != "host" && mode != "lists" {
		return fmt.Errorf("network.policy_mode must be host or lists")
	}
	v.Set("network.policy_mode", mode)
	for _, key := range optionalModuleKeys {
		selected := profile == ""
		if v.IsSet(key) {
			selected = v.GetBool(key)
		}
		v.Set(key, selected)
	}
	// The bridge publishes to the SysWarden WAAP socket. Refuse a selected
	// producer with no selected consumer instead of enabling either implicitly.
	if v.GetBool("waap.log_bridge_enabled") && !v.GetBool("waap.enabled") {
		return fmt.Errorf("waap.log_bridge_enabled requires explicit waap.enabled=true; no module was enabled automatically")
	}
	return nil
}

func validateOptionalModuleDocument(relative string, document map[string]any) error {
	keys := append([]string{"core.install_profile", "network.policy_mode"}, optionalModuleKeys...)
	keys = append(keys, freshModuleKeys...)
	for _, key := range keys {
		var value any = document
		present := true
		for _, part := range strings.Split(key, ".") {
			table, ok := value.(map[string]any)
			if !ok {
				return fmt.Errorf("%s selection parent must be a TOML table", relative)
			}
			for name := range table {
				if strings.EqualFold(name, part) && name != part {
					return fmt.Errorf("%s selection keys must use canonical lower case", relative)
				}
			}
			value, present = table[part]
			if !present {
				break
			}
		}
		if !present {
			continue
		}
		if key == "core.install_profile" {
			profile, ok := value.(string)
			if !ok || (profile != "" && profile != StandardInstallProfile && profile != UnconfiguredInstallProfile) {
				return fmt.Errorf("%s core.install_profile must be %q, %q or empty for historical configuration", relative, StandardInstallProfile, UnconfiguredInstallProfile)
			}
		} else if key == "network.policy_mode" {
			mode, ok := value.(string)
			if !ok || (mode != "host" && mode != "lists") {
				return fmt.Errorf("%s network.policy_mode must be host or lists", relative)
			}
		} else if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s %s must be a TOML boolean", relative, key)
		}
	}
	return nil
}
