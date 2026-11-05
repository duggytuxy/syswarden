//go:build linux

package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

// Only literal assignments in the reviewed loader's bounded configuration
// vocabulary are observed. Never source these files, even for a status query.
func parseNFTOpenRCConfig(content []byte, values map[string]string) error {
	if len(content) > 65536 || strings.ContainsAny(string(content), "\x00\r") {
		return fmt.Errorf("OpenRC nftables configuration exceeds its text bounds")
	}
	seen := make(map[string]bool)
	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.Trim(raw, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.Trim(key, " \t") != key || seen[key] {
			return fmt.Errorf("OpenRC nftables configuration contains a nonliteral or repeated assignment")
		}
		seen[key] = true
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		} else if strings.ContainsAny(value, " \t") {
			return fmt.Errorf("OpenRC nftables configuration has an unquoted multiword assignment")
		}
		// A deliberately small grammar also rejects inline shell operators,
		// interpolation, command substitution, escapes and multiline values.
		for _, r := range value {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" /_.:-", r)) {
				return fmt.Errorf("OpenRC nftables configuration contains unsupported shell syntax")
			}
		}
		if !validNFTOpenRCValue(key, value) {
			return fmt.Errorf("OpenRC nftables configuration has an unsupported setting %q", key)
		}
		values[key] = value
	}
	return nil
}

func validNFTOpenRCValue(key, value string) bool {
	switch key {
	case "rules_file", "NFTABLES_SAVE", "save_file":
		return canonicalNFTPersistencePath(value, false) && !strings.ContainsAny(value, " :")
	case "save_on_stop", "SAVE_ON_STOP", "enable_forwarding":
		return value == "no" || value == "NO" || value == "false" || value == "FALSE" || value == "0"
	case "netns", "vrf", "rc_env_allow", "save_options", "SAVE_OPTIONS":
		return value == ""
	case "save_objects":
		return value == "ruleset" || value == "counters limits quotas"
	case "rc_sys":
		return value == "" || value == "podman" || value == "docker" || value == "lxc"
	case "rc_cgroup_mode":
		return value == "legacy" || value == "hybrid" || value == "unified"
	case "rc_parallel", "rc_interactive", "rc_logger", "rc_verbose", "rc_nocolor":
		return value == "yes" || value == "YES" || value == "no" || value == "NO"
	case "rc_tty_number", "respawn_delay", "respawn_max", "respawn_period":
		number, err := strconv.ParseUint(value, 10, 32)
		return err == nil && strconv.FormatUint(number, 10) == value
	default:
		return false
	}
}

func nftOpenRCRulesFile(values map[string]string) string {
	if value := values["rules_file"]; value != "" {
		return value
	}
	if value := values["NFTABLES_SAVE"]; value != "" {
		return value
	}
	return "/etc/nftables.nft"
}
