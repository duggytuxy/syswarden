package platformpaths

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// WhitelistCommand permits one canonical address or prefix on one TCP port.
// A port is mandatory: an unscoped whitelist also mutates global ban ownership.
func WhitelistCommand(value, port string) (*exec.Cmd, error) {
	target, err := canonicalWhitelistTarget(value)
	if err != nil {
		return nil, err
	}
	parsed, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != port {
		return nil, fmt.Errorf("whitelist port must be canonical decimal in 1..65535")
	}
	return whitelistCommand(target, port), nil
}

func canonicalWhitelistTarget(value string) (string, error) {
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Masked().Addr() {
			return "", fmt.Errorf("invalid canonical whitelist prefix")
		}
		canonical := prefix.Masked().String()
		if canonical != value {
			return "", fmt.Errorf("whitelist prefix is not canonical")
		}
		return canonical, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.Is4In6() || address.Zone() != "" {
		return "", fmt.Errorf("invalid canonical whitelist address")
	}
	canonical := address.String()
	if canonical != value {
		return "", fmt.Errorf("whitelist address is not canonical")
	}
	return canonical, nil
}
