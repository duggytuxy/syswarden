package platformpaths

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// WhitelistCommand returns a native CLI command for one canonical address or prefix.
func WhitelistCommand(value string) (*exec.Cmd, error) {
	target, err := canonicalWhitelistTarget(value)
	if err != nil {
		return nil, err
	}
	return whitelistCommand(target), nil
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
