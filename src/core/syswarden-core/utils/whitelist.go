package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
	coreconfig "syswarden-core/config"
)

const (
	maximumWhitelistSourceBytes = 1024 * 1024
	maximumWhitelistLineBytes   = 4096
	configuredWhitelistKey      = "network.whitelist_ips"
)

var (
	whitelistCache            map[netip.Addr]struct{}
	whitelistCIDRCache        []netip.Prefix
	whitelistCacheErr         error
	whitelistCacheInitialized bool
	whitelistCacheSourceState string
	cacheMutex                sync.RWMutex
	lastLoad                  time.Time
	whitelistSourceFiles      = []whitelistSource{
		{path: "/etc/syswarden/lists/syswarden_whitelist.ipv4", required: true},
		{path: "/etc/syswarden/lists/syswarden_whitelist.ipv6", required: true},
		{path: "/etc/syswarden/lists/syswarden_saas_monitors.ipv4", publicOnly: true, enabled: saasWhitelistEnabled},
		{path: "/etc/syswarden/lists/syswarden_saas_monitors.ipv6", publicOnly: true, enabled: saasWhitelistEnabled},
	}
)

type whitelistSource struct {
	path       string
	required   bool
	publicOnly bool
	enabled    func() bool
}

func saasWhitelistEnabled() bool {
	if viper.IsSet("network.saas.allow_monitors") {
		return viper.GetBool("network.saas.allow_monitors")
	}
	if viper.IsSet("integrations.saas.enabled") {
		return viper.GetBool("integrations.saas.enabled")
	}
	return false
}

// IsWhitelisted checks whether an address belongs to the infrastructure
// whitelist or local loopback. Legacy callers retain a boolean interface; a
// failed authoritative refresh is treated as protected. Privileged mutation
// boundaries must use IsWhitelistedStrict and fail closed on its error.
func IsWhitelisted(value string) bool {
	whitelisted, err := IsWhitelistedStrict(value)
	return err != nil || whitelisted
}

// IsWhitelistedStrict checks the canonical whitelist and reports any read,
// integrity, scan, or parse failure instead of silently treating it as empty.
func IsWhitelistedStrict(value string) (bool, error) {
	address, err := canonicalWhitelistTarget(value)
	if err != nil {
		return false, err
	}
	if address.IsLoopback() {
		return true, nil
	}

	configuredWhitelist := configuredWhitelistValues()
	sourceState := currentWhitelistSourceState(whitelistSourceFiles, configuredWhitelist)
	cacheMutex.RLock()
	needsRefresh := time.Since(lastLoad) > 60*time.Second || !whitelistCacheInitialized || whitelistCacheSourceState != sourceState
	cacheMutex.RUnlock()
	if needsRefresh {
		refreshWhitelistCache(sourceState, configuredWhitelist)
	}

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	if whitelistCacheErr != nil {
		return false, whitelistCacheErr
	}
	if _, found := whitelistCache[address]; found {
		return true, nil
	}
	for _, prefix := range whitelistCIDRCache {
		if prefix.Contains(address) {
			return true, nil
		}
	}
	return false, nil
}

func canonicalWhitelistTarget(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "localhost" {
		return netip.MustParseAddr("127.0.0.1"), nil
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return netip.Addr{}, fmt.Errorf("unsupported whitelist target")
		}
		return address.Unmap(), nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		address, parseErr := netip.ParseAddr(host)
		if parseErr == nil && !address.Is4In6() && address.Zone() == "" {
			return address.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("invalid whitelist target")
}

func configuredWhitelistValues() []string {
	return append([]string(nil), viper.GetStringSlice(configuredWhitelistKey)...)
}

func refreshWhitelistCache(sourceState string, configuredWhitelist []string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()
	if time.Since(lastLoad) <= 60*time.Second && whitelistCacheInitialized && whitelistCacheSourceState == sourceState {
		return
	}
	addresses, prefixes, err := loadWhitelistSources(whitelistSourceFiles)
	if err == nil {
		var configuredAddresses map[netip.Addr]struct{}
		var configuredPrefixes []netip.Prefix
		configuredAddresses, configuredPrefixes, err = loadConfiguredWhitelist(configuredWhitelist)
		if err == nil {
			for address := range configuredAddresses {
				addresses[address] = struct{}{}
			}
			prefixSet := make(map[netip.Prefix]struct{}, len(prefixes)+len(configuredPrefixes))
			for _, prefix := range prefixes {
				prefixSet[prefix] = struct{}{}
			}
			for _, prefix := range configuredPrefixes {
				if _, duplicate := prefixSet[prefix]; duplicate {
					continue
				}
				prefixSet[prefix] = struct{}{}
				prefixes = append(prefixes, prefix)
			}
		}
	}
	lastLoad = time.Now()
	whitelistCacheInitialized = true
	whitelistCacheSourceState = sourceState
	whitelistCacheErr = err
	if err != nil {
		return
	}
	whitelistCache = addresses
	whitelistCIDRCache = prefixes
}

func currentWhitelistSourceState(sources []whitelistSource, configuredWhitelist []string) string {
	var state strings.Builder
	for _, source := range sources {
		enabled := source.enabled == nil || source.enabled()
		fmt.Fprintf(&state, "%s\x00%t\x00", source.path, enabled)
	}
	fmt.Fprintf(&state, "%s\x00%d\x00", configuredWhitelistKey, len(configuredWhitelist))
	for _, value := range configuredWhitelist {
		fmt.Fprintf(&state, "%d\x00%s\x00", len(value), value)
	}
	return state.String()
}

func loadConfiguredWhitelist(values []string) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	addresses := make(map[netip.Addr]struct{})
	prefixSet := make(map[netip.Prefix]struct{})
	for index, value := range values {
		if coreconfig.IsRetiredUnspecifiedWhitelistEntry(value) {
			continue
		}
		address, prefix, portScoped, err := parseStrictWhitelistLine(value)
		if err != nil {
			return nil, nil, fmt.Errorf("%s[%d]: %w", configuredWhitelistKey, index, err)
		}
		if portScoped {
			return nil, nil, fmt.Errorf("%s[%d]: port-scoped entries are not supported", configuredWhitelistKey, index)
		}
		if address.IsValid() {
			addresses[address] = struct{}{}
		} else {
			prefixSet[prefix] = struct{}{}
		}
	}
	prefixes := make([]netip.Prefix, 0, len(prefixSet))
	for prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	return addresses, prefixes, nil
}

func loadWhitelistSources(sources []whitelistSource) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	addresses := make(map[netip.Addr]struct{})
	prefixSet := make(map[netip.Prefix]struct{})
	for _, source := range sources {
		if source.enabled != nil && !source.enabled() {
			continue
		}
		wire, err := readWhitelistSource(source.path)
		if errors.Is(err, fs.ErrNotExist) {
			if source.required {
				return nil, nil, fmt.Errorf("required whitelist source %q is missing", source.path)
			}
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		scanner := bufio.NewScanner(strings.NewReader(string(wire)))
		scanner.Buffer(make([]byte, 1024), maximumWhitelistLineBytes)
		for lineNumber := 1; scanner.Scan(); lineNumber++ {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			address, prefix, portScoped, err := parseStrictWhitelistLine(line)
			if err != nil {
				return nil, nil, fmt.Errorf("whitelist source %q line %d: %w", source.path, lineNumber, err)
			}
			if source.publicOnly {
				if portScoped {
					return nil, nil, fmt.Errorf("whitelist source %q line %d: public source must not contain a port-scoped entry", source.path, lineNumber)
				}
				value := prefix.String()
				if address.IsValid() {
					value = address.String()
				}
				if _, _, err := CanonicalFirewallNetworkEntry(value, FirewallNetworkPolicy{}); err != nil {
					return nil, nil, fmt.Errorf("whitelist source %q line %d: %w", source.path, lineNumber, err)
				}
			}
			if portScoped {
				continue
			}
			if address.IsValid() {
				addresses[address] = struct{}{}
			} else {
				prefixSet[prefix] = struct{}{}
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, nil, fmt.Errorf("scan whitelist source %q: %w", source.path, err)
		}
	}
	prefixes := make([]netip.Prefix, 0, len(prefixSet))
	for prefix := range prefixSet {
		prefixes = append(prefixes, prefix)
	}
	return addresses, prefixes, nil
}

func parseStrictWhitelistLine(line string) (netip.Addr, netip.Prefix, bool, error) {
	parseNetwork := func(value string) (netip.Addr, netip.Prefix, error) {
		if err := coreconfig.ValidateWhitelistEntry(value); err != nil {
			return netip.Addr{}, netip.Prefix{}, err
		}
		if address, err := netip.ParseAddr(value); err == nil {
			if address.Is4In6() || address.Zone() != "" {
				return netip.Addr{}, netip.Prefix{}, fmt.Errorf("unsupported address")
			}
			if address.String() != value {
				return netip.Addr{}, netip.Prefix{}, fmt.Errorf("address is not canonical")
			}
			return address.Unmap(), netip.Prefix{}, nil
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix != prefix.Masked() || prefix.String() != value {
			return netip.Addr{}, netip.Prefix{}, fmt.Errorf("entry is not a canonical IP or CIDR")
		}
		minimumBits := MinimumFirewallIPv6PrefixBits
		if prefix.Addr().Is4() {
			minimumBits = MinimumFirewallIPv4PrefixBits
		}
		if prefix.Bits() < minimumBits {
			return netip.Addr{}, netip.Prefix{}, fmt.Errorf("whitelist prefix is broader than the /%d minimum", minimumBits)
		}
		return netip.Addr{}, prefix, nil
	}
	if address, prefix, err := parseNetwork(line); err == nil {
		return address, prefix, false, nil
	}
	host, rawPort, err := net.SplitHostPort(line)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, false, fmt.Errorf("entry is not a canonical IP, CIDR, or address-port pair")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != rawPort {
		return netip.Addr{}, netip.Prefix{}, false, fmt.Errorf("port is not canonical or outside 1-65535")
	}
	address, prefix, err := parseNetwork(host)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, false, err
	}
	if net.JoinHostPort(host, rawPort) != line {
		return netip.Addr{}, netip.Prefix{}, false, fmt.Errorf("address-port pair is not canonical")
	}
	return address, prefix, true, nil
}

func readWhitelistSource(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("whitelist source %q must be a regular file", path)
	}
	file, err := os.Open(path) // #nosec G304 -- fixed production paths or test-controlled paths passed to the internal loader
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("whitelist source %q changed while opening", path)
	}
	wire, err := io.ReadAll(io.LimitReader(file, maximumWhitelistSourceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maximumWhitelistSourceBytes {
		return nil, fmt.Errorf("whitelist source %q exceeds %d bytes", path, maximumWhitelistSourceBytes)
	}
	return wire, nil
}
