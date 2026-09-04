package utils

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func isolateWhitelistCache(t *testing.T, sources []whitelistSource) {
	t.Helper()
	cacheMutex.Lock()
	savedAddresses := whitelistCache
	savedPrefixes := whitelistCIDRCache
	savedErr := whitelistCacheErr
	savedInitialized := whitelistCacheInitialized
	savedSourceState := whitelistCacheSourceState
	savedLastLoad := lastLoad
	savedSources := whitelistSourceFiles
	whitelistCache = nil
	whitelistCIDRCache = nil
	whitelistCacheErr = nil
	whitelistCacheInitialized = false
	whitelistCacheSourceState = ""
	lastLoad = time.Time{}
	whitelistSourceFiles = sources
	cacheMutex.Unlock()
	t.Cleanup(func() {
		cacheMutex.Lock()
		whitelistCache = savedAddresses
		whitelistCIDRCache = savedPrefixes
		whitelistCacheErr = savedErr
		whitelistCacheInitialized = savedInitialized
		whitelistCacheSourceState = savedSourceState
		lastLoad = savedLastLoad
		whitelistSourceFiles = savedSources
		cacheMutex.Unlock()
	})
}

func TestLoadWhitelistSourcesCanonicalAndStrict_SW_SEC_M9(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "whitelist")
	if err := os.WriteFile(valid, []byte("8.8.8.8\n2606:4700:4700::/64\n8.8.4.4:443\n[2606:4700:4700::44]:2222\n"), 0600); err != nil {
		t.Fatal(err)
	}
	addresses, prefixes, err := loadWhitelistSources([]whitelistSource{
		{path: valid, required: true},
		{path: filepath.Join(directory, "optional-missing")},
	})
	if err != nil {
		t.Fatalf("loadWhitelistSources() error = %v", err)
	}
	if len(addresses) != 1 || len(prefixes) != 1 {
		t.Fatalf("strict whitelist = %v/%v, want one address and one prefix", addresses, prefixes)
	}
	if _, globallyImmune := addresses[netip.MustParseAddr("8.8.4.4")]; globallyImmune {
		t.Fatal("port-scoped whitelist entry became global host immunity")
	}

	invalid := filepath.Join(directory, "invalid")
	if err := os.WriteFile(invalid, []byte("not-an-address\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWhitelistSources([]whitelistSource{{path: invalid, required: true}}); err == nil {
		t.Fatal("strict whitelist accepted an invalid entry")
	}
	unsafe := filepath.Join(directory, "unsafe")
	if err := os.WriteFile(unsafe, []byte("0.0.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWhitelistSources([]whitelistSource{{path: unsafe, required: true}}); err == nil {
		t.Fatal("file-backed whitelist neutralized an unsafe entry reserved only for configuration compatibility")
	}

	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("8.8.4.4\n"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(victim, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadWhitelistSources([]whitelistSource{{path: symlink, required: true}}); err == nil {
		t.Fatal("strict whitelist followed a symbolic link")
	}
	if _, _, err := loadWhitelistSources([]whitelistSource{{
		path: filepath.Join(directory, "required-missing"), required: true,
	}}); err == nil {
		t.Fatal("strict whitelist accepted a missing required source")
	}
}

func TestIsWhitelistedBooleanFailsSafeOnStrictSourceFailure_SW_SEC_M9(t *testing.T) {
	isolateWhitelistCache(t, []whitelistSource{{path: filepath.Join(t.TempDir(), "missing"), required: true}})

	if _, err := IsWhitelistedStrict("8.8.8.8"); err == nil {
		t.Fatal("strict whitelist hid a missing required source")
	}
	if !IsWhitelisted("8.8.8.8") {
		t.Fatal("boolean whitelist caller failed open on an authoritative source error")
	}
}

func TestConfiguredWhitelistIsEffectiveAndInvalidatesFreshCache_SW_SEC_M9(t *testing.T) {
	directory := t.TempDir()
	ipv4 := filepath.Join(directory, "whitelist.ipv4")
	ipv6 := filepath.Join(directory, "whitelist.ipv6")
	if err := os.WriteFile(ipv4, []byte("1.1.1.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipv6, nil, 0600); err != nil {
		t.Fatal(err)
	}
	isolateWhitelistCache(t, []whitelistSource{
		{path: ipv4, required: true},
		{path: ipv6, required: true},
	})
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set(configuredWhitelistKey, []string{"8.8.8.8", "2606:4700:4700::/64"})

	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1234"} {
		whitelisted, err := IsWhitelistedStrict(value)
		if err != nil {
			t.Fatalf("IsWhitelistedStrict(%q) error = %v", value, err)
		}
		if !whitelisted {
			t.Fatalf("IsWhitelistedStrict(%q) = false, want true", value)
		}
	}

	// The first lookup populated a fresh cache. Changing only the Viper value
	// must bypass the 60-second TTL immediately.
	viper.Set(configuredWhitelistKey, []string{"9.9.9.9"})
	whitelisted, err := IsWhitelistedStrict("8.8.8.8")
	if err != nil {
		t.Fatalf("old configured whitelist lookup error = %v", err)
	}
	if whitelisted {
		t.Fatal("old configured whitelist entry survived a Viper value change")
	}
	whitelisted, err = IsWhitelistedStrict("9.9.9.9")
	if err != nil {
		t.Fatalf("new configured whitelist lookup error = %v", err)
	}
	if !whitelisted {
		t.Fatal("new configured whitelist entry did not invalidate the fresh cache")
	}
}

func TestConfiguredWhitelistUsesStrictAddressGrammar_SW_SEC_M9(t *testing.T) {
	addresses, prefixes, err := loadConfiguredWhitelist([]string{
		"8.8.8.8",
		"2606:4700:4700::/64",
		"8.8.8.8",
	})
	if err != nil {
		t.Fatalf("loadConfiguredWhitelist() error = %v", err)
	}
	if len(addresses) != 1 || len(prefixes) != 1 {
		t.Fatalf("configured whitelist = %v/%v, want one address and one prefix", addresses, prefixes)
	}

	for _, value := range []string{"0.0.0.0/24", "127.0.0.1", "169.254.10.20", "10.0.0.0/8", "2001:0db8::1", "8.8.8.8:443"} {
		_, _, err := loadConfiguredWhitelist([]string{"8.8.4.4", value})
		if err == nil || !strings.Contains(err.Error(), configuredWhitelistKey+"[1]") {
			t.Fatalf("loadConfiguredWhitelist(%q) error = %v, want indexed strict rejection", value, err)
		}
	}
}

func TestConfiguredWhitelistNeutralizesRetiredZeroEntriesOnly_SW_SEC_M1(t *testing.T) {
	addresses, prefixes, err := loadConfiguredWhitelist([]string{
		"0.0.0.0",
		"10.20.30.40",
		"0.0.0.0/32",
		"192.0.2.0/24",
		"fd00:1234::/64",
	})
	if err != nil {
		t.Fatalf("loadConfiguredWhitelist() error = %v", err)
	}
	if len(addresses) != 1 {
		t.Fatalf("configured whitelist addresses = %v, want one retained address", addresses)
	}
	if _, found := addresses[netip.MustParseAddr("10.20.30.40")]; !found {
		t.Fatalf("configured whitelist addresses = %v, want retained private address", addresses)
	}
	if len(prefixes) != 2 {
		t.Fatalf("configured whitelist prefixes = %v, want two retained prefixes", prefixes)
	}
	for _, want := range []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("fd00:1234::/64"),
	} {
		found := false
		for _, prefix := range prefixes {
			if prefix == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("configured whitelist prefixes = %v, want %s", prefixes, want)
		}
	}
}

func TestSaaSWhitelistRequiresEnablementAndSafePublicEntries_SW_SEC_H4(t *testing.T) {
	directory := t.TempDir()
	requiredIPv4 := filepath.Join(directory, "whitelist.ipv4")
	requiredIPv6 := filepath.Join(directory, "whitelist.ipv6")
	staleSaaS := filepath.Join(directory, "saas.ipv4")
	for path, content := range map[string]string{
		requiredIPv4: "8.8.4.4\n",
		requiredIPv6: "2606:4700:4700::44\n",
		staleSaaS:    "0.0.0.0/0\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	enabled := false
	sources := []whitelistSource{
		{path: requiredIPv4, required: true},
		{path: requiredIPv6, required: true},
		{path: staleSaaS, publicOnly: true, enabled: func() bool { return enabled }},
	}
	addresses, _, err := loadWhitelistSources(sources)
	if err != nil {
		t.Fatalf("disabled stale SaaS source affected whitelist: %v", err)
	}
	if _, found := addresses[netip.MustParseAddr("8.8.4.4")]; !found {
		t.Fatal("required whitelist entry was not loaded")
	}
	enabled = true
	if _, _, err := loadWhitelistSources(sources); err == nil {
		t.Fatal("enabled SaaS source accepted an unsafe default route")
	}
	if err := os.WriteFile(staleSaaS, []byte("8.8.8.0/24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, prefixes, err := loadWhitelistSources(sources)
	if err != nil {
		t.Fatalf("safe enabled SaaS source was rejected: %v", err)
	}
	if len(prefixes) != 1 || prefixes[0] != netip.MustParsePrefix("8.8.8.0/24") {
		t.Fatalf("enabled SaaS prefixes = %v", prefixes)
	}
}

func TestStrictWhitelistRejectsOverbroadPrefixes_SW_SEC_H4(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "10.0.0.0/8", "::/0", "2001:db8::/32"} {
		if _, _, _, err := parseStrictWhitelistLine(value); err == nil {
			t.Fatalf("parseStrictWhitelistLine(%q) accepted an overbroad prefix", value)
		}
	}
}

func TestReadWhitelistSourceBoundsAndMissing_SW_SEC_M9(t *testing.T) {
	directory := t.TempDir()
	if _, err := readWhitelistSource(filepath.Join(directory, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing whitelist error = %v", err)
	}
	oversized := filepath.Join(directory, "oversized")
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = root.Close()
	})
	file, err := root.OpenFile("oversized", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maximumWhitelistSourceBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readWhitelistSource(oversized); err == nil {
		t.Fatal("strict whitelist accepted an oversized source")
	}
}
