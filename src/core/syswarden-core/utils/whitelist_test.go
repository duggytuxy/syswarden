package utils

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
	whitelistSourceFiles = []whitelistSource{{path: filepath.Join(t.TempDir(), "missing"), required: true}}
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

	if _, err := IsWhitelistedStrict("8.8.8.8"); err == nil {
		t.Fatal("strict whitelist hid a missing required source")
	}
	if !IsWhitelisted("8.8.8.8") {
		t.Fatal("boolean whitelist caller failed open on an authoritative source error")
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
