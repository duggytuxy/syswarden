//go:build linux

package firewall

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUniversalPrefixManualListRefusalPreservesExistingState(t *testing.T) {
	for _, value := range []string{
		"0.0.0.0/0", "8.8.8.8/0", "255.255.255.255/0", "0.0.0.0/00",
		"::/0", "0:0:0:0:0:0:0:0/0", "2606:4700:4700::1111/0",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0", "::ffff:192.0.2.1/96",
	} {
		t.Run(value, func(t *testing.T) {
			// This is the parser AddToBlocklist uses before its backend preflight.
			if entry, err := parseCanonicalListEntry(value, false); err == nil || entry.network != "" {
				t.Fatalf("manual block parser returned a universal entry: %#v, %v", entry, err)
			}
			target := approvedListFile{directory: t.TempDir(), name: "blocklist"}
			before := []byte("# administrator fixture\n8.8.8.8\n2606:4700:4700::1111\n")
			if err := writeListFileAt(target, before); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(target.directory, target.name)
			beforeInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := addToListFileAt(target, value); err == nil {
				t.Fatal("universal prefix reached persistent list mutation")
			}
			after, err := readListFileAt(target)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("refusal changed existing list bytes: %v", err)
			}
			afterInfo, err := os.Stat(path)
			if err != nil || !os.SameFile(beforeInfo, afterInfo) || beforeInfo.Mode() != afterInfo.Mode() || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
				t.Fatalf("refusal changed existing list metadata: %v", err)
			}
		})
	}
}

func TestUniversalPrefixStoredBlocklistCannotPopulateEitherFamily(t *testing.T) {
	for _, fixture := range []struct {
		entry string
		set   string
	}{
		{"0.0.0.0/0", "syswarden_blacklist"},
		{"8.8.8.8/0", "syswarden_blacklist"},
		{"::/0", "syswarden_blacklist6"},
		{"0:0:0:0:0:0:0:0/0", "syswarden_blacklist6"},
		{"2606:4700:4700::1111/0", "syswarden_blacklist6"},
	} {
		t.Run(fixture.entry, func(t *testing.T) {
			target := approvedListFile{directory: t.TempDir(), name: "stored-blocklist"}
			if err := writeListFileAt(target, []byte(fixture.entry+"\n")); err != nil {
				t.Fatal(err)
			}
			population, err := populateSet(t.Context(), []nftListSource{{path: filepath.Join(target.directory, target.name), required: true}}, fixture.set)
			if err == nil || len(population.entries) != 0 {
				t.Fatalf("stored universal prefix became active population: %#v, %v", population, err)
			}
		})
	}
}

func TestUniversalPrefixRefusalPreservesScopedDualStackAllowPolicy(t *testing.T) {
	for _, fixture := range []struct {
		name, host, scoped, addressSet, portSet string
	}{
		{"IPv4", "8.8.8.8", "1.1.1.0/24", "syswarden_whitelist", "syswarden_whitelist_ports"},
		{"IPv6", "2606:4700:4700::1111", "2606:4700:1000:1::/64", "syswarden_whitelist6", "syswarden_whitelist_ports6"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			entry, err := newCanonicalListEntry(fixture.scoped, "443")
			if err != nil {
				t.Fatal(err)
			}
			target := approvedListFile{directory: t.TempDir(), name: "allowlist"}
			if err := writeListFileAt(target, []byte(fixture.host+"\n"+entry.String()+"\n")); err != nil {
				t.Fatal(err)
			}
			addresses, ports, err := populateWhitelistSets(t.Context(), []nftListSource{{path: filepath.Join(target.directory, target.name), required: true}}, fixture.addressSet, fixture.portSet)
			if err != nil || !reflect.DeepEqual(addresses.entries, []string{fixture.host}) || !reflect.DeepEqual(ports.entries, []string{fixture.scoped + " . 443"}) {
				t.Fatalf("scoped allow policy changed: %#v, %#v, %v", addresses, ports, err)
			}
		})
	}
	for _, value := range []string{"0.0.0.0/0", "8.8.8.8/0", "::/0", "2606:4700::1/0"} {
		if err := ValidateWhitelistEntry(value, "443"); err == nil {
			t.Fatalf("universal prefix became an application allow rule: %q", value)
		}
	}
	// Feed exclusions and application ACCEPT authority remain separate: none
	// of these special-use ranges becomes an implicit whitelist entry.
	for _, value := range []string{"100.64.0.1", "169.254.1.1", "224.0.0.1", "240.0.0.1", "fe80::1", "ff02::1"} {
		if err := ValidateWhitelistEntry(value, ""); err == nil {
			t.Fatalf("special-use exclusion became application trust: %q", value)
		}
	}
}
