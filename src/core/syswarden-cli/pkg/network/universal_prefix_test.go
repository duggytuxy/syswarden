package network

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUniversalPrefixFeedRefusalIndependentOfPolicy(t *testing.T) {
	for _, value := range []string{
		"0.0.0.0/0", "8.8.8.8/0", "255.255.255.255/0",
		"::/0", "0:0:0:0:0:0:0:0/0", "2606:4700:4700::1111/0",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0",
	} {
		t.Run(value, func(t *testing.T) {
			for _, policy := range []cidrFeedPolicy{
				{},
				{minimumEntries: 1, requirePublicAddresses: true, skipNonPublicEntries: true},
				{minimumEntries: 1, minimumIPv4PrefixBits: 24, minimumIPv6PrefixBits: 64, requirePublicAddresses: true},
			} {
				prefix, err := parseCanonicalFeedPrefix(value, policy)
				if err == nil || prefix.IsValid() || !strings.Contains(err.Error(), "universal") {
					t.Fatalf("universal prefix returned usable feed policy: %v, %v", prefix, err)
				}
				feed, err := canonicalizeCIDRFeed([]byte("8.8.8.8\n"+value+"\n2606:4700:4700::1111\n"), policy)
				if err == nil || len(feed.content) != 0 || len(feed.prefixes) != 0 {
					t.Fatalf("mixed universal feed returned partial content: %#v, %v", feed, err)
				}
			}
		})
	}
}

func TestUniversalPrefixHABlocklistRefusalPreservesRecovery(t *testing.T) {
	for _, value := range []string{
		"0.0.0.0/0", "8.8.8.8/0", "::/0", "0:0:0:0:0:0:0:0/0",
		"2606:4700:4700::1111/0", "::ffff:192.0.2.1/96",
	} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blocklist")
			before := []byte("8.8.8.8\n" + value + "\n2606:4700:4700::1111\n")
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			beforeInfo, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := getLocalBlocklist(path)
			if err == nil || entries != nil || !strings.Contains(err.Error(), "universal") {
				t.Fatalf("universal stored policy returned outgoing HA bans: %v, %v", entries, err)
			}
			after, err := os.ReadFile(path) // #nosec G304 -- exact private fixture created above
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("HA refusal changed retained blocklist: %v", err)
			}
			afterInfo, err := os.Stat(path)
			if err != nil || !os.SameFile(beforeInfo, afterInfo) || beforeInfo.Mode() != afterInfo.Mode() || beforeInfo.ModTime() != afterInfo.ModTime() {
				t.Fatalf("HA refusal replaced or changed retained blocklist metadata: %v", err)
			}
			// The same representation remains readable for explicit unban and
			// retained-ledger inspection. This is not authorization to add it.
			canonical, err := canonicalHAAddress(value)
			if err != nil || canonical != "0.0.0.0/0" && canonical != "::/0" {
				t.Fatalf("legacy recovery parsing changed: %q, %v", canonical, err)
			}
			if entries, err := canonicalHAIPList([]string{value}); err != nil || len(entries) != 1 || entries[0] != canonical {
				t.Fatalf("legacy unban representation was rejected: %v, %v", entries, err)
			}
		})
	}
}

func TestUniversalPrefixGuardPreservesScopedFeedFamilies(t *testing.T) {
	for _, value := range []string{"8.8.8.0/24", "8.8.8.8", "2606:4700:4700::/64", "2606:4700:4700::1111"} {
		policy := cidrFeedPolicy{minimumEntries: 1, minimumIPv4PrefixBits: 24, minimumIPv6PrefixBits: 64, requirePublicAddresses: true}
		feed, err := canonicalizeCIDRFeed([]byte(value+"\n"), policy)
		if err != nil || len(feed.prefixes) != 1 || feed.prefixes[0].Bits() == 0 {
			t.Fatalf("scoped IPv4/IPv6 feed entry was changed: %q, %#v, %v", value, feed, err)
		}
	}
}
