package network

import (
	"errors"
	"testing"
)

func TestRetired6boneFeedExclusionBoundaries(t *testing.T) {
	policy := cidrFeedPolicy{minimumEntries: 1, requirePublicAddresses: true}
	for _, value := range []string{
		"3ffe::", "3ffe::1", "3ffe:1234:5678::1",
		"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"3FFE:0000:0000:0000:0000:0000:0000:0001",
		"3ffe::/16", "3ffe::1/16", "3ffe::/15",
		"3ffe::/64", "3ffe:ffff:ffff:ffff::/64", "3ffe:1234::abcd/64",
		"3ffe::/128", "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	} {
		t.Run(value, func(t *testing.T) {
			prefix, err := parseCanonicalFeedPrefix(value, policy)
			if prefix.IsValid() || !errors.Is(err, errNonPublicFeedPrefix) {
				t.Fatalf("retired allocation became a feed prefix: %v, %v", prefix, err)
			}
			feed, err := canonicalizeCIDRFeed([]byte("2606:4700:4700::1111\n"+value+"\n"), policy)
			if !errors.Is(err, errNonPublicFeedPrefix) || len(feed.content) != 0 || len(feed.prefixes) != 0 {
				t.Fatalf("strict feed returned partial authority: %#v, %v", feed, err)
			}
		})
	}
	for _, value := range []string{"::ffff:3ffe:1", "::ffff:63.254.0.1", "::ffff:3ffe:1/128"} {
		if prefix, err := parseCanonicalFeedPrefix(value, policy); err == nil || prefix.IsValid() {
			t.Fatalf("mapped representation became a feed prefix: %q, %v, %v", value, prefix, err)
		}
	}
}

func TestRetired6boneOSINTFilteringPreservesPublicEntries(t *testing.T) {
	policy := cidrFeedPolicy{
		minimumEntries: 2, minimumIPv4PrefixBits: 32, minimumIPv6PrefixBits: 128,
		requireHostPrefixes: true, requirePublicAddresses: true, skipNonPublicEntries: true,
	}
	feed, err := canonicalizeCIDRFeed([]byte("3ffe::\n2606:4700:4700::1111\n3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n2a00:1450:4001::1\n"), policy)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2606:4700:4700::1111/128\n2a00:1450:4001::1/128\n"; string(feed.content) != want || feed.ignoredNonPublicEntries != 2 {
		t.Fatalf("special-use exclusion changed public authority: %#v", feed)
	}
	for _, value := range []string{"2606:4700:4700::/64", "2a00:1450:4001::/64"} {
		prefix, err := parseCanonicalFeedPrefix(value, cidrFeedPolicy{minimumIPv6PrefixBits: 64, requirePublicAddresses: true})
		if err != nil || prefix.String() != value {
			t.Fatalf("allocated public prefix changed: %q, %v, %v", value, prefix, err)
		}
	}
}
