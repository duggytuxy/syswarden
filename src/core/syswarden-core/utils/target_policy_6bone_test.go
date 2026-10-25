package utils

import (
	"errors"
	"testing"
)

func TestRetired6boneCannotBecomeFirewallMutationAuthority(t *testing.T) {
	whitelistCalls := 0
	policy := FirewallTargetPolicy{IsWhitelisted: func(string) (bool, error) {
		whitelistCalls++
		return false, nil
	}}
	for _, value := range []string{
		"3ffe::", "3ffe::1", "3ffe:1234:5678::1",
		"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"3FFE:0000:0000:0000:0000:0000:0000:0001",
	} {
		canonical, err := CanonicalFirewallMutationTarget(value, policy)
		if canonical != "" || !errors.Is(err, ErrProtectedFirewallTarget) {
			t.Fatalf("retired 6bone host became a mutation target: %q, %q, %v", value, canonical, err)
		}
		canonical, _, err = CanonicalFirewallNetworkEntry(value, FirewallNetworkPolicy{})
		if canonical != "" || !errors.Is(err, ErrProtectedFirewallTarget) {
			t.Fatalf("retired 6bone host became network policy: %q, %q, %v", value, canonical, err)
		}
	}
	if whitelistCalls != 0 {
		t.Fatalf("retired addresses reached the application trust lookup %d times", whitelistCalls)
	}
	for _, value := range []string{
		"3ffe::/128", "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
		"3ffe::/64", "3ffe:ffff:ffff:ffff::/64", "3ffe:1234::abcd/64",
	} {
		canonical, _, err := CanonicalFirewallNetworkEntry(value, FirewallNetworkPolicy{})
		if canonical != "" || !errors.Is(err, ErrProtectedFirewallTarget) {
			t.Fatalf("retired 6bone prefix became network policy: %q, %q, %v", value, canonical, err)
		}
	}
	for _, value := range []string{"3ffe::/16", "3ffe::1/16", "3ffe::/15"} {
		if canonical, _, err := CanonicalFirewallNetworkEntry(value, FirewallNetworkPolicy{}); err == nil || canonical != "" {
			t.Fatalf("broad retired network became policy: %q, %q, %v", value, canonical, err)
		}
	}
}

func TestRetired6boneExclusionPreservesAllocatedPublicTargets(t *testing.T) {
	policy := FirewallTargetPolicy{IsWhitelisted: func(string) (bool, error) { return false, nil }}
	for _, host := range []string{"2606:4700:4700::1111", "2a00:1450:4001::1"} {
		if canonical, err := CanonicalFirewallMutationTarget(host, policy); err != nil || canonical != host {
			t.Fatalf("allocated public host changed: %q, %q, %v", host, canonical, err)
		}
		if canonical, _, err := CanonicalFirewallNetworkEntry(host+"/128", FirewallNetworkPolicy{}); err != nil || canonical != host+"/128" {
			t.Fatalf("allocated public host prefix changed: %q, %q, %v", host, canonical, err)
		}
	}
	// Mapped IPv4 text is not an alias for the retired IPv6 allocation. Keep
	// rejecting the ambiguous address form independently of range exclusions.
	for _, value := range []string{"::ffff:3ffe:1", "::ffff:63.254.0.1"} {
		if canonical, err := CanonicalFirewallMutationTarget(value, policy); err == nil || canonical != "" {
			t.Fatalf("mapped host became a mutation target: %q, %q, %v", value, canonical, err)
		}
		for _, entry := range []string{value, value + "/128"} {
			if canonical, _, err := CanonicalFirewallNetworkEntry(entry, FirewallNetworkPolicy{}); err == nil || canonical != "" {
				t.Fatalf("mapped entry became network policy: %q, %q, %v", entry, canonical, err)
			}
		}
	}
}
