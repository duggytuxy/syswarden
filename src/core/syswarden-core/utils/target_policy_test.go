package utils

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestCanonicalFirewallMutationTargetRejectsProtectedBoundaries_SW_SEC_M1(t *testing.T) {
	basePolicy := FirewallTargetPolicy{
		LocalAddresses:    []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")},
		IsWhitelisted: func(address string) (bool, error) {
			return address == "1.1.1.1", nil
		},
	}
	tests := []struct {
		name  string
		value string
	}{
		{name: "IPv4 default route", value: "0.0.0.0/0"},
		{name: "IPv6 default route", value: "::/0"},
		{name: "IPv6 compatible address", value: "::2"},
		{name: "IPv6 compatible IPv4 encoding", value: "::c000:201"},
		{name: "deprecated IPv6 site local", value: "fec0::1"},
		{name: "CIDR mutation", value: "8.8.8.0/24"},
		{name: "loopback", value: "127.0.0.1"},
		{name: "private address", value: "10.0.0.8"},
		{name: "carrier grade NAT", value: "100.64.0.8"},
		{name: "IPv4 documentation range", value: "192.0.2.8"},
		{name: "IPv6 documentation range", value: "2001:db8::8"},
		{name: "AS112 direct delegation", value: "192.31.196.8"},
		{name: "AMT relay anycast", value: "192.52.193.8"},
		{name: "AS112 service", value: "192.175.48.8"},
		{name: "IPv6 translation", value: "64:ff9b::8"},
		{name: "IPv6 local translation", value: "64:ff9b:1::8"},
		{name: "IPv6 protocol assignment", value: "2001::8"},
		{name: "IPv6 6to4", value: "2002::8"},
		{name: "IPv6 dummy prefix", value: "100:0:0:1::8"},
		{name: "IPv6 AS112", value: "2620:4f:8000::8"},
		{name: "IPv6 second documentation range", value: "3fff::8"},
		{name: "IPv6 SRv6 SID", value: "5f00::8"},
		{name: "local interface", value: "9.9.9.9"},
		{name: "HA peer", value: "8.8.4.44"},
		{name: "whitelist", value: "1.1.1.1"},
		{name: "mapped address", value: "::ffff:8.8.8.8"},
		{name: "leading whitespace", value: " 8.8.8.8"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if canonical, err := CanonicalFirewallMutationTarget(test.value, basePolicy); err == nil {
				t.Fatalf("CanonicalFirewallMutationTarget(%q) = %q, want rejection", test.value, canonical)
			}
		})
	}
}

func TestCanonicalFirewallMutationTargetPreservesPublicHostsAndFailsClosed_SW_SEC_M1(t *testing.T) {
	policy := FirewallTargetPolicy{
		IsWhitelisted: func(string) (bool, error) { return false, nil },
	}
	for input, want := range map[string]string{
		"8.8.8.8":              "8.8.8.8",
		"2606:4700:4700::1111": "2606:4700:4700::1111",
	} {
		if got, err := CanonicalFirewallMutationTarget(input, policy); err != nil || got != want {
			t.Fatalf("CanonicalFirewallMutationTarget(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := CanonicalFirewallMutationTarget("8.8.8.8", FirewallTargetPolicy{}); err == nil {
		t.Fatal("target policy accepted an unavailable whitelist boundary")
	}
	policy.IsWhitelisted = func(string) (bool, error) { return false, errors.New("injected whitelist failure") }
	if _, err := CanonicalFirewallMutationTarget("8.8.8.8", policy); err == nil {
		t.Fatal("target policy accepted a whitelist evaluation failure")
	}
}

func TestCanonicalFirewallNetworkEntryEnforcesPrefixAndProtectedRanges_SW_SEC_M1(t *testing.T) {
	policy := FirewallNetworkPolicy{
		LocalAddresses:    []netip.Addr{netip.MustParseAddr("9.9.9.9")},
		ProtectedPrefixes: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24")},
	}
	for _, value := range []string{
		"0.0.0.0/0",
		"::/0",
		"8.8.0.0/16",
		"2606:4700::/48",
		"10.0.0.0/24",
		"100.64.0.0/24",
		"198.51.100.0/24",
		"2001:db8::/64",
		"192.31.196.0/24",
		"192.52.193.0/24",
		"192.175.48.0/24",
		"64:ff9b::/96",
		"64:ff9b:1::/64",
		"2001::/64",
		"2002::/64",
		"100:0:0:1::/64",
		"2620:4f:8000::/64",
		"3fff::/64",
		"5f00::/64",
		"9.9.9.0/24",
		"8.8.4.0/24",
	} {
		if canonical, _, err := CanonicalFirewallNetworkEntry(value, policy); err == nil {
			t.Fatalf("CanonicalFirewallNetworkEntry(%q) = %q, want rejection", value, canonical)
		}
	}
	for input, want := range map[string]string{
		"8.8.8.8":              "8.8.8.8",
		"8.8.8.0/24":           "8.8.8.0/24",
		"2606:4700:4700::/64":  "2606:4700:4700::/64",
		"2606:4700:4700::1111": "2606:4700:4700::1111",
	} {
		if got, _, err := CanonicalFirewallNetworkEntry(input, policy); err != nil || got != want {
			t.Fatalf("CanonicalFirewallNetworkEntry(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestLocalInterfaceAddressesCanonicalInventoryAndRefresh(t *testing.T) {
	addresses := []net.Addr{
		&net.IPAddr{IP: net.ParseIP("::ffff:192.0.2.1")},
		&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)},
		&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(24, 32)},
	}
	enumerate := func() ([]net.Addr, error) { return addresses, nil }
	got, err := localInterfaceAddresses(enumerate)
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("inventory = %v, %v; want %v", got, err, want)
	}
	addresses = []net.Addr{&net.IPAddr{IP: net.ParseIP("192.0.2.2")}}
	got, err = localInterfaceAddresses(enumerate)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("192.0.2.2") {
		t.Fatalf("fresh inventory = %v, %v", got, err)
	}
}

func TestLocalInterfaceAddressesRejectsIncompleteInventory(t *testing.T) {
	failure := errors.New("incomplete kernel dump")
	valid := &net.IPAddr{IP: net.ParseIP("192.0.2.1")}
	got, err := localInterfaceAddresses(func() ([]net.Addr, error) {
		return []net.Addr{valid}, failure
	})
	if got != nil || !errors.Is(err, failure) {
		t.Fatalf("enumeration failure returned %v, %v", got, err)
	}
	for _, invalid := range []net.Addr{nil, &net.IPAddr{IP: net.IP{1, 2}}, &net.UnixAddr{Name: "unsupported"}} {
		got, err := localInterfaceAddresses(func() ([]net.Addr, error) {
			return []net.Addr{valid, invalid}, nil
		})
		if got != nil || err == nil {
			t.Fatalf("invalid inventory returned %v, %v", got, err)
		}
	}
}
