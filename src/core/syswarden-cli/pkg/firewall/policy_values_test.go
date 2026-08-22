package firewall

import (
	"reflect"
	"testing"
)

func TestCanonicalPolicyNetworksRejectsRuleInjection_SW_FW_001(t *testing.T) {
	tests := []string{
		"10.0.0.0/8 } add table inet injected",
		"10.0.0.0/8\nadd table inet injected",
		"10.0.0.0/999",
		"::ffff:192.0.2.1",
		"::ffff:192.0.2.1/120",
		"example.invalid",
		"0.0.0.0/0",
		"::/0",
		"0.0.0.0",
		"::",
		"169.254.0.0/16",
		"fe80::/64",
		"224.0.0.0/4",
		"ff00::/8",
	}
	for _, value := range tests {
		if _, err := canonicalPolicyNetworks(nil, value); err == nil {
			t.Fatalf("canonicalPolicyNetworks() accepted %q", value)
		}
	}
}

func TestCanonicalPolicyNetworksPreservesBroadPrivateLANs_SW_SEC_M1(t *testing.T) {
	got, err := canonicalPolicyNetworks(nil, "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fd00::/8 127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8", "127.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalPolicyNetworks() = %#v, want %#v", got, want)
	}
}

func TestCanonicalPolicyNetworksMasksAndDeduplicates_SW_FW_001(t *testing.T) {
	got, err := canonicalPolicyNetworks(
		[]string{"10.0.0.0/8"},
		"192.0.2.99/24, 2001:db8::99/64 10.0.0.0/8",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.0.2.0/24", "2001:db8::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalPolicyNetworks() = %#v, want %#v", got, want)
	}
}

func TestPolicyNetworksAreSeparatedByAddressFamily_SW_FW_001(t *testing.T) {
	ipv4, ipv6, err := splitPolicyNetworksByFamily([]string{
		"10.0.0.0/8", "2001:db8::/64", "192.0.2.0/24", "2001:db8:1::/64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "192.0.2.0/24"}; !reflect.DeepEqual(ipv4, want) {
		t.Fatalf("IPv4 policies = %#v, want %#v", ipv4, want)
	}
	if want := []string{"2001:db8::/64", "2001:db8:1::/64"}; !reflect.DeepEqual(ipv6, want) {
		t.Fatalf("IPv6 policies = %#v, want %#v", ipv6, want)
	}
}

func TestCanonicalPortsRejectsInjectionAndBounds_SW_FW_001(t *testing.T) {
	for _, value := range []string{"", "0", "65536", "-1", "22/tcp", "22; add rule", "22\n23"} {
		if _, err := canonicalPort(value); err == nil {
			t.Fatalf("canonicalPort() accepted %q", value)
		}
	}
	got, err := canonicalPorts("fixture", []string{"080", "443", "80"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"80", "443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("canonicalPorts() = %#v, want %#v", got, want)
	}
}

func TestPolicyIdentifiersRejectInjection_SW_FW_001(t *testing.T) {
	for _, value := range []string{"eth0; flush ruleset", "eth0\npass all", `eth0"`} {
		if _, err := canonicalInterfaceName(value); err == nil {
			t.Fatalf("canonicalInterfaceName() accepted %q", value)
		}
	}
	if _, err := canonicalIPv4Network("10.20.30.99/24; drop", "WireGuard subnet"); err == nil {
		t.Fatal("canonicalIPv4Network() accepted an injected subnet")
	}
	if _, err := canonicalIPv4Network("2001:db8::/64", "WireGuard subnet"); err == nil {
		t.Fatal("canonicalIPv4Network() accepted IPv6 for an IPv4 nftables expression")
	}
	if _, err := canonicalIPv4Network("0.0.0.0/0", "WireGuard subnet"); err == nil {
		t.Fatal("canonicalIPv4Network() accepted the IPv4 default route")
	}
}
