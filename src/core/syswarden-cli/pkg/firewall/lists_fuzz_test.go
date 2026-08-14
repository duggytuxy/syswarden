package firewall

import (
	"net"
	"testing"
)

const maxIPAddressFuzzBytes = 32 * 1024

func FuzzIsValidIP(f *testing.F) {
	seeds := []string{
		"",
		"192.0.2.1",
		"2001:db8::1",
		"192.0.2.0/24",
		"2001:db8::/32",
		"192.0.2.1/33",
		"[2001:db8::1]:443",
		"192.0.2.1 # comment",
		"999.0.2.1",
		"example.com",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxIPAddressFuzzBytes {
			t.Skip()
		}

		valid, isIPv4 := IsValidIP(input)
		validAgain, isIPv4Again := IsValidIP(input)
		if valid != validAgain || isIPv4 != isIPv4Again {
			t.Fatalf("IsValidIP(%q) is not deterministic: (%t, %t), then (%t, %t)", input, valid, isIPv4, validAgain, isIPv4Again)
		}
		if !valid {
			if isIPv4 {
				t.Fatalf("IsValidIP(%q) classified an invalid value as IPv4", input)
			}
			return
		}

		parsed := net.ParseIP(input)
		if parsed == nil {
			var err error
			parsed, _, err = net.ParseCIDR(input)
			if err != nil || parsed == nil {
				t.Fatalf("IsValidIP(%q) accepted a value rejected by net.ParseIP and net.ParseCIDR", input)
			}
		}
		if gotIPv4 := parsed.To4() != nil; gotIPv4 != isIPv4 {
			t.Fatalf("IsValidIP(%q) IPv4 classification = %t, want %t", input, isIPv4, gotIPv4)
		}
	})
}
