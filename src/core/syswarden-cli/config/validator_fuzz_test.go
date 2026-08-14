package config

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

const maxValidatorFuzzBytes = 32 * 1024

func FuzzIPCIDRPortValidators(f *testing.F) {
	seeds := []string{
		"",
		"192.0.2.1",
		"2001:db8::1",
		"192.0.2.0/24",
		"2001:db8::/32",
		"1",
		"65535",
		"0",
		"65536",
		"-1",
		"192.0.2.1/33",
		"[2001:db8::1]:443",
		"not-an-address",
		"192.0.2.1\x002001:db8::1",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxValidatorFuzzBytes {
			t.Skip()
		}

		assertValidationResult(t, input, "ip", input == "" || net.ParseIP(input) != nil)
		_, _, cidrErr := net.ParseCIDR(input)
		assertValidationResult(t, input, "cidr", input == "" || cidrErr == nil)
		port, portErr := strconv.Atoi(input)
		assertValidationResult(t, input, "port", input == "" || portErr == nil && port > 0 && port <= 65535)

		values := strings.Split(input, "\x00")
		assertValidationResult(t, values, "ip_slice", allStringsMatch(values, func(value string) bool {
			return value == "" || net.ParseIP(value) != nil
		}))
		assertValidationResult(t, values, "cidr_slice", allStringsMatch(values, func(value string) bool {
			if value == "" {
				return true
			}
			_, _, err := net.ParseCIDR(value)
			return err == nil
		}))
		assertValidationResult(t, values, "port_slice", allStringsMatch(values, func(value string) bool {
			if value == "" {
				return true
			}
			parsed, err := strconv.Atoi(value)
			return err == nil && parsed > 0 && parsed <= 65535
		}))
	})
}

func assertValidationResult(t *testing.T, value any, tag string, wantValid bool) {
	t.Helper()
	firstErr := validate.Var(value, tag)
	secondErr := validate.Var(value, tag)
	if errorText(firstErr) != errorText(secondErr) {
		t.Fatalf("validation for tag %q is not deterministic: first error %v, second error %v", tag, firstErr, secondErr)
	}
	if gotValid := firstErr == nil; gotValid != wantValid {
		t.Fatalf("validate.Var(%#v, %q) validity = %t, want %t (error: %v)", value, tag, gotValid, wantValid, firstErr)
	}
}

func allStringsMatch(values []string, predicate func(string) bool) bool {
	for _, value := range values {
		if !predicate(value) {
			return false
		}
	}
	return true
}
