//go:build freebsd

package firewall

import "testing"

func TestParseFreeBSDDefaultGateway(t *testing.T) {
	gateway, err := parseFreeBSDDefaultGateway("   route to: default\ngateway: 192.0.2.1\ninterface: vtnet0\n")
	if err != nil || gateway != "192.0.2.1" {
		t.Fatalf("gateway = %q, err = %v", gateway, err)
	}
	for _, invalid := range []string{"gateway: 127.0.0.1\n", "gateway: ::1\n", "gateway: not-an-ip\n"} {
		if _, err := parseFreeBSDDefaultGateway(invalid); err == nil {
			t.Fatalf("invalid gateway output accepted: %q", invalid)
		}
	}
}
