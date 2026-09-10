package engine

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestProductionSSHSessionAuthentication(t *testing.T) {
	detector := newProductionTestEngine(t)
	for _, process := range []string{"sshd", "sshd-session"} {
		for _, address := range []string{"192.0.2.44", "2001:db8::44"} {
			for _, prefix := range []string{"", "Sep 10 11:53:27 gateway "} {
				for _, event := range []string{
					"Invalid user native-probe",
					"Failed password for invalid user native-probe",
					"Failed password for root",
					"POSSIBLE BREAK-IN attempt",
				} {
					line := fmt.Sprintf("%s%s[7393]: %s from %s port 33071", prefix, process, event, address)
					t.Run(line, func(t *testing.T) {
						match := detector.Scan(line)
						if match == nil || match.RuleID != "ssh-auth" || match.Action != "track" || match.Service != "sshd" {
							t.Fatalf("native SSH authentication record was not tracked: %#v", match)
						}
						if match.Host != netip.MustParseAddr(address) || !match.MetricEligible || match.RiskCategory != "brute_force" {
							t.Fatalf("SSH source or risk attribution changed: %#v", match)
						}
					})
				}
			}
		}
	}
}

func TestProductionSSHSessionRejectsNonAuthenticationAndForgedIdentity(t *testing.T) {
	detector := newProductionTestEngine(t)
	for _, line := range []string{
		"Sep 10 11:53:27 gateway sshd-session[7393]: Accepted publickey for root from 192.0.2.44 port 33071 ssh2",
		"Sep 10 11:53:27 gateway sshd-session[7393]: Connection closed by invalid user native-probe 192.0.2.44 port 33071 [preauth]",
		"Sep 10 11:53:27 gateway not-sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"Sep 10 11:53:27 gateway sshd-session-extra[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"Sep 10 11:53:27 gateway sshd-session[7393]: Invalid user native-probe from 999.0.2.44 port 33071",
		"Sep 10 11:53:27 gateway nginx[7393]: sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
	} {
		t.Run(line, func(t *testing.T) {
			if match := detector.Scan(line); match != nil {
				t.Fatalf("non-authentication or forged SSH record was admitted: %#v", match)
			}
		})
	}
	line := "Sep 10 11:53:27 gateway sshd-session[7393]: Failed password for invalid user alice from 198.51.100.99 from 192.0.2.44 port 33071 ssh2"
	match := detector.Scan(line)
	if match == nil || match.RuleID != "ssh-auth" || match.Host != netip.MustParseAddr("192.0.2.44") {
		t.Fatalf("username redirected the SSH enforcement address: %#v", match)
	}
}
