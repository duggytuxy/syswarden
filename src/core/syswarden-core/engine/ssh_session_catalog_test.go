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
			for _, prefix := range []string{
				"", "Sep 10 11:53:27 gateway ",
				"2030-01-02T03:04:05.123456+00:00 gateway ",
				"2030-01-02T03:04:05Z gateway ",
				"2030-01-02T05:04:05+02:00 gateway ",
				"2030-01-01T22:04:05.123456789-05:00 gateway ",
			} {
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

func TestProductionSSHRejectsMalformedISOEnvelope(t *testing.T) {
	detector := newProductionTestEngine(t)
	for _, line := range []string{
		"2030-01-02T03:04:05 gateway sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05.1234567890Z gateway sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05+0000 gateway sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05Z gateway nginx[7393]: sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05Z gateway not-sshd-session[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05Z gateway sshd-session-extra[7393]: Invalid user native-probe from 192.0.2.44 port 33071",
		"2030-01-02T03:04:05Z gateway sshd-session[7393]: Accepted publickey for root from 192.0.2.44 port 33071 ssh2",
		"2030-01-02T03:04:05Z gateway sshd-session[7393]: Connection closed by invalid user native-probe 192.0.2.44 port 33071 [preauth]",
	} {
		t.Run(line, func(t *testing.T) {
			if match := detector.Scan(line); match != nil {
				t.Fatalf("malformed or non-authentication record was admitted: %#v", match)
			}
		})
	}
}

func TestProductionSSHISOIngressThreshold(t *testing.T) {
	detector, err := NewEngine("../signatures.json", 4, 61)
	if err != nil {
		t.Fatal(err)
	}
	decisions := 0
	for index := range 4 {
		line := fmt.Sprintf("2030-01-02T03:04:05.%06d+00:00 gateway sshd-session[%d]: Invalid user native-probe from 192.0.2.44 port %d", index, 7393+index, 33071+index)
		match := detector.ScanIngress(IngressSourceUDS, line)
		if match == nil || match.RuleID != "ssh-auth" || match.Action != "track" || match.Host != netip.MustParseAddr("192.0.2.44") {
			t.Fatalf("native ISO record was not attributed: %#v", match)
		}
		if detector.EvaluateThreshold(match.Host.String(), match.RuleID, match.Threshold, match.Window) {
			decisions++
		}
		if duplicate := detector.ScanIngress(IngressSourceDirect, line); duplicate != nil {
			t.Fatalf("second collector duplicated a physical SSH event: %#v", duplicate)
		}
	}
	if decisions != 1 {
		t.Fatalf("four physical events produced %d threshold decisions, want one", decisions)
	}
}
