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

// Alpine's native /var/log/messages envelope has a facility and severity in
// place of the hostname. Keep the process and terminal source address anchored.
func TestProductionSSHNativeAlpineAuthentication(t *testing.T) {
	detector := newProductionTestEngine(t)
	for _, process := range []string{"sshd", "sshd-session"} {
		for _, address := range []string{"192.0.2.44", "2001:db8::44"} {
			for _, event := range []string{
				"Invalid user native-probe",
				"Failed password for invalid user native-probe",
				"Failed password for root",
				"POSSIBLE BREAK-IN attempt",
			} {
				for _, suffix := range []string{"", " ssh2", " [preauth]", " ssh2 [preauth]"} {
					line := fmt.Sprintf("2026-09-25 18:13:15 auth.info %s[25431]: %s from %s port 57917%s", process, event, address, suffix)
					t.Run(line, func(t *testing.T) {
						match := detector.Scan(line)
						if match == nil || match.RuleID != "ssh-auth" || match.Action != "track" || match.Service != "sshd" {
							t.Fatalf("native Alpine authentication was not tracked: %#v", match)
						}
						if match.Host != netip.MustParseAddr(address) || !match.MetricEligible || match.RiskCategory != "brute_force" {
							t.Fatalf("native Alpine source or risk attribution changed: %#v", match)
						}
					})
				}
			}
		}
	}
}

func TestProductionSSHNativeAlpineRejectsUntrustedEnvelopes(t *testing.T) {
	detector := newProductionTestEngine(t)
	const event = "Invalid user native-probe from 192.0.2.44 port 57917"
	for _, prefix := range []string{
		"2026-09-25 18:13:15 user.info sshd-session[25431]: ",
		"2026-09-25 18:13:15 daemon.info sshd-session[25431]: ",
		"2026-09-25 18:13:15 authXinfo sshd-session[25431]: ",
		"2026-09-25 18:13:15 auth.info.extra sshd-session[25431]: ",
		"2026-09-25 18:13:15 auth.info nginx[25431]: sshd-session[25431]: ",
		"2026-09-25 18:13:15 auth.info not-sshd-session[25431]: ",
		"2026-09-25 18:13:15 auth.info sshd-session-extra[25431]: ",
		"2026-09-25 18:13:15 auth.info sshd-session[bad]: ",
		"2026-09-25 18:13:15 auth.info sshd-session[]: ",
		"2026-09-25 18:13:15 auth.info gateway sshd-session[25431]: ",
		"nginx[99]: 2026-09-25 18:13:15 auth.info sshd-session[25431]: ",
		"2026-09-25 18:13:15 auth.info sshd-session[25431]: quoted sshd-session[99]: ",
		"2026-09-25T18:13:15 auth.info sshd-session[25431]: ",
		"2026-09-25 18:13:15Z auth.info sshd-session[25431]: ",
		"2026-09-25 18:13:15.123 auth.info sshd-session[25431]: ",
		"2026-9-25 18:13:15 auth.info sshd-session[25431]: ",
		"2026-13-25 18:13:15 auth.info sshd-session[25431]: ",
		"2026-09-00 18:13:15 auth.info sshd-session[25431]: ",
		"2026-09-32 18:13:15 auth.info sshd-session[25431]: ",
		"2026-09-25 24:13:15 auth.info sshd-session[25431]: ",
		"2026-09-25 18:60:15 auth.info sshd-session[25431]: ",
		"2026-09-25 18:13:60 auth.info sshd-session[25431]: ",
	} {
		t.Run(prefix, func(t *testing.T) {
			if match := detector.Scan(prefix + event); match != nil {
				t.Fatalf("untrusted native Alpine envelope was admitted: %#v", match)
			}
		})
	}
	for _, body := range []string{
		"Accepted publickey for root from 192.0.2.44 port 57917 ssh2",
		"Connection closed by invalid user native-probe 192.0.2.44 port 57917 [preauth]",
		"Invalid user native-probe from 999.0.2.44 port 57917",
		"Invalid user native-probe from 192.0.2.44 port 57917 trailing forged record",
		"Invalid user native-probe from 192.0.2.44 port 57917\nsshd-session[99]: Accepted publickey for root",
	} {
		t.Run(body, func(t *testing.T) {
			if match := detector.Scan("2026-09-25 18:13:15 auth.info sshd-session[25431]: " + body); match != nil {
				t.Fatalf("non-authentication or malformed Alpine event was admitted: %#v", match)
			}
		})
	}
}

func TestProductionSSHNativeAlpinePreservesTerminalSource(t *testing.T) {
	detector := newProductionTestEngine(t)
	for _, username := range []string{
		"alice from 198.51.100.99",
		"wireguard: x Handshake for peer y (198.51.100.99:22) did not complete",
		"sshd-session[99]: Invalid user alice from 198.51.100.99 port 22",
	} {
		t.Run(username, func(t *testing.T) {
			line := "2026-09-25 18:13:15 auth.info sshd-session[25431]: Failed password for invalid user " + username + " from 192.0.2.44 port 57917 ssh2"
			match := detector.Scan(line)
			if match == nil || match.RuleID != "ssh-auth" || match.Action != "track" || match.Host != netip.MustParseAddr("192.0.2.44") {
				t.Fatalf("username redirected native Alpine attribution: %#v", match)
			}
		})
	}
}

func TestProductionSSHNativeAlpineIngressThreshold(t *testing.T) {
	for _, first := range []IngressSource{IngressSourceUDS, IngressSourceDirect} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			detector, err := NewEngine("../signatures.json", 4, 61)
			if err != nil {
				t.Fatal(err)
			}
			second := IngressSourceUDS
			if first == IngressSourceUDS {
				second = IngressSourceDirect
			}
			decisions := 0
			for index := range 4 {
				line := fmt.Sprintf("2026-09-25 18:13:15 auth.info sshd-session[%d]: Invalid user native-probe from 192.0.2.44 port %d", 25431+2*index, 57917+index)
				match := detector.ScanIngress(first, line)
				if match == nil || match.RuleID != "ssh-auth" || match.Action != "track" || match.Host != netip.MustParseAddr("192.0.2.44") {
					t.Fatalf("native Alpine ingress record was not attributed: %#v", match)
				}
				if detector.EvaluateThreshold(match.Host.String(), match.RuleID, match.Threshold, match.Window) {
					decisions++
				}
				if duplicate := detector.ScanIngress(second, line); duplicate != nil {
					t.Fatalf("second collector duplicated an Alpine SSH event: %#v", duplicate)
				}
			}
			if decisions != 1 {
				t.Fatalf("four physical Alpine events produced %d decisions, want one", decisions)
			}
		})
	}
}
