package telemetry

import (
	"strings"
	"testing"
	"time"
)

func TestKernelEchoRequestsDoNotCreateAlertsOrPortscanStrikes(t *testing.T) {
	for _, packet := range []string{
		"SRC=198.51.100.20 DST=192.0.2.10 PROTO=ICMP TYPE=8 CODE=0 ID=123 SEQ=1",
		"SRC=2001:db8::20 DST=2001:db8::10 PROTO=ICMPv6 TYPE=128 CODE=0 ID=123 SEQ=1",
	} {
		t.Run(packet, func(t *testing.T) {
			tracker := newKernelStrikeTracker()
			firewall := &kernelTestFirewall{}
			alerts := 0
			alert := func(string, string, string, RuleEvidence) { alerts++ }
			start := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
			for probe := 0; probe < 20; probe++ {
				processKernelDropLine("kernel: [SYSWARDEN-BLOCK] [CATCH-ALL] IN=eth0 OUT= "+packet,
					start.Add(time.Duration(probe)*time.Second), tracker, firewall,
					alert, alert, alert, func(string) bool { return false })
			}
			if alerts != 0 || len(firewall.bans) != 0 || len(tracker.observations) != 0 {
				t.Fatalf("echo probes created alerts=%d bans=%v strikes=%v", alerts, firewall.bans, tracker.observations)
			}
		})
	}
}

func TestKernelEchoExceptionRejectsAmbiguousAndNonEchoRecords(t *testing.T) {
	const echo = "SRC=198.51.100.20 PROTO=ICMP TYPE=8 CODE=0"
	for name, packet := range map[string]string{
		"echo reply":            strings.Replace(echo, "TYPE=8", "TYPE=0", 1),
		"unreachable":           strings.Replace(echo, "TYPE=8", "TYPE=3", 1),
		"invalid code":          strings.Replace(echo, "CODE=0", "CODE=1", 1),
		"missing type":          strings.Replace(echo, "TYPE=8 ", "", 1),
		"missing code":          strings.Replace(echo, " CODE=0", "", 1),
		"invalid source":        strings.Replace(echo, "198.51.100.20", "not-an-ip", 1),
		"unspecified source":    strings.Replace(echo, "198.51.100.20", "0.0.0.0", 1),
		"multicast source":      strings.Replace(echo, "198.51.100.20", "224.0.0.1", 1),
		"wrong family":          strings.Replace(echo, "198.51.100.20", "2001:db8::20", 1),
		"mapped source":         strings.Replace(echo, "198.51.100.20", "::ffff:198.51.100.20", 1),
		"tcp":                   strings.Replace(echo, "PROTO=ICMP", "PROTO=TCP", 1),
		"udp":                   strings.Replace(echo, "PROTO=ICMP", "PROTO=UDP", 1),
		"substring field":       strings.Replace(echo, "PROTO=", "OTHERPROTO=", 1),
		"duplicate protocol":    echo + " PROTO=ICMP",
		"conflicting protocol":  echo + " PROTO=TCP",
		"duplicate source":      echo + " SRC=198.51.100.21",
		"duplicate type":        echo + " TYPE=8",
		"duplicate code":        echo + " CODE=0",
		"transport source":      echo + " SPT=12345",
		"transport destination": echo + " DPT=443",
		"ipv6 echo reply":       "SRC=2001:db8::20 PROTO=ICMPv6 TYPE=129 CODE=0",
		"ipv6 unreachable":      "SRC=2001:db8::20 PROTO=ICMPv6 TYPE=1 CODE=0",
		"ipv6 wrong family":     "SRC=198.51.100.20 PROTO=ICMPv6 TYPE=128 CODE=0",
		"ipv6 zone":             "SRC=fe80::1%eth0 PROTO=ICMPv6 TYPE=128 CODE=0",
	} {
		t.Run(name, func(t *testing.T) {
			if isICMPEchoRequest(packet) {
				t.Fatalf("incorrectly suppressed %q", packet)
			}
		})
	}
}

func TestKernelEchoProbesDoNotIncrementOrClearTransportStrikes(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP"} {
		t.Run(protocol, func(t *testing.T) {
			tracker := newKernelStrikeTracker()
			firewall := &kernelTestFirewall{}
			var events []string
			ban := func(_, jail, _ string, _ RuleEvidence) { events = append(events, "ban:"+jail) }
			shadow := func(_, jail, _ string, _ RuleEvidence) { events = append(events, "shadow:"+jail) }
			start := time.Date(2026, 9, 19, 9, 0, 0, 0, time.UTC)
			observe := func(packet string) {
				processKernelDropLine("[CATCH-ALL] SRC=198.51.100.20 "+packet, start,
					tracker, firewall, ban, shadow, nil, func(string) bool { return false })
			}
			observe("PROTO=" + protocol + " DPT=23")
			observe("PROTO=" + protocol + " DPT=25")
			for probe := 0; probe < 20; probe++ {
				observe("PROTO=ICMP TYPE=8 CODE=0")
			}
			if len(events) != 2 || len(firewall.bans) != 0 {
				t.Fatalf("echo probes changed transport sequence: %v / %v", events, firewall.bans)
			}
			observe("PROTO=" + protocol + " DPT=445")
			if strings.Join(events, ",") != "shadow:L3-PORTSCAN,shadow:L3-PORTSCAN,ban:L3-PORTSCAN" || len(firewall.bans) != 1 {
				t.Fatalf("transport detection changed: %v / %v", events, firewall.bans)
			}
		})
	}
}

func TestKernelEchoExceptionDoesNotSuppressDedicatedAttackSignals(t *testing.T) {
	tracker := newKernelStrikeTracker()
	firewall := &kernelTestFirewall{}
	var events []string
	record := func(_, jail, _ string, _ RuleEvidence) { events = append(events, jail) }
	for _, prefix := range []string{"[SYSWARDEN-HONEYPORT]", "[SYSWARDEN-ARP-FLOOD]"} {
		processKernelDropLine(prefix+" SRC=198.51.100.20 PROTO=ICMP TYPE=8 CODE=0",
			time.Now(), tracker, firewall, record, record, record, func(string) bool { return false })
	}
	if strings.Join(events, ",") != "L3-HONEYPORT-SCAN,L2-ARP-FLOOD" || len(firewall.bans) != 1 {
		t.Fatalf("dedicated attack signals changed: %v / %v", events, firewall.bans)
	}
}
