package telemetry

import (
	"strings"
	"testing"
	"time"
)

func kernelEvent(action, ip, jail, payload string, evidence RuleEvidence) TelemetryEvent {
	eligible := evidence.MetricEligible
	window := evidence.EffectiveWindowSeconds
	return TelemetryEvent{
		Action:                  action,
		Timestamp:               evidence.ObservedAt.Format(time.RFC3339Nano),
		IP:                      ip,
		Jail:                    jail,
		Payload:                 payload,
		RuleID:                  evidence.RuleID,
		RiskCategory:            evidence.RiskCategory,
		RuleAction:              evidence.RuleAction,
		EffectiveThreshold:      evidence.EffectiveThreshold,
		EffectiveWindowSeconds:  &window,
		SignatureCatalogVersion: evidence.SignatureCatalogVersion,
		SignatureCatalogSHA256:  evidence.SignatureCatalogSHA256,
		RiskModelVersion:        evidence.RiskModelVersion,
		MetricEligible:          &eligible,
		ObservationModel:        evidence.ObservationModel,
		ObservationDisposition:  evidence.ObservationDisposition,
		RuleAttestationStatus:   "attested",
	}
}

func TestKernelPortscanCountsEveryObservationAndExactJail_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	strikes := newKernelStrikeTracker()
	var events []TelemetryEvent
	logDetected := func(ip, jail, payload string, evidence RuleEvidence) {
		events = append(events, kernelEvent("DETECTED", ip, jail, payload, evidence))
	}
	logShadow := func(ip, jail, payload string, evidence RuleEvidence) {
		events = append(events, kernelEvent("SHADOW-ALERT", ip, jail, payload, evidence))
	}
	for attempt := 0; attempt < 3; attempt++ {
		line := "kernel: [CATCH-ALL] SRC=8.8.4.4 DST=192.0.2.1 PROTO=TCP DPT=22"
		processKernelDropLine(line, start.Add(time.Duration(attempt)*10*time.Second), strikes, logShadow, logDetected, func(string) bool { return false })
	}

	if len(events) != 3 || events[0].Action != "SHADOW-ALERT" || events[1].Action != "SHADOW-ALERT" || events[2].Action != "DETECTED" {
		t.Fatalf("kernel event sequence = %#v", events)
	}
	metrics, categories, jails, rejected := buildAttackerMetrics(events, riskCatalog{})
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("kernel metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 3 || metric.jailHits != 3 || metric.policyHits != 3 || metric.primaryJail != "L3-PORTSCAN" ||
		metric.peakWindowHits != 3 || metric.severityScore != 80 || !metric.thresholdReached || metric.thresholdEvidence != "observed-window" ||
		metric.metricQuality != metricQualityAttested {
		t.Fatalf("kernel port-scan metric = %#v", metric)
	}
	if categories["reconnaissance"] != 3 || jails["L3-PORTSCAN"] != 3 {
		t.Fatalf("kernel category/jail counters = %#v/%#v", categories, jails)
	}
}

func TestKernelIGMPAllHostsControlTrafficDoesNotBecomePortscanEvidence_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 9, 4, 6, 0, 0, 0, time.UTC)
	for _, protocol := range []string{"IGMP", "2"} {
		t.Run(protocol, func(t *testing.T) {
			strikes := newKernelStrikeTracker()
			var shadows, detections, whitelistLookups int
			processKernelDropLine(
				"kernel: [CATCH-ALL] SRC=0.0.0.0 DST=224.0.0.1 PROTO="+protocol,
				start,
				strikes,
				func(string, string, string, RuleEvidence) { shadows++ },
				func(string, string, string, RuleEvidence) { detections++ },
				func(string) bool {
					whitelistLookups++
					return false
				},
			)
			if shadows != 0 || detections != 0 || whitelistLookups != 0 || len(strikes.observations) != 0 {
				t.Fatalf(
					"IGMP all-hosts control traffic produced telemetry: shadows=%d detections=%d whitelist_lookups=%d strikes=%v",
					shadows,
					detections,
					whitelistLookups,
					strikes.observations,
				)
			}
		})
	}
}

func TestKernelIGMPExceptionKeepsOtherZeroSourceTrafficObservable_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 9, 4, 6, 0, 0, 0, time.UTC)
	tests := map[string]string{
		"different destination": "kernel: [CATCH-ALL] SRC=0.0.0.0 DST=224.0.0.2 PROTO=IGMP",
		"different source":      "kernel: [CATCH-ALL] SRC=198.51.100.42 DST=224.0.0.1 PROTO=IGMP",
		"different protocol":    "kernel: [CATCH-ALL] SRC=0.0.0.0 DST=224.0.0.1 PROTO=UDP DPT=67",
		"missing destination":   "kernel: [CATCH-ALL] SRC=0.0.0.0 PROTO=IGMP",
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			strikes := newKernelStrikeTracker()
			shadows := 0
			whitelistLookups := 0
			processKernelDropLine(
				line,
				start,
				strikes,
				func(string, string, string, RuleEvidence) { shadows++ },
				nil,
				func(string) bool {
					whitelistLookups++
					return false
				},
			)
			if shadows != 1 || whitelistLookups != 1 || len(strikes.observations) != 1 {
				t.Fatalf("near-match traffic was hidden: shadows=%d whitelist_lookups=%d strikes=%v", shadows, whitelistLookups, strikes.observations)
			}
		})
	}
}

func TestKernelJailsDoNotShareThresholdAndDetectionsRemainMeasured_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	strikes := newKernelStrikeTracker()
	var actions []string
	logDetected := func(_, jail, _ string, _ RuleEvidence) { actions = append(actions, "detected:"+jail) }
	logShadow := func(_, jail, _ string, _ RuleEvidence) { actions = append(actions, "shadow:"+jail) }
	notWhitelisted := func(string) bool { return false }

	for attempt := 0; attempt < 2; attempt++ {
		processKernelDropLine("[CATCH-ALL] SRC=9.9.9.9 PROTO=TCP DPT=22", start.Add(time.Duration(attempt)*time.Second), strikes, logShadow, logDetected, notWhitelisted)
	}
	processKernelDropLine("[SYSWARDEN-HONEYPORT] SRC=9.9.9.9 PROTO=TCP DPT=62026", start.Add(2*time.Second), strikes, logShadow, logDetected, notWhitelisted)
	processKernelDropLine("[CATCH-ALL] SRC=9.9.9.9 PROTO=TCP DPT=23", start.Add(3*time.Second), strikes, logShadow, logDetected, notWhitelisted)

	want := []string{"shadow:L3-PORTSCAN", "shadow:L3-PORTSCAN", "detected:L3-HONEYPORT-SCAN", "detected:L3-PORTSCAN"}
	if len(actions) != len(want) {
		t.Fatalf("kernel actions = %#v, want %#v", actions, want)
	}
	for index := range want {
		if actions[index] != want[index] {
			t.Fatalf("kernel action %d = %q, want %q", index, actions[index], want[index])
		}
	}
}

func TestKernelPortscanWindowExpiresOldStrikes_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tracker := newKernelStrikeTracker()
	if hits, triggered, _ := tracker.observe("8.8.8.8\x00L3-PORTSCAN", start, 3, time.Minute); hits != 1 || triggered {
		t.Fatalf("first strike = %d/%t", hits, triggered)
	}
	if hits, triggered, _ := tracker.observe("8.8.8.8\x00L3-PORTSCAN", start.Add(61*time.Second), 3, time.Minute); hits != 1 || triggered {
		t.Fatalf("expired strike retained = %d/%t", hits, triggered)
	}
	if hits, triggered, _ := tracker.observe("8.8.8.8\x00L3-PORTSCAN", start.Add(62*time.Second), 3, time.Minute); hits != 2 || triggered {
		t.Fatalf("second live strike = %d/%t", hits, triggered)
	}
	if hits, triggered, _ := tracker.observe("8.8.8.8\x00L3-PORTSCAN", start.Add(63*time.Second), 3, time.Minute); hits != 3 || !triggered {
		t.Fatalf("third live strike = %d/%t", hits, triggered)
	}
}

func TestKernelDelegatesCataloguedManagementPortAndDoesNotClaimARPBan_SW_KPI_001(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tracker := newKernelStrikeTracker()
	var shadows, detections int
	logShadow := func(_, _, _ string, _ RuleEvidence) { shadows++ }
	var arpEvidence RuleEvidence
	logDetected := func(_, jail, _ string, evidence RuleEvidence) {
		if jail != "L2-ARP-FLOOD" {
			t.Fatalf("detected jail = %q", jail)
		}
		detections++
		arpEvidence = evidence
	}
	notWhitelisted := func(string) bool { return false }

	for attempt := 0; attempt < 3; attempt++ {
		processKernelDropLine("[CATCH-ALL] SRC=8.8.8.8 PROTO=TCP DPT=62026", now.Add(time.Duration(attempt)*time.Second), tracker, logShadow, logDetected, notWhitelisted)
	}
	processKernelDropLine("[CATCH-ALL] SRC=8.8.8.8 PROTO=UDP DPT=62026", now.Add(3*time.Second), tracker, logShadow, logDetected, notWhitelisted)
	processKernelDropLine("[SYSWARDEN-ARP-FLOOD] SRC=8.8.8.8 MAC=00:11:22:33:44:55", now.Add(4*time.Second), tracker, logShadow, logDetected, notWhitelisted)

	if shadows != 1 || detections != 1 {
		t.Fatalf("producer observations mismatch: shadows=%d detections=%d", shadows, detections)
	}
	if arpEvidence.RuleAction != "detect" || arpEvidence.EffectiveThreshold != 1 || arpEvidence.EffectiveWindowSeconds != 0 ||
		arpEvidence.ObservationDisposition != "kernel-packet-dropped" {
		t.Fatalf("ARP evidence = %#v", arpEvidence)
	}
}

func TestKernelRuleCatalogHasOneCanonicalPolicyTable_SW_KPI_001(t *testing.T) {
	const expectedWire = "L2-ARP-FLOOD|denial_of_service|detect|1|0\nL3-HONEYPORT-SCAN|reconnaissance|ban|1|0\nL3-PORTSCAN|reconnaissance|track|3|60\n"
	const expectedDigest = "c4ab4166ddd725a5ef73cf8017746078c4e981d04d04dadaa4bb383cfe0623ca"
	if kernelRuleCatalogWire != expectedWire || kernelRuleCatalogSHA256 != expectedDigest {
		t.Fatalf("kernel catalog wire/digest changed: %q / %s", kernelRuleCatalogWire, kernelRuleCatalogSHA256)
	}
	if len(kernelRuleProfiles) != 3 {
		t.Fatalf("kernel policy count = %d", len(kernelRuleProfiles))
	}
	for _, profile := range kernelRuleProfiles {
		evidence, ok := kernelRuleEvidence(profile.ruleID, time.Unix(0, 0), true)
		if !ok || evidence.RiskCategory != profile.riskCategory || evidence.RuleAction != profile.ruleAction ||
			evidence.EffectiveThreshold != profile.threshold || evidence.EffectiveWindowSeconds != profile.windowSeconds ||
			evidence.SignatureCatalogSHA256 != expectedDigest || !strings.HasPrefix(evidence.ObservationModel, "kernel-log-observation") {
			t.Fatalf("kernel evidence drift for %s: %#v", profile.ruleID, evidence)
		}
	}
}

func TestKernelStrikeStateIsTTLAndCapacityBounded_SW_KPI_001(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tracker := newKernelStrikeTracker()
	tracker.limit = 2
	if _, _, degraded := tracker.observe("a", now, 3, time.Minute); degraded {
		t.Fatal("first bounded state was degraded")
	}
	if _, _, degraded := tracker.observe("b", now.Add(time.Second), 3, time.Minute); degraded {
		t.Fatal("second bounded state was degraded")
	}
	if _, _, degraded := tracker.observe("c", now.Add(2*time.Second), 3, time.Minute); !degraded {
		t.Fatal("capacity eviction was not reported")
	}
	if _, _, degraded := tracker.observe("b", now.Add(62*time.Second), 3, time.Minute); !degraded {
		t.Fatal("degraded epoch ended before the inclusive observation window boundary")
	}
	if len(tracker.observations) != 2 || tracker.order.Len() != 2 || tracker.observations["a"] != nil {
		t.Fatalf("bounded tracker state = keys:%d order:%d a:%#v", len(tracker.observations), tracker.order.Len(), tracker.observations["a"])
	}
	if _, _, degraded := tracker.observe("d", now.Add(3*time.Minute), 3, time.Minute); degraded {
		t.Fatal("TTL expiry was incorrectly reported as capacity degradation")
	}
	if len(tracker.observations) != 1 || tracker.order.Len() != 1 || tracker.observations["d"] == nil {
		t.Fatalf("expired tracker state = keys:%d order:%d", len(tracker.observations), tracker.order.Len())
	}
}

func TestKernelPacketSourcesRemainObservationsAtEveryThreshold(t *testing.T) {
	// The producer deliberately has no manager or ban callback argument. Even
	// authentic packet records cannot establish the origin of a source address.
	for _, source := range []string{"8.8.4.4", "192.0.2.10", "10.0.0.1", "127.0.0.1", "0.0.0.0", "2001:db8::1", "not-an-address"} {
		t.Run(source, func(t *testing.T) {
			strikes := newKernelStrikeTracker()
			var events []TelemetryEvent
			shadow := func(ip, jail, payload string, evidence RuleEvidence) {
				events = append(events, kernelEvent("SHADOW-ALERT", ip, jail, payload, evidence))
			}
			detected := func(ip, jail, payload string, evidence RuleEvidence) {
				events = append(events, kernelEvent("DETECTED", ip, jail, payload, evidence))
			}
			start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
			for attempt := 0; attempt < 9; attempt++ {
				line := "synthetic syslog text [CATCH-ALL] SRC=" + source + " PROTO=TCP DPT=23"
				processKernelDropLine(line, start.Add(time.Duration(attempt)*time.Second), strikes, shadow, detected, func(string) bool { return false })
			}
			processKernelDropLine("[SYSWARDEN-HONEYPORT] SRC="+source, start, strikes, shadow, detected, func(string) bool { return false })
			if len(events) != 10 {
				t.Fatalf("observations were silently discarded: %#v", events)
			}
			for index, event := range events {
				want := "SHADOW-ALERT"
				if index%3 == 2 || index == 9 {
					want = "DETECTED"
				}
				disposition := ""
				if want == "DETECTED" {
					disposition = "packet-source-unverified"
				}
				if event.Action != want || event.IP != source || event.ObservationDisposition != disposition {
					t.Fatalf("packet text acquired enforcement authority: %#v", event)
				}
			}
		})
	}
}

func TestKernelMissingDetectionCallbackRetainsThresholdShadow(t *testing.T) {
	strikes := newKernelStrikeTracker()
	shadows := 0
	shadow := func(string, string, string, RuleEvidence) { shadows++ }
	for attempt := 0; attempt < 3; attempt++ {
		processKernelDropLine("[CATCH-ALL] SRC=192.0.2.1 PROTO=TCP DPT=23", time.Now(), strikes, shadow, nil, func(string) bool { return false })
	}
	processKernelDropLine("[SYSWARDEN-HONEYPORT] SRC=192.0.2.1", time.Now(), strikes, shadow, nil, func(string) bool { return false })
	if shadows != 4 {
		t.Fatalf("missing detection callback discarded threshold observations: %d", shadows)
	}
}

func TestKernelSourceDispositionCannotAssertEnforcement(t *testing.T) {
	for _, jail := range []string{"L3-PORTSCAN", "L3-HONEYPORT-SCAN"} {
		evidence, _ := kernelRuleEvidence(jail, time.Now().UTC(), true)
		evidence.ObservationDisposition = "packet-source-unverified"
		for _, action := range []string{"DETECTED", "BANNED", "SIMULATED-BAN", "SHADOW-ALERT"} {
			event := kernelEvent(action, "192.0.2.80", jail, "synthetic packet observation", evidence)
			if got := validObservationDisposition(event); got != (action == "DETECTED") {
				t.Fatalf("unexpected %s disposition validity for %s: %t", action, jail, got)
			}
			if action == "DETECTED" {
				metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{event}, riskCatalog{})
				if rejected != 0 || len(metrics) != 1 || metrics[0].hits != 1 || metrics[0].metricQuality != metricQualityAttested {
					t.Fatalf("observation classification was lost: %#v, rejected=%d", metrics, rejected)
				}
			}
		}
	}
}
