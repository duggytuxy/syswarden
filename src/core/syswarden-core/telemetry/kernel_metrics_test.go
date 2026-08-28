package telemetry

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type kernelTestFirewall struct {
	bans []string
	err  error
}

func (firewall *kernelTestFirewall) Ban(ip string) error {
	if firewall.err != nil {
		return firewall.err
	}
	firewall.bans = append(firewall.bans, ip)
	return nil
}

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
	firewall := &kernelTestFirewall{}
	var events []TelemetryEvent
	logBan := func(ip, jail, payload string, evidence RuleEvidence) {
		events = append(events, kernelEvent("BANNED", ip, jail, payload, evidence))
	}
	logShadow := func(ip, jail, payload string, evidence RuleEvidence) {
		events = append(events, kernelEvent("SHADOW-ALERT", ip, jail, payload, evidence))
	}
	for attempt := 0; attempt < 3; attempt++ {
		line := "kernel: [CATCH-ALL] SRC=8.8.4.4 DST=192.0.2.1 PROTO=TCP DPT=22"
		processKernelDropLine(line, start.Add(time.Duration(attempt)*10*time.Second), strikes, firewall, logBan, logShadow, nil, func(string) bool { return false })
	}

	if len(events) != 3 || events[0].Action != "SHADOW-ALERT" || events[1].Action != "SHADOW-ALERT" || events[2].Action != "BANNED" {
		t.Fatalf("kernel event sequence = %#v", events)
	}
	if len(firewall.bans) != 1 || firewall.bans[0] != "8.8.4.4" {
		t.Fatalf("kernel firewall decisions = %#v", firewall.bans)
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

func TestKernelJailsDoNotShareThresholdAndFailuresRemainMeasured_SW_KPI_001(t *testing.T) {
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	strikes := newKernelStrikeTracker()
	firewall := &kernelTestFirewall{err: errors.New("test rejection")}
	var actions []string
	logBan := func(_, _, _ string, _ RuleEvidence) { actions = append(actions, "ban") }
	logShadow := func(_, jail, _ string, _ RuleEvidence) { actions = append(actions, "shadow:"+jail) }
	notWhitelisted := func(string) bool { return false }

	for attempt := 0; attempt < 2; attempt++ {
		processKernelDropLine("[CATCH-ALL] SRC=9.9.9.9 PROTO=TCP DPT=22", start.Add(time.Duration(attempt)*time.Second), strikes, firewall, logBan, logShadow, nil, notWhitelisted)
	}
	processKernelDropLine("[SYSWARDEN-HONEYPORT] SRC=9.9.9.9 PROTO=TCP DPT=62026", start.Add(2*time.Second), strikes, firewall, logBan, logShadow, nil, notWhitelisted)
	processKernelDropLine("[CATCH-ALL] SRC=9.9.9.9 PROTO=TCP DPT=23", start.Add(3*time.Second), strikes, firewall, logBan, logShadow, nil, notWhitelisted)

	want := []string{"shadow:L3-PORTSCAN", "shadow:L3-PORTSCAN", "shadow:L3-HONEYPORT-SCAN", "shadow:L3-PORTSCAN"}
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
	firewall := &kernelTestFirewall{}
	var bans, shadows, detections int
	logBan := func(_, _, _ string, _ RuleEvidence) { bans++ }
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
		processKernelDropLine("[CATCH-ALL] SRC=8.8.8.8 PROTO=TCP DPT=62026", now.Add(time.Duration(attempt)*time.Second), tracker, firewall, logBan, logShadow, logDetected, notWhitelisted)
	}
	processKernelDropLine("[CATCH-ALL] SRC=8.8.8.8 PROTO=UDP DPT=62026", now.Add(3*time.Second), tracker, firewall, logBan, logShadow, logDetected, notWhitelisted)
	processKernelDropLine("[SYSWARDEN-ARP-FLOOD] SRC=8.8.8.8 MAC=00:11:22:33:44:55", now.Add(4*time.Second), tracker, firewall, logBan, logShadow, logDetected, notWhitelisted)

	if bans != 0 || shadows != 1 || detections != 1 || len(firewall.bans) != 0 {
		t.Fatalf("producer authority mismatch: bans=%d shadows=%d detections=%d firewall=%v", bans, shadows, detections, firewall.bans)
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
