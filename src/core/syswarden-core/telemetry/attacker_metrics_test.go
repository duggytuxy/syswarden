package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func productionRiskCatalog(t *testing.T) riskCatalog {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "signatures.json")) // #nosec G304 -- fixed repository fixture
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := parseRiskCatalog(data, 5, 60)
	if err != nil {
		t.Fatalf("parse production risk catalog: %v", err)
	}
	return catalog
}

func attestedAttackEvent(profile riskProfile, action, ip string, observedAt time.Time) TelemetryEvent {
	eligible := profile.metricEligible
	window := profile.windowSeconds
	return TelemetryEvent{
		Action:                  action,
		Timestamp:               observedAt.UTC().Format(time.RFC3339Nano),
		IP:                      ip,
		Jail:                    profile.ruleID,
		Payload:                 "PROTO=TCP DPT=22",
		RuleID:                  profile.ruleID,
		RiskCategory:            profile.category,
		RuleAction:              profile.action,
		EffectiveThreshold:      profile.threshold,
		EffectiveWindowSeconds:  &window,
		SignatureCatalogVersion: profile.catalogVersion,
		SignatureCatalogSHA256:  profile.catalogSHA256,
		RiskModelVersion:        profile.riskModel,
		MetricEligible:          &eligible,
		ObservationModel:        "collector-content-window-v1",
		RuleAttestationStatus:   "attested",
	}
}

func TestProductionRiskCatalogContract_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	if catalog.ruleCount != 78 || len(catalog.profiles) != 78 {
		t.Fatalf("catalog rule count = %d/%d, want 78/78", catalog.ruleCount, len(catalog.profiles))
	}
	if catalog.catalogVersion != "sw-signatures-v1" || catalog.riskModelVersion != "sw-risk-v1" || len(catalog.catalogSHA256) != 64 {
		t.Fatalf("catalog identity is incomplete: %#v", catalog)
	}

	actions := make(map[string]int)
	categories := make(map[string]int)
	excluded := make(map[string]bool)
	for ruleID, profile := range catalog.profiles {
		actions[profile.action]++
		categories[profile.category]++
		if !profile.metricEligible {
			excluded[ruleID] = true
		}
	}
	if actions["ban"] != 37 || actions["track"] != 32 || actions["detect"] != 9 {
		t.Fatalf("action counts = %#v", actions)
	}
	wantCategories := map[string]int{
		"exploit": 24, "brute_force": 26, "reconnaissance": 17,
		"denial_of_service": 1, "abuse": 10,
	}
	for category, want := range wantCategories {
		if categories[category] != want {
			t.Fatalf("category %s count = %d, want %d", category, categories[category], want)
		}
	}
	if len(excluded) != 1 || !excluded["ha-cluster"] {
		t.Fatalf("metric exclusions = %#v", excluded)
	}

	wantExplicit := map[string][2]int{
		"idor-enum": {15, 60}, "syswarden-l4-protect": {3, 60},
		"syswarden-l7-protect": {3, 60}, "anssi-methods": {2, 60},
	}
	for ruleID, expected := range wantExplicit {
		profile := catalog.profiles[ruleID]
		if profile.threshold != expected[0] || profile.windowSeconds != expected[1] {
			t.Fatalf("%s policy = %d/%d, want %d/%d", ruleID, profile.threshold, profile.windowSeconds, expected[0], expected[1])
		}
	}
	for _, ruleID := range []string{"sqli", "mitre-t1190-exploit-public", "slowloris"} {
		profile := catalog.profiles[ruleID]
		if profile.action != "track" && (profile.threshold != 1 || profile.windowSeconds != 0) {
			t.Fatalf("immediate rule %s policy = %d/%d, want 1/0", ruleID, profile.threshold, profile.windowSeconds)
		}
	}
	matrix := make([]string, 0, len(catalog.profiles))
	for ruleID, profile := range catalog.profiles {
		matrix = append(matrix, fmt.Sprintf("%s\t%s\t%s\t%d\t%d\t%t\n",
			ruleID, profile.category, profile.action, profile.threshold, profile.windowSeconds, profile.metricEligible))
	}
	sort.Strings(matrix)
	digest := sha256.Sum256([]byte(strings.Join(matrix, "")))
	if got := hex.EncodeToString(digest[:]); got != "865729fca6da8b98ec405158d8a59b80f564d306026c0a7c93c45a502dc99962" {
		t.Fatalf("normalized policy matrix digest = %s", got)
	}
}

func TestAttackerMetricsUseRealSSHHitsAndWindow_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	profile := catalog.profiles["ssh-auth"]
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	var events []TelemetryEvent
	for attempt := 0; attempt < 4; attempt++ {
		events = append(events, attestedAttackEvent(profile, "SHADOW-ALERT", "192.0.2.10", start.Add(time.Duration(attempt)*10*time.Second)))
	}

	metrics, categories, jails, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 4 || metric.jailHits != 4 || metric.peakWindowHits != 4 {
		t.Fatalf("SSH hit evidence = total:%d jail:%d peak:%d", metric.hits, metric.jailHits, metric.peakWindowHits)
	}
	if metric.severityScore != 52 || metric.severity != "52/100 (High Risk)" {
		t.Fatalf("four-attempt SSH severity = %d %q", metric.severityScore, metric.severity)
	}
	if metric.primaryJail != "ssh-auth" || metric.riskCategory != "brute_force" || metric.metricQuality != metricQualityAttested {
		t.Fatalf("SSH metric attribution = %#v", metric)
	}
	if categories["brute_force"] != 4 || jails["ssh-auth"] != 4 {
		t.Fatalf("category/jail counts = %#v/%#v", categories, jails)
	}

	events = append(events, attestedAttackEvent(profile, "BANNED", "192.0.2.10", start.Add(40*time.Second)))
	metrics, _, _, rejected = buildAttackerMetrics(events, catalog)
	metric = metrics[0]
	if rejected != 0 || metric.hits != 5 || metric.peakWindowHits != 5 || metric.severityScore != 80 || !strings.Contains(metric.severity, "Critical") {
		t.Fatalf("threshold SSH metric = %#v rejected=%d", metric, rejected)
	}
}

func TestAttackerMetricsDistinguishSlowAttemptsFromBurst_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	profile := catalog.profiles["ssh-auth"]
	start := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	events := make([]TelemetryEvent, 0, 4)
	for attempt := 0; attempt < 4; attempt++ {
		events = append(events, attestedAttackEvent(profile, "SHADOW-ALERT", "192.0.2.11", start.Add(time.Duration(attempt)*2*time.Minute)))
	}
	metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 4 || metric.peakWindowHits != 1 || metric.severityScore != 28 || metric.severity != "28/100 (Suspicious)" {
		t.Fatalf("slow SSH metric = %#v", metric)
	}
}

func TestAttackerMetricsExploitAndDDoSSeverity_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		ruleID    string
		action    string
		hits      int
		wantScore int
		wantLabel string
	}{
		{name: "immediate SQL injection", ruleID: "sqli", action: "BANNED", hits: 1, wantScore: 80, wantLabel: "Critical"},
		{name: "detected public exploit", ruleID: "mitre-t1190-exploit-public", action: "DETECTED", hits: 1, wantScore: 70, wantLabel: "High Risk"},
		{name: "one slowloris", ruleID: "slowloris", action: "BANNED", hits: 1, wantScore: 70, wantLabel: "High Risk"},
		{name: "repeated slowloris", ruleID: "slowloris", action: "BANNED", hits: 2, wantScore: 80, wantLabel: "Critical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := catalog.profiles[test.ruleID]
			events := make([]TelemetryEvent, 0, test.hits)
			for index := 0; index < test.hits; index++ {
				events = append(events, attestedAttackEvent(profile, test.action, "198.51.100.10", now.Add(time.Duration(index)*time.Second)))
			}
			metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
			if rejected != 0 || len(metrics) != 1 || metrics[0].hits != test.hits || metrics[0].severityScore != test.wantScore || !strings.Contains(metrics[0].severity, test.wantLabel) {
				t.Fatalf("metric = %#v rejected=%d", metrics, rejected)
			}
		})
	}
}

func TestAttackerMetricsKeepGlobalHitsAndSelectRiskPerJail_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	ssh := catalog.profiles["ssh-auth"]
	sqli := catalog.profiles["sqli"]
	events := make([]TelemetryEvent, 0, 7)
	for index := 0; index < 4; index++ {
		events = append(events, attestedAttackEvent(ssh, "SHADOW-ALERT", "203.0.113.8", now.Add(time.Duration(index)*10*time.Second)))
	}
	events = append(events, attestedAttackEvent(sqli, "BANNED", "203.0.113.8", now.Add(45*time.Second)))
	// Repeated bans are independent physical events and must accumulate.
	events = append(events,
		attestedAttackEvent(sqli, "BANNED", "203.0.113.9", now),
		attestedAttackEvent(sqli, "BANNED", "203.0.113.9", now.Add(time.Second)),
	)

	metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 0 || len(metrics) != 2 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	byIP := make(map[string]attackerMetric)
	for _, metric := range metrics {
		byIP[metric.ip] = metric
	}
	mixed := byIP["203.0.113.8"]
	if mixed.hits != 5 || mixed.primaryJail != "sqli" || mixed.jailHits != 1 || mixed.severityScore != 80 {
		t.Fatalf("mixed-jail metric = %#v", mixed)
	}
	repeated := byIP["203.0.113.9"]
	if repeated.hits != 2 || repeated.jailHits != 2 || repeated.severityScore != 90 {
		t.Fatalf("repeated-ban metric = %#v", repeated)
	}
}

func TestAttackerMetricsMarkLegacyAndExcludeNonMetrics_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	events := []TelemetryEvent{
		{Action: "BANNED", Timestamp: now.Format(time.RFC3339), IP: "192.0.2.20", Jail: "sqli", Payload: "legacy"},
		{Action: "BANNED", Timestamp: now.Format(time.RFC3339), IP: "192.0.2.21", Jail: "ha-cluster", Payload: "replicated"},
		{Action: "ALLOWED", Timestamp: now.Format(time.RFC3339), IP: "192.0.2.22", Jail: "sshd"},
		{Action: "COMPLIANCE-DRIFT", Timestamp: now.Format(time.RFC3339), IP: "127.0.0.1", Jail: "NIS2-AUDIT"},
		{Action: "BANNED", Timestamp: now.Format(time.RFC3339), IP: "not-an-ip", Jail: "sqli"},
		{Action: "BANNED", Timestamp: "invalid", IP: "192.0.2.23", Jail: "sqli"},
	}
	metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 2 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	if metrics[0].ip != "192.0.2.20" || metrics[0].metricQuality != metricQualityLegacy || metrics[0].severityScore != 80 {
		t.Fatalf("legacy metric = %#v", metrics[0])
	}
	if metrics[0].signatureCatalogVersion != "" || metrics[0].signatureCatalogSHA256 != "" || metrics[0].legacyHits != 1 ||
		metrics[0].attestedHits != 0 || metrics[0].recordedHits != 0 {
		t.Fatalf("legacy event falsely inherited current catalog evidence: %#v", metrics[0])
	}
}

func TestAttackerMetricsDecisionEventProvesTrackThresholdWithoutChangingRawPeak_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	profile := catalog.profiles["ssh-auth"]
	event := attestedAttackEvent(profile, "BANNED", "192.0.2.24", time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC))
	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{event}, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 1 || metric.policyHits != 1 || metric.peakWindowHits != 1 || metric.severityScore != 80 ||
		!metric.thresholdReached || metric.thresholdEvidence != "decision-event" {
		t.Fatalf("isolated threshold decision = %#v", metric)
	}
}

func TestAttackerMetricsSeparateJailAndPolicyCohortsForGRC_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	current := catalog.profiles["ssh-auth"]
	legacy := TelemetryEvent{
		Action: "SHADOW-ALERT", Timestamp: now.Format(time.RFC3339Nano), IP: "192.0.2.25", Jail: "ssh-auth", Payload: "legacy",
	}
	events := []TelemetryEvent{legacy}
	for index := 0; index < 2; index++ {
		events = append(events, attestedAttackEvent(current, "SHADOW-ALERT", "192.0.2.25", now.Add(time.Duration(index+1)*time.Second)))
	}
	metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 3 || metric.jailHits != 3 || metric.policyHits != 2 || metric.attestedHits != 2 || metric.legacyHits != 1 ||
		metric.metricQuality != metricQualityMixed || metric.selectedPolicyQuality != metricQualityAttested || metric.metricScope != metricScopeRetained {
		t.Fatalf("mixed policy metric = %#v", metric)
	}
}

func TestAttackerMetricsRejectPartialOrIncoherentAttestation_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	mismatch := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.26", now)
	mismatch.Jail = "ssh-auth"
	wrongTransition := attestedAttackEvent(catalog.profiles["mitre-t1190-exploit-public"], "BANNED", "192.0.2.27", now)
	modelOnly := TelemetryEvent{
		Action: "BANNED", Timestamp: now.Format(time.RFC3339Nano), IP: "192.0.2.28", Jail: "sqli",
		ObservationModel: "collector-content-window-v1",
	}
	unknownModel := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.29", now)
	unknownModel.ObservationModel = "untrusted-model"
	invalidStatus := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.30", now)
	invalidStatus.RuleAttestationStatus = "invalid"
	absentStatus := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.31", now)
	absentStatus.RuleAttestationStatus = ""
	collectorDisposition := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.32", now)
	collectorDisposition.ObservationDisposition = "kernel-packet-dropped"

	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{
		mismatch, wrongTransition, modelOnly, unknownModel, invalidStatus, absentStatus, collectorDisposition,
	}, catalog)
	if len(metrics) != 0 || rejected != 7 {
		t.Fatalf("invalid attestation metrics=%#v rejected=%d", metrics, rejected)
	}
}

func TestAttackerMetricsVerifyCurrentCatalogAndClassifyHistoricalEvidence_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	current := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.32", now)
	historical := current
	historical.SignatureCatalogSHA256 = strings.Repeat("c", 64)
	profileMismatch := current
	profileMismatch.RiskCategory = "abuse"
	eligibilityMismatch := current
	eligible := false
	eligibilityMismatch.MetricEligible = &eligible

	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{
		current, historical, profileMismatch, eligibilityMismatch,
	}, catalog)
	if rejected != 2 || len(metrics) != 1 {
		t.Fatalf("catalog verification metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 2 || metric.attestedHits != 1 || metric.recordedHits != 1 || metric.legacyHits != 0 ||
		metric.metricQuality != metricQualityMixed || metric.selectedPolicyQuality != metricQualityAttested ||
		metric.signatureCatalogSHA256 != catalog.catalogSHA256 {
		t.Fatalf("current/historical catalog attribution = %#v", metric)
	}

	recordedOnly := historical
	recordedOnly.IP = "192.0.2.33"
	metrics, _, _, rejected = buildAttackerMetrics([]TelemetryEvent{recordedOnly}, catalog)
	if rejected != 0 || len(metrics) != 1 || metrics[0].metricQuality != metricQualityRecorded ||
		metrics[0].selectedPolicyQuality != metricQualityRecorded || metrics[0].recordedHits != 1 ||
		metrics[0].attestedHits != 0 || metrics[0].legacyHits != 0 ||
		metrics[0].signatureCatalogSHA256 != recordedOnly.SignatureCatalogSHA256 {
		t.Fatalf("historical recorded evidence = %#v rejected=%d", metrics, rejected)
	}
}

func TestAttackerMetricsRequireExactKernelCatalogAndProfile_SW_KPI_001(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	evidence, ok := kernelRuleEvidence("L3-PORTSCAN", now, true)
	if !ok {
		t.Fatal("kernel rule evidence is unavailable")
	}
	current := kernelEvent("SHADOW-ALERT", "192.0.2.34", evidence.RuleID, "PROTO=TCP DPT=22", evidence)
	wrongDigest := current
	wrongDigest.SignatureCatalogSHA256 = strings.Repeat("d", 64)
	wrongProfile := current
	wrongProfile.EffectiveThreshold = 4
	wrongDisposition := current
	wrongDisposition.ObservationDisposition = "kernel-packet-dropped"
	arpEvidence, ok := kernelRuleEvidence("L2-ARP-FLOOD", now, true)
	if !ok {
		t.Fatal("ARP kernel rule evidence is unavailable")
	}
	arp := kernelEvent("DETECTED", "192.0.2.35", arpEvidence.RuleID, "ARP packet", arpEvidence)
	arp.ObservationDisposition = "kernel-packet-dropped"

	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{current, wrongDigest, wrongProfile, wrongDisposition, arp}, riskCatalog{})
	if rejected != 2 || len(metrics) != 2 {
		t.Fatalf("kernel catalog verification metrics=%#v rejected=%d", metrics, rejected)
	}
	byJail := make(map[string]attackerMetric, len(metrics))
	for _, metric := range metrics {
		byJail[metric.primaryJail] = metric
	}
	portscan := byJail["L3-PORTSCAN"]
	if portscan.attestedHits != 1 || portscan.recordedHits != 1 || portscan.metricQuality != metricQualityMixed ||
		portscan.selectedPolicyQuality != metricQualityAttested || portscan.signatureCatalogSHA256 != kernelRuleCatalogSHA256 {
		t.Fatalf("kernel port-scan attestation = %#v", portscan)
	}
	arpMetric := byJail["L2-ARP-FLOOD"]
	if arpMetric.attestedHits != 1 || arpMetric.recordedHits != 0 ||
		arpMetric.signatureCatalogSHA256 != kernelRuleCatalogSHA256 {
		t.Fatalf("kernel ARP attestation = %#v", arpMetric)
	}
}

func TestAttackerMetricsPreserveHistoricalKernelCutoverAsRecorded_SW_KPI_001(t *testing.T) {
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	evidence, ok := kernelRuleEvidence("L3-PORTSCAN", now, true)
	if !ok {
		t.Fatal("kernel rule evidence is unavailable")
	}
	current := kernelEvent("SHADOW-ALERT", "192.0.2.36", evidence.RuleID, "current", evidence)
	historical := current
	historical.Timestamp = now.Add(-time.Second).Format(time.RFC3339Nano)
	historical.Payload = "historical"
	historical.SignatureCatalogVersion = "sw-kernel-signals-v0"
	historical.SignatureCatalogSHA256 = strings.Repeat("e", 64)
	historical.EffectiveThreshold = 4

	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{historical, current}, riskCatalog{})
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("kernel cutover metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 2 || metric.attestedHits != 1 || metric.recordedHits != 1 || metric.legacyHits != 0 ||
		metric.metricQuality != metricQualityMixed || metric.selectedPolicyQuality != metricQualityAttested ||
		metric.signatureCatalogSHA256 != kernelRuleCatalogSHA256 {
		t.Fatalf("kernel cutover provenance = %#v", metric)
	}

	metrics, _, _, rejected = buildAttackerMetrics([]TelemetryEvent{historical}, riskCatalog{})
	if rejected != 0 || len(metrics) != 1 || metrics[0].metricQuality != metricQualityRecorded ||
		metrics[0].selectedPolicyQuality != metricQualityRecorded || metrics[0].recordedHits != 1 ||
		metrics[0].effectiveThreshold != 4 || metrics[0].signatureCatalogSHA256 != historical.SignatureCatalogSHA256 {
		t.Fatalf("historical kernel-only provenance = %#v rejected=%d", metrics, rejected)
	}
}

func TestMetricAdmissionDistinguishesExcludedFromRejected_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	current := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "::ffff:192.0.2.35", now)
	profile, ip, observedAt, admitted, excluded := admitMetricEvent(current, catalog)
	if !admitted || excluded || ip != "192.0.2.35" || !observedAt.Equal(now) || profile.ruleID != "sqli" {
		t.Fatalf("current event admission = profile:%#v ip:%q time:%s admitted:%t excluded:%t", profile, ip, observedAt, admitted, excluded)
	}

	allowed := current
	allowed.Action = "ALLOWED"
	if _, _, _, admitted, excluded = admitMetricEvent(allowed, catalog); admitted || !excluded {
		t.Fatalf("non-KPI action admission = admitted:%t excluded:%t", admitted, excluded)
	}
	legacyExcluded := TelemetryEvent{
		Action: "BANNED", Timestamp: "invalid", IP: "not-an-ip", Jail: "ha-cluster",
	}
	if _, _, _, admitted, excluded = admitMetricEvent(legacyExcluded, catalog); admitted || !excluded {
		t.Fatalf("metric-excluded rule admission = admitted:%t excluded:%t", admitted, excluded)
	}
	malformed := current
	malformed.IP = "not-an-ip"
	if _, _, _, admitted, excluded = admitMetricEvent(malformed, catalog); admitted || excluded {
		t.Fatalf("malformed event admission = admitted:%t excluded:%t", admitted, excluded)
	}
}

func TestRiskAttributionDrivesSeverityWithoutChangingOneHitOrEnforcement_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	enforcement := catalog.profiles["generic-auth"]
	attribution := catalog.profiles["owasp-a03-xss"]
	event := attestedAttackEvent(enforcement, "SHADOW-ALERT", "192.0.2.36", now)
	attributionWindow := attribution.windowSeconds
	attributionEligible := attribution.metricEligible
	event.RiskAttributionRuleID = attribution.ruleID
	event.RiskAttributionCategory = attribution.category
	event.RiskAttributionAction = attribution.action
	event.RiskAttributionThreshold = attribution.threshold
	event.RiskAttributionWindowSeconds = &attributionWindow
	event.RiskAttributionMetricEligible = &attributionEligible

	metrics, categories, jails, rejected := buildAttackerMetrics([]TelemetryEvent{event}, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("attributed metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.hits != 1 || metric.attestedHits != 1 || metric.primaryJail != "owasp-a03-xss" ||
		metric.riskCategory != "exploit" || metric.severityScore != 70 || metric.policyHits != 1 ||
		metric.enforcementJail != "generic-auth" || metric.enforcementAction != "track" ||
		categories["exploit"] != 1 || jails["owasp-a03-xss"] != 1 || event.RuleID != "generic-auth" || event.RuleAction != "track" {
		t.Fatalf("risk attribution metric = %#v categories=%#v jails=%#v event=%#v", metric, categories, jails, event)
	}

	tampered := event
	tampered.RiskAttributionCategory = "abuse"
	if metrics, _, _, rejected = buildAttackerMetrics([]TelemetryEvent{tampered}, catalog); rejected != 1 || len(metrics) != 0 {
		t.Fatalf("tampered attribution was admitted: metrics=%#v rejected=%d", metrics, rejected)
	}

	historical := event
	historical.SignatureCatalogVersion = "sw-signatures-v0"
	historical.SignatureCatalogSHA256 = strings.Repeat("e", 64)
	metrics, _, _, rejected = buildAttackerMetrics([]TelemetryEvent{historical}, catalog)
	if rejected != 0 || len(metrics) != 1 || metrics[0].recordedHits != 1 ||
		metrics[0].selectedPolicyQuality != metricQualityRecorded || metrics[0].primaryJail != "owasp-a03-xss" {
		t.Fatalf("historical attribution was not preserved: metrics=%#v rejected=%d", metrics, rejected)
	}
}

func TestKPIEvidenceStateIsExplicitAndConservative_SW_KPI_001(t *testing.T) {
	complete := kpiEvidenceState{
		catalogAvailable:     true,
		journalScanComplete:  true,
		journalBytesTotal:    4096,
		journalBytesScanned:  4096,
		metricExcludedEvents: 2,
		metricAdmittedEvents: 4,
	}
	if complete.quality() != kpiEvidenceQualityComplete {
		t.Fatalf("intentional exclusions degraded KPI evidence: %#v", complete)
	}
	var waf WAF
	complete.apply(&waf)
	if waf.KPIEvidenceQuality != kpiEvidenceQualityComplete || waf.JournalScanComplete == nil || !*waf.JournalScanComplete ||
		waf.JournalBytesTotal == nil || *waf.JournalBytesTotal != 4096 ||
		waf.JournalBytesScanned == nil || *waf.JournalBytesScanned != 4096 ||
		waf.JournalDecodeErrors == nil || *waf.JournalDecodeErrors != 0 ||
		waf.MetricRejectedEvents == nil || *waf.MetricRejectedEvents != 0 ||
		waf.MetricExcludedEvents == nil || *waf.MetricExcludedEvents != 2 ||
		waf.MetricAdmittedEvents == nil || *waf.MetricAdmittedEvents != 4 {
		t.Fatalf("explicit KPI evidence fields = %#v", waf)
	}
	encoded, err := json.Marshal(waf)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"journal_scan_complete":true`, `"journal_bytes_total":4096`, `"journal_bytes_scanned":4096`,
		`"journal_decode_errors":0`, `"metric_rejected_events":0`,
		`"metric_excluded_events":2`, `"metric_admitted_events":4`,
	} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("KPI evidence JSON omitted %s: %s", field, encoded)
		}
	}

	degradedStates := []kpiEvidenceState{
		{journalScanComplete: true},
		{catalogAvailable: true},
		{catalogAvailable: true, journalScanComplete: true, journalDecodeErrors: 1},
		{catalogAvailable: true, journalScanComplete: true, metricRejectedEvents: 1},
		{catalogAvailable: true, journalScanComplete: true, journalBytesTotal: 2, journalBytesScanned: 1},
	}
	for _, state := range degradedStates {
		if state.quality() != kpiEvidenceQualityDegraded {
			t.Fatalf("incomplete KPI evidence was accepted: %#v", state)
		}
	}
	const expectedLog = "[Telemetry Worker] KPI evidence degraded: catalog_available=%t journal_scan_complete=%t journal_bytes_scanned=%d journal_bytes_total=%d journal_decode_errors=%d metric_rejected_events=%d metric_excluded_events=%d metric_admitted_events=%d"
	if kpiEvidenceDegradedLog != expectedLog {
		t.Fatalf("KPI degraded log contract = %q", kpiEvidenceDegradedLog)
	}
}

func TestAttackerMetricsPreferAttestedPolicyOnExactTie_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	legacy := TelemetryEvent{
		Action: "BANNED", Timestamp: now.Format(time.RFC3339Nano), IP: "192.0.2.30", Jail: "sqli", Payload: "legacy",
	}
	attested := attestedAttackEvent(catalog.profiles["sqli"], "BANNED", "192.0.2.30", now)
	metrics, _, _, rejected := buildAttackerMetrics([]TelemetryEvent{legacy, attested}, catalog)
	if rejected != 0 || len(metrics) != 1 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	metric := metrics[0]
	if metric.selectedPolicyQuality != metricQualityAttested || metric.signatureCatalogSHA256 == "" || metric.policyHits != 1 || metric.jailHits != 2 {
		t.Fatalf("tied policy selection = %#v", metric)
	}
}

func TestAttackerMetricsSortByHitsThenRiskAndTime_SW_KPI_001(t *testing.T) {
	catalog := productionRiskCatalog(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	ssh := catalog.profiles["ssh-auth"]
	sqli := catalog.profiles["sqli"]
	events := []TelemetryEvent{
		attestedAttackEvent(sqli, "BANNED", "192.0.2.30", now),
		attestedAttackEvent(ssh, "SHADOW-ALERT", "192.0.2.31", now),
		attestedAttackEvent(ssh, "SHADOW-ALERT", "192.0.2.31", now.Add(time.Second)),
		attestedAttackEvent(ssh, "SHADOW-ALERT", "192.0.2.32", now),
		attestedAttackEvent(sqli, "BANNED", "192.0.2.33", now.Add(time.Second)),
	}
	metrics, _, _, rejected := buildAttackerMetrics(events, catalog)
	if rejected != 0 || len(metrics) != 4 {
		t.Fatalf("metrics=%#v rejected=%d", metrics, rejected)
	}
	want := []string{"192.0.2.31", "192.0.2.33", "192.0.2.30", "192.0.2.32"}
	for index, ip := range want {
		if metrics[index].ip != ip {
			t.Fatalf("rank %d = %s, want %s", index, metrics[index].ip, ip)
		}
	}
}
