package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	defaultRiskModelVersion = "sw-risk-v1"
	metricQualityAttested   = "attested"
	metricQualityRecorded   = "recorded-unverified"
	metricQualityMixed      = "mixed"
	metricQualityLegacy     = "legacy-estimate"
	metricScopeRetained     = "retained-telemetry-journal"
	metricScopeRetainedTail = "retained-telemetry-journal-tail"
)

var riskCategoryBase = map[string]int{
	"exploit":           50,
	"brute_force":       20,
	"reconnaissance":    20,
	"denial_of_service": 40,
	"abuse":             10,
}

type riskCatalogDocument struct {
	CatalogVersion      string              `json:"catalog_version"`
	RiskModelVersion    string              `json:"risk_model_version"`
	RiskCategories      map[string][]string `json:"risk_categories"`
	MetricExcludedRules []string            `json:"metric_excluded_rules"`
	Rules               []struct {
		ID        string `json:"id"`
		Action    string `json:"action"`
		Threshold int    `json:"threshold"`
		Window    int    `json:"window"`
	} `json:"rules"`
}

type riskProfile struct {
	ruleID         string
	category       string
	action         string
	threshold      int
	windowSeconds  int
	catalogVersion string
	catalogSHA256  string
	riskModel      string
	metricEligible bool
	attested       bool
	recorded       bool
}

type riskCatalog struct {
	profiles         map[string]riskProfile
	ruleCount        int
	catalogVersion   string
	catalogSHA256    string
	riskModelVersion string
}

func parseRiskCatalog(data []byte, defaultThreshold, defaultWindow int) (riskCatalog, error) {
	if defaultThreshold <= 0 || defaultWindow <= 0 {
		return riskCatalog{}, fmt.Errorf("risk defaults must be positive")
	}
	var document riskCatalogDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return riskCatalog{}, fmt.Errorf("decode risk catalog: %w", err)
	}
	if document.CatalogVersion == "" || document.RiskModelVersion == "" || len(document.Rules) == 0 {
		return riskCatalog{}, fmt.Errorf("risk catalog metadata or rules are missing")
	}
	if document.RiskModelVersion != defaultRiskModelVersion {
		return riskCatalog{}, fmt.Errorf("unsupported risk model %q", document.RiskModelVersion)
	}
	if len(document.RiskCategories) != len(riskCategoryBase) {
		return riskCatalog{}, fmt.Errorf("risk catalog must contain exactly %d categories", len(riskCategoryBase))
	}

	categoryByRule := make(map[string]string, len(document.Rules))
	for category, ruleIDs := range document.RiskCategories {
		if _, supported := riskCategoryBase[category]; !supported {
			return riskCatalog{}, fmt.Errorf("unsupported risk category %q", category)
		}
		if len(ruleIDs) == 0 {
			return riskCatalog{}, fmt.Errorf("risk category %q is empty", category)
		}
		for _, ruleID := range ruleIDs {
			if previous, duplicate := categoryByRule[ruleID]; duplicate {
				return riskCatalog{}, fmt.Errorf("rule %q is classified as both %q and %q", ruleID, previous, category)
			}
			categoryByRule[ruleID] = category
		}
	}
	excluded := make(map[string]struct{}, len(document.MetricExcludedRules))
	for _, ruleID := range document.MetricExcludedRules {
		if ruleID == "" {
			return riskCatalog{}, fmt.Errorf("metric exclusion has an empty rule ID")
		}
		if _, duplicate := excluded[ruleID]; duplicate {
			return riskCatalog{}, fmt.Errorf("metric exclusion for %q is duplicated", ruleID)
		}
		excluded[ruleID] = struct{}{}
	}

	digest := sha256.Sum256(data)
	digestText := hex.EncodeToString(digest[:])
	profiles := make(map[string]riskProfile, len(document.Rules))
	for _, rule := range document.Rules {
		if rule.ID == "" {
			return riskCatalog{}, fmt.Errorf("risk catalog contains an empty rule ID")
		}
		if _, duplicate := profiles[rule.ID]; duplicate {
			return riskCatalog{}, fmt.Errorf("risk catalog rule %q is duplicated", rule.ID)
		}
		category, classified := categoryByRule[rule.ID]
		if !classified {
			return riskCatalog{}, fmt.Errorf("risk catalog rule %q is not classified", rule.ID)
		}
		action := rule.Action
		if action == "" {
			action = "ban"
		}
		if !validRuleAction(action) {
			return riskCatalog{}, fmt.Errorf("risk catalog rule %q has unsupported action %q", rule.ID, action)
		}
		if rule.Threshold < 0 || rule.Window < 0 {
			return riskCatalog{}, fmt.Errorf("risk catalog rule %q has a negative threshold or window", rule.ID)
		}
		threshold := rule.Threshold
		window := rule.Window
		if action == "track" {
			if threshold == 0 {
				threshold = defaultThreshold
			}
			if window == 0 {
				window = defaultWindow
			}
		} else {
			if threshold != 0 || window != 0 {
				return riskCatalog{}, fmt.Errorf("immediate risk catalog rule %q must not define a threshold or window", rule.ID)
			}
			threshold = 1
			window = 0
		}
		_, omitted := excluded[rule.ID]
		profiles[rule.ID] = riskProfile{
			ruleID:         rule.ID,
			category:       category,
			action:         action,
			threshold:      threshold,
			windowSeconds:  window,
			catalogVersion: document.CatalogVersion,
			catalogSHA256:  digestText,
			riskModel:      document.RiskModelVersion,
			metricEligible: !omitted,
		}
	}
	for ruleID := range categoryByRule {
		if _, exists := profiles[ruleID]; !exists {
			return riskCatalog{}, fmt.Errorf("risk category references unknown rule %q", ruleID)
		}
	}
	for ruleID := range excluded {
		if _, exists := profiles[ruleID]; !exists {
			return riskCatalog{}, fmt.Errorf("metric exclusion references unknown rule %q", ruleID)
		}
	}
	return riskCatalog{
		profiles:         profiles,
		ruleCount:        len(document.Rules),
		catalogVersion:   document.CatalogVersion,
		catalogSHA256:    digestText,
		riskModelVersion: document.RiskModelVersion,
	}, nil
}

func validRuleAction(action string) bool {
	return action == "ban" || action == "detect" || action == "track"
}

func validRiskCategory(category string) bool {
	_, ok := riskCategoryBase[category]
	return ok
}

func profileForEvent(event TelemetryEvent, catalog riskCatalog) (riskProfile, bool) {
	if validRecordedEvent(event) {
		profile := recordedRiskProfile(event)
		switch {
		case isCollectorObservationModel(event.ObservationModel):
			if isCurrentCatalogIdentity(event, catalog) {
				enforcement, exists := catalog.profiles[event.RuleID]
				if !exists || !eventMatchesProfile(event, enforcement) {
					return riskProfile{}, false
				}
				if event.RiskAttributionRuleID != "" {
					attribution, attributed := catalog.profiles[event.RiskAttributionRuleID]
					if !attributed || !riskAttributionMatchesProfile(event, attribution) {
						return riskProfile{}, false
					}
					attribution.attested = true
					return attribution, true
				}
				enforcement.attested = true
				return enforcement, true
			}
			// Retained journals can legitimately contain events from a prior
			// signed package. Their self-recorded policy remains useful, but an
			// unknown catalog digest cannot be presented as locally verified.
			profile.recorded = true
			return profile, true
		case isKernelObservationModel(event.ObservationModel):
			if event.RiskAttributionRuleID != "" {
				return riskProfile{}, false
			}
			if event.SignatureCatalogVersion == kernelRuleCatalogVersion &&
				event.SignatureCatalogSHA256 == kernelRuleCatalogSHA256 {
				expected, exists := syntheticRiskProfile(event.RuleID)
				if event.MetricEligible != nil {
					expected.metricEligible = *event.MetricEligible
				}
				if !exists || !eventMatchesProfile(event, expected) {
					return riskProfile{}, false
				}
				expected.catalogVersion = kernelRuleCatalogVersion
				expected.catalogSHA256 = kernelRuleCatalogSHA256
				expected.metricEligible = *event.MetricEligible
				expected.attested = true
				return expected, true
			}
			// A prior compiled kernel catalog is not available for local replay.
			// Keep its self-recorded policy visible without upgrading it to an
			// exact-current attestation.
			profile.recorded = true
			return profile, true
		}
	}
	if hasRuleAttestation(event) {
		return riskProfile{}, false
	}
	if profile, exists := catalog.profiles[event.Jail]; exists {
		profile.attested = false
		// The current catalog can estimate a legacy event's category and policy,
		// but it cannot attest which historical bytes evaluated that event.
		profile.catalogVersion = ""
		profile.catalogSHA256 = ""
		return profile, true
	}
	return syntheticRiskProfile(event.Jail)
}

func recordedRiskProfile(event TelemetryEvent) riskProfile {
	profile := riskProfile{
		ruleID:         event.RuleID,
		category:       event.RiskCategory,
		action:         event.RuleAction,
		threshold:      event.EffectiveThreshold,
		windowSeconds:  *event.EffectiveWindowSeconds,
		catalogVersion: event.SignatureCatalogVersion,
		catalogSHA256:  event.SignatureCatalogSHA256,
		riskModel:      event.RiskModelVersion,
		metricEligible: *event.MetricEligible,
	}
	if event.RiskAttributionRuleID != "" {
		profile.ruleID = event.RiskAttributionRuleID
		profile.category = event.RiskAttributionCategory
		profile.action = event.RiskAttributionAction
		profile.threshold = event.RiskAttributionThreshold
		profile.windowSeconds = *event.RiskAttributionWindowSeconds
		profile.metricEligible = *event.RiskAttributionMetricEligible
	}
	return profile
}

func validRecordedEvent(event TelemetryEvent) bool {
	if event.RuleAttestationStatus != metricQualityAttested || event.RuleID == "" || event.RuleID != event.Jail ||
		event.MetricEligible == nil || event.SignatureCatalogVersion == "" ||
		len(event.SignatureCatalogSHA256) != sha256.Size*2 || event.RiskModelVersion != defaultRiskModelVersion ||
		!validRiskCategory(event.RiskCategory) || !validRuleAction(event.RuleAction) ||
		!validEventRuleAction(event.Action, event.RuleAction) || !validObservationModel(event.ObservationModel) ||
		!validRiskAttributionEvidence(event) ||
		!validObservationDisposition(event) ||
		event.EffectiveWindowSeconds == nil ||
		!validAttestedPolicy(event.RuleAction, event.EffectiveThreshold, *event.EffectiveWindowSeconds) {
		return false
	}
	_, err := hex.DecodeString(event.SignatureCatalogSHA256)
	return err == nil
}

func hasRiskAttributionEvidence(event TelemetryEvent) bool {
	return event.RiskAttributionRuleID != "" || event.RiskAttributionCategory != "" ||
		event.RiskAttributionAction != "" || event.RiskAttributionThreshold != 0 ||
		event.RiskAttributionWindowSeconds != nil || event.RiskAttributionMetricEligible != nil
}

func validRiskAttributionEvidence(event TelemetryEvent) bool {
	if !hasRiskAttributionEvidence(event) {
		return true
	}
	return isCollectorObservationModel(event.ObservationModel) && event.RiskAttributionRuleID != "" &&
		event.RiskAttributionRuleID != event.RuleID && validRiskCategory(event.RiskAttributionCategory) &&
		validRuleAction(event.RiskAttributionAction) && event.RiskAttributionWindowSeconds != nil &&
		event.RiskAttributionMetricEligible != nil &&
		validAttestedPolicy(event.RiskAttributionAction, event.RiskAttributionThreshold, *event.RiskAttributionWindowSeconds)
}

func isCurrentCatalogIdentity(event TelemetryEvent, catalog riskCatalog) bool {
	return catalog.catalogVersion != "" && catalog.catalogSHA256 != "" && catalog.riskModelVersion != "" &&
		event.SignatureCatalogVersion == catalog.catalogVersion &&
		event.SignatureCatalogSHA256 == catalog.catalogSHA256 &&
		event.RiskModelVersion == catalog.riskModelVersion
}

func eventMatchesProfile(event TelemetryEvent, expected riskProfile) bool {
	return event.RuleID == expected.ruleID && event.RiskCategory == expected.category &&
		event.RuleAction == expected.action && event.EffectiveThreshold == expected.threshold &&
		event.EffectiveWindowSeconds != nil && *event.EffectiveWindowSeconds == expected.windowSeconds &&
		event.RiskModelVersion == expected.riskModel && event.MetricEligible != nil &&
		*event.MetricEligible == expected.metricEligible
}

func riskAttributionMatchesProfile(event TelemetryEvent, expected riskProfile) bool {
	return event.RiskAttributionRuleID == expected.ruleID && event.RiskAttributionCategory == expected.category &&
		event.RiskAttributionAction == expected.action && event.RiskAttributionThreshold == expected.threshold &&
		event.RiskAttributionWindowSeconds != nil && *event.RiskAttributionWindowSeconds == expected.windowSeconds &&
		event.RiskAttributionMetricEligible != nil && *event.RiskAttributionMetricEligible == expected.metricEligible
}

func isCollectorObservationModel(model string) bool {
	return model == "collector-content-window-v1" || model == "collector-content-window-degraded-v1"
}

func isKernelObservationModel(model string) bool {
	return model == "kernel-log-observation-v1" || model == "kernel-log-observation-degraded-v1"
}

func validObservationDisposition(event TelemetryEvent) bool {
	if event.ObservationDisposition == "" {
		return true
	}
	return event.ObservationDisposition == "kernel-packet-dropped" && event.Action == "DETECTED" &&
		event.RuleID == "L2-ARP-FLOOD" && event.Jail == "L2-ARP-FLOOD" &&
		isKernelObservationModel(event.ObservationModel)
}

func hasRuleAttestation(event TelemetryEvent) bool {
	return event.RuleID != "" || event.RiskCategory != "" || event.RuleAction != "" ||
		event.EffectiveThreshold != 0 || event.EffectiveWindowSeconds != nil ||
		event.SignatureCatalogVersion != "" || event.SignatureCatalogSHA256 != "" ||
		event.RiskModelVersion != "" || event.MetricEligible != nil || event.ObservationModel != "" ||
		hasRiskAttributionEvidence(event) ||
		event.ObservationDisposition != "" || event.RuleAttestationStatus != ""
}

func validEventRuleAction(eventAction, ruleAction string) bool {
	switch eventAction {
	case "BANNED", "SIMULATED-BAN", "SHADOW-ALERT":
		return ruleAction == "ban" || ruleAction == "track"
	case "DETECTED":
		return ruleAction == "ban" || ruleAction == "track" || ruleAction == "detect"
	default:
		return false
	}
}

func validObservationModel(model string) bool {
	switch model {
	case "collector-content-window-v1", "collector-content-window-degraded-v1", "kernel-log-observation-v1", "kernel-log-observation-degraded-v1":
		return true
	default:
		return false
	}
}

func validAttestedPolicy(action string, threshold, window int) bool {
	if action == "track" {
		return threshold > 0 && window > 0
	}
	if action == "ban" || action == "detect" {
		return threshold == 1 && window == 0
	}
	return false
}

func syntheticRiskProfile(ruleID string) (riskProfile, bool) {
	for _, kernelProfile := range kernelRuleProfiles {
		if kernelProfile.ruleID != ruleID {
			continue
		}
		return riskProfile{
			ruleID:         kernelProfile.ruleID,
			category:       kernelProfile.riskCategory,
			action:         kernelProfile.ruleAction,
			threshold:      kernelProfile.threshold,
			windowSeconds:  kernelProfile.windowSeconds,
			riskModel:      defaultRiskModelVersion,
			metricEligible: true,
		}, true
	}
	return riskProfile{}, false
}

type riskPolicyKey struct {
	ruleID         string
	category       string
	action         string
	threshold      int
	windowSeconds  int
	catalogVersion string
	catalogSHA256  string
	riskModel      string
	attested       bool
	recorded       bool
}

type policyMetric struct {
	profile               riskProfile
	times                 []time.Time
	thresholdEvidence     bool
	last                  time.Time
	lastPayload           string
	lastEnforcementRuleID string
	lastEnforcementAction string
}

type jailMetric struct {
	hits     int
	policies map[riskPolicyKey]*policyMetric
}

type attackerAccumulator struct {
	ip           string
	hits         int
	attestedHits int
	recordedHits int
	legacyHits   int
	missingModel int
	degradedHits int
	models       map[string]int
	first        time.Time
	last         time.Time
	jails        map[string]*jailMetric
}

type attackerMetric struct {
	ip                      string
	hits                    int
	firstSeen               string
	lastSeen                string
	primaryJail             string
	enforcementJail         string
	enforcementAction       string
	jailHits                int
	policyHits              int
	attestedHits            int
	recordedHits            int
	legacyHits              int
	riskCategory            string
	severityScore           int
	severity                string
	peakWindowHits          int
	effectiveThreshold      int
	effectiveWindowSeconds  int
	metricQuality           string
	selectedPolicyQuality   string
	thresholdReached        bool
	thresholdEvidence       string
	metricScope             string
	hitEvidence             string
	hitQuality              string
	degradedHits            int
	riskModelVersion        string
	signatureCatalogVersion string
	signatureCatalogSHA256  string
	payload                 string
	firstObserved           time.Time
	lastObserved            time.Time
}

func buildAttackerMetrics(events []TelemetryEvent, catalog riskCatalog) ([]attackerMetric, map[string]int, map[string]int, int) {
	attackers := make(map[string]*attackerAccumulator)
	categoryCounts := make(map[string]int, len(riskCategoryBase))
	jailCounts := make(map[string]int)
	rejected := 0
	for _, event := range events {
		profile, ip, observedAt, admitted, excluded := admitMetricEvent(event, catalog)
		if excluded {
			continue
		}
		if !admitted {
			rejected++
			continue
		}
		attacker := attackers[ip]
		if attacker == nil {
			attacker = &attackerAccumulator{ip: ip, jails: make(map[string]*jailMetric), models: make(map[string]int)}
			attackers[ip] = attacker
		}
		attacker.hits++
		if profile.attested {
			attacker.attestedHits++
		} else if profile.recorded {
			attacker.recordedHits++
		} else {
			attacker.legacyHits++
		}
		if event.ObservationModel == "" {
			attacker.missingModel++
		} else {
			attacker.models[event.ObservationModel]++
			if strings.Contains(event.ObservationModel, "degraded") {
				attacker.degradedHits++
			}
		}
		if attacker.first.IsZero() || observedAt.Before(attacker.first) {
			attacker.first = observedAt
		}
		if attacker.last.IsZero() || observedAt.After(attacker.last) {
			attacker.last = observedAt
		}
		jail := attacker.jails[profile.ruleID]
		if jail == nil {
			jail = &jailMetric{policies: make(map[riskPolicyKey]*policyMetric)}
			attacker.jails[profile.ruleID] = jail
		}
		jail.hits++
		key := riskPolicyKey{
			ruleID: profile.ruleID, category: profile.category, action: profile.action,
			threshold: profile.threshold, windowSeconds: profile.windowSeconds,
			catalogVersion: profile.catalogVersion, catalogSHA256: profile.catalogSHA256,
			riskModel: profile.riskModel, attested: profile.attested, recorded: profile.recorded,
		}
		policy := jail.policies[key]
		if policy == nil {
			policy = &policyMetric{profile: profile}
			jail.policies[key] = policy
		}
		policy.times = append(policy.times, observedAt)
		if event.Action == "BANNED" || event.Action == "SIMULATED-BAN" || event.Action == "DETECTED" {
			policy.thresholdEvidence = true
		}
		if policy.last.IsZero() || observedAt.After(policy.last) {
			policy.last = observedAt
			policy.lastPayload = event.Payload
			policy.lastEnforcementRuleID = event.RuleID
			policy.lastEnforcementAction = event.RuleAction
		}
		categoryCounts[profile.category]++
		jailCounts[profile.ruleID]++
	}

	metrics := make([]attackerMetric, 0, len(attackers))
	for _, attacker := range attackers {
		metric := attackerMetric{
			ip: attacker.ip, hits: attacker.hits,
			attestedHits:  attacker.attestedHits,
			recordedHits:  attacker.recordedHits,
			legacyHits:    attacker.legacyHits,
			degradedHits:  attacker.degradedHits,
			firstSeen:     attacker.first.UTC().Format(time.RFC3339Nano),
			lastSeen:      attacker.last.UTC().Format(time.RFC3339Nano),
			firstObserved: attacker.first,
			lastObserved:  attacker.last,
			metricScope:   metricScopeRetained,
		}
		qualityKinds := 0
		if attacker.attestedHits > 0 {
			qualityKinds++
		}
		if attacker.recordedHits > 0 {
			qualityKinds++
		}
		if attacker.legacyHits > 0 {
			qualityKinds++
		}
		switch {
		case qualityKinds > 1:
			metric.metricQuality = metricQualityMixed
		case attacker.attestedHits > 0:
			metric.metricQuality = metricQualityAttested
		case attacker.recordedHits > 0:
			metric.metricQuality = metricQualityRecorded
		default:
			metric.metricQuality = metricQualityLegacy
		}
		metric.hitEvidence = observationEvidence(attacker)
		metric.hitQuality = observationQuality(attacker)
		var selected *policyMetric
		var selectedKey riskPolicyKey
		selectedScore := -1
		selectedPeak := 0
		for jailID, jail := range attacker.jails {
			for key, policy := range jail.policies {
				peak := peakHitsInWindow(policy.times, time.Duration(policy.profile.windowSeconds)*time.Second)
				score := calculateRiskScore(policy.profile, len(policy.times), peak, policy.thresholdEvidence)
				if selected == nil || score > selectedScore ||
					(score == selectedScore && len(policy.times) > metric.policyHits) ||
					(score == selectedScore && len(policy.times) == metric.policyHits && jail.hits > metric.jailHits) ||
					(score == selectedScore && len(policy.times) == metric.policyHits && jail.hits == metric.jailHits && policy.last.After(selected.last)) ||
					(score == selectedScore && len(policy.times) == metric.policyHits && jail.hits == metric.jailHits && policy.last.Equal(selected.last) &&
						(jailID < metric.primaryJail || (jailID == metric.primaryJail && riskPolicyKeyLess(key, selectedKey)))) {
					selected = policy
					selectedKey = key
					selectedScore = score
					selectedPeak = peak
					metric.primaryJail = jailID
					metric.jailHits = jail.hits
					metric.policyHits = len(policy.times)
				}
			}
		}
		if selected == nil {
			continue
		}
		metric.riskCategory = selected.profile.category
		metric.enforcementJail = selected.lastEnforcementRuleID
		metric.enforcementAction = selected.lastEnforcementAction
		metric.severityScore = selectedScore
		metric.severity = fmt.Sprintf("%d/100 (%s)", selectedScore, riskSeverityLabel(selectedScore))
		metric.peakWindowHits = selectedPeak
		metric.effectiveThreshold = selected.profile.threshold
		metric.effectiveWindowSeconds = selected.profile.windowSeconds
		switch {
		case selected.profile.attested:
			metric.selectedPolicyQuality = metricQualityAttested
		case selected.profile.recorded:
			metric.selectedPolicyQuality = metricQualityRecorded
		default:
			metric.selectedPolicyQuality = metricQualityLegacy
		}
		metric.thresholdReached, metric.thresholdEvidence = thresholdEvidenceForPolicy(selected, selectedPeak)
		metric.riskModelVersion = selected.profile.riskModel
		metric.signatureCatalogVersion = selected.profile.catalogVersion
		metric.signatureCatalogSHA256 = selected.profile.catalogSHA256
		metric.payload = selected.lastPayload
		metrics = append(metrics, metric)
	}
	sort.Slice(metrics, func(i, j int) bool {
		if metrics[i].hits != metrics[j].hits {
			return metrics[i].hits > metrics[j].hits
		}
		if metrics[i].severityScore != metrics[j].severityScore {
			return metrics[i].severityScore > metrics[j].severityScore
		}
		if !metrics[i].lastObserved.Equal(metrics[j].lastObserved) {
			return metrics[i].lastObserved.After(metrics[j].lastObserved)
		}
		return metrics[i].ip < metrics[j].ip
	})
	return metrics, categoryCounts, jailCounts, rejected
}

// admitMetricEvent is the single admission boundary for every attack KPI.
// Excluded events are intentionally outside the metric population; malformed
// or unverifiable events are rejected so callers can surface evidence loss.
func admitMetricEvent(event TelemetryEvent, catalog riskCatalog) (
	profile riskProfile,
	canonicalIP string,
	observedAt time.Time,
	admitted bool,
	excluded bool,
) {
	if !metricActionEligible(event.Action) {
		return riskProfile{}, "", time.Time{}, false, true
	}
	profile, known := profileForEvent(event, catalog)
	if !known {
		return riskProfile{}, "", time.Time{}, false, false
	}
	if !profile.metricEligible {
		return riskProfile{}, "", time.Time{}, false, true
	}
	address, err := netip.ParseAddr(event.IP)
	if err != nil || address.Zone() != "" {
		return riskProfile{}, "", time.Time{}, false, false
	}
	observedAt, err = time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return riskProfile{}, "", time.Time{}, false, false
	}
	return profile, address.Unmap().String(), observedAt, true, false
}

func observationEvidence(attacker *attackerAccumulator) string {
	if attacker == nil {
		return metricQualityLegacy
	}
	if attacker.missingModel > 0 {
		if len(attacker.models) > 0 {
			return metricQualityMixed
		}
		return metricQualityLegacy
	}
	if len(attacker.models) == 1 {
		for model := range attacker.models {
			return model
		}
	}
	if len(attacker.models) > 1 {
		return metricQualityMixed
	}
	return metricQualityLegacy
}

func observationQuality(attacker *attackerAccumulator) string {
	if attacker == nil {
		return metricQualityLegacy
	}
	if attacker.degradedHits > 0 {
		return "degraded"
	}
	if attacker.missingModel > 0 {
		if len(attacker.models) > 0 {
			return metricQualityMixed
		}
		return metricQualityLegacy
	}
	if len(attacker.models) > 0 {
		return "measured"
	}
	return metricQualityLegacy
}

func thresholdEvidenceForPolicy(policy *policyMetric, peak int) (bool, string) {
	if policy == nil {
		return false, "none"
	}
	switch policy.profile.action {
	case "ban", "detect":
		return true, "immediate-rule"
	case "track":
		if peak >= policy.profile.threshold {
			return true, "observed-window"
		}
		if policy.thresholdEvidence {
			return true, "decision-event"
		}
	}
	return false, "none"
}

func riskPolicyKeyLess(left, right riskPolicyKey) bool {
	if left.attested != right.attested || left.recorded != right.recorded {
		return riskPolicyQualityRank(left) > riskPolicyQualityRank(right)
	}
	if left.ruleID != right.ruleID {
		return left.ruleID < right.ruleID
	}
	if left.category != right.category {
		return left.category < right.category
	}
	if left.action != right.action {
		return left.action < right.action
	}
	if left.threshold != right.threshold {
		return left.threshold < right.threshold
	}
	if left.windowSeconds != right.windowSeconds {
		return left.windowSeconds < right.windowSeconds
	}
	if left.catalogVersion != right.catalogVersion {
		return left.catalogVersion < right.catalogVersion
	}
	if left.catalogSHA256 != right.catalogSHA256 {
		return left.catalogSHA256 < right.catalogSHA256
	}
	if left.riskModel != right.riskModel {
		return left.riskModel < right.riskModel
	}
	return false
}

func riskPolicyQualityRank(key riskPolicyKey) int {
	if key.attested {
		return 2
	}
	if key.recorded {
		return 1
	}
	return 0
}

func metricActionEligible(action string) bool {
	switch action {
	case "BANNED", "DETECTED", "SHADOW-ALERT", "SIMULATED-BAN":
		return true
	default:
		return false
	}
}

func peakHitsInWindow(times []time.Time, window time.Duration) int {
	if len(times) == 0 || window <= 0 {
		return 0
	}
	ordered := append([]time.Time(nil), times...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Before(ordered[j]) })
	peak := 0
	left := 0
	for right := range ordered {
		for left <= right && ordered[right].Sub(ordered[left]) > window {
			left++
		}
		if count := right - left + 1; count > peak {
			peak = count
		}
	}
	return peak
}

func calculateRiskScore(profile riskProfile, ruleHits, peakWindowHits int, thresholdEvidence bool) int {
	base, exists := riskCategoryBase[profile.category]
	if !exists {
		base = 10
	}
	score := base
	switch profile.action {
	case "ban":
		score += 20 + 10*minInt(ruleHits, 4)
	case "detect":
		score += 10 + 10*minInt(ruleHits, 4)
	case "track":
		threshold := profile.threshold
		if threshold < 1 {
			threshold = 1
		}
		effectivePeak := peakWindowHits
		if thresholdEvidence && effectivePeak < threshold {
			effectivePeak = threshold
		}
		boundedPeak := minInt(effectivePeak, threshold)
		score += (40*boundedPeak + threshold - 1) / threshold
		if peakWindowHits >= threshold || thresholdEvidence {
			score += 20
		}
	}
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}

func riskSeverityLabel(score int) string {
	if score >= 80 {
		return "Critical"
	}
	if score >= 50 {
		return "High Risk"
	}
	return "Suspicious"
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func mitreForRiskCategory(category string) string {
	switch category {
	case "brute_force":
		return "T1110: Brute Force"
	case "reconnaissance":
		return "T1595: Active Scanning"
	case "denial_of_service":
		return "T1498: Network Denial of Service"
	case "exploit":
		return "T1190: Exploit Public-Facing Application"
	case "abuse":
		return "Abuse / Spam"
	default:
		return "Unclassified"
	}
}
