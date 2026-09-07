package telemetry

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func testGRCCatalog() riskCatalog {
	return riskCatalog{catalogVersion: "2026.09", catalogSHA256: strings.Repeat("a", 64), riskModelVersion: defaultRiskModelVersion}
}

func testGRCMetric(ip string, hits int) attackerMetric {
	first := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	last := first.Add(time.Minute)
	profile := riskProfile{category: "brute_force", action: "track", threshold: 3, windowSeconds: 60}
	reached := hits >= profile.threshold
	thresholdEvidence := "none"
	if reached {
		thresholdEvidence = "observed-window"
	}
	return attackerMetric{
		ip: ip, hits: hits, firstSeen: first.Format(time.RFC3339Nano), lastSeen: last.Format(time.RFC3339Nano),
		firstObserved: first, lastObserved: last, primaryJail: "BF-SSH", jailHits: hits,
		enforcementJail: "BF-SSH", enforcementAction: "ban", riskCategory: "brute_force",
		policyAction: "track", policyHits: hits,
		severityScore: calculateRiskScore(profile, hits, hits, reached), peakWindowHits: hits, effectiveThreshold: 3, effectiveWindowSeconds: 60,
		thresholdReached: reached, thresholdEvidence: thresholdEvidence, metricQuality: metricQualityAttested,
		selectedPolicyQuality: metricQualityAttested, hitEvidence: "kernel-log-observation-v1", hitQuality: "measured",
		metricScope:      metricScopeRetained,
		riskModelVersion: defaultRiskModelVersion, signatureCatalogVersion: "2026.09", signatureCatalogSHA256: strings.Repeat("a", 64),
	}
}

func completeGRCEvidence(admitted int) kpiEvidenceState {
	return kpiEvidenceState{catalogAvailable: true, journalScanComplete: true, journalBytesTotal: 100, journalBytesScanned: 100, metricAdmittedEvents: admitted}
}

func buildTestGRCKPIDocumentWithRuntime(
	metrics []attackerMetric,
	catalog riskCatalog,
	evidence kpiEvidenceState,
	lifecycle grcKPILifecycleCounts,
) GRCKPIDocument {
	states := make(map[string]string, len(metrics))
	for _, metric := range metrics {
		states[metric.ip] = "active"
	}
	return buildGRCKPIDocumentWithRuntime(
		metrics,
		catalog,
		evidence,
		lifecycle,
		runtimeEnforcementView{
			scope: "ha-v2-runtime-snapshot", linked: true, complete: true,
			clusterID: "cluster-a", epoch: 7, nodeID: "node-a", role: "writer", coordination: "healthy",
			modelSHA256: strings.Repeat("b", 64), checkpointSHA256: strings.Repeat("c", 64),
			peerCheckpointSHA256: strings.Repeat("c", 64), checkpointAt: "2026-09-03T11:59:59Z", capturedAt: "2026-09-03T12:00:00Z",
			active: len(metrics), byIP: states,
		},
		states,
	)
}

func TestGRCKPIUsesExactTUIAttackerMetricsWithoutOSINT(t *testing.T) {
	metric := testGRCMetric("192.0.2.10", 4)
	document := buildTestGRCKPIDocumentWithRuntime([]attackerMetric{metric}, testGRCCatalog(), completeGRCEvidence(4), grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityComplete || len(document.Records) != 1 {
		t.Fatalf("unexpected GRC KPI document: %#v", document)
	}
	record := document.Records[0]
	if record.PhysicalHits != metric.hits || record.SelectedJail != metric.primaryJail || record.JailHits != metric.jailHits ||
		record.PolicyHits != metric.policyHits || record.PolicyAction != metric.policyAction ||
		record.Enforcement.Jail != metric.enforcementJail || record.Enforcement.Action != metric.enforcementAction ||
		record.SeverityScore != metric.severityScore || record.SeverityLabel != riskSeverityLabel(metric.severityScore) ||
		record.Catalog.SHA256 != metric.signatureCatalogSHA256 {
		t.Fatalf("GRC record diverges from admitted TUI metric: %#v", record)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "country") || strings.Contains(string(encoded), "threat") || strings.Contains(string(encoded), "org") {
		t.Fatalf("OSINT leaked into GRC risk evidence: %s", encoded)
	}
}

func TestGRCKPIDeterministicOrderingAndBytes(t *testing.T) {
	left := testGRCMetric("192.0.2.20", 2)
	right := testGRCMetric("192.0.2.10", 4)
	a := buildTestGRCKPIDocumentWithRuntime([]attackerMetric{left, right}, testGRCCatalog(), completeGRCEvidence(6), grcKPILifecycleCounts{})
	b := buildTestGRCKPIDocumentWithRuntime([]attackerMetric{right, left}, testGRCCatalog(), completeGRCEvidence(6), grcKPILifecycleCounts{})
	wireA, err := marshalGRCKPIDocument(a)
	if err != nil {
		t.Fatal(err)
	}
	wireB, err := marshalGRCKPIDocument(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(wireA) != string(wireB) || a.Records[0].IP != "192.0.2.10" {
		t.Fatalf("GRC KPI ordering is unstable\n%s\n%s", wireA, wireB)
	}
	decoded, err := decodeGRCKPIDocument(wireA)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, decoded) {
		t.Fatal("strict round trip changed document")
	}
}

func TestGRCKPIDashboardConsumerCarriesTheSameDocument(t *testing.T) {
	document := buildTestGRCKPIDocumentWithRuntime([]attackerMetric{testGRCMetric("192.0.2.10", 4)}, testGRCCatalog(), completeGRCEvidence(4), grcKPILifecycleCounts{})
	documentWire, err := marshalGRCKPIDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	dashboardWire, err := json.Marshal(DashboardData{WAF: WAF{GRCKPI: &document}})
	if err != nil {
		t.Fatal(err)
	}
	var dashboard struct {
		WAF struct {
			GRCKPI json.RawMessage `json:"grc_kpi"`
		} `json:"waf"`
	}
	if err := json.Unmarshal(dashboardWire, &dashboard); err != nil {
		t.Fatal(err)
	}
	if string(dashboard.WAF.GRCKPI) != string(documentWire) {
		t.Fatalf("dashboard consumer changed GRC KPI bytes\nwant %s\ngot  %s", documentWire, dashboard.WAF.GRCKPI)
	}
}

func TestGRCKPIExactEmptyJSONShape(t *testing.T) {
	document := buildTestGRCKPIDocumentWithRuntime(nil, testGRCCatalog(), completeGRCEvidence(0), grcKPILifecycleCounts{})
	wire, err := marshalGRCKPIDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"status":"complete","window":{"scope":"retained-telemetry-journal","complete":true},"catalog":{"version":"2026.09","sha256":"` + strings.Repeat("a", 64) + `","risk_model_version":"sw-risk-v1"},"evidence":{"journal_bytes_total":100,"journal_bytes_scanned":100,"journal_decode_errors":0,"admitted_events":0,"rejected_events":0,"excluded_events":0,"records_truncated":0},"lifecycle":{"scope":"ha-v2-runtime-snapshot","deletion_records":0,"expiry_records":0,"tombstone_records":0,"runtime_state_linked":true,"runtime_snapshot_complete":true,"runtime_cluster_id":"cluster-a","runtime_epoch":7,"runtime_node_id":"node-a","runtime_role":"writer","runtime_coordination":"healthy","runtime_model_sha256":"` + strings.Repeat("b", 64) + `","runtime_checkpoint_sha256":"` + strings.Repeat("c", 64) + `","runtime_peer_checkpoint_sha256":"` + strings.Repeat("c", 64) + `","runtime_checkpoint_at":"2026-09-03T11:59:59Z","runtime_captured_at":"2026-09-03T12:00:00Z"},"records":[]}`
	if string(wire) != want {
		t.Fatalf("exact GRC KPI JSON changed\nwant %s\ngot  %s", want, wire)
	}
}

func TestGRCKPIDegradesOnIncompleteEvidenceCatalogOrBounds(t *testing.T) {
	metric := testGRCMetric("192.0.2.10", 1)
	metric.hitQuality = "degraded"
	metric.hitEvidence = "kernel-log-observation-degraded-v1"
	metric.degradedHits = 1
	document := buildGRCKPIDocument([]attackerMetric{metric}, testGRCCatalog(), kpiEvidenceState{catalogAvailable: true, metricRejectedEvents: 1}, grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityDegraded {
		t.Fatal("incomplete evidence over-declared")
	}
	metrics := make([]attackerMetric, maxGRCKPIRecords+1)
	for index := range metrics {
		metrics[index] = testGRCMetric(fmt.Sprintf("2001:db8::%x", index+1), 1)
	}
	document = buildGRCKPIDocument(metrics, testGRCCatalog(), completeGRCEvidence(len(metrics)), grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityDegraded || len(document.Records) != maxGRCKPIRecords || document.Evidence.RecordsTruncated != 1 {
		t.Fatalf("record bound not surfaced: %#v", document.Evidence)
	}
}

func TestGRCKPILifecycleRecordsAreExcludedFromPhysicalHits(t *testing.T) {
	counts := grcKPILifecycleCounts{}
	for _, action := range []string{"UNBANNED", "EXPIRED", "TOMBSTONE", "DELETED"} {
		observeGRCKPILifecycle(action, &counts)
	}
	document := buildGRCKPIDocument(nil, testGRCCatalog(), completeGRCEvidence(0), counts)
	if len(document.Records) != 0 || document.Lifecycle.DeletionRecords != 2 || document.Lifecycle.ExpiryRecords != 1 || document.Lifecycle.TombstoneRecords != 1 || document.Lifecycle.RuntimeStateLinked {
		t.Fatalf("lifecycle evidence was misrepresented: %#v", document)
	}
}

func TestGRCKPIStrictDecoderRejectsUnknownDuplicateTrailingAndOversize(t *testing.T) {
	document := buildTestGRCKPIDocumentWithRuntime(nil, testGRCCatalog(), completeGRCEvidence(0), grcKPILifecycleCounts{})
	wire, err := marshalGRCKPIDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		append(wire[:len(wire)-1], []byte(`,"unknown":true}`)...),
		[]byte(strings.Replace(string(wire), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)),
		append(wire, []byte(` {}`)...),
		make([]byte, maxGRCKPIJSONBytes+1),
	}
	for index, candidate := range cases {
		if _, err := decodeGRCKPIDocument(candidate); err == nil {
			t.Fatalf("invalid document %d accepted", index)
		}
	}
}

func TestGRCKPIRejectsNonCanonicalOrInconsistentEvidence(t *testing.T) {
	valid := buildTestGRCKPIDocumentWithRuntime(
		[]attackerMetric{testGRCMetric("192.0.2.10", 4)},
		testGRCCatalog(),
		completeGRCEvidence(4),
		grcKPILifecycleCounts{},
	)
	if _, err := marshalGRCKPIDocument(valid); err != nil {
		t.Fatalf("valid fixture failed validation: %v", err)
	}

	cases := map[string]func(*GRCKPIDocument){
		"nil records": func(document *GRCKPIDocument) {
			document.Records = nil
		},
		"partial catalog": func(document *GRCKPIDocument) {
			document.Status = kpiEvidenceQualityDegraded
			document.Catalog.SHA256 = ""
		},
		"uppercase digest": func(document *GRCKPIDocument) {
			document.Catalog.SHA256 = strings.Repeat("A", 64)
		},
		"noncanonical timestamp": func(document *GRCKPIDocument) {
			document.Records[0].LastObserved = "2026-09-03T08:01:00+00:00"
			document.Window.Last = document.Records[0].LastObserved
		},
		"incorrect window": func(document *GRCKPIDocument) {
			document.Window.First = "2026-09-03T07:59:59Z"
		},
		"incorrect physical sum": func(document *GRCKPIDocument) {
			document.Evidence.AdmittedEvents++
		},
		"incorrect jail count": func(document *GRCKPIDocument) {
			document.Records[0].JailHits = document.Records[0].PhysicalHits + 1
		},
		"incorrect policy count": func(document *GRCKPIDocument) {
			document.Records[0].PolicyHits = document.Records[0].JailHits + 1
		},
		"incorrect severity": func(document *GRCKPIDocument) {
			document.Records[0].SeverityScore--
			document.Records[0].SeverityLabel = riskSeverityLabel(document.Records[0].SeverityScore)
		},
		"incorrect threshold evidence": func(document *GRCKPIDocument) {
			document.Records[0].ThresholdEvidence = "none"
		},
		"partial enforcement": func(document *GRCKPIDocument) {
			document.Records[0].Enforcement.Action = ""
		},
		"legacy catalog overclaim": func(document *GRCKPIDocument) {
			document.Status = kpiEvidenceQualityDegraded
			document.Records[0].MetricQuality = metricQualityLegacy
			document.Records[0].PolicyQuality = metricQualityLegacy
			document.Records[0].HitQuality = metricQualityLegacy
			document.Records[0].HitEvidence = metricQualityLegacy
			document.Records[0].Enforcement = GRCKPIEnforcement{}
		},
		"complete recorded policy": func(document *GRCKPIDocument) {
			document.Records[0].MetricQuality = metricQualityRecorded
			document.Records[0].PolicyQuality = metricQualityRecorded
		},
		"lifecycle exceeds excluded": func(document *GRCKPIDocument) {
			document.Lifecycle.ExpiryRecords = 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document := cloneGRCKPIDocument(t, valid)
			mutate(&document)
			if _, err := marshalGRCKPIDocument(document); err == nil {
				t.Fatal("inconsistent evidence was accepted")
			}
		})
	}
}

func TestGRCKPIRejectsDuplicateAndNonCanonicalRecordOrder(t *testing.T) {
	left := testGRCMetric("192.0.2.20", 4)
	right := testGRCMetric("192.0.2.10", 2)
	document := buildTestGRCKPIDocumentWithRuntime([]attackerMetric{left, right}, testGRCCatalog(), completeGRCEvidence(6), grcKPILifecycleCounts{})
	if _, err := marshalGRCKPIDocument(document); err != nil {
		t.Fatalf("valid fixture failed validation: %v", err)
	}

	unordered := cloneGRCKPIDocument(t, document)
	unordered.Records[0], unordered.Records[1] = unordered.Records[1], unordered.Records[0]
	if _, err := marshalGRCKPIDocument(unordered); err == nil {
		t.Fatal("noncanonical record order was accepted")
	}

	duplicate := cloneGRCKPIDocument(t, document)
	duplicate.Records[1].IP = duplicate.Records[0].IP
	if _, err := marshalGRCKPIDocument(duplicate); err == nil {
		t.Fatal("duplicate IP was accepted")
	}
}

func TestGRCKPIDegradedLegacyAndHistoricalCatalogsRemainExplicit(t *testing.T) {
	legacy := testGRCMetric("192.0.2.10", 2)
	legacy.metricQuality = metricQualityLegacy
	legacy.selectedPolicyQuality = metricQualityLegacy
	legacy.hitEvidence = metricQualityLegacy
	legacy.hitQuality = metricQualityLegacy
	legacy.enforcementJail = ""
	legacy.enforcementAction = ""
	legacy.signatureCatalogVersion = ""
	legacy.signatureCatalogSHA256 = ""
	document := buildGRCKPIDocument([]attackerMetric{legacy}, testGRCCatalog(), completeGRCEvidence(2), grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityDegraded || document.Records[0].Catalog != (GRCKPICatalog{}) {
		t.Fatalf("legacy policy was not represented conservatively: %#v", document)
	}
	if _, err := marshalGRCKPIDocument(document); err != nil {
		t.Fatalf("explicit legacy evidence was rejected: %v", err)
	}

	historical := testGRCMetric("192.0.2.20", 2)
	historical.metricQuality = metricQualityRecorded
	historical.selectedPolicyQuality = metricQualityRecorded
	historical.signatureCatalogVersion = "2026.08"
	historical.signatureCatalogSHA256 = strings.Repeat("b", 64)
	document = buildGRCKPIDocument([]attackerMetric{historical}, testGRCCatalog(), completeGRCEvidence(2), grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityDegraded || document.Records[0].Catalog == document.Catalog {
		t.Fatalf("historical catalog was over-attested: %#v", document)
	}
	if _, err := marshalGRCKPIDocument(document); err != nil {
		t.Fatalf("explicit historical evidence was rejected: %v", err)
	}

	emptyCatalog := buildGRCKPIDocument(nil, riskCatalog{}, kpiEvidenceState{}, grcKPILifecycleCounts{})
	if emptyCatalog.Status != kpiEvidenceQualityDegraded || emptyCatalog.Catalog != (GRCKPICatalog{}) {
		t.Fatalf("unavailable catalog was over-attested: %#v", emptyCatalog)
	}
	if _, err := marshalGRCKPIDocument(emptyCatalog); err != nil {
		t.Fatalf("safe unavailable-catalog evidence was rejected: %v", err)
	}
}

func TestGRCKPIProductionBoundaryUsesValidatedDegradedFallback(t *testing.T) {
	invalid := testGRCMetric("not-an-ip", 4)
	document, err := prepareGRCKPIDocument([]attackerMetric{invalid}, testGRCCatalog(), completeGRCEvidence(4), grcKPILifecycleCounts{})
	if err == nil {
		t.Fatal("invalid production document did not report validation failure")
	}
	if document == nil || document.Status != kpiEvidenceQualityDegraded || document.Window.Complete ||
		document.Window.Scope != metricScopeRetainedTail || len(document.Records) != 0 || document.Evidence.AdmittedEvents != 0 {
		t.Fatalf("invalid production document did not use the safe fallback: %#v", document)
	}
	if _, validationErr := marshalGRCKPIDocument(*document); validationErr != nil {
		t.Fatalf("production fallback is not valid: %v", validationErr)
	}
}

func TestGRCKPIUnlinkedRuntimeCannotClaimComplete_SW_GRC_018(t *testing.T) {
	document := buildGRCKPIDocument(nil, testGRCCatalog(), completeGRCEvidence(0), grcKPILifecycleCounts{})
	if document.Status != kpiEvidenceQualityComplete || document.Lifecycle.RuntimeStateLinked {
		t.Fatalf("test fixture did not isolate the unlinked overclaim: %#v", document)
	}
	if _, err := marshalGRCKPIDocument(document); err == nil {
		t.Fatal("complete GRC KPI evidence without a runtime identity was accepted")
	}
	prepared, err := prepareGRCKPIDocument(nil, testGRCCatalog(), completeGRCEvidence(0), grcKPILifecycleCounts{})
	if err != nil || prepared == nil || prepared.Status != kpiEvidenceQualityDegraded || prepared.Lifecycle.RuntimeStateLinked {
		t.Fatalf("unlinked production evidence was not downgraded safely: %#v err=%v", prepared, err)
	}
}

func TestGRCKPITruncationEvidenceMatchesOmittedRecordsAndHits(t *testing.T) {
	metrics := make([]attackerMetric, maxGRCKPIRecords+2)
	for index := range metrics {
		metrics[index] = testGRCMetric(fmt.Sprintf("2001:db8::%x", index+1), 1)
	}
	document := buildGRCKPIDocument(metrics, testGRCCatalog(), completeGRCEvidence(len(metrics)), grcKPILifecycleCounts{})
	if _, err := marshalGRCKPIDocument(document); err != nil {
		t.Fatalf("valid truncation evidence was rejected: %v", err)
	}
	document.Evidence.AdmittedEvents--
	if _, err := marshalGRCKPIDocument(document); err == nil {
		t.Fatal("truncation with fewer omitted hits than records was accepted")
	}
}

func TestGRCKPIRuntimeLifecycleBindingIsExactAndVersioned_SW_GRC_015(t *testing.T) {
	metrics := []attackerMetric{
		testGRCMetric("192.0.2.10", 4),
		testGRCMetric("192.0.2.20", 2),
	}
	view := runtimeEnforcementView{
		scope: "ha-v2-runtime-snapshot", linked: true, complete: true,
		clusterID: "cluster-a", epoch: 7, nodeID: "node-a", role: "writer", coordination: "healthy",
		modelSHA256: strings.Repeat("b", 64), checkpointSHA256: strings.Repeat("c", 64),
		peerCheckpointSHA256: strings.Repeat("c", 64), checkpointAt: "2026-09-03T11:59:59Z", capturedAt: "2026-09-03T12:00:00Z",
		active: 1, deleted: 1, byIP: map[string]string{"192.0.2.10": "active", "192.0.2.20": "deleted"},
	}
	document := buildGRCKPIDocumentWithRuntime(
		metrics,
		testGRCCatalog(),
		completeGRCEvidence(6),
		grcKPILifecycleCounts{},
		view,
		map[string]string{"192.0.2.10": "active", "192.0.2.20": "deleted"},
	)
	if document.Status != kpiEvidenceQualityComplete || !document.Lifecycle.RuntimeStateLinked ||
		!document.Lifecycle.RuntimeSnapshotComplete || document.Lifecycle.RuntimeSnapshotTruncated ||
		document.Lifecycle.RuntimeClusterID != "cluster-a" ||
		document.Lifecycle.RuntimeEpoch != 7 ||
		document.Lifecycle.RuntimeNodeID != "node-a" ||
		document.Lifecycle.RuntimeModelSHA256 != strings.Repeat("b", 64) ||
		document.Lifecycle.RuntimeCheckpointSHA256 != strings.Repeat("c", 64) ||
		document.Lifecycle.RuntimePeerCheckpointSHA256 != document.Lifecycle.RuntimeCheckpointSHA256 ||
		document.Lifecycle.RuntimeCheckpointAt != "2026-09-03T11:59:59Z" ||
		document.Lifecycle.RuntimeCapturedAt != "2026-09-03T12:00:00Z" ||
		document.Records[0].EnforcementState != "active" || document.Records[1].EnforcementState != "deleted" {
		t.Fatalf("runtime lifecycle was not bound exactly: %#v", document)
	}
	if _, err := marshalGRCKPIDocument(document); err != nil {
		t.Fatalf("valid runtime-bound KPI document was rejected: %v", err)
	}
}

func TestGRCKPIRuntimeLifecycleRejectsOverclaim_SW_GRC_016(t *testing.T) {
	metric := testGRCMetric("192.0.2.10", 4)
	view := runtimeEnforcementView{
		scope: "ha-v2-runtime-snapshot", linked: true, complete: true,
		clusterID: "cluster-a", epoch: 7, nodeID: "node-a", role: "writer", coordination: "healthy", modelSHA256: strings.Repeat("b", 64),
		checkpointSHA256: strings.Repeat("c", 64), peerCheckpointSHA256: strings.Repeat("c", 64),
		checkpointAt: "2026-09-03T11:59:59Z", capturedAt: "2026-09-03T12:00:00Z", byIP: map[string]string{"192.0.2.10": "active"},
	}
	valid := buildGRCKPIDocumentWithRuntime(
		[]attackerMetric{metric}, testGRCCatalog(), completeGRCEvidence(4), grcKPILifecycleCounts{},
		view, map[string]string{"192.0.2.10": "active"},
	)
	cases := map[string]func(*GRCKPIDocument){
		"scope":            func(document *GRCKPIDocument) { document.Lifecycle.Scope = "observed-telemetry-records-only" },
		"cluster identity": func(document *GRCKPIDocument) { document.Lifecycle.RuntimeClusterID = "Cluster A" },
		"epoch":            func(document *GRCKPIDocument) { document.Lifecycle.RuntimeEpoch = 0 },
		"node identity":    func(document *GRCKPIDocument) { document.Lifecycle.RuntimeNodeID = "" },
		"completion": func(document *GRCKPIDocument) {
			document.Lifecycle.RuntimeSnapshotComplete = false
		},
		"digest":     func(document *GRCKPIDocument) { document.Lifecycle.RuntimeModelSHA256 = "short" },
		"checkpoint": func(document *GRCKPIDocument) { document.Lifecycle.RuntimeCheckpointSHA256 = "short" },
		"peer checkpoint": func(document *GRCKPIDocument) {
			document.Lifecycle.RuntimePeerCheckpointSHA256 = strings.Repeat("d", 64)
		},
		"checkpoint time": func(document *GRCKPIDocument) { document.Lifecycle.RuntimeCheckpointAt = "2026-09-03T13:59:59+02:00" },
		"calendar date":   func(document *GRCKPIDocument) { document.Lifecycle.RuntimeCheckpointAt = "2026-02-30T11:59:59Z" },
		"capture":         func(document *GRCKPIDocument) { document.Lifecycle.RuntimeCapturedAt = "2026-09-03T14:00:00+02:00" },
		"stale healthy checkpoint": func(document *GRCKPIDocument) {
			document.Status = kpiEvidenceQualityDegraded
			document.Lifecycle.RuntimeCheckpointAt = "2026-09-03T11:54:59Z"
		},
		"future degraded checkpoint": func(document *GRCKPIDocument) {
			document.Status = kpiEvidenceQualityDegraded
			document.Lifecycle.RuntimeCoordination = "degraded"
			document.Lifecycle.RuntimeCheckpointAt = "2026-09-03T12:05:00.000000001Z"
		},
		"degraded healthy peer mismatch": func(document *GRCKPIDocument) {
			document.Status = kpiEvidenceQualityDegraded
			document.Lifecycle.RuntimePeerCheckpointSHA256 = strings.Repeat("d", 64)
		},
		"claim count": func(document *GRCKPIDocument) { document.Lifecycle.ActiveClaims = maximumHAReplicationClaims + 1 },
		"state":       func(document *GRCKPIDocument) { document.Records[0].EnforcementState = "removed" },
		"unknown complete": func(document *GRCKPIDocument) {
			document.Records[0].EnforcementState = "unknown"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			document := cloneGRCKPIDocument(t, valid)
			mutate(&document)
			if _, err := marshalGRCKPIDocument(document); err == nil {
				t.Fatal("invalid runtime lifecycle evidence was accepted")
			}
		})
	}

	unlinked := buildGRCKPIDocumentWithRuntime(
		[]attackerMetric{metric}, testGRCCatalog(), completeGRCEvidence(4), grcKPILifecycleCounts{},
		unavailableRuntimeEnforcementView(), nil,
	)
	if unlinked.Status != kpiEvidenceQualityDegraded || unlinked.Records[0].EnforcementState != "unknown" {
		t.Fatalf("unlinked runtime evidence was overclaimed: %#v", unlinked)
	}
	if _, err := marshalGRCKPIDocument(unlinked); err != nil {
		t.Fatalf("explicitly degraded runtime evidence was rejected: %v", err)
	}
}

func cloneGRCKPIDocument(t *testing.T, document GRCKPIDocument) GRCKPIDocument {
	t.Helper()
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var clone GRCKPIDocument
	if err := json.Unmarshal(wire, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
