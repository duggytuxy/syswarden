package telemetry

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"syswarden-core/firewall"
)

const (
	grcKPISchemaVersion = 1
	maxGRCKPIRecords    = 512
	maxGRCKPIJSONBytes  = 4 * 1024 * 1024
)

type GRCKPICatalog struct {
	Version          string `json:"version"`
	SHA256           string `json:"sha256"`
	RiskModelVersion string `json:"risk_model_version"`
}

type GRCKPIWindow struct {
	Scope    string `json:"scope"`
	First    string `json:"first_observed,omitempty"`
	Last     string `json:"last_observed,omitempty"`
	Complete bool   `json:"complete"`
}

type GRCKPIEvidence struct {
	JournalBytesTotal   int64 `json:"journal_bytes_total"`
	JournalBytesScanned int64 `json:"journal_bytes_scanned"`
	JournalDecodeErrors int   `json:"journal_decode_errors"`
	AdmittedEvents      int   `json:"admitted_events"`
	RejectedEvents      int   `json:"rejected_events"`
	ExcludedEvents      int   `json:"excluded_events"`
	RecordsTruncated    int   `json:"records_truncated"`
}

type GRCKPILifecycle struct {
	Scope                       string                             `json:"scope"`
	DeletionRecords             int                                `json:"deletion_records"`
	ExpiryRecords               int                                `json:"expiry_records"`
	TombstoneRecords            int                                `json:"tombstone_records"`
	RuntimeStateLinked          bool                               `json:"runtime_state_linked"`
	RuntimeSnapshotComplete     bool                               `json:"runtime_snapshot_complete,omitempty"`
	RuntimeSnapshotTruncated    bool                               `json:"runtime_snapshot_truncated,omitempty"`
	RuntimeClusterID            string                             `json:"runtime_cluster_id,omitempty"`
	RuntimeEpoch                uint64                             `json:"runtime_epoch,omitempty"`
	RuntimeNodeID               string                             `json:"runtime_node_id,omitempty"`
	RuntimeRole                 string                             `json:"runtime_role,omitempty"`
	RuntimeCoordination         string                             `json:"runtime_coordination,omitempty"`
	RuntimeModelSHA256          string                             `json:"runtime_model_sha256,omitempty"`
	RuntimeCheckpointSHA256     string                             `json:"runtime_checkpoint_sha256,omitempty"`
	RuntimePeerCheckpointSHA256 string                             `json:"runtime_peer_checkpoint_sha256,omitempty"`
	RuntimeCheckpointAt         string                             `json:"runtime_checkpoint_at,omitempty"`
	RuntimeCapturedAt           string                             `json:"runtime_captured_at,omitempty"`
	ActiveClaims                int                                `json:"active_claims,omitempty"`
	ExpiredClaims               int                                `json:"expired_claims,omitempty"`
	DeletedClaims               int                                `json:"deleted_claims,omitempty"`
	TombstonedClaims            int                                `json:"tombstoned_claims,omitempty"`
	RuntimeLocalSnapshot        *firewall.RuntimeLifecycleSnapshot `json:"runtime_local_snapshot,omitempty"`
}

type GRCKPIEnforcement struct {
	Jail   string `json:"jail,omitempty"`
	Action string `json:"action,omitempty"`
}

type GRCKPIRecord struct {
	IP                     string            `json:"ip"`
	PhysicalHits           int               `json:"physical_hits"`
	FirstObserved          string            `json:"first_observed"`
	LastObserved           string            `json:"last_observed"`
	SelectedJail           string            `json:"selected_jail"`
	JailHits               int               `json:"jail_hits"`
	PolicyHits             int               `json:"policy_hits"`
	Enforcement            GRCKPIEnforcement `json:"enforcement"`
	EnforcementState       string            `json:"enforcement_state,omitempty"`
	RiskCategory           string            `json:"risk_category"`
	PolicyAction           string            `json:"policy_action"`
	SeverityScore          int               `json:"severity_score"`
	SeverityLabel          string            `json:"severity_label"`
	PeakWindowHits         int               `json:"peak_window_hits"`
	EffectiveThreshold     int               `json:"effective_threshold"`
	EffectiveWindowSeconds int               `json:"effective_window_seconds"`
	ThresholdReached       bool              `json:"threshold_reached"`
	ThresholdEvidence      string            `json:"threshold_evidence"`
	MetricQuality          string            `json:"metric_quality"`
	PolicyQuality          string            `json:"policy_quality"`
	HitEvidence            string            `json:"hit_evidence"`
	HitQuality             string            `json:"hit_quality"`
	DegradedHits           int               `json:"degraded_hits"`
	Catalog                GRCKPICatalog     `json:"catalog"`
}

type GRCKPIDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	Window        GRCKPIWindow    `json:"window"`
	Catalog       GRCKPICatalog   `json:"catalog"`
	Evidence      GRCKPIEvidence  `json:"evidence"`
	Lifecycle     GRCKPILifecycle `json:"lifecycle"`
	Records       []GRCKPIRecord  `json:"records"`
}

type grcKPILifecycleCounts struct {
	deletions  int
	expiries   int
	tombstones int
}

func observeGRCKPILifecycle(action string, counts *grcKPILifecycleCounts) {
	if counts == nil {
		return
	}
	switch action {
	case "UNBANNED", "DELETED":
		counts.deletions++
	case "EXPIRED":
		counts.expiries++
	case "TOMBSTONE":
		counts.tombstones++
	}
}

func buildGRCKPIDocument(metrics []attackerMetric, catalog riskCatalog, evidence kpiEvidenceState, lifecycle grcKPILifecycleCounts) GRCKPIDocument {
	document := GRCKPIDocument{
		SchemaVersion: grcKPISchemaVersion,
		Status:        evidence.quality(),
		Window:        GRCKPIWindow{Scope: metricScopeRetained, Complete: evidence.journalScanComplete},
		Catalog:       GRCKPICatalog{Version: catalog.catalogVersion, SHA256: catalog.catalogSHA256, RiskModelVersion: catalog.riskModelVersion},
		Evidence: GRCKPIEvidence{
			JournalBytesTotal: evidence.journalBytesTotal, JournalBytesScanned: evidence.journalBytesScanned,
			JournalDecodeErrors: evidence.journalDecodeErrors, AdmittedEvents: evidence.metricAdmittedEvents,
			RejectedEvents: evidence.metricRejectedEvents, ExcludedEvents: evidence.metricExcludedEvents,
		},
		Lifecycle: GRCKPILifecycle{
			Scope: "observed-telemetry-records-only", DeletionRecords: lifecycle.deletions,
			ExpiryRecords: lifecycle.expiries, TombstoneRecords: lifecycle.tombstones, RuntimeStateLinked: false,
		},
		Records: []GRCKPIRecord{},
	}
	if !evidence.journalScanComplete {
		document.Window.Scope = metricScopeRetainedTail
	}
	ordered := append([]attackerMetric(nil), metrics...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].hits != ordered[j].hits {
			return ordered[i].hits > ordered[j].hits
		}
		if ordered[i].severityScore != ordered[j].severityScore {
			return ordered[i].severityScore > ordered[j].severityScore
		}
		if !ordered[i].lastObserved.Equal(ordered[j].lastObserved) {
			return ordered[i].lastObserved.After(ordered[j].lastObserved)
		}
		return ordered[i].ip < ordered[j].ip
	})
	if len(ordered) > maxGRCKPIRecords {
		document.Evidence.RecordsTruncated = len(ordered) - maxGRCKPIRecords
		ordered = ordered[:maxGRCKPIRecords]
		document.Status = kpiEvidenceQualityDegraded
	}
	for _, metric := range ordered {
		firstObserved := metric.firstObserved.UTC().Format(time.RFC3339Nano)
		lastObserved := metric.lastObserved.UTC().Format(time.RFC3339Nano)
		if document.Window.First == "" || metric.firstObserved.Before(mustParseGRCTimestamp(document.Window.First)) {
			document.Window.First = firstObserved
		}
		if document.Window.Last == "" || metric.lastObserved.After(mustParseGRCTimestamp(document.Window.Last)) {
			document.Window.Last = lastObserved
		}
		if metric.metricScope != document.Window.Scope {
			document.Status = kpiEvidenceQualityDegraded
		}
		recordCatalog := GRCKPICatalog{
			Version: metric.signatureCatalogVersion, SHA256: metric.signatureCatalogSHA256, RiskModelVersion: metric.riskModelVersion,
		}
		if metric.selectedPolicyQuality == metricQualityLegacy {
			recordCatalog = GRCKPICatalog{}
		}
		record := GRCKPIRecord{
			IP: metric.ip, PhysicalHits: metric.hits, FirstObserved: firstObserved, LastObserved: lastObserved,
			SelectedJail: metric.primaryJail, JailHits: metric.jailHits, PolicyHits: metric.policyHits,
			Enforcement:  GRCKPIEnforcement{Jail: metric.enforcementJail, Action: metric.enforcementAction},
			RiskCategory: metric.riskCategory, PolicyAction: metric.policyAction,
			SeverityScore: metric.severityScore,
			SeverityLabel: riskSeverityLabel(metric.severityScore), PeakWindowHits: metric.peakWindowHits,
			EffectiveThreshold: metric.effectiveThreshold, EffectiveWindowSeconds: metric.effectiveWindowSeconds,
			ThresholdReached: metric.thresholdReached, ThresholdEvidence: metric.thresholdEvidence,
			MetricQuality: metric.metricQuality, PolicyQuality: metric.selectedPolicyQuality,
			HitEvidence: metric.hitEvidence, HitQuality: metric.hitQuality, DegradedHits: metric.degradedHits,
			Catalog: recordCatalog,
		}
		if record.Catalog != document.Catalog || record.MetricQuality != metricQualityAttested ||
			record.PolicyQuality != metricQualityAttested || record.HitQuality != "measured" || record.DegradedHits != 0 {
			document.Status = kpiEvidenceQualityDegraded
		}
		document.Records = append(document.Records, record)
	}
	if document.Catalog.Version == "" || document.Catalog.SHA256 == "" || document.Catalog.RiskModelVersion == "" {
		document.Status = kpiEvidenceQualityDegraded
	}
	return document
}

func buildGRCKPIDocumentWithRuntime(
	metrics []attackerMetric,
	catalog riskCatalog,
	evidence kpiEvidenceState,
	lifecycle grcKPILifecycleCounts,
	runtimeView runtimeEnforcementView,
	states map[string]string,
) GRCKPIDocument {
	document := buildGRCKPIDocument(metrics, catalog, evidence, lifecycle)
	if !runtimeView.linked {
		document.Status = kpiEvidenceQualityDegraded
		for index := range document.Records {
			document.Records[index].EnforcementState = states[document.Records[index].IP]
			if document.Records[index].EnforcementState == "" {
				document.Records[index].EnforcementState = "unknown"
			}
		}
		return document
	}
	document.Lifecycle.Scope = runtimeView.scope
	document.Lifecycle.RuntimeStateLinked = true
	document.Lifecycle.RuntimeSnapshotComplete = runtimeView.complete
	document.Lifecycle.RuntimeSnapshotTruncated = runtimeView.truncated
	document.Lifecycle.RuntimeClusterID = runtimeView.clusterID
	document.Lifecycle.RuntimeEpoch = runtimeView.epoch
	document.Lifecycle.RuntimeNodeID = runtimeView.nodeID
	document.Lifecycle.RuntimeRole = runtimeView.role
	document.Lifecycle.RuntimeCoordination = runtimeView.coordination
	document.Lifecycle.RuntimeModelSHA256 = runtimeView.modelSHA256
	document.Lifecycle.RuntimeCheckpointSHA256 = runtimeView.checkpointSHA256
	document.Lifecycle.RuntimePeerCheckpointSHA256 = runtimeView.peerCheckpointSHA256
	document.Lifecycle.RuntimeCheckpointAt = runtimeView.checkpointAt
	document.Lifecycle.RuntimeCapturedAt = runtimeView.capturedAt
	document.Lifecycle.ActiveClaims = runtimeView.active
	document.Lifecycle.ExpiredClaims = runtimeView.expired
	document.Lifecycle.DeletedClaims = runtimeView.deleted
	document.Lifecycle.TombstonedClaims = runtimeView.tombstoned
	document.Lifecycle.RuntimeLocalSnapshot = runtimeView.localSnapshot
	if !runtimeView.complete || runtimeView.localSnapshot == nil && runtimeView.coordination != "healthy" {
		document.Status = kpiEvidenceQualityDegraded
	}
	for index := range document.Records {
		state := states[document.Records[index].IP]
		if state == "" {
			state = "unknown"
		}
		document.Records[index].EnforcementState = state
		if state == "unknown" {
			document.Status = kpiEvidenceQualityDegraded
		}
	}
	return document
}

// mustParseGRCTimestamp is used only while constructing a document from timestamps
// that are validated before publication. Invalid values return the zero time so the
// final validation rejects the document and production emits the safe fallback.
func mustParseGRCTimestamp(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func prepareGRCKPIDocument(metrics []attackerMetric, catalog riskCatalog, evidence kpiEvidenceState, lifecycle grcKPILifecycleCounts) (*GRCKPIDocument, error) {
	document := buildGRCKPIDocument(metrics, catalog, evidence, lifecycle)
	document.Status = kpiEvidenceQualityDegraded
	if _, err := marshalGRCKPIDocument(document); err == nil {
		return &document, nil
	} else {
		fallback := safeDegradedGRCKPIDocument(document.Catalog)
		if _, fallbackErr := marshalGRCKPIDocument(fallback); fallbackErr != nil {
			return nil, fmt.Errorf("validate GRC KPI document: %v; validate fallback: %w", err, fallbackErr)
		}
		return &fallback, fmt.Errorf("validate GRC KPI document: %w", err)
	}
}

func prepareGRCKPIDocumentWithRuntime(
	metrics []attackerMetric,
	catalog riskCatalog,
	evidence kpiEvidenceState,
	lifecycle grcKPILifecycleCounts,
	runtimeView runtimeEnforcementView,
	states map[string]string,
) (*GRCKPIDocument, error) {
	document := buildGRCKPIDocumentWithRuntime(metrics, catalog, evidence, lifecycle, runtimeView, states)
	if _, err := marshalGRCKPIDocument(document); err == nil {
		return &document, nil
	} else {
		fallback := safeDegradedGRCKPIDocument(document.Catalog)
		if _, fallbackErr := marshalGRCKPIDocument(fallback); fallbackErr != nil {
			return nil, fmt.Errorf("validate GRC KPI document: %v; validate fallback: %w", err, fallbackErr)
		}
		return &fallback, fmt.Errorf("validate GRC KPI document: %w", err)
	}
}

func safeDegradedGRCKPIDocument(catalog GRCKPICatalog) GRCKPIDocument {
	if _, err := validateGRCCatalog(catalog, true); err != nil {
		catalog = GRCKPICatalog{}
	}
	return GRCKPIDocument{
		SchemaVersion: grcKPISchemaVersion,
		Status:        kpiEvidenceQualityDegraded,
		Window:        GRCKPIWindow{Scope: metricScopeRetainedTail, Complete: false},
		Catalog:       catalog,
		Lifecycle:     GRCKPILifecycle{Scope: "observed-telemetry-records-only", RuntimeStateLinked: false},
		Records:       []GRCKPIRecord{},
	}
}

func marshalGRCKPIDocument(document GRCKPIDocument) ([]byte, error) {
	if err := validateGRCKPIDocument(document); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxGRCKPIJSONBytes {
		return nil, fmt.Errorf("GRC KPI document exceeds %d bytes", maxGRCKPIJSONBytes)
	}
	return wire, nil
}

func decodeGRCKPIDocument(wire []byte) (GRCKPIDocument, error) {
	if len(wire) == 0 || len(wire) > maxGRCKPIJSONBytes {
		return GRCKPIDocument{}, fmt.Errorf("GRC KPI document exceeds bounds")
	}
	if err := rejectDuplicateJSONKeys(wire); err != nil {
		return GRCKPIDocument{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(wire), maxGRCKPIJSONBytes+1))
	decoder.DisallowUnknownFields()
	var document GRCKPIDocument
	if err := decoder.Decode(&document); err != nil {
		return GRCKPIDocument{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return GRCKPIDocument{}, fmt.Errorf("GRC KPI document has trailing JSON")
	}
	if err := validateGRCKPIDocument(document); err != nil {
		return GRCKPIDocument{}, err
	}
	return document, nil
}

func validateGRCKPIDocument(document GRCKPIDocument) error {
	if document.SchemaVersion != grcKPISchemaVersion ||
		(document.Status != kpiEvidenceQualityComplete && document.Status != kpiEvidenceQualityDegraded) ||
		document.Records == nil || len(document.Records) > maxGRCKPIRecords || document.Evidence.JournalBytesTotal < 0 ||
		document.Evidence.JournalBytesScanned < 0 || document.Evidence.JournalBytesScanned > document.Evidence.JournalBytesTotal ||
		document.Evidence.JournalDecodeErrors < 0 || document.Evidence.AdmittedEvents < 0 ||
		document.Evidence.RejectedEvents < 0 || document.Evidence.ExcludedEvents < 0 || document.Evidence.RecordsTruncated < 0 {
		return fmt.Errorf("invalid GRC KPI document metadata")
	}
	globalCatalogPresent, err := validateGRCCatalog(document.Catalog, document.Status == kpiEvidenceQualityDegraded)
	if err != nil {
		return fmt.Errorf("invalid GRC KPI catalog identity: %w", err)
	}
	if document.Window.Complete {
		if document.Evidence.JournalBytesScanned != document.Evidence.JournalBytesTotal || document.Window.Scope != metricScopeRetained {
			return fmt.Errorf("complete GRC KPI window has an invalid scope")
		}
	} else if document.Window.Scope != metricScopeRetainedTail {
		return fmt.Errorf("partial GRC KPI window has an invalid scope")
	}
	if document.Lifecycle.DeletionRecords < 0 || document.Lifecycle.ExpiryRecords < 0 || document.Lifecycle.TombstoneRecords < 0 {
		return fmt.Errorf("invalid GRC KPI lifecycle evidence")
	}
	if err := validateGRCRuntimeLifecycle(document.Lifecycle); err != nil {
		return err
	}
	excludedEvents := uint64(document.Evidence.ExcludedEvents)
	lifecycleTotal := uint64(document.Lifecycle.DeletionRecords)
	if lifecycleTotal > excludedEvents || uint64(document.Lifecycle.ExpiryRecords) > excludedEvents-lifecycleTotal {
		return fmt.Errorf("GRC KPI lifecycle evidence exceeds excluded events")
	}
	lifecycleTotal += uint64(document.Lifecycle.ExpiryRecords)
	if uint64(document.Lifecycle.TombstoneRecords) > excludedEvents-lifecycleTotal {
		return fmt.Errorf("GRC KPI lifecycle evidence exceeds excluded events")
	}
	if document.Evidence.RecordsTruncated > 0 && len(document.Records) != maxGRCKPIRecords {
		return fmt.Errorf("GRC KPI truncation evidence is inconsistent")
	}

	seenIPs := make(map[string]struct{}, len(document.Records))
	var firstWindow time.Time
	var lastWindow time.Time
	var previous *GRCKPIRecord
	var previousLast time.Time
	var admittedHits uint64
	allRecordsComplete := true
	allRuntimeStatesExact := true
	for index, record := range document.Records {
		address, addressErr := netip.ParseAddr(record.IP)
		first, firstErr := parseCanonicalGRCTimestamp(record.FirstObserved)
		last, lastErr := parseCanonicalGRCTimestamp(record.LastObserved)
		if record.IP == "" || record.PhysicalHits <= 0 || record.JailHits <= 0 || record.JailHits > record.PhysicalHits ||
			record.PolicyHits <= 0 || record.PolicyHits > record.JailHits ||
			!validGRCText(record.SelectedJail, 256) || record.SeverityScore < 0 || record.SeverityScore > 100 ||
			addressErr != nil || address.Zone() != "" || address.Unmap().String() != record.IP || firstErr != nil || lastErr != nil || last.Before(first) {
			return fmt.Errorf("invalid GRC KPI record %d", index)
		}
		if _, duplicate := seenIPs[record.IP]; duplicate {
			return fmt.Errorf("duplicate GRC KPI IP at record %d", index)
		}
		seenIPs[record.IP] = struct{}{}
		if record.SeverityLabel != riskSeverityLabel(record.SeverityScore) || !validRiskCategory(record.RiskCategory) ||
			!validRuleAction(record.PolicyAction) || !validGRCMetricQuality(record.MetricQuality) ||
			!validGRCPolicyQuality(record.PolicyQuality) || !validGRCHitQuality(record.HitQuality) ||
			!validGRCHitEvidence(record.HitEvidence) || !validGRCEnforcementState(record.EnforcementState, document.Lifecycle.RuntimeStateLinked) ||
			record.DegradedHits < 0 || record.DegradedHits > record.PhysicalHits {
			return fmt.Errorf("invalid GRC KPI risk evidence at record %d", index)
		}
		if err := validateGRCQualityConsistency(record); err != nil {
			return fmt.Errorf("invalid GRC KPI quality evidence at record %d: %w", index, err)
		}
		if err := validateGRCPolicyEvidence(record); err != nil {
			return fmt.Errorf("invalid GRC KPI policy evidence at record %d: %w", index, err)
		}
		recordCatalogPresent, catalogErr := validateGRCCatalog(record.Catalog, record.PolicyQuality == metricQualityLegacy)
		if catalogErr != nil {
			return fmt.Errorf("invalid GRC KPI record catalog %d: %w", index, catalogErr)
		}
		if record.PolicyQuality == metricQualityLegacy && recordCatalogPresent {
			return fmt.Errorf("legacy GRC KPI policy carries an attested catalog at record %d", index)
		}
		if record.PolicyQuality != metricQualityLegacy && !recordCatalogPresent {
			return fmt.Errorf("verified GRC KPI policy lacks a catalog at record %d", index)
		}
		if record.MetricQuality == metricQualityAttested && record.PolicyQuality != metricQualityAttested ||
			record.MetricQuality == metricQualityRecorded && record.PolicyQuality != metricQualityRecorded ||
			record.MetricQuality == metricQualityLegacy && record.PolicyQuality != metricQualityLegacy {
			return fmt.Errorf("GRC KPI metric and policy qualities conflict at record %d", index)
		}
		if previous != nil && !grcRecordLess(*previous, previousLast, record, last) {
			return fmt.Errorf("GRC KPI records are not canonically ordered at record %d", index)
		}
		previous = &document.Records[index]
		previousLast = last
		if firstWindow.IsZero() || first.Before(firstWindow) {
			firstWindow = first
		}
		if lastWindow.IsZero() || last.After(lastWindow) {
			lastWindow = last
		}
		physicalHits := uint64(record.PhysicalHits)
		admittedTotal := uint64(document.Evidence.AdmittedEvents)
		if physicalHits > admittedTotal || admittedHits > admittedTotal-physicalHits {
			return fmt.Errorf("GRC KPI physical-hit sum exceeds admitted events at record %d", index)
		}
		admittedHits += physicalHits
		recordComplete := globalCatalogPresent && record.Catalog == document.Catalog &&
			record.MetricQuality == metricQualityAttested && record.PolicyQuality == metricQualityAttested &&
			record.HitQuality == "measured" && record.DegradedHits == 0
		if !recordComplete {
			allRecordsComplete = false
		}
		if document.Lifecycle.RuntimeStateLinked && record.EnforcementState == "unknown" {
			allRuntimeStatesExact = false
		}
	}
	if len(document.Records) == 0 {
		if document.Window.First != "" || document.Window.Last != "" {
			return fmt.Errorf("empty GRC KPI records have a non-empty observation window")
		}
	} else if document.Window.First != firstWindow.UTC().Format(time.RFC3339Nano) ||
		document.Window.Last != lastWindow.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("GRC KPI observation window does not match its records")
	}
	admittedTotal := uint64(document.Evidence.AdmittedEvents)
	if document.Evidence.RecordsTruncated == 0 {
		if admittedHits != admittedTotal {
			return fmt.Errorf("GRC KPI physical-hit sum does not match admitted events")
		}
	} else {
		missingHits := admittedTotal - minUint64(admittedTotal, admittedHits)
		if admittedHits >= admittedTotal || missingHits < uint64(document.Evidence.RecordsTruncated) {
			return fmt.Errorf("GRC KPI truncated physical-hit sum is inconsistent")
		}
	}
	runtimeEvidenceComplete := completeGRCRuntimeLifecycle(document.Lifecycle)
	completeEvidence := globalCatalogPresent && document.Window.Complete && document.Window.Scope == metricScopeRetained &&
		document.Evidence.JournalDecodeErrors == 0 && document.Evidence.RejectedEvents == 0 &&
		document.Evidence.RecordsTruncated == 0 && allRecordsComplete && runtimeEvidenceComplete && allRuntimeStatesExact
	if document.Status == kpiEvidenceQualityComplete && !completeEvidence {
		return fmt.Errorf("GRC KPI document over-declares complete evidence")
	}
	return nil
}

func validateGRCRuntimeLifecycle(lifecycle GRCKPILifecycle) error {
	if lifecycle.Scope == "local-native-runtime-snapshot" {
		return validateGRCLocalRuntimeLifecycle(lifecycle)
	}
	if lifecycle.RuntimeLocalSnapshot != nil {
		return fmt.Errorf("local native evidence cannot be attached to another lifecycle scope")
	}
	if !lifecycle.RuntimeStateLinked {
		if lifecycle.Scope != "observed-telemetry-records-only" || lifecycle.RuntimeSnapshotComplete ||
			lifecycle.RuntimeSnapshotTruncated || lifecycle.RuntimeClusterID != "" || lifecycle.RuntimeEpoch != 0 || lifecycle.RuntimeNodeID != "" ||
			lifecycle.RuntimeRole != "" || lifecycle.RuntimeCoordination != "" ||
			lifecycle.RuntimeModelSHA256 != "" || lifecycle.RuntimeCheckpointSHA256 != "" || lifecycle.RuntimePeerCheckpointSHA256 != "" ||
			lifecycle.RuntimeCheckpointAt != "" || lifecycle.RuntimeCapturedAt != "" ||
			lifecycle.ActiveClaims != 0 || lifecycle.ExpiredClaims != 0 || lifecycle.DeletedClaims != 0 || lifecycle.TombstonedClaims != 0 {
			return fmt.Errorf("invalid unlinked GRC KPI runtime evidence")
		}
		return nil
	}
	if lifecycle.Scope != "ha-v2-runtime-snapshot" || lifecycle.RuntimeSnapshotComplete == lifecycle.RuntimeSnapshotTruncated ||
		!runtimeEnforcementIDPattern.MatchString(lifecycle.RuntimeClusterID) || lifecycle.RuntimeEpoch == 0 ||
		!runtimeEnforcementIDPattern.MatchString(lifecycle.RuntimeNodeID) ||
		(lifecycle.RuntimeRole != "writer" && lifecycle.RuntimeRole != "standby") {
		return fmt.Errorf("invalid linked GRC KPI runtime evidence")
	}
	switch lifecycle.RuntimeCoordination {
	case "healthy", "degraded", "fenced", "recovering":
	default:
		return fmt.Errorf("invalid GRC KPI runtime coordination evidence")
	}
	if len(lifecycle.RuntimeModelSHA256) != 64 || strings.ToLower(lifecycle.RuntimeModelSHA256) != lifecycle.RuntimeModelSHA256 {
		return fmt.Errorf("invalid GRC KPI runtime model digest")
	}
	if _, err := hex.DecodeString(lifecycle.RuntimeModelSHA256); err != nil {
		return fmt.Errorf("invalid GRC KPI runtime model digest")
	}
	if len(lifecycle.RuntimeCheckpointSHA256) != 64 || strings.ToLower(lifecycle.RuntimeCheckpointSHA256) != lifecycle.RuntimeCheckpointSHA256 {
		return fmt.Errorf("invalid GRC KPI runtime checkpoint digest")
	}
	if _, err := hex.DecodeString(lifecycle.RuntimeCheckpointSHA256); err != nil {
		return fmt.Errorf("invalid GRC KPI runtime checkpoint digest")
	}
	if lifecycle.RuntimePeerCheckpointSHA256 != "" {
		if len(lifecycle.RuntimePeerCheckpointSHA256) != 64 || strings.ToLower(lifecycle.RuntimePeerCheckpointSHA256) != lifecycle.RuntimePeerCheckpointSHA256 {
			return fmt.Errorf("invalid GRC KPI peer runtime checkpoint digest")
		}
		if _, err := hex.DecodeString(lifecycle.RuntimePeerCheckpointSHA256); err != nil {
			return fmt.Errorf("invalid GRC KPI peer runtime checkpoint digest")
		}
	}
	if lifecycle.RuntimeCoordination == "healthy" && lifecycle.RuntimePeerCheckpointSHA256 != lifecycle.RuntimeCheckpointSHA256 {
		return fmt.Errorf("healthy GRC KPI runtime checkpoints diverge")
	}
	checkpointAt, err := parseCanonicalGRCTimestamp(lifecycle.RuntimeCheckpointAt)
	if err != nil {
		return fmt.Errorf("invalid GRC KPI runtime checkpoint time")
	}
	capturedAt, err := parseCanonicalGRCTimestamp(lifecycle.RuntimeCapturedAt)
	if err != nil {
		return fmt.Errorf("invalid GRC KPI runtime capture time")
	}
	if err := validateRuntimeCheckpointTiming(checkpointAt, capturedAt, lifecycle.RuntimeCoordination); err != nil {
		return fmt.Errorf("invalid GRC KPI runtime checkpoint timing: %w", err)
	}
	counts := []int{lifecycle.ActiveClaims, lifecycle.ExpiredClaims, lifecycle.DeletedClaims, lifecycle.TombstonedClaims}
	total := 0
	for _, count := range counts {
		if count < 0 || count > maximumHAReplicationClaims || total > maximumHAReplicationClaims-count {
			return fmt.Errorf("GRC KPI runtime claim counts are outside bounds")
		}
		total += count
	}
	return nil
}

func validGRCEnforcementState(state string, runtimeLinked bool) bool {
	if state == "" {
		return !runtimeLinked
	}
	switch state {
	case "active", "expired", "deleted", "tombstoned", "absent", "unknown":
		return true
	default:
		return false
	}
}

func validateGRCCatalog(catalog GRCKPICatalog, allowEmpty bool) (bool, error) {
	empty := catalog == (GRCKPICatalog{})
	if empty {
		if allowEmpty {
			return false, nil
		}
		return false, fmt.Errorf("catalog is absent")
	}
	if catalog.Version == "" || catalog.SHA256 == "" || catalog.RiskModelVersion == "" {
		return false, fmt.Errorf("catalog identity is partial")
	}
	if !validGRCText(catalog.Version, 128) || catalog.RiskModelVersion != defaultRiskModelVersion ||
		len(catalog.SHA256) != 64 || strings.ToLower(catalog.SHA256) != catalog.SHA256 {
		return false, fmt.Errorf("catalog identity is not canonical")
	}
	if _, err := hex.DecodeString(catalog.SHA256); err != nil {
		return false, fmt.Errorf("catalog digest is invalid")
	}
	return true, nil
}

func parseCanonicalGRCTimestamp(value string) (time.Time, error) {
	if len(value) == 0 || len(value) > 64 || !strings.HasSuffix(value, "Z") {
		return time.Time{}, fmt.Errorf("timestamp is not canonical UTC")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("timestamp is not canonical UTC")
	}
	return parsed, nil
}

func validGRCText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validGRCMetricQuality(quality string) bool {
	return quality == metricQualityAttested || quality == metricQualityRecorded ||
		quality == metricQualityMixed || quality == metricQualityLegacy
}

func validGRCPolicyQuality(quality string) bool {
	return quality == metricQualityAttested || quality == metricQualityRecorded || quality == metricQualityLegacy
}

func validGRCHitQuality(quality string) bool {
	return quality == "measured" || quality == "degraded" || quality == metricQualityMixed || quality == metricQualityLegacy
}

func validGRCHitEvidence(evidence string) bool {
	switch evidence {
	case "collector-content-window-v1", "collector-content-window-degraded-v1",
		"kernel-log-observation-v1", "kernel-log-observation-degraded-v1",
		metricQualityMixed, metricQualityLegacy:
		return true
	default:
		return false
	}
}

func validateGRCQualityConsistency(record GRCKPIRecord) error {
	switch record.HitQuality {
	case "measured":
		if record.DegradedHits != 0 || record.HitEvidence == metricQualityLegacy || strings.Contains(record.HitEvidence, "degraded") {
			return fmt.Errorf("measured hits carry degraded or legacy evidence")
		}
	case "degraded":
		if record.DegradedHits == 0 || !(record.HitEvidence == metricQualityMixed || strings.Contains(record.HitEvidence, "degraded")) {
			return fmt.Errorf("degraded hits lack degraded evidence")
		}
	case metricQualityMixed:
		if record.HitEvidence != metricQualityMixed {
			return fmt.Errorf("mixed hit quality lacks mixed evidence")
		}
	case metricQualityLegacy:
		if record.DegradedHits != 0 || record.HitEvidence != metricQualityLegacy {
			return fmt.Errorf("legacy hit quality conflicts with evidence")
		}
	}
	return nil
}

func validateGRCPolicyEvidence(record GRCKPIRecord) error {
	if (record.Enforcement.Jail == "") != (record.Enforcement.Action == "") {
		return fmt.Errorf("enforcement identity is partial")
	}
	if record.Enforcement.Jail != "" && (!validGRCText(record.Enforcement.Jail, 256) || !validRuleAction(record.Enforcement.Action)) {
		return fmt.Errorf("enforcement identity is invalid")
	}
	if record.PolicyQuality == metricQualityLegacy {
		if record.Enforcement != (GRCKPIEnforcement{}) {
			return fmt.Errorf("legacy policy over-declares enforcement evidence")
		}
	} else if record.Enforcement == (GRCKPIEnforcement{}) {
		return fmt.Errorf("verified policy lacks enforcement evidence")
	}
	if record.PeakWindowHits < 0 || record.PeakWindowHits > record.PolicyHits || record.EffectiveThreshold <= 0 ||
		record.EffectiveThreshold > 1_000_000_000 || record.EffectiveWindowSeconds < 0 ||
		record.EffectiveWindowSeconds > 31_536_000 {
		return fmt.Errorf("policy counters are invalid")
	}
	switch record.PolicyAction {
	case "ban", "detect":
		if record.EffectiveThreshold != 1 || record.EffectiveWindowSeconds != 0 || record.PeakWindowHits != 0 ||
			!record.ThresholdReached || record.ThresholdEvidence != "immediate-rule" {
			return fmt.Errorf("immediate policy evidence is inconsistent")
		}
	case "track":
		if record.EffectiveWindowSeconds <= 0 {
			return fmt.Errorf("tracked policy lacks a positive window")
		}
		switch record.ThresholdEvidence {
		case "observed-window":
			if !record.ThresholdReached || record.PeakWindowHits < record.EffectiveThreshold {
				return fmt.Errorf("observed threshold evidence is inconsistent")
			}
		case "decision-event":
			if !record.ThresholdReached || record.PeakWindowHits >= record.EffectiveThreshold {
				return fmt.Errorf("decision threshold evidence is inconsistent")
			}
		case "none":
			if record.ThresholdReached || record.PeakWindowHits >= record.EffectiveThreshold {
				return fmt.Errorf("absent threshold evidence is inconsistent")
			}
		default:
			return fmt.Errorf("threshold evidence is unsupported")
		}
	}
	profile := riskProfile{
		category: record.RiskCategory, action: record.PolicyAction,
		threshold: record.EffectiveThreshold, windowSeconds: record.EffectiveWindowSeconds,
	}
	expectedScore := calculateRiskScore(profile, record.PolicyHits, record.PeakWindowHits, record.ThresholdReached)
	if record.SeverityScore != expectedScore {
		return fmt.Errorf("severity score does not match admitted policy evidence")
	}
	return nil
}

func grcRecordLess(left GRCKPIRecord, leftLast time.Time, right GRCKPIRecord, rightLast time.Time) bool {
	if left.PhysicalHits != right.PhysicalHits {
		return left.PhysicalHits > right.PhysicalHits
	}
	if left.SeverityScore != right.SeverityScore {
		return left.SeverityScore > right.SeverityScore
	}
	if !leftLast.Equal(rightLast) {
		return leftLast.After(rightLast)
	}
	return left.IP < right.IP
}

func minUint64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}
