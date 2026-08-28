package telemetry

import (
	"bufio"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"syswarden-core/internal/runtimepaths"
	"syswarden-core/utils"

	"github.com/spf13/viper"
)

type FirewallManager interface {
	Ban(ip string) error
}

// RuleEvidence carries the exact policy and observation time used by a
// non-signature producer. The main package converts it to the logger's rule
// context without creating a telemetry/logger import cycle.
type RuleEvidence struct {
	RuleID                  string
	RiskCategory            string
	RuleAction              string
	EffectiveThreshold      int
	EffectiveWindowSeconds  int
	SignatureCatalogVersion string
	SignatureCatalogSHA256  string
	RiskModelVersion        string
	MetricEligible          bool
	ObservedAt              time.Time
	ObservationModel        string
	ObservationDisposition  string
}

type ruleEvidenceLogger func(ip, jail, payload string, evidence RuleEvidence)

const (
	kernelRuleCatalogVersion = "sw-kernel-signals-v1"
)

type kernelRuleProfile struct {
	ruleID        string
	riskCategory  string
	ruleAction    string
	threshold     int
	windowSeconds int
}

var kernelRuleProfiles = []kernelRuleProfile{
	{ruleID: "L2-ARP-FLOOD", riskCategory: "denial_of_service", ruleAction: "detect", threshold: 1},
	{ruleID: "L3-HONEYPORT-SCAN", riskCategory: "reconnaissance", ruleAction: "ban", threshold: 1},
	{ruleID: "L3-PORTSCAN", riskCategory: "reconnaissance", ruleAction: "track", threshold: 3, windowSeconds: 60},
}

var kernelRuleCatalogWire = func() string {
	var wire strings.Builder
	for _, profile := range kernelRuleProfiles {
		_, _ = fmt.Fprintf(&wire, "%s|%s|%s|%d|%d\n", profile.ruleID, profile.riskCategory, profile.ruleAction, profile.threshold, profile.windowSeconds)
	}
	return wire.String()
}()

var kernelRuleCatalogSHA256 = func() string {
	digest := sha256.Sum256([]byte(kernelRuleCatalogWire))
	return hex.EncodeToString(digest[:])
}()

type Service struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Status string `json:"status"`
}

type Port struct {
	IP       string `json:"ip"`
	State    string `json:"state"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type SystemData struct {
	Hostname    string    `json:"hostname"`
	Uptime      string    `json:"uptime"`
	LoadAverage string    `json:"load_average"`
	RamUsedMb   int       `json:"ram_used_mb"`
	RamTotalMb  int       `json:"ram_total_mb"`
	DiskUsedMb  int       `json:"disk_used_mb"`
	DiskTotalMb int       `json:"disk_total_mb"`
	Cores       string    `json:"cores"`
	Arch        string    `json:"arch"`
	Os          string    `json:"os"`
	CpuModel    string    `json:"cpu_model"`
	ServerIP    string    `json:"server_ip"`
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
}

type platformSystemStats struct {
	Uptime      string
	LoadAverage string
	RamUsedMb   int
	RamTotalMb  int
	CpuModel    string
}

type Layer3 struct {
	GlobalBlocked int  `json:"global_blocked"`
	GeoIPBlocked  int  `json:"geoip_blocked"`
	ASNBlocked    int  `json:"asn_blocked"`
	L7Banned      int  `json:"l7_banned"`
	ZeroTrustMode bool `json:"zero_trust_mode"`
}

type JailData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Mitre string `json:"mitre"`
}

type AllowedEvent struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Service   string `json:"service"`
	Payload   string `json:"payload"`
}

type BannedIP struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
	Mitre     string `json:"mitre"`
	Action    string `json:"action"`
}

type Attacker struct {
	IP                      string `json:"ip"`
	Severity                string `json:"severity"`
	Port                    string `json:"port"`
	Country                 string `json:"country"`
	ASN                     string `json:"asn"`
	Threat                  string `json:"threat"`
	Org                     string `json:"org"`
	Hits                    int    `json:"hits"`
	LastSeen                string `json:"last_seen"`
	FirstSeen               string `json:"first_seen,omitempty"`
	PrimaryJail             string `json:"primary_jail,omitempty"`
	EnforcementJail         string `json:"enforcement_jail,omitempty"`
	EnforcementAction       string `json:"enforcement_action,omitempty"`
	JailHits                int    `json:"jail_hits,omitempty"`
	PolicyHits              int    `json:"policy_hits,omitempty"`
	AttestedHits            int    `json:"attested_hits,omitempty"`
	RecordedHits            int    `json:"recorded_hits,omitempty"`
	LegacyHits              int    `json:"legacy_hits,omitempty"`
	RiskCategory            string `json:"risk_category,omitempty"`
	SeverityScore           int    `json:"severity_score,omitempty"`
	PeakWindowHits          int    `json:"peak_window_hits,omitempty"`
	EffectiveThreshold      int    `json:"effective_threshold,omitempty"`
	EffectiveWindowSeconds  *int   `json:"effective_window_seconds,omitempty"`
	MetricQuality           string `json:"metric_quality,omitempty"`
	SelectedPolicyQuality   string `json:"selected_policy_quality,omitempty"`
	ThresholdReached        *bool  `json:"threshold_reached,omitempty"`
	ThresholdEvidence       string `json:"threshold_evidence,omitempty"`
	MetricScope             string `json:"metric_scope,omitempty"`
	HitEvidence             string `json:"hit_evidence,omitempty"`
	HitQuality              string `json:"hit_quality,omitempty"`
	DegradedHits            int    `json:"degraded_hits,omitempty"`
	RiskModelVersion        string `json:"risk_model_version,omitempty"`
	SignatureCatalogVersion string `json:"signature_catalog_version,omitempty"`
	SignatureCatalogSHA256  string `json:"signature_catalog_sha256,omitempty"`
}

type TargetedPort struct {
	Port      string `json:"port"`
	Service   string `json:"service"`
	Hits      int    `json:"hits"`
	UniqueIPs int    `json:"unique_ips"`
}

type WAF struct {
	TotalBanned          int            `json:"total_banned"`
	TotalDetected        int            `json:"total_detected"`
	ActiveSignatures     int            `json:"active_signatures"`
	KPIEvidenceQuality   string         `json:"kpi_evidence_quality,omitempty"`
	JournalScanComplete  *bool          `json:"journal_scan_complete,omitempty"`
	JournalBytesTotal    *int64         `json:"journal_bytes_total,omitempty"`
	JournalBytesScanned  *int64         `json:"journal_bytes_scanned,omitempty"`
	JournalDecodeErrors  *int           `json:"journal_decode_errors,omitempty"`
	MetricRejectedEvents *int           `json:"metric_rejected_events,omitempty"`
	MetricExcludedEvents *int           `json:"metric_excluded_events,omitempty"`
	MetricAdmittedEvents *int           `json:"metric_admitted_events,omitempty"`
	SignaturesData       []JailData     `json:"signatures_data"`
	TargetedPorts        []TargetedPort `json:"targeted_ports"`
	BannedIPs            []BannedIP     `json:"banned_ips"`
	TopAttackers         []Attacker     `json:"top_attackers"`
	RiskRadar            []int          `json:"risk_radar"`
	Sparkline24h         [24]int        `json:"sparkline_24h"`
	AllowedEvents        []AllowedEvent `json:"allowed_events"`
}

const (
	kpiEvidenceQualityComplete = "complete"
	kpiEvidenceQualityDegraded = "degraded"
	kpiEvidenceDegradedLog     = "[Telemetry Worker] KPI evidence degraded: catalog_available=%t journal_scan_complete=%t journal_bytes_scanned=%d journal_bytes_total=%d journal_decode_errors=%d metric_rejected_events=%d metric_excluded_events=%d metric_admitted_events=%d"
	maxKPIJournalScanBytes     = int64(16 * 1024 * 1024)
)

type kpiEvidenceState struct {
	catalogAvailable     bool
	journalScanComplete  bool
	journalBytesTotal    int64
	journalBytesScanned  int64
	journalDecodeErrors  int
	metricRejectedEvents int
	metricExcludedEvents int
	metricAdmittedEvents int
}

func (state kpiEvidenceState) quality() string {
	if !state.catalogAvailable || !state.journalScanComplete || state.journalDecodeErrors > 0 || state.metricRejectedEvents > 0 ||
		state.journalBytesTotal < 0 || state.journalBytesScanned < 0 ||
		state.journalBytesScanned > state.journalBytesTotal ||
		state.journalScanComplete && state.journalBytesScanned != state.journalBytesTotal {
		return kpiEvidenceQualityDegraded
	}
	return kpiEvidenceQualityComplete
}

func (state kpiEvidenceState) apply(waf *WAF) {
	if waf == nil {
		return
	}
	waf.KPIEvidenceQuality = state.quality()
	journalScanComplete := state.journalScanComplete
	journalBytesTotal := state.journalBytesTotal
	journalBytesScanned := state.journalBytesScanned
	journalDecodeErrors := state.journalDecodeErrors
	metricRejectedEvents := state.metricRejectedEvents
	metricExcludedEvents := state.metricExcludedEvents
	metricAdmittedEvents := state.metricAdmittedEvents
	waf.JournalScanComplete = &journalScanComplete
	waf.JournalBytesTotal = &journalBytesTotal
	waf.JournalBytesScanned = &journalBytesScanned
	waf.JournalDecodeErrors = &journalDecodeErrors
	waf.MetricRejectedEvents = &metricRejectedEvents
	waf.MetricExcludedEvents = &metricExcludedEvents
	waf.MetricAdmittedEvents = &metricAdmittedEvents
}

func (state kpiEvidenceState) logDegraded() {
	if state.quality() != kpiEvidenceQualityDegraded {
		return
	}
	log.Printf(
		kpiEvidenceDegradedLog,
		state.catalogAvailable,
		state.journalScanComplete,
		state.journalBytesScanned,
		state.journalBytesTotal,
		state.journalDecodeErrors,
		state.metricRejectedEvents,
		state.metricExcludedEvents,
		state.metricAdmittedEvents,
	)
}

type kpiJournalSnapshot struct {
	totalBytes   int64
	scannedBytes int64
	complete     bool
}

type kpiJournalSource struct {
	path     string
	file     *os.File
	identity os.FileInfo
}

type kpiJournalWindow struct {
	sources            []kpiJournalSource
	previousPath       string
	previousWasMissing bool
	readers            []*kpiJournalReader
	snapshot           kpiJournalSnapshot
}

type kpiJournalReader struct {
	reader   io.Reader
	consumed int64
}

func (reader *kpiJournalReader) Read(buffer []byte) (int, error) {
	if reader == nil || reader.reader == nil {
		return 0, io.EOF
	}
	count, err := reader.reader.Read(buffer)
	reader.consumed += int64(count)
	return count, err
}

func prepareKPIJournalSegment(file *os.File, totalBytes, maxBytes int64) (io.Reader, int64, bool, error) {
	if file == nil || totalBytes < 0 || maxBytes <= 0 {
		return nil, 0, false, fmt.Errorf("invalid KPI journal segment")
	}
	start := int64(0)
	complete := true
	if totalBytes > maxBytes {
		start = totalBytes - maxBytes
		complete = false
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, 0, false, fmt.Errorf("seek KPI journal snapshot: %w", err)
	}
	limited := &io.LimitedReader{R: file, N: totalBytes - start}
	reader := bufio.NewReader(limited)
	if start > 0 {
		if _, err := file.Seek(start-1, io.SeekStart); err != nil {
			return nil, 0, false, fmt.Errorf("inspect KPI journal record boundary: %w", err)
		}
		var previous [1]byte
		if _, err := io.ReadFull(file, previous[:]); err != nil {
			return nil, 0, false, fmt.Errorf("read KPI journal record boundary: %w", err)
		}
		if _, err := file.Seek(start, io.SeekStart); err != nil {
			return nil, 0, false, fmt.Errorf("restore KPI journal snapshot offset: %w", err)
		}
		limited = &io.LimitedReader{R: file, N: totalBytes - start}
		reader = bufio.NewReader(limited)
		if previous[0] != '\n' {
			discarded, discardErr := reader.ReadBytes('\n')
			start += int64(len(discarded))
			if discardErr != nil && discardErr != io.EOF {
				return nil, 0, false, fmt.Errorf("align KPI journal snapshot: %w", discardErr)
			}
		}
	}
	return reader, totalBytes - start, complete, nil
}

// openKPIJournalSnapshot bounds CPU and memory exposure to an attacker-grown
// telemetry journal. If the retained file exceeds maxBytes, the reader starts
// at the next complete NDJSON record and callers must expose the result as a
// partial tail scope rather than a complete historical metric.
func openKPIJournalSnapshot(path string, maxBytes int64) (*os.File, *kpiJournalReader, kpiJournalSnapshot, error) {
	if maxBytes <= 0 {
		return nil, nil, kpiJournalSnapshot{}, fmt.Errorf("KPI journal scan limit must be positive")
	}
	file, err := os.Open(path) // #nosec G304 -- fixed production path or test-owned path
	if err != nil {
		return nil, nil, kpiJournalSnapshot{}, err
	}
	fail := func(err error) (*os.File, *kpiJournalReader, kpiJournalSnapshot, error) {
		_ = file.Close()
		return nil, nil, kpiJournalSnapshot{}, err
	}
	info, err := file.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect KPI journal: %w", err))
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return fail(fmt.Errorf("KPI journal must be a regular file"))
	}

	reader, scannedBytes, complete, err := prepareKPIJournalSegment(file, info.Size(), maxBytes)
	if err != nil {
		return fail(err)
	}
	return file, &kpiJournalReader{reader: reader}, kpiJournalSnapshot{
		totalBytes:   info.Size(),
		scannedBytes: scannedBytes,
		complete:     complete,
	}, nil
}

func openKPIJournalWindow(activePath string, maxBytes int64) (*kpiJournalWindow, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("KPI journal scan limit must be positive")
	}
	window := &kpiJournalWindow{previousPath: activePath + ".1"}
	closeOnFailure := func(err error) (*kpiJournalWindow, error) {
		_ = window.Close()
		return nil, err
	}
	for _, candidate := range []struct {
		path     string
		optional bool
	}{
		{path: window.previousPath, optional: true},
		{path: activePath},
	} {
		file, err := os.Open(candidate.path) // #nosec G304 -- fixed production path or test-owned path
		if err != nil {
			if candidate.optional && errors.Is(err, os.ErrNotExist) {
				window.previousWasMissing = true
				continue
			}
			return closeOnFailure(err)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
			_ = file.Close()
			if err == nil {
				err = fmt.Errorf("KPI journal generation must be a regular file")
			}
			return closeOnFailure(err)
		}
		window.sources = append(window.sources, kpiJournalSource{path: candidate.path, file: file, identity: info})
	}
	if len(window.sources) == 0 || window.sources[len(window.sources)-1].path != activePath {
		return closeOnFailure(fmt.Errorf("active KPI journal is unavailable"))
	}

	allocations := make([]int64, len(window.sources))
	remaining := maxBytes
	for index := len(window.sources) - 1; index >= 0 && remaining > 0; index-- {
		size := window.sources[index].identity.Size()
		allocation := size
		if allocation > remaining {
			allocation = remaining
		}
		allocations[index] = allocation
		remaining -= allocation
	}
	totalBytes := int64(0)
	scannedBytes := int64(0)
	for index, source := range window.sources {
		totalBytes += source.identity.Size()
		if allocations[index] == 0 {
			continue
		}
		reader, scanned, _, err := prepareKPIJournalSegment(source.file, source.identity.Size(), allocations[index])
		if err != nil {
			return closeOnFailure(err)
		}
		window.readers = append(window.readers, &kpiJournalReader{reader: reader})
		scannedBytes += scanned
	}
	window.snapshot = kpiJournalSnapshot{
		totalBytes:   totalBytes,
		scannedBytes: scannedBytes,
		complete:     totalBytes <= maxBytes,
	}
	return window, nil
}

func (window *kpiJournalWindow) consumedBytes() int64 {
	if window == nil {
		return 0
	}
	consumed := int64(0)
	for _, reader := range window.readers {
		consumed += reader.consumed
	}
	return consumed
}

func (window *kpiJournalWindow) stable() bool {
	if window == nil {
		return false
	}
	for _, source := range window.sources {
		current, err := os.Lstat(source.path)
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(source.identity, current) {
			return false
		}
	}
	if window.previousWasMissing {
		if _, err := os.Lstat(window.previousPath); !errors.Is(err, os.ErrNotExist) {
			return false
		}
	}
	return true
}

func (window *kpiJournalWindow) Close() error {
	if window == nil {
		return nil
	}
	var closeErrors []error
	for _, source := range window.sources {
		if err := source.file.Close(); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	window.sources = nil
	return errors.Join(closeErrors...)
}

type Whitelist struct {
	ActiveIPs int      `json:"active_ips"`
	IPs       []string `json:"ips"`
}

type DashboardData struct {
	Timestamp     string       `json:"timestamp"`
	GithubStars   string       `json:"github_stars"`
	GithubRelease string       `json:"github_release"`
	ProfileName   string       `json:"profile_name"`
	System        SystemData   `json:"system"`
	Layer3        Layer3       `json:"layer3"`
	WAF           WAF          `json:"waf"`
	Whitelist     Whitelist    `json:"whitelist"`
	HA            *HATelemetry `json:"ha,omitempty"`
}

// TelemetryEvent parses lines from waf.json
type TelemetryEvent struct {
	Action                        string `json:"action"`
	Timestamp                     string `json:"timestamp"`
	IP                            string `json:"ip"`
	Jail                          string `json:"jail"`
	Payload                       string `json:"payload"`
	Severity                      int    `json:"severity,omitempty"`
	RuleID                        string `json:"rule_id,omitempty"`
	RiskCategory                  string `json:"risk_category,omitempty"`
	RuleAction                    string `json:"rule_action,omitempty"`
	EffectiveThreshold            int    `json:"effective_threshold,omitempty"`
	EffectiveWindowSeconds        *int   `json:"effective_window_seconds,omitempty"`
	RiskAttributionRuleID         string `json:"risk_attribution_rule_id,omitempty"`
	RiskAttributionCategory       string `json:"risk_attribution_category,omitempty"`
	RiskAttributionAction         string `json:"risk_attribution_action,omitempty"`
	RiskAttributionThreshold      int    `json:"risk_attribution_threshold,omitempty"`
	RiskAttributionWindowSeconds  *int   `json:"risk_attribution_window_seconds,omitempty"`
	RiskAttributionMetricEligible *bool  `json:"risk_attribution_metric_eligible,omitempty"`
	SignatureCatalogVersion       string `json:"signature_catalog_version,omitempty"`
	SignatureCatalogSHA256        string `json:"signature_catalog_sha256,omitempty"`
	RiskModelVersion              string `json:"risk_model_version,omitempty"`
	MetricEligible                *bool  `json:"metric_eligible,omitempty"`
	ObservationModel              string `json:"observation_model,omitempty"`
	ObservationDisposition        string `json:"observation_disposition,omitempty"`
	RuleAttestationStatus         string `json:"rule_attestation_status,omitempty"`
}

// StartWorker launches the background telemetry generator replacing the cron bash script
func StartWorker(
	ctx context.Context,
	wg *sync.WaitGroup,
	fwManager FirewallManager,
	logAllowed func(ip, service, payload string),
	logBan ruleEvidenceLogger,
	logShadowAlert ruleEvidenceLogger,
	logDetected ruleEvidenceLogger,
) {
	startOSINTEnrichmentWorkers(ctx, wg)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[Telemetry Worker] Started background worker (eliminating cron)")

		// Refresh every 5 seconds to provide near real-time TUI updates
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		generateTelemetry()

		for {
			select {
			case <-ctx.Done():
				log.Println("[Telemetry Worker] Shutting down gracefully...")
				return
			case <-ticker.C:
				generateTelemetry()
			}
		}
	}()

	// Start ALLOWED events monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorAllowedEvents(ctx, logAllowed)
	}()

	// Start ARP Flood & Portscan monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorKernelDrops(ctx, fwManager, logBan, logShadowAlert, logDetected)
	}()
}

func monitorAllowedEvents(ctx context.Context, logAllowed func(ip, service, payload string)) {
	if logAllowed == nil {
		return
	}

	cmd := allowedEventsCommand(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[Telemetry Worker] Failed to start tail for ALLOWED events: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse SSH (Debian/Ubuntu auth.log or RHEL secure)
		if strings.Contains(line, "sshd") && (strings.Contains(line, "Accepted password for") || strings.Contains(line, "Accepted publickey for")) {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "from" && i+1 < len(parts) {
					ip := parts[i+1]
					logAllowed(ip, "sshd", line)
					break
				}
			}
		} else if strings.Contains(line, "HTTP/1.") || strings.Contains(line, "HTTP/2.") {
			// Nginx / Apache access log format
			// 1.2.3.4 - - [date] "GET / HTTP/1.1" 200 ...
			if strings.Contains(line, "\" 200 ") || strings.Contains(line, "\" 201 ") || strings.Contains(line, "\" 204 ") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ip := parts[0]
					logAllowed(ip, "nginx/apache2", line)
				}
			}
		}
	}
	_ = cmd.Wait()
}

type kernelStrikeTracker struct {
	observations  map[string]*kernelStrikeState
	order         *list.List
	limit         int
	degradedUntil time.Time
}

type kernelStrikeState struct {
	times     []time.Time
	lastSeen  time.Time
	orderItem *list.Element
}

const kernelStrikeStateLimit = 16 * 1024

func newKernelStrikeTracker() *kernelStrikeTracker {
	return &kernelStrikeTracker{
		observations: make(map[string]*kernelStrikeState),
		order:        list.New(),
		limit:        kernelStrikeStateLimit,
	}
}

func (tracker *kernelStrikeTracker) observe(key string, observedAt time.Time, threshold int, window time.Duration) (int, bool, bool) {
	if threshold <= 1 {
		return 1, true, false
	}
	tracker.expire(observedAt, window)
	state := tracker.observations[key]
	degraded := false
	if state == nil {
		if tracker.limit <= 0 {
			return 1, false, true
		}
		for len(tracker.observations) >= tracker.limit && tracker.order.Len() > 0 {
			tracker.remove(tracker.order.Front().Value.(string))
			degraded = true
		}
		if degraded {
			tracker.degradedUntil = observedAt.Add(window)
		}
		state = &kernelStrikeState{}
		state.orderItem = tracker.order.PushBack(key)
		tracker.observations[key] = state
	} else {
		tracker.order.MoveToBack(state.orderItem)
	}
	if !tracker.degradedUntil.IsZero() && !observedAt.After(tracker.degradedUntil) {
		degraded = true
	}
	cutoff := observedAt.Add(-window)
	first := 0
	for first < len(state.times) && state.times[first].Before(cutoff) {
		first++
	}
	if first > 0 {
		state.times = append([]time.Time(nil), state.times[first:]...)
	}
	state.times = append(state.times, observedAt)
	state.lastSeen = observedAt
	hits := len(state.times)
	triggered := hits >= threshold
	if triggered {
		tracker.remove(key)
	}
	return hits, triggered, degraded
}

func (tracker *kernelStrikeTracker) expire(observedAt time.Time, window time.Duration) {
	for tracker.order.Len() > 0 {
		key := tracker.order.Front().Value.(string)
		state := tracker.observations[key]
		if state == nil {
			tracker.order.Remove(tracker.order.Front())
			continue
		}
		age := observedAt.Sub(state.lastSeen)
		if age <= window {
			break
		}
		tracker.remove(key)
	}
}

func (tracker *kernelStrikeTracker) remove(key string) {
	state := tracker.observations[key]
	if state == nil {
		return
	}
	tracker.order.Remove(state.orderItem)
	delete(tracker.observations, key)
}

func kernelRuleEvidence(jail string, observedAt time.Time, eligible bool) (RuleEvidence, bool) {
	for _, profile := range kernelRuleProfiles {
		if profile.ruleID != jail {
			continue
		}
		return RuleEvidence{
			RuleID:                  profile.ruleID,
			RiskCategory:            profile.riskCategory,
			RuleAction:              profile.ruleAction,
			EffectiveThreshold:      profile.threshold,
			EffectiveWindowSeconds:  profile.windowSeconds,
			SignatureCatalogVersion: kernelRuleCatalogVersion,
			SignatureCatalogSHA256:  kernelRuleCatalogSHA256,
			RiskModelVersion:        defaultRiskModelVersion,
			MetricEligible:          eligible,
			ObservedAt:              observedAt.UTC(),
			ObservationModel:        "kernel-log-observation-v1",
		}, true
	}
	return RuleEvidence{}, false
}

func monitorKernelDrops(ctx context.Context, fwManager FirewallManager, logBan, logShadowAlert, logDetected ruleEvidenceLogger) {
	if logBan == nil {
		return
	}

	cmd := kernelDropsCommand(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[Telemetry Worker] Failed to start tail for kernel drop events: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	strikes := newKernelStrikeTracker()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		processKernelDropLine(scanner.Text(), time.Now().UTC(), strikes, fwManager, logBan, logShadowAlert, logDetected, utils.IsWhitelisted)
	}
	_ = cmd.Wait()
}

func processKernelDropLine(
	line string,
	observedAt time.Time,
	strikes *kernelStrikeTracker,
	fwManager FirewallManager,
	logBan, logShadowAlert, logDetected ruleEvidenceLogger,
	isWhitelisted func(string) bool,
) {
	if strikes == nil || logBan == nil || isWhitelisted == nil {
		return
	}
	if strings.Contains(line, "[CATCH-ALL]") {
		ip := extractField(line, "SRC=")
		if ip == "" || isWhitelisted(ip) {
			return
		}
		// Port 62026 is owned by the catalogued syswarden-l4-protect rule
		// flowing through the correlated UDS/direct engine. Keeping it out of
		// the kernel producer prevents a second tracker, event and firewall ban.
		if extractField(line, "DPT=") == "62026" && extractField(line, "PROTO=") == "TCP" {
			return
		}
		evidence, _ := kernelRuleEvidence("L3-PORTSCAN", observedAt, true)
		_, triggered, degraded := strikes.observe(ip+"\x00"+evidence.RuleID, observedAt, evidence.EffectiveThreshold, time.Duration(evidence.EffectiveWindowSeconds)*time.Second)
		if degraded {
			evidence.ObservationModel = "kernel-log-observation-degraded-v1"
		}
		if !triggered {
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		if fwManager == nil {
			log.Printf("[Telemetry Worker] Firewall unavailable; recording port-scan detection for %s", ip)
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		if err := fwManager.Ban(ip); err != nil {
			log.Printf("[Telemetry Worker] Firewall rejected port-scan ban for %s: %v", ip, err)
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		logBan(ip, evidence.RuleID, line, evidence)
		return
	}
	if strings.Contains(line, "[SYSWARDEN-HONEYPORT]") {
		ip := extractField(line, "SRC=")
		if ip == "" {
			return
		}
		whitelisted := isWhitelisted(ip)
		evidence, _ := kernelRuleEvidence("L3-HONEYPORT-SCAN", observedAt, !whitelisted)
		if whitelisted {
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		if fwManager == nil {
			log.Printf("[Telemetry Worker] Firewall unavailable; recording honeyport detection for %s", ip)
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		if err := fwManager.Ban(ip); err != nil {
			log.Printf("[Telemetry Worker] Firewall rejected honeyport ban for %s: %v", ip, err)
			if logShadowAlert != nil {
				logShadowAlert(ip, evidence.RuleID, line, evidence)
			}
			return
		}
		logBan(ip, evidence.RuleID, line, evidence)
		return
	}
	if strings.Contains(line, "[SYSWARDEN-ARP-FLOOD]") {
		if logDetected == nil {
			return
		}
		ip := extractField(line, "SRC=")
		if ip == "" {
			ip = extractField(line, "MAC=")
		}
		if ip == "" {
			ip = "Unknown-ARP-Attacker"
		}
		evidence, _ := kernelRuleEvidence("L2-ARP-FLOOD", observedAt, net.ParseIP(ip) != nil)
		evidence.ObservationDisposition = "kernel-packet-dropped"
		// The kernel has already rate-limited/dropped this packet. No durable
		// source ban is claimed unless a firewall mutation actually succeeds.
		logDetected(ip, evidence.RuleID, line, evidence)
	}
}

func extractField(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx != -1 {
		parts := strings.Fields(line[idx:])
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], prefix)
		}
	}
	return ""
}

func generateTelemetry() {
	data := DashboardData{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		GithubStars:   getGithubStars(),
		GithubRelease: getGithubRelease(),
		ProfileName:   viper.GetString("user.profile_name"),
		System:        getSystemStats(),
		Layer3:        getLayer3Stats(),
		WAF:           getWAFStats(),
		Whitelist:     getWhitelistStats(),
		HA:            getHATelemetry(),
	}

	uiDir := "/var/lib/syswarden/ui"
	_ = os.MkdirAll(uiDir, 0750)
	dataFile := filepath.Join(uiDir, "data.json")

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[Telemetry Worker] Error marshaling telemetry data: %v", err)
		return
	}

	// Write atomically using a tmp file
	tmpFile := dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, jsonData, 0600); err != nil {
		log.Printf("[Telemetry Worker] Error writing telemetry data: %v", err)
		return
	}

	if err := os.Rename(tmpFile, dataFile); err != nil {
		log.Printf("[Telemetry Worker] Error moving telemetry data: %v", err)
	}
}

var cachedSys SystemData
var lastSysFetch time.Time

func GetOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer func() {
		_ = conn.Close()
	}()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getSystemStats() SystemData {
	if time.Since(lastSysFetch) < 60*time.Second && cachedSys.Hostname != "" {
		return cachedSys
	}

	sys := SystemData{
		Hostname: "Unknown",
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Cores:    fmt.Sprintf("%d", runtime.NumCPU()),
	}
	if h, err := os.Hostname(); err == nil {
		sys.Hostname = h
	}
	sys.ServerIP = GetOutboundIP()

	platformStats := collectPlatformSystemStats()
	sys.Uptime = platformStats.Uptime
	sys.LoadAverage = platformStats.LoadAverage
	sys.CpuModel = platformStats.CpuModel
	sys.RamTotalMb = platformStats.RamTotalMb
	sys.RamUsedMb = platformStats.RamUsedMb

	// Disk Space
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		sys.DiskTotalMb = int((stat.Blocks * uint64(stat.Bsize)) / 1024 / 1024)               // #nosec G115
		sys.DiskUsedMb = int(((stat.Blocks - stat.Bfree) * uint64(stat.Bsize)) / 1024 / 1024) // #nosec G115
	}

	osName := runtime.GOOS
	if b, err := os.ReadFile("/etc/os-release"); err == nil { // #nosec
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	sys.Os = osName

	sys.Services = collectPlatformServices()
	sys.Ports = collectPlatformPorts()
	if sys.Ports == nil {
		sys.Ports = make([]Port, 0)
	}

	// --- Virtual Service: SYSWARDEN-HA-CLUSTER ---
	haStatus := "SKIPPED"
	haEnabled := false
	haPort := "62026"

	if viper.GetBool("integrations.ha.enabled") {
		haEnabled = true
		if p := viper.GetInt("integrations.ha.peer_port"); p > 0 {
			haPort = strconv.Itoa(p)
		} else if ps := viper.GetString("integrations.ha.peer_port"); ps != "" {
			haPort = ps
		}
	}
	if haEnabled {
		haStatus = "INACTIVE"
		for _, p := range sys.Ports {
			if p.Port == haPort && p.State == "LISTEN" {
				haStatus = "ACTIVE"
				break
			}
		}
	}
	sys.Services = append(sys.Services, Service{
		Name:   "SYSWARDEN-HA-CLUSTER",
		Status: haStatus,
	})

	// --- Virtual Service: SYSWARDEN-UPDATE-FEEDS ---
	feedsTimer := "SKIPPED"
	outFeeds, errFeeds := exec.Command("crontab", "-l").Output() // #nosec
	if errFeeds == nil {
		lines := strings.Split(string(outFeeds), "\n")
		for _, line := range lines {
			if strings.Contains(line, "syswarden-cli update-feeds") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					minute, errMin := strconv.Atoi(parts[0])
					if errMin == nil {
						now := time.Now()
						nextRun := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), minute, 0, 0, now.Location())
						if now.After(nextRun) {
							nextRun = nextRun.Add(time.Hour)
						}
						diff := nextRun.Sub(now)
						h := int(diff.Hours())
						m := int(diff.Minutes()) % 60
						s := int(diff.Seconds()) % 60
						feedsTimer = fmt.Sprintf("%02d:%02d:%02d", h, m, s)
					}
				}
			}
		}
	}
	sys.Services = append(sys.Services, Service{
		Name:   "SYSWARDEN-UPDATE-FEEDS",
		Status: feedsTimer,
	})

	cachedSys = sys
	lastSysFetch = time.Now()
	return sys
}

var cachedL3 Layer3
var lastL3Fetch time.Time

func countLinesInFile(path string) int {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return 0
	}
	defer func() {
		_ = file.Close()
	}()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}

func getLayer3Stats() Layer3 {
	if !lastL3Fetch.IsZero() && time.Since(lastL3Fetch) < 2*time.Minute {
		return cachedL3
	}
	cachedL3 = collectLayer3Stats("/etc/syswarden/lists", liveNftGeoIPBlockedCount)
	lastL3Fetch = time.Now()
	return cachedL3
}

func collectLayer3Stats(listDirectory string, geoIPBlockedCount func() int) Layer3 {
	var l3 Layer3

	if len(viper.GetStringSlice("network.geo.allowed_countries")) > 0 {
		l3.ZeroTrustMode = true
	}
	if len(viper.GetStringSlice("network.asn.allowed_asns")) > 0 {
		l3.ZeroTrustMode = true
	}

	l3.L7Banned = countLinesInFile(filepath.Join(listDirectory, "syswarden_blacklist.ipv4")) + countLinesInFile(filepath.Join(listDirectory, "syswarden_blacklist.ipv6"))
	l3.GlobalBlocked = l3.L7Banned + countLinesInFile(filepath.Join(listDirectory, "syswarden_threatintel.ipv4")) + countLinesInFile(filepath.Join(listDirectory, "syswarden_threatintel.ipv6"))

	if matches, err := filepath.Glob(filepath.Join(listDirectory, "AS*.ipv*")); err == nil {
		for _, m := range matches {
			l3.ASNBlocked += countLinesInFile(m)
		}
	}

	// GeoIP policy is embedded in the signed CLI and applied directly to the
	// kernel. Retained country files are legacy artifacts, not active policy.
	if geoIPBlockedCount != nil {
		l3.GeoIPBlocked = geoIPBlockedCount()
	}
	return l3
}

type IPAPIResponse struct {
	CountryCode string `json:"country_code"`
	Asn         string `json:"asn"`
	Org         string `json:"org"`
	Threat      string `json:"threat"`
}

const (
	osintCachePath          = "/var/lib/syswarden/ui/osint_cache.json"
	osintCacheSchemaVersion = 1
	osintCacheMaxEntries    = 4096
	osintCacheMaxBytes      = int64(4 * 1024 * 1024)
	osintQueueCapacity      = 256
	osintWorkerCount        = 2
	osintPositiveTTL        = 24 * time.Hour
	osintNegativeTTL        = 15 * time.Minute
	osintPersistDelay       = 2 * time.Second
	osintResponseMaxBytes   = int64(64 * 1024)
)

type osintCacheRecord struct {
	Attacker  Attacker  `json:"attacker"`
	FetchedAt time.Time `json:"fetched_at"`
	Negative  bool      `json:"negative,omitempty"`
}

type osintCacheDocument struct {
	SchemaVersion int                         `json:"schema_version"`
	Records       map[string]osintCacheRecord `json:"records"`
}

type osintLRUEntry struct {
	ip string
}

var (
	osintCache          = make(map[string]osintCacheRecord)
	osintLRU            = list.New()
	osintLRUIndex       = make(map[string]*list.Element)
	osintPending        = make(map[string]struct{})
	osintJobs           = make(chan string, osintQueueCapacity)
	osintPersistRequest = make(chan struct{}, 1)
	osintMu             sync.Mutex
	osintPersistMu      sync.Mutex
	osintCacheOnce      sync.Once
	osintWorkersOnce    sync.Once
	osintHTTPClient     = &http.Client{
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 || request.URL.Scheme != "https" || request.URL.Hostname() != "ip.wiredalter.com" {
				return fmt.Errorf("refusing OSINT redirect outside the pinned HTTPS origin")
			}
			return nil
		},
	}
)

func canonicalPublicOSINTIP(raw string) (string, bool) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" {
		return "", false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "", false
	}
	return address.String(), true
}

func ensureOSINTCacheLoaded() {
	osintCacheOnce.Do(func() {
		loaded := loadOSINTCacheDocument(osintCachePath)
		osintMu.Lock()
		defer osintMu.Unlock()
		keys := make([]string, 0, len(loaded))
		for ip := range loaded {
			keys = append(keys, ip)
		}
		sort.Strings(keys)
		if len(keys) > osintCacheMaxEntries {
			keys = keys[len(keys)-osintCacheMaxEntries:]
		}
		for _, ip := range keys {
			cacheOSINTRecordLocked(ip, loaded[ip])
		}
	})
}

func loadOSINTCacheDocument(path string) map[string]osintCacheRecord {
	loaded := make(map[string]osintCacheRecord)
	file, err := os.Open(path) // #nosec G304 -- fixed production path or test-owned path
	if err != nil {
		return loaded
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > osintCacheMaxBytes {
		return loaded
	}
	wire, err := io.ReadAll(io.LimitReader(file, osintCacheMaxBytes+1))
	if err != nil || int64(len(wire)) > osintCacheMaxBytes {
		return loaded
	}
	var document osintCacheDocument
	if err := json.Unmarshal(wire, &document); err == nil && document.SchemaVersion == osintCacheSchemaVersion {
		for rawIP, record := range document.Records {
			ip, valid := canonicalPublicOSINTIP(rawIP)
			if !valid || ip != rawIP || record.Attacker.IP != "" && record.Attacker.IP != ip {
				continue
			}
			record.Attacker = normalizedOSINTAttacker(ip, record.Attacker)
			loaded[ip] = record
		}
		return loaded
	}

	// v4.03.x stored a plain IP-to-attacker map. Import it as stale data so it
	// remains visible while the bounded asynchronous workers refresh it.
	var legacy map[string]Attacker
	if err := json.Unmarshal(wire, &legacy); err != nil {
		return loaded
	}
	for rawIP, attacker := range legacy {
		ip, valid := canonicalPublicOSINTIP(rawIP)
		if !valid || ip != rawIP || attacker.IP != "" && attacker.IP != ip {
			continue
		}
		attacker = normalizedOSINTAttacker(ip, attacker)
		loaded[ip] = osintCacheRecord{Attacker: attacker}
	}
	return loaded
}

func cacheOSINTRecordLocked(ip string, record osintCacheRecord) {
	if element := osintLRUIndex[ip]; element != nil {
		osintCache[ip] = record
		osintLRU.MoveToBack(element)
		return
	}
	for len(osintCache) >= osintCacheMaxEntries && osintLRU.Len() > 0 {
		oldest := osintLRU.Front()
		entry := oldest.Value.(osintLRUEntry)
		delete(osintCache, entry.ip)
		delete(osintLRUIndex, entry.ip)
		osintLRU.Remove(oldest)
	}
	osintCache[ip] = record
	osintLRUIndex[ip] = osintLRU.PushBack(osintLRUEntry{ip: ip})
}

func queueOSINTRefresh(ip string) {
	if canonical, valid := canonicalPublicOSINTIP(ip); !valid || canonical != ip {
		return
	}
	osintMu.Lock()
	if _, pending := osintPending[ip]; pending {
		osintMu.Unlock()
		return
	}
	osintPending[ip] = struct{}{}
	select {
	case osintJobs <- ip:
		osintMu.Unlock()
	default:
		delete(osintPending, ip)
		osintMu.Unlock()
	}
}

func requestOSINTCachePersist() {
	select {
	case osintPersistRequest <- struct{}{}:
	default:
	}
}

func startOSINTEnrichmentWorkers(ctx context.Context, wg *sync.WaitGroup) {
	if ctx == nil || wg == nil {
		return
	}
	osintWorkersOnce.Do(func() {
		ensureOSINTCacheLoaded()
		for range osintWorkerCount {
			wg.Add(1)
			go func() {
				defer wg.Done()
				osintEnrichmentWorker(ctx)
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			osintCachePersister(ctx)
		}()
	})
}

func osintEnrichmentWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-osintJobs:
			requestCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			attacker, err := fetchOSINT(requestCtx, ip)
			cancel()

			osintMu.Lock()
			delete(osintPending, ip)
			if ctx.Err() == nil {
				cacheOSINTRecordLocked(ip, osintCacheRecord{
					Attacker:  attacker,
					FetchedAt: time.Now().UTC(),
					Negative:  err != nil,
				})
			}
			osintMu.Unlock()
			if ctx.Err() == nil {
				requestOSINTCachePersist()
			}
		}
	}
}

func fetchOSINT(ctx context.Context, ip string) (Attacker, error) {
	attacker := Attacker{IP: ip, Country: "N/A", ASN: "N/A", Org: "N/A"}
	canonical, valid := canonicalPublicOSINTIP(ip)
	if !valid || canonical != ip {
		return attacker, fmt.Errorf("invalid public OSINT address")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://ip.wiredalter.com/json?ip="+ip, nil)
	if err != nil {
		return attacker, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "SysWarden-OSINT/1")
	response, err := osintHTTPClient.Do(request)
	if err != nil {
		return attacker, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return attacker, fmt.Errorf("OSINT endpoint returned HTTP %d", response.StatusCode)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, osintResponseMaxBytes+1))
	if err != nil {
		return attacker, err
	}
	if int64(len(wire)) > osintResponseMaxBytes {
		return attacker, fmt.Errorf("OSINT response exceeds %d bytes", osintResponseMaxBytes)
	}
	var result IPAPIResponse
	if err := json.Unmarshal(wire, &result); err != nil {
		return attacker, err
	}
	attacker.Country = boundedOSINTText(result.CountryCode, 16, "N/A")
	attacker.ASN = boundedOSINTText(result.Asn, 64, "N/A")
	attacker.Org = boundedOSINTText(result.Org, 256, "N/A")
	attacker.Threat = boundedOSINTText(result.Threat, 128, "")
	return attacker, nil
}

func boundedOSINTText(value string, limit int, fallback string) string {
	if limit <= 0 {
		return fallback
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	runes := make([]rune, 0, minInt(len(value), limit))
	for _, character := range value {
		if !unicode.IsGraphic(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) ||
			character == '[' || character == ']' {
			continue
		}
		runes = append(runes, character)
		if len(runes) == limit {
			break
		}
	}
	if len(runes) == 0 {
		return fallback
	}
	return string(runes)
}

func normalizedOSINTAttacker(ip string, attacker Attacker) Attacker {
	return Attacker{
		IP:      ip,
		Country: boundedOSINTText(attacker.Country, 16, "N/A"),
		ASN:     boundedOSINTText(attacker.ASN, 64, "N/A"),
		Org:     boundedOSINTText(attacker.Org, 256, "N/A"),
		Threat:  boundedOSINTText(attacker.Threat, 128, ""),
	}
}

func osintCachePersister(ctx context.Context) {
	var timer *time.Timer
	var timerChannel <-chan time.Time
	dirty := false
	for {
		select {
		case <-ctx.Done():
			if timer != nil && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if dirty {
				persistOSINTCache(osintCachePath)
			}
			return
		case <-osintPersistRequest:
			dirty = true
			if timer == nil {
				timer = time.NewTimer(osintPersistDelay)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(osintPersistDelay)
			}
			timerChannel = timer.C
		case <-timerChannel:
			persistOSINTCache(osintCachePath)
			dirty = false
			timerChannel = nil
		}
	}
}

func persistOSINTCache(path string) {
	osintPersistMu.Lock()
	defer osintPersistMu.Unlock()
	ensureOSINTCacheLoaded()

	osintMu.Lock()
	records := make(map[string]osintCacheRecord, len(osintCache))
	for ip, record := range osintCache {
		records[ip] = record
	}
	osintMu.Unlock()
	document := osintCacheDocument{SchemaVersion: osintCacheSchemaVersion, Records: records}
	wire, err := json.Marshal(document)
	if err != nil || int64(len(wire)) > osintCacheMaxBytes {
		log.Printf("[Telemetry Worker] Refusing oversized or invalid OSINT cache publication")
		return
	}

	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0750); err != nil {
		log.Printf("[Telemetry Worker] Cannot create OSINT cache directory: %v", err)
		return
	}
	temporary, err := os.CreateTemp(directory, ".osint-cache-*.tmp")
	if err != nil {
		log.Printf("[Telemetry Worker] Cannot create OSINT cache staging file: %v", err)
		return
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		log.Printf("[Telemetry Worker] Cannot protect OSINT cache staging file: %v", err)
		return
	}
	if _, err := temporary.Write(wire); err != nil {
		log.Printf("[Telemetry Worker] Cannot write OSINT cache staging file: %v", err)
		return
	}
	if err := temporary.Sync(); err != nil {
		log.Printf("[Telemetry Worker] Cannot sync OSINT cache staging file: %v", err)
		return
	}
	if err := temporary.Close(); err != nil {
		log.Printf("[Telemetry Worker] Cannot close OSINT cache staging file: %v", err)
		return
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		log.Printf("[Telemetry Worker] Cannot publish OSINT cache: %v", err)
		return
	}
	published = true
	if directoryFile, err := os.Open(directory); err == nil { // #nosec G304 -- directory is derived from the fixed product-owned OSINT cache path
		_ = directoryFile.Sync()
		_ = directoryFile.Close()
	}
}

func getActiveSSHPort() string {
	activeSSHPortMu.Lock()
	defer activeSSHPortMu.Unlock()
	if activeSSHPort != "" && time.Since(activeSSHPortFetched) < 5*time.Minute {
		return activeSSHPort
	}
	resolved := getConfiguredSSHPort()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if output, err := activeSSHConfigOutput(ctx); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || !strings.EqualFold(fields[0], "port") {
				continue
			}
			if parsed, err := strconv.Atoi(fields[1]); err == nil && parsed > 0 && parsed <= 65535 {
				resolved = strconv.Itoa(parsed)
				break
			}
		}
	}
	activeSSHPort = resolved
	activeSSHPortFetched = time.Now()
	return resolved
}

var customSSHPort string
var sshPortMu sync.Mutex
var activeSSHPort string
var activeSSHPortFetched time.Time
var activeSSHPortMu sync.Mutex
var activeSSHConfigOutput = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "sshd", "-T").Output() // #nosec G204 -- fixed executable and fixed arguments
}

func getConfiguredSSHPort() string {
	sshPortMu.Lock()
	defer sshPortMu.Unlock()
	if customSSHPort != "" {
		return customSSHPort
	}

	if p := viper.GetString("core.ssh_port"); p != "" {
		customSSHPort = p
		return customSSHPort
	}
	customSSHPort = "22"
	return customSSHPort
}

func getServiceName(port string) string {
	services := map[string]string{
		"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
		"80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS", "445": "SMB",
		"3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "6379": "Redis",
		"8080": "HTTP-Alt", "8443": "HTTPS-Alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "Port " + port
}

func extractPort(payload string) string {
	port := "MULTI"
	if payload != "" {
		if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			protoStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(protoStr, " "); spaceIdx != -1 {
				protoStr = protoStr[:spaceIdx]
			}

			if protoStr == "ICMP" || protoStr == "ICMPv6" || protoStr == "IGMP" || protoStr == "GRE" || protoStr == "IPSEC" || protoStr == "IPIP" {
				port = protoStr
			} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
				dptStr := payload[dptIdx+4:]
				if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
					dptStr = dptStr[:spaceIdx]
				}
				port = dptStr
			} else {
				port = protoStr
			}
		} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			dptStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
				dptStr = dptStr[:spaceIdx]
			}
			port = dptStr
		} else if idx := strings.Index(payload, "port "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				port = parts[0]
			}
		} else if strings.Contains(strings.ToLower(payload), "http") || strings.Contains(strings.ToLower(payload), "nginx") || strings.Contains(strings.ToLower(payload), "apache") {
			port = "80/443"
		}
	}
	return port
}

func enrichOSINT(ip string, payload string, jail string) Attacker {
	ensureOSINTCacheLoaded()
	att := Attacker{IP: ip, Country: "N/A", ASN: "N/A", Org: "N/A"}
	canonical, public := canonicalPublicOSINTIP(ip)
	refresh := public && canonical == ip
	if refresh {
		osintMu.Lock()
		if record, cached := osintCache[ip]; cached {
			att = record.Attacker
			if element := osintLRUIndex[ip]; element != nil {
				osintLRU.MoveToBack(element)
			}
			ttl := osintPositiveTTL
			if record.Negative {
				ttl = osintNegativeTTL
			}
			age := time.Since(record.FetchedAt)
			refresh = record.FetchedAt.IsZero() || age < 0 || age > ttl
		}
		osintMu.Unlock()
		if refresh {
			queueOSINTRefresh(ip)
		}
	}

	// Extract port or protocol from payload dynamically
	port := "MULTI"
	if payload != "" {
		if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			protoStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(protoStr, " "); spaceIdx != -1 {
				protoStr = protoStr[:spaceIdx]
			}

			if protoStr == "ICMP" || protoStr == "ICMPv6" || protoStr == "IGMP" || protoStr == "GRE" || protoStr == "IPSEC" || protoStr == "IPIP" {
				port = protoStr
			} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
				dptStr := payload[dptIdx+4:]
				if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
					dptStr = dptStr[:spaceIdx]
				}
				port = dptStr
			} else {
				port = protoStr
			}
		} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			dptStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
				dptStr = dptStr[:spaceIdx]
			}
			port = dptStr
		}
	}

	if port == "MULTI" {
		j := strings.ToLower(jail)
		if strings.Contains(j, "ssh") || strings.Contains(j, "bruteforce") {
			port = getActiveSSHPort()
		}
	}

	att.Port = port

	return att
}

var cachedStars string = "260"
var lastStarFetch time.Time

func getGithubStars() string {
	if time.Since(lastStarFetch) < 1*time.Hour && cachedStars != "N/A" {
		return cachedStars
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/duggytuxy/syswarden", nil)
	if err != nil {
		return cachedStars
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err == nil {
		defer func() {
			_ = resp.Body.Close()
		}()
		if resp.StatusCode == 200 {
			var res struct {
				StargazersCount int `json:"stargazers_count"`
			}
			if json.NewDecoder(resp.Body).Decode(&res) == nil {
				cachedStars = fmt.Sprintf("%d", res.StargazersCount)
				lastStarFetch = time.Now()
			}
		}
	}
	return cachedStars
}

var cachedRelease string = "Unknown"
var lastReleaseFetch time.Time

func getGithubRelease() string {
	if time.Since(lastReleaseFetch) < 1*time.Hour && cachedRelease != "Unknown" {
		return cachedRelease
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/duggytuxy/syswarden/releases/latest", nil)
	if err != nil {
		return cachedRelease
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == 200 {
			var res struct {
				TagName string `json:"tag_name"`
			}
			if json.NewDecoder(resp.Body).Decode(&res) == nil {
				cachedRelease = res.TagName
				lastReleaseFetch = time.Now()
			}
		}
	}
	return cachedRelease
}

var cachedWAF WAF
var lastWAFFetch time.Time

func getWAFStats() WAF {
	if !lastWAFFetch.IsZero() && time.Since(lastWAFFetch) < 15*time.Second {
		return cachedWAF
	}

	var waf WAF
	waf.BannedIPs = []BannedIP{}
	waf.TopAttackers = []Attacker{}
	waf.SignaturesData = []JailData{}
	evidenceState := kpiEvidenceState{}

	defaultThreshold := viper.GetInt("waap.bruteforce_threshold")
	if defaultThreshold <= 0 {
		defaultThreshold = 5
	}
	defaultWindow := viper.GetInt("waap.bruteforce_window_seconds")
	if defaultWindow <= 0 {
		defaultWindow = 60
	}
	var catalog riskCatalog
	if data, err := runtimepaths.ReadSignatures(); err != nil {
		log.Printf("[Telemetry Worker] Cannot read the risk catalog: %v", err)
	} else if parsed, err := parseRiskCatalog(data, defaultThreshold, defaultWindow); err != nil {
		log.Printf("[Telemetry Worker] Refusing invalid risk catalog metrics: %v", err)
	} else {
		catalog = parsed
		evidenceState.catalogAvailable = true
		waf.ActiveSignatures = parsed.ruleCount
	}

	activeBans := make(map[string]bool)
	if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4"); err == nil { // #nosec
		for _, line := range strings.Split(string(content), "\n") {
			if ip := strings.TrimSpace(line); ip != "" {
				activeBans[ip] = true
			}
		}
	}
	if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv6"); err == nil { // #nosec
		for _, line := range strings.Split(string(content), "\n") {
			if ip := strings.TrimSpace(line); ip != "" {
				activeBans[ip] = true
			}
		}
	}
	waf.TotalBanned = len(activeBans)

	// Parse the protected NDJSON journal without deriving historical actions
	// from the current firewall state.
	journalWindow, err := openKPIJournalWindow("/var/log/syswarden/waf.json", maxKPIJournalScanBytes)
	if err != nil {
		evidenceState.apply(&waf)
		evidenceState.logDegraded()
		return waf
	}
	journalSnapshot := journalWindow.snapshot
	evidenceState.journalBytesTotal = journalSnapshot.totalBytes
	defer func() {
		_ = journalWindow.Close()
	}()

	var allBans []BannedIP
	var allAllowed []AllowedEvent
	var metricEvents []TelemetryEvent

	processJournalRecord := func(wire []byte) {
		var event TelemetryEvent
		if err := json.Unmarshal(wire, &event); err != nil {
			evidenceState.journalDecodeErrors++
			return
		}
		isAllowed := event.Action == "ALLOWED"
		if isAllowed {
			allAllowed = append(allAllowed, AllowedEvent{
				Timestamp: event.Timestamp,
				IP:        event.IP,
				Service:   event.Jail,
				Payload:   event.Payload,
			})
		}
		_, canonicalIP, observedAt, admitted, excluded := admitMetricEvent(event, catalog)
		switch {
		case admitted:
			evidenceState.metricAdmittedEvents++
			metricEvent := event
			metricEvent.IP = canonicalIP
			metricEvent.Timestamp = observedAt.UTC().Format(time.RFC3339Nano)
			metricEvents = append(metricEvents, metricEvent)
			if event.Action == "SHADOW-ALERT" || event.Action == "DETECTED" {
				waf.TotalDetected++
			}
		case excluded:
			evidenceState.metricExcludedEvents++
		default:
			evidenceState.metricRejectedEvents++
		}
		if isAllowed {
			return
		}
		// BannedIPs deliberately remains the raw eligible-action journal view;
		// KPI aggregates below use only metricEvents admitted above.
		if !metricActionEligible(event.Action) {
			return
		}
		profile, known := profileForEvent(event, catalog)
		mitre := "Unclassified"
		if known {
			mitre = mitreForRiskCategory(profile.category)
		}
		allBans = append(allBans, BannedIP{
			Timestamp: event.Timestamp,
			IP:        event.IP,
			Jail:      event.Jail,
			Payload:   event.Payload,
			Mitre:     mitre,
			Action:    event.Action,
		})
	}
	var journalScanErrors []error
	for _, journalReader := range journalWindow.readers {
		scanner := bufio.NewScanner(journalReader)
		scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
		for scanner.Scan() {
			processJournalRecord(scanner.Bytes())
		}
		if scanErr := scanner.Err(); scanErr != nil {
			journalScanErrors = append(journalScanErrors, scanErr)
		}
	}
	evidenceState.journalBytesScanned = journalWindow.consumedBytes()
	journalScopeComplete := false
	if scanErr := errors.Join(journalScanErrors...); scanErr != nil {
		log.Printf("[Telemetry Worker] Telemetry journal scan stopped: %v", scanErr)
	} else if evidenceState.journalBytesScanned != journalSnapshot.scannedBytes {
		log.Printf(
			"[Telemetry Worker] Telemetry journal snapshot ended early: scanned=%d expected=%d",
			evidenceState.journalBytesScanned,
			journalSnapshot.scannedBytes,
		)
	} else if !journalWindow.stable() {
		log.Printf("[Telemetry Worker] Telemetry journal generations changed during the KPI snapshot")
	} else {
		journalScopeComplete = journalSnapshot.complete
		evidenceState.journalScanComplete = journalScopeComplete
	}

	// Get last 50 allowed IPs for display
	startA := 0
	if len(allAllowed) > 50 {
		startA = len(allAllowed) - 50
	}
	for i := len(allAllowed) - 1; i >= startA; i-- {
		waf.AllowedEvents = append(waf.AllowedEvents, allAllowed[i])
	}

	// Keep the latest unique observations for the event table. Top Attackers is
	// aggregated independently from all eligible observations below.
	sort.SliceStable(allBans, func(i, j int) bool {
		left, leftErr := time.Parse(time.RFC3339Nano, allBans[i].Timestamp)
		right, rightErr := time.Parse(time.RFC3339Nano, allBans[j].Timestamp)
		if leftErr != nil || rightErr != nil {
			return false
		}
		return left.Before(right)
	})
	seenIPs := make(map[string]bool)
	for i := len(allBans) - 1; i >= 0; i-- {
		if len(waf.BannedIPs) >= 50 {
			break
		}
		if seenIPs[allBans[i].IP] {
			continue
		}
		seenIPs[allBans[i].IP] = true
		waf.BannedIPs = append(waf.BannedIPs, allBans[i])
	}

	metrics, categoryCounts, jailCounts, rejectedMetrics := buildAttackerMetrics(metricEvents, catalog)
	if !journalScopeComplete {
		for index := range metrics {
			metrics[index].metricScope = metricScopeRetainedTail
		}
	}
	if rejectedMetrics > 0 {
		evidenceState.metricRejectedEvents += rejectedMetrics
	}
	if len(metrics) > 50 {
		metrics = metrics[:50]
	}
	for _, metric := range metrics {
		attacker := enrichOSINT(metric.ip, metric.payload, metric.primaryJail)
		attacker.Hits = metric.hits
		attacker.FirstSeen = metric.firstSeen
		attacker.LastSeen = metric.lastSeen
		attacker.PrimaryJail = metric.primaryJail
		attacker.EnforcementJail = metric.enforcementJail
		attacker.EnforcementAction = metric.enforcementAction
		attacker.JailHits = metric.jailHits
		attacker.PolicyHits = metric.policyHits
		attacker.AttestedHits = metric.attestedHits
		attacker.RecordedHits = metric.recordedHits
		attacker.LegacyHits = metric.legacyHits
		attacker.RiskCategory = metric.riskCategory
		attacker.SeverityScore = metric.severityScore
		attacker.Severity = metric.severity
		attacker.PeakWindowHits = metric.peakWindowHits
		attacker.EffectiveThreshold = metric.effectiveThreshold
		window := metric.effectiveWindowSeconds
		attacker.EffectiveWindowSeconds = &window
		attacker.MetricQuality = metric.metricQuality
		attacker.SelectedPolicyQuality = metric.selectedPolicyQuality
		reached := metric.thresholdReached
		attacker.ThresholdReached = &reached
		attacker.ThresholdEvidence = metric.thresholdEvidence
		attacker.MetricScope = metric.metricScope
		attacker.HitEvidence = metric.hitEvidence
		attacker.HitQuality = metric.hitQuality
		attacker.DegradedHits = metric.degradedHits
		attacker.RiskModelVersion = metric.riskModelVersion
		attacker.SignatureCatalogVersion = metric.signatureCatalogVersion
		attacker.SignatureCatalogSHA256 = metric.signatureCatalogSHA256
		waf.TopAttackers = append(waf.TopAttackers, attacker)
	}

	for jail, count := range jailCounts {
		mitre := "Unclassified"
		if profile, exists := catalog.profiles[jail]; exists {
			mitre = mitreForRiskCategory(profile.category)
		} else if profile, exists := syntheticRiskProfile(jail); exists {
			mitre = mitreForRiskCategory(profile.category)
		}
		waf.SignaturesData = append(waf.SignaturesData, JailData{
			Name:  jail,
			Count: count,
			Mitre: mitre,
		})
	}
	sort.Slice(waf.SignaturesData, func(i, j int) bool {
		if waf.SignaturesData[i].Count != waf.SignaturesData[j].Count {
			return waf.SignaturesData[i].Count > waf.SignaturesData[j].Count
		}
		return waf.SignaturesData[i].Name < waf.SignaturesData[j].Name
	})

	// Targeted Ports
	portCounts := make(map[string]int)
	portIPs := make(map[string]map[string]bool)
	for _, event := range metricEvents {
		p := extractPort(event.Payload)
		portCounts[p]++
		if portIPs[p] == nil {
			portIPs[p] = make(map[string]bool)
		}
		portIPs[p][event.IP] = true
	}
	for p, count := range portCounts {
		waf.TargetedPorts = append(waf.TargetedPorts, TargetedPort{
			Port:      p,
			Service:   getServiceName(p),
			Hits:      count,
			UniqueIPs: len(portIPs[p]),
		})
	}
	sort.Slice(waf.TargetedPorts, func(i, j int) bool {
		return waf.TargetedPorts[i].Hits > waf.TargetedPorts[j].Hits
	})
	if len(waf.TargetedPorts) > 5 {
		waf.TargetedPorts = waf.TargetedPorts[:5]
	}

	// Sparkline 24h
	sparkCache := make(map[string]int)
	metricsFile := "/var/lib/syswarden/ui/metrics_24h.json"
	if b, err := os.ReadFile(metricsFile); err == nil { // #nosec
		_ = json.Unmarshal(b, &sparkCache)
	}

	currentHourCounts := make(map[string]int)
	for _, event := range metricEvents {
		if event.Action == "BANNED" || event.Action == "DETECTED" {
			if t, err := time.Parse(time.RFC3339Nano, event.Timestamp); err == nil {
				key := t.UTC().Format("2006-01-02-15")
				currentHourCounts[key]++
			}
		}
	}

	for k, v := range currentHourCounts {
		if v > sparkCache[k] {
			sparkCache[k] = v
		}
	}

	now := time.Now().UTC()
	var spark [24]int
	for i := 0; i < 24; i++ {
		t := now.Add(time.Duration(-i) * time.Hour)
		key := t.Format("2006-01-02-15")
		spark[23-i] = sparkCache[key]
	}

	for k := range sparkCache {
		if t, err := time.Parse("2006-01-02-15", k); err == nil && now.Sub(t) > 25*time.Hour {
			delete(sparkCache, k)
		}
	}

	if b, err := json.Marshal(sparkCache); err == nil {
		_ = os.WriteFile(metricsFile, b, 0600) // #nosec
	}

	waf.Sparkline24h = spark

	waf.RiskRadar = []int{
		categoryCounts["exploit"],
		categoryCounts["brute_force"],
		categoryCounts["reconnaissance"],
		categoryCounts["denial_of_service"],
		categoryCounts["abuse"],
	}
	evidenceState.apply(&waf)
	evidenceState.logDegraded()

	cachedWAF = waf
	lastWAFFetch = time.Now()
	return waf
}

func getWhitelistStats() Whitelist {
	var wl Whitelist
	wl.IPs = []string{}

	files := []string{"/etc/syswarden/lists/syswarden_whitelist.ipv4", "/etc/syswarden/lists/syswarden_whitelist.ipv6"}
	for _, file := range files {
		if content, err := os.ReadFile(file); err == nil { // #nosec
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				ip := strings.TrimSpace(line)
				if ip != "" && !strings.HasPrefix(ip, "#") {
					wl.IPs = append(wl.IPs, ip)
				}
			}
		}
	}
	wl.ActiveIPs = len(wl.IPs)
	return wl
}
