package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const DataFile = "/var/lib/syswarden/ui/data.json"
const SysWardenVersion = "v4.10.0"
const haPeerCABundleFile = "/etc/syswarden/ha-ca.pem"
const haModularConfigDirectory = "/etc/syswarden/config"
const maxTUIHAResponseBytes = 1024 * 1024
const tuiRemovalTombstonePath = "/var/lib/syswarden/removal-in-progress-v1"
const tuiRemovalTombstoneRecord = "SYSWARDEN_REMOVAL_V1\nstate=in-progress\n"
const (
	dashboardSnapshotTitle = "SYSWARDEN LOCAL DASHBOARD (SNAPSHOT)"
	emptyRegistryMessage   = "Registry is empty. No active entries."
	// Five minutes exceeds the HA v2 heartbeat timeout ceiling of two minutes
	// while leaving bounded room for serialization latency and host clock skew.
	tuiRuntimeCheckpointTimeTolerance = 5 * time.Minute
)

var (
	haPeerPort          = "62026"
	haBearerToken       string
	haRuntimeConfigErr  error
	haRuntimeConfigMu   sync.RWMutex
	httpClient, haCAErr = newHAHTTPClient(haPeerCABundleFile)
	activeNode          = tuiNodeSelection{ip: "local"}
	dashboardFetchMu    sync.Mutex
)

type tuiNodeSelection struct {
	mu         sync.RWMutex
	ip         string
	generation uint64
}

func (selection *tuiNodeSelection) selectNode(ip string) {
	selection.mu.Lock()
	defer selection.mu.Unlock()
	if selection.ip == ip {
		return
	}
	selection.ip = ip
	selection.generation++
}

func (selection *tuiNodeSelection) snapshot() (string, uint64) {
	selection.mu.RLock()
	defer selection.mu.RUnlock()
	return selection.ip, selection.generation
}

func (selection *tuiNodeSelection) ifCurrent(ip string, generation uint64, publish func()) bool {
	selection.mu.RLock()
	defer selection.mu.RUnlock()
	if selection.ip != ip || selection.generation != generation {
		return false
	}
	publish()
	return true
}

func inspectTUIRemovalTombstone(path string, expectedUID, expectedGID uint32) (bool, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "removal-in-progress-v1" {
		return true, fmt.Errorf("removal tombstone path is not fixed, clean, and absolute")
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("inspect removal state directory: %w", err)
	}
	parentStat, parentOK := parent.Sys().(*syscall.Stat_t)
	if !parentOK || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0022 != 0 ||
		parentStat.Uid != expectedUID || parentStat.Gid != expectedGID {
		return true, fmt.Errorf("refusing unsafe or modified removal tombstone")
	}
	parentFD, err := unix.Open(parentPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) // #nosec G304 -- fixed production path or isolated test fixture
	if err != nil {
		return true, fmt.Errorf("pin removal state directory: %w", err)
	}
	parentFile := os.NewFile(uintptr(parentFD), parentPath)
	if parentFile == nil {
		_ = unix.Close(parentFD)
		return true, fmt.Errorf("pin removal state directory")
	}
	defer parentFile.Close()
	openedParent, parentStatErr := parentFile.Stat()
	afterParent, afterParentErr := os.Lstat(parentPath)
	if parentStatErr != nil || afterParentErr != nil || !os.SameFile(parent, openedParent) || !os.SameFile(openedParent, afterParent) {
		return true, errors.Join(fmt.Errorf("removal state directory changed while pinning"), parentStatErr, afterParentErr)
	}
	fileFD, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("open removal tombstone without following links: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), path)
	if file == nil {
		_ = unix.Close(fileFD)
		return true, fmt.Errorf("pin removal tombstone")
	}
	defer file.Close()
	opened, statErr := file.Stat()
	fileStat, fileOK := opened.Sys().(*syscall.Stat_t)
	if statErr != nil || !fileOK || opened.Mode()&os.ModeSymlink != 0 || !opened.Mode().IsRegular() ||
		opened.Mode().Perm() != 0600 || fileStat.Uid != expectedUID || fileStat.Gid != expectedGID ||
		fileStat.Nlink != 1 || opened.Size() != int64(len(tuiRemovalTombstoneRecord)) {
		return true, errors.Join(fmt.Errorf("refusing unsafe or modified removal tombstone"), statErr)
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(len(tuiRemovalTombstoneRecord)+1)))
	var after unix.Stat_t
	afterErr := unix.Fstatat(parentFD, filepath.Base(path), &after, unix.AT_SYMLINK_NOFOLLOW)
	finalParent, finalParentErr := os.Lstat(parentPath)
	if readErr != nil || afterErr != nil || finalParentErr != nil ||
		!os.SameFile(openedParent, finalParent) || fileStat.Dev != uint64(after.Dev) ||
		fileStat.Ino != after.Ino || fileStat.Mode != after.Mode || fileStat.Uid != after.Uid ||
		fileStat.Gid != after.Gid || fileStat.Nlink != after.Nlink || fileStat.Size != after.Size ||
		string(content) != tuiRemovalTombstoneRecord {
		return true, errors.Join(
			fmt.Errorf("removal tombstone changed during TUI startup attestation"),
			readErr,
			afterErr,
			finalParentErr,
		)
	}
	return true, nil
}

func newHAHTTPClient(caBundleFile string) (*http.Client, error) {
	rootCAs, err := loadHATrustRoots(caBundleFile)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    rootCAs,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("HA redirects are disabled")
		},
	}
	return client, nil
}

func loadHATrustRoots(caBundleFile string) (*x509.CertPool, error) {
	caBundleFile = filepath.Clean(caBundleFile)
	info, err := os.Lstat(caBundleFile)
	if errors.Is(err, fs.ErrNotExist) {
		roots, systemErr := x509.SystemCertPool()
		if systemErr != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		return roots, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect HA CA bundle: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
		return nil, fmt.Errorf("HA CA bundle has an unexpected owner")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("HA CA bundle must not be group/world writable")
	}
	parent := filepath.Dir(caBundleFile)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA CA bundle parent must be a real directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle parent: %w", err)
	}
	defer root.Close()
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return nil, fmt.Errorf("HA CA bundle parent changed while opening")
	}
	file, err := root.Open(filepath.Base(caBundleFile))
	if err != nil {
		return nil, fmt.Errorf("open HA CA bundle: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened HA CA bundle: %w", err)
	}
	currentInfo, err := root.Lstat(filepath.Base(caBundleFile))
	if err != nil || !openedInfo.Mode().IsRegular() || !currentInfo.Mode().IsRegular() ||
		!os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, currentInfo) {
		return nil, fmt.Errorf("HA CA bundle changed while opening")
	}
	const maxHACABytes = 1024 * 1024
	bundle, err := io.ReadAll(io.LimitReader(file, maxHACABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HA CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if len(bundle) > maxHACABytes {
		return nil, fmt.Errorf("HA CA bundle contains no valid certificate")
	}
	if err := addStrictHATrustCertificates(roots, bundle); err != nil {
		return nil, fmt.Errorf("HA CA bundle is invalid: %w", err)
	}
	return roots, nil
}

func addStrictHATrustCertificates(roots *x509.CertPool, bundle []byte) error {
	if roots == nil {
		return fmt.Errorf("certificate pool is unavailable")
	}
	remaining := bundle
	certificates := 0
	for {
		remaining = bytes.TrimLeft(remaining, " \t\r\n")
		if len(remaining) == 0 {
			break
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("unexpected data outside a CERTIFICATE block")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return fmt.Errorf("invalid CERTIFICATE block")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CERTIFICATE block: %w", err)
		}
		roots.AddCert(certificate)
		certificates++
		remaining = rest
	}
	if certificates == 0 {
		return fmt.Errorf("bundle contains no certificate")
	}
	return nil
}

func haPeerURL(peer, path string) (string, error) {
	peer = strings.TrimSpace(peer)
	if strings.HasPrefix(peer, "[") && strings.HasSuffix(peer, "]") {
		peer = strings.TrimSuffix(strings.TrimPrefix(peer, "["), "]")
	}
	address, err := netip.ParseAddr(peer)
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return "", fmt.Errorf("HA destination must be an exact IP address")
	}
	haRuntimeConfigMu.RLock()
	port := haPeerPort
	haRuntimeConfigMu.RUnlock()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid HA peer port")
	}
	return "https://" + net.JoinHostPort(address.String(), strconv.Itoa(portNumber)) + path, nil
}

func haGet(url string) (*http.Response, error) {
	if haCAErr != nil {
		return nil, fmt.Errorf("HA TLS trust configuration: %w", haCAErr)
	}
	haRuntimeConfigMu.RLock()
	token := haBearerToken
	configErr := haRuntimeConfigErr
	haRuntimeConfigMu.RUnlock()
	if configErr != nil {
		return nil, fmt.Errorf("HA configuration unavailable: %w", configErr)
	}
	if token == "" || strings.TrimSpace(token) != token {
		return nil, fmt.Errorf("HA bearer token is required; configure integrations.ha.token and upgrade legacy HA clients")
	}
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	wire, readErr := io.ReadAll(io.LimitReader(response.Body, maxTUIHAResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read HA response: %w", readErr)
	}
	if len(wire) > maxTUIHAResponseBytes {
		return nil, fmt.Errorf("HA response exceeds %d bytes", maxTUIHAResponseBytes)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close HA response: %w", closeErr)
	}
	response.Body = io.NopCloser(bytes.NewReader(wire))
	return response, nil
}

// --- DATA MODELS ---
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

type Layer3 struct {
	GlobalBlocked int                `json:"global_blocked"`
	GeoIPBlocked  int                `json:"geoip_blocked"`
	ASNBlocked    int                `json:"asn_blocked"`
	L7Banned      int                `json:"l7_banned"`
	ZeroTrustMode bool               `json:"zero_trust_mode"`
	ThreatFeeds   []ThreatFeedStatus `json:"threat_feeds,omitempty"`
}

type ThreatFeedStatus struct {
	FeedName          string   `json:"feed_name"`
	AddressFamily     string   `json:"address_family"`
	State             string   `json:"state"`
	Freshness         string   `json:"freshness"`
	Attestation       string   `json:"attestation"`
	SourceOrigins     []string `json:"source_origins"`
	RetrievedAt       string   `json:"retrieved_at,omitempty"`
	AgeSeconds        *int64   `json:"age_seconds,omitempty"`
	LicenseIdentifier string   `json:"license_identifier,omitempty"`
	EvidenceQuality   string   `json:"evidence_quality,omitempty"`
	SHA256            string   `json:"sha256,omitempty"`
	AcceptedCount     int      `json:"accepted_count"`
	SkippedCount      int      `json:"skipped_count"`
	RejectedCount     int      `json:"rejected_count"`
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
	Timestamp        string `json:"timestamp"`
	IP               string `json:"ip"`
	Jail             string `json:"jail"`
	Payload          string `json:"payload"`
	Mitre            string `json:"mitre"`
	Action           string `json:"action"`
	EnforcementState string `json:"enforcement_state,omitempty"`
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
	EnforcementState        string `json:"enforcement_state,omitempty"`
	JailHits                int    `json:"jail_hits,omitempty"`
	PolicyHits              int    `json:"policy_hits,omitempty"`
	AttestedHits            int    `json:"attested_hits,omitempty"`
	RecordedHits            int    `json:"recorded_hits,omitempty"`
	LegacyHits              int    `json:"legacy_hits,omitempty"`
	RiskCategory            string `json:"risk_category,omitempty"`
	PolicyAction            string `json:"policy_action,omitempty"`
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
	TotalBanned          int             `json:"total_banned"`
	TotalDetected        int             `json:"total_detected"`
	ActiveSignatures     int             `json:"active_signatures"`
	KPIEvidenceQuality   string          `json:"kpi_evidence_quality,omitempty"`
	JournalScanComplete  *bool           `json:"journal_scan_complete,omitempty"`
	JournalBytesTotal    *int64          `json:"journal_bytes_total,omitempty"`
	JournalBytesScanned  *int64          `json:"journal_bytes_scanned,omitempty"`
	JournalDecodeErrors  *int            `json:"journal_decode_errors,omitempty"`
	MetricRejectedEvents *int            `json:"metric_rejected_events,omitempty"`
	MetricExcludedEvents *int            `json:"metric_excluded_events,omitempty"`
	MetricAdmittedEvents *int            `json:"metric_admitted_events,omitempty"`
	SignaturesData       []JailData      `json:"signatures_data"`
	TargetedPorts        []TargetedPort  `json:"targeted_ports"`
	BannedIPs            []BannedIP      `json:"banned_ips"`
	TopAttackers         []Attacker      `json:"top_attackers"`
	RiskRadar            []int           `json:"risk_radar"`
	Sparkline24h         [24]int         `json:"sparkline_24h"`
	AllowedEvents        []AllowedEvent  `json:"allowed_events"`
	GRCKPI               json.RawMessage `json:"grc_kpi,omitempty"`
}

type Whitelist struct {
	ActiveIPs int      `json:"active_ips"`
	IPs       []string `json:"ips"`
}

type DashboardProjection struct {
	Quality           string `json:"quality"`
	Reason            string `json:"reason,omitempty"`
	PayloadsProjected int    `json:"payloads_projected,omitempty"`
}

type DashboardData struct {
	Timestamp     string               `json:"timestamp"`
	GithubStars   string               `json:"github_stars"`
	GithubRelease string               `json:"github_release"`
	ProfileName   string               `json:"profile_name"`
	System        SystemData           `json:"system"`
	Layer3        Layer3               `json:"layer3"`
	WAF           WAF                  `json:"waf"`
	Whitelist     Whitelist            `json:"whitelist"`
	Projection    *DashboardProjection `json:"projection,omitempty"`
}

const (
	maxTUIDashboardJSONBytes   = 1024 * 1024
	maxTUIDashboardEntries     = 65536
	maxTUIDashboardStringBytes = 4096
)

func readTUIDashboardFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- fixed production path or isolated test fixture
	if err != nil {
		return nil, err
	}
	defer file.Close()
	wire, err := io.ReadAll(io.LimitReader(file, maxTUIDashboardJSONBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 || len(wire) > maxTUIDashboardJSONBytes {
		return nil, fmt.Errorf("telemetry snapshot size is outside accepted bounds")
	}
	return wire, nil
}

func decodeTUIDashboardData(wire []byte) (DashboardData, error) {
	if len(wire) == 0 || len(wire) > maxTUIDashboardJSONBytes {
		return DashboardData{}, fmt.Errorf("telemetry snapshot size is outside accepted bounds")
	}
	var decoded DashboardData
	if err := json.Unmarshal(wire, &decoded); err != nil {
		return DashboardData{}, fmt.Errorf("invalid telemetry JSON: %w", err)
	}
	if err := validateTUIDashboardData(decoded); err != nil {
		return DashboardData{}, fmt.Errorf("invalid telemetry snapshot: %w", err)
	}
	return decoded, nil
}

func validateTUIDashboardData(snapshot DashboardData) error {
	if err := validateTUIDashboardStrings(snapshot); err != nil {
		return err
	}
	if snapshot.Projection != nil {
		switch snapshot.Projection.Quality {
		case "complete":
			if snapshot.Projection.Reason != "" || snapshot.Projection.PayloadsProjected != 0 {
				return fmt.Errorf("complete dashboard projection carries degradation evidence")
			}
		case "degraded":
			if snapshot.Projection.PayloadsProjected <= 0 ||
				(snapshot.Projection.Reason != "display-payload-bound" && snapshot.Projection.Reason != "dashboard-envelope-bound") {
				return fmt.Errorf("degraded dashboard projection lacks valid evidence")
			}
			if snapshot.Projection.PayloadsProjected > len(snapshot.WAF.BannedIPs)+len(snapshot.WAF.AllowedEvents) {
				return fmt.Errorf("degraded dashboard projection exceeds the payload inventory")
			}
		default:
			return fmt.Errorf("dashboard projection quality is invalid")
		}
	}
	if snapshot.System.RamUsedMb < 0 || snapshot.System.RamTotalMb < 0 ||
		snapshot.System.DiskUsedMb < 0 || snapshot.System.DiskTotalMb < 0 ||
		(snapshot.System.RamTotalMb == 0 && snapshot.System.RamUsedMb != 0) ||
		(snapshot.System.DiskTotalMb == 0 && snapshot.System.DiskUsedMb != 0) {
		return fmt.Errorf("system capacity counters are outside accepted bounds")
	}
	if snapshot.Layer3.GlobalBlocked < 0 || snapshot.Layer3.GeoIPBlocked < 0 ||
		snapshot.Layer3.ASNBlocked < 0 || snapshot.Layer3.L7Banned < 0 ||
		snapshot.WAF.TotalBanned < 0 || snapshot.WAF.TotalDetected < 0 ||
		snapshot.WAF.ActiveSignatures < 0 || snapshot.Whitelist.ActiveIPs < 0 {
		return fmt.Errorf("dashboard counters are outside accepted bounds")
	}
	collections := []struct {
		name  string
		count int
	}{
		{name: "services", count: len(snapshot.System.Services)},
		{name: "ports", count: len(snapshot.System.Ports)},
		{name: "threat feeds", count: len(snapshot.Layer3.ThreatFeeds)},
		{name: "signature counters", count: len(snapshot.WAF.SignaturesData)},
		{name: "targeted ports", count: len(snapshot.WAF.TargetedPorts)},
		{name: "ban observations", count: len(snapshot.WAF.BannedIPs)},
		{name: "top attackers", count: len(snapshot.WAF.TopAttackers)},
		{name: "risk radar", count: len(snapshot.WAF.RiskRadar)},
		{name: "allowed observations", count: len(snapshot.WAF.AllowedEvents)},
		{name: "whitelist", count: len(snapshot.Whitelist.IPs)},
	}
	for _, collection := range collections {
		if collection.count > maxTUIDashboardEntries {
			return fmt.Errorf("%s inventory exceeds accepted bounds", collection.name)
		}
	}
	for _, feed := range snapshot.Layer3.ThreatFeeds {
		if feed.AcceptedCount < 0 || feed.SkippedCount < 0 || feed.RejectedCount < 0 ||
			feed.AgeSeconds != nil && *feed.AgeSeconds < 0 {
			return fmt.Errorf("threat feed counters are outside accepted bounds")
		}
	}
	for _, jail := range snapshot.WAF.SignaturesData {
		if jail.Count < 0 {
			return fmt.Errorf("signature counter is outside accepted bounds")
		}
	}
	for _, port := range snapshot.WAF.TargetedPorts {
		if port.Hits < 0 || port.UniqueIPs < 0 || port.UniqueIPs > port.Hits {
			return fmt.Errorf("targeted port counters are outside accepted bounds")
		}
	}
	for _, attacker := range snapshot.WAF.TopAttackers {
		if attacker.Hits < 0 || attacker.JailHits < 0 || attacker.PolicyHits < 0 ||
			attacker.AttestedHits < 0 || attacker.RecordedHits < 0 || attacker.LegacyHits < 0 ||
			attacker.DegradedHits < 0 || attacker.PeakWindowHits < 0 || attacker.EffectiveThreshold < 0 ||
			attacker.SeverityScore < 0 || attacker.SeverityScore > 100 ||
			attacker.EffectiveWindowSeconds != nil && *attacker.EffectiveWindowSeconds < 0 {
			return fmt.Errorf("attacker metrics are outside accepted bounds")
		}
	}
	for _, count := range snapshot.WAF.RiskRadar {
		if count < 0 {
			return fmt.Errorf("risk radar counter is outside accepted bounds")
		}
	}
	for _, count := range snapshot.WAF.Sparkline24h {
		if count < 0 {
			return fmt.Errorf("sparkline counter is outside accepted bounds")
		}
	}
	pointerCounters := []interface{}{
		snapshot.WAF.JournalBytesTotal,
		snapshot.WAF.JournalBytesScanned,
		snapshot.WAF.JournalDecodeErrors,
		snapshot.WAF.MetricRejectedEvents,
		snapshot.WAF.MetricExcludedEvents,
		snapshot.WAF.MetricAdmittedEvents,
	}
	for _, counter := range pointerCounters {
		switch value := counter.(type) {
		case *int:
			if value != nil && *value < 0 {
				return fmt.Errorf("KPI evidence counter is outside accepted bounds")
			}
		case *int64:
			if value != nil && *value < 0 {
				return fmt.Errorf("KPI evidence counter is outside accepted bounds")
			}
		}
	}
	if len(snapshot.WAF.GRCKPI) > maxTUIGRCKPIJSONBytes {
		return fmt.Errorf("GRC KPI evidence exceeds accepted bounds")
	}
	return nil
}

func validateTUIDashboardStrings(snapshot DashboardData) error {
	return validateTUIDashboardValue(reflect.ValueOf(snapshot), "dashboard")
}

func validateTUIDashboardValue(value reflect.Value, path string) error {
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.String:
		text := value.String()
		if len(text) > maxTUIDashboardStringBytes || !utf8.ValidString(text) {
			return fmt.Errorf("%s string is outside accepted bounds", path)
		}
		for _, r := range text {
			if unicode.IsControl(r) {
				return fmt.Errorf("%s string contains terminal control characters", path)
			}
		}
	case reflect.Struct:
		valueType := value.Type()
		for index := 0; index < value.NumField(); index++ {
			if err := validateTUIDashboardValue(value.Field(index), path+"."+valueType.Field(index).Name); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for index := 0; index < value.Len(); index++ {
			if err := validateTUIDashboardValue(value.Index(index), fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if err := validateTUIDashboardValue(iterator.Key(), path+".key"); err != nil {
				return err
			}
			if err := validateTUIDashboardValue(iterator.Value(), path+".value"); err != nil {
				return err
			}
		}
	}
	return nil
}

const (
	topAttackersTitleNormal   = " [white]❖ TOP ATTACKERS (OSINT HISTORY)[-] "
	topAttackersTitleDegraded = " [red]❖ TOP ATTACKERS (OSINT HISTORY) - KPI EVIDENCE DEGRADED[-] "
)

func kpiEvidenceDegradedOrUnavailable(waf WAF) bool {
	if waf.KPIEvidenceQuality != "complete" || waf.JournalScanComplete == nil || !*waf.JournalScanComplete {
		return true
	}
	if waf.JournalBytesTotal == nil || waf.JournalBytesScanned == nil || waf.JournalDecodeErrors == nil || waf.MetricRejectedEvents == nil ||
		waf.MetricExcludedEvents == nil || waf.MetricAdmittedEvents == nil {
		return true
	}
	return *waf.JournalBytesTotal < 0 || *waf.JournalBytesScanned < 0 ||
		*waf.JournalBytesScanned != *waf.JournalBytesTotal ||
		*waf.JournalDecodeErrors > 0 || *waf.MetricRejectedEvents > 0 ||
		!grcKPIEvidenceComplete(waf.GRCKPI)
}

const maxTUIGRCKPIJSONBytes = 4 * 1024 * 1024

type tuiGRCKPICatalog struct {
	Version          string `json:"version"`
	SHA256           string `json:"sha256"`
	RiskModelVersion string `json:"risk_model_version"`
}

type tuiGRCKPIWindow struct {
	Scope    string `json:"scope"`
	First    string `json:"first_observed,omitempty"`
	Last     string `json:"last_observed,omitempty"`
	Complete bool   `json:"complete"`
}

type tuiGRCKPIEvidence struct {
	JournalBytesTotal   int64 `json:"journal_bytes_total"`
	JournalBytesScanned int64 `json:"journal_bytes_scanned"`
	JournalDecodeErrors int   `json:"journal_decode_errors"`
	AdmittedEvents      int   `json:"admitted_events"`
	RejectedEvents      int   `json:"rejected_events"`
	ExcludedEvents      int   `json:"excluded_events"`
	RecordsTruncated    int   `json:"records_truncated"`
}

type tuiGRCKPILifecycle struct {
	Scope                       string `json:"scope"`
	DeletionRecords             int    `json:"deletion_records"`
	ExpiryRecords               int    `json:"expiry_records"`
	TombstoneRecords            int    `json:"tombstone_records"`
	RuntimeStateLinked          bool   `json:"runtime_state_linked"`
	RuntimeSnapshotComplete     bool   `json:"runtime_snapshot_complete,omitempty"`
	RuntimeSnapshotTruncated    bool   `json:"runtime_snapshot_truncated,omitempty"`
	RuntimeClusterID            string `json:"runtime_cluster_id,omitempty"`
	RuntimeEpoch                uint64 `json:"runtime_epoch,omitempty"`
	RuntimeNodeID               string `json:"runtime_node_id,omitempty"`
	RuntimeRole                 string `json:"runtime_role,omitempty"`
	RuntimeCoordination         string `json:"runtime_coordination,omitempty"`
	RuntimeModelSHA256          string `json:"runtime_model_sha256,omitempty"`
	RuntimeCheckpointSHA256     string `json:"runtime_checkpoint_sha256,omitempty"`
	RuntimePeerCheckpointSHA256 string `json:"runtime_peer_checkpoint_sha256,omitempty"`
	RuntimeCheckpointAt         string `json:"runtime_checkpoint_at,omitempty"`
	RuntimeCapturedAt           string `json:"runtime_captured_at,omitempty"`
	ActiveClaims                int    `json:"active_claims,omitempty"`
	ExpiredClaims               int    `json:"expired_claims,omitempty"`
	DeletedClaims               int    `json:"deleted_claims,omitempty"`
	TombstonedClaims            int    `json:"tombstoned_claims,omitempty"`
}

type tuiGRCKPIEnforcement struct {
	Jail   string `json:"jail,omitempty"`
	Action string `json:"action,omitempty"`
}

type tuiGRCKPIRecord struct {
	IP                     string               `json:"ip"`
	PhysicalHits           int                  `json:"physical_hits"`
	FirstObserved          string               `json:"first_observed"`
	LastObserved           string               `json:"last_observed"`
	SelectedJail           string               `json:"selected_jail"`
	JailHits               int                  `json:"jail_hits"`
	PolicyHits             int                  `json:"policy_hits"`
	Enforcement            tuiGRCKPIEnforcement `json:"enforcement"`
	EnforcementState       string               `json:"enforcement_state"`
	RiskCategory           string               `json:"risk_category"`
	PolicyAction           string               `json:"policy_action"`
	SeverityScore          int                  `json:"severity_score"`
	SeverityLabel          string               `json:"severity_label"`
	PeakWindowHits         int                  `json:"peak_window_hits"`
	EffectiveThreshold     int                  `json:"effective_threshold"`
	EffectiveWindowSeconds int                  `json:"effective_window_seconds"`
	ThresholdReached       bool                 `json:"threshold_reached"`
	ThresholdEvidence      string               `json:"threshold_evidence"`
	MetricQuality          string               `json:"metric_quality"`
	PolicyQuality          string               `json:"policy_quality"`
	HitEvidence            string               `json:"hit_evidence"`
	HitQuality             string               `json:"hit_quality"`
	DegradedHits           int                  `json:"degraded_hits"`
	Catalog                tuiGRCKPICatalog     `json:"catalog"`
}

type grcKPIEvidenceEnvelope struct {
	SchemaVersion int                `json:"schema_version"`
	Status        string             `json:"status"`
	Window        tuiGRCKPIWindow    `json:"window"`
	Catalog       tuiGRCKPICatalog   `json:"catalog"`
	Evidence      tuiGRCKPIEvidence  `json:"evidence"`
	Lifecycle     tuiGRCKPILifecycle `json:"lifecycle"`
	Records       []tuiGRCKPIRecord  `json:"records"`
}

func grcKPIEvidenceSummary(raw json.RawMessage) string {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "unavailable"
	}
	envelope, err := decodeTUIGRCKPIEvidence(raw)
	if err != nil {
		return "invalid"
	}
	if !envelope.Lifecycle.RuntimeStateLinked {
		return envelope.Status + "/runtime-unlinked"
	}
	return envelope.Status + "/ha-v2-" + envelope.Lifecycle.RuntimeCoordination
}

func grcKPIEvidenceComplete(raw json.RawMessage) bool {
	envelope, err := decodeTUIGRCKPIEvidence(raw)
	return err == nil && envelope.Status == "complete"
}

func decodeTUIGRCKPIEvidence(raw json.RawMessage) (grcKPIEvidenceEnvelope, error) {
	if len(raw) == 0 || len(raw) > maxTUIGRCKPIJSONBytes {
		return grcKPIEvidenceEnvelope{}, fmt.Errorf("GRC KPI evidence exceeds bounds")
	}
	if err := rejectTUIDuplicateJSONKeys(raw); err != nil {
		return grcKPIEvidenceEnvelope{}, err
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(raw), maxTUIGRCKPIJSONBytes+1))
	decoder.DisallowUnknownFields()
	var envelope grcKPIEvidenceEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return grcKPIEvidenceEnvelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return grcKPIEvidenceEnvelope{}, fmt.Errorf("GRC KPI evidence has trailing JSON")
	}
	if err := validateTUIGRCKPIEvidence(raw, envelope); err != nil {
		return grcKPIEvidenceEnvelope{}, err
	}
	return envelope, nil
}

func rejectTUIDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanTUIUniqueJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("GRC KPI evidence has trailing JSON")
	}
	return nil
}

func scanTUIUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("GRC KPI object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate GRC KPI object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanTUIUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("malformed GRC KPI object")
		}
	case '[':
		for decoder.More() {
			if err := scanTUIUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("malformed GRC KPI array")
		}
	default:
		return fmt.Errorf("unexpected GRC KPI JSON delimiter %q", delimiter)
	}
	return nil
}

func validateTUIGRCKPIEvidence(raw []byte, envelope grcKPIEvidenceEnvelope) error {
	root, err := requireTUIJSONObjectKeys(raw, "document",
		[]string{"schema_version", "status", "window", "catalog", "evidence", "lifecycle", "records"}, nil)
	if err != nil {
		return err
	}
	if _, err := requireTUIJSONObjectKeys(root["window"], "window", []string{"scope", "complete"}, []string{"first_observed", "last_observed"}); err != nil {
		return err
	}
	if _, err := requireTUIJSONObjectKeys(root["catalog"], "catalog", []string{"version", "sha256", "risk_model_version"}, nil); err != nil {
		return err
	}
	if _, err := requireTUIJSONObjectKeys(root["evidence"], "evidence", []string{
		"journal_bytes_total", "journal_bytes_scanned", "journal_decode_errors", "admitted_events",
		"rejected_events", "excluded_events", "records_truncated",
	}, nil); err != nil {
		return err
	}
	lifecycleRequired := []string{"scope", "deletion_records", "expiry_records", "tombstone_records", "runtime_state_linked"}
	lifecycleOptional := []string(nil)
	if envelope.Lifecycle.RuntimeStateLinked {
		lifecycleRequired = append(lifecycleRequired,
			"runtime_cluster_id", "runtime_epoch", "runtime_node_id", "runtime_role",
			"runtime_coordination", "runtime_model_sha256", "runtime_checkpoint_sha256",
			"runtime_checkpoint_at", "runtime_captured_at",
		)
		lifecycleOptional = []string{
			"runtime_snapshot_complete", "runtime_snapshot_truncated", "active_claims",
			"expired_claims", "deleted_claims", "tombstoned_claims", "runtime_peer_checkpoint_sha256",
		}
	}
	if _, err := requireTUIJSONObjectKeys(root["lifecycle"], "lifecycle", lifecycleRequired, lifecycleOptional); err != nil {
		return err
	}
	var rawRecords []json.RawMessage
	if err := json.Unmarshal(root["records"], &rawRecords); err != nil || rawRecords == nil || len(rawRecords) != len(envelope.Records) {
		return fmt.Errorf("GRC KPI records shape is invalid")
	}
	for index, rawRecord := range rawRecords {
		record, err := requireTUIJSONObjectKeys(rawRecord, fmt.Sprintf("record %d", index), []string{
			"ip", "physical_hits", "first_observed", "last_observed", "selected_jail", "jail_hits", "policy_hits",
			"enforcement", "enforcement_state", "risk_category", "policy_action", "severity_score", "severity_label",
			"peak_window_hits", "effective_threshold", "effective_window_seconds", "threshold_reached", "threshold_evidence",
			"metric_quality", "policy_quality", "hit_evidence", "hit_quality", "degraded_hits", "catalog",
		}, nil)
		if err != nil {
			return err
		}
		enforcementKeys := []string(nil)
		if envelope.Records[index].Enforcement.Jail != "" || envelope.Records[index].Enforcement.Action != "" {
			enforcementKeys = []string{"jail", "action"}
		}
		if _, err := requireTUIJSONObjectKeys(record["enforcement"], fmt.Sprintf("record %d enforcement", index), enforcementKeys, nil); err != nil {
			return err
		}
		if _, err := requireTUIJSONObjectKeys(record["catalog"], fmt.Sprintf("record %d catalog", index), []string{"version", "sha256", "risk_model_version"}, nil); err != nil {
			return err
		}
	}

	if envelope.SchemaVersion != 1 || envelope.Status != "complete" && envelope.Status != "degraded" || envelope.Records == nil || len(envelope.Records) > 512 {
		return fmt.Errorf("GRC KPI document metadata is invalid")
	}
	if envelope.Window.Complete {
		if envelope.Window.Scope != "retained-telemetry-journal" || envelope.Evidence.JournalBytesScanned != envelope.Evidence.JournalBytesTotal {
			return fmt.Errorf("GRC KPI complete window is invalid")
		}
	} else if envelope.Window.Scope != "retained-telemetry-journal-tail" {
		return fmt.Errorf("GRC KPI partial window is invalid")
	}
	if !validTUIGRCCatalog(envelope.Catalog, envelope.Status == "degraded") ||
		envelope.Evidence.JournalBytesTotal < 0 || envelope.Evidence.JournalBytesScanned < 0 ||
		envelope.Evidence.JournalBytesScanned > envelope.Evidence.JournalBytesTotal ||
		envelope.Evidence.JournalDecodeErrors < 0 || envelope.Evidence.AdmittedEvents < 0 ||
		envelope.Evidence.RejectedEvents < 0 || envelope.Evidence.ExcludedEvents < 0 || envelope.Evidence.RecordsTruncated < 0 {
		return fmt.Errorf("GRC KPI evidence metadata is invalid")
	}
	if err := validateTUIGRCLifecycle(envelope.Lifecycle); err != nil {
		return err
	}
	excludedEvents := uint64(envelope.Evidence.ExcludedEvents)      // #nosec G115 -- the evidence counter is validated as nonnegative immediately above
	lifecycleRecords := uint64(envelope.Lifecycle.DeletionRecords)  // #nosec G115 -- validateTUIGRCLifecycle rejects every negative lifecycle counter
	expiryRecords := uint64(envelope.Lifecycle.ExpiryRecords)       // #nosec G115 -- validateTUIGRCLifecycle rejects every negative lifecycle counter
	tombstoneRecords := uint64(envelope.Lifecycle.TombstoneRecords) // #nosec G115 -- validateTUIGRCLifecycle rejects every negative lifecycle counter
	if lifecycleRecords > excludedEvents || expiryRecords > excludedEvents-lifecycleRecords {
		return fmt.Errorf("GRC KPI lifecycle counters are invalid")
	}
	lifecycleRecords += expiryRecords
	if tombstoneRecords > excludedEvents-lifecycleRecords {
		return fmt.Errorf("GRC KPI lifecycle counters are invalid")
	}

	seen := make(map[string]struct{}, len(envelope.Records))
	var physicalHits uint64
	admittedEvents := uint64(envelope.Evidence.AdmittedEvents)
	var firstWindow time.Time
	var lastWindow time.Time
	allRecordsComplete := true
	for index, record := range envelope.Records {
		address, addressErr := netip.ParseAddr(record.IP)
		first, firstErr := parseCanonicalTUITimestamp(record.FirstObserved)
		last, lastErr := parseCanonicalTUITimestamp(record.LastObserved)
		if addressErr != nil || address.Zone() != "" || address.Unmap().String() != record.IP || firstErr != nil || lastErr != nil || last.Before(first) ||
			record.PhysicalHits <= 0 || record.JailHits <= 0 || record.JailHits > record.PhysicalHits ||
			record.PolicyHits <= 0 || record.PolicyHits > record.JailHits || record.PeakWindowHits < 0 || record.PeakWindowHits > record.PolicyHits ||
			record.EffectiveThreshold <= 0 || record.EffectiveThreshold > 1_000_000_000 || record.EffectiveWindowSeconds < 0 ||
			record.EffectiveWindowSeconds > 31_536_000 || record.DegradedHits < 0 || record.DegradedHits > record.PhysicalHits ||
			!validTUIPrintableASCII(record.SelectedJail, 256) || !validTUIEnforcementState(record.EnforcementState) ||
			record.SeverityScore < 0 || record.SeverityScore > 100 || record.SeverityLabel != tuiSeverityLabel(record.SeverityScore) ||
			!validTUIRiskCategory(record.RiskCategory) || !validTUIRuleAction(record.PolicyAction) ||
			!validTUIGRCMetricQuality(record.MetricQuality) || !validTUIGRCPolicyQuality(record.PolicyQuality) ||
			!validTUIGRCHitQuality(record.HitQuality) || !validTUIGRCHitEvidence(record.HitEvidence) ||
			!validTUIGRCCatalog(record.Catalog, true) {
			return fmt.Errorf("GRC KPI record %d is invalid", index)
		}
		if _, duplicate := seen[record.IP]; duplicate {
			return fmt.Errorf("GRC KPI record %d duplicates an IP", index)
		}
		seen[record.IP] = struct{}{}
		if record.Enforcement.Jail == "" || record.Enforcement.Action == "" {
			if record.Enforcement != (tuiGRCKPIEnforcement{}) {
				return fmt.Errorf("GRC KPI record %d has partial enforcement", index)
			}
		} else if !validTUIPrintableASCII(record.Enforcement.Jail, 256) ||
			record.Enforcement.Action != "ban" && record.Enforcement.Action != "detect" && record.Enforcement.Action != "track" {
			return fmt.Errorf("GRC KPI record %d enforcement is invalid", index)
		}
		if err := validateTUIGRCQualityConsistency(record); err != nil {
			return fmt.Errorf("GRC KPI record %d quality is invalid: %w", index, err)
		}
		if err := validateTUIGRCPolicyEvidence(record); err != nil {
			return fmt.Errorf("GRC KPI record %d policy is invalid: %w", index, err)
		}
		if record.PolicyQuality == "legacy-estimate" {
			if record.Enforcement != (tuiGRCKPIEnforcement{}) || record.Catalog != (tuiGRCKPICatalog{}) {
				return fmt.Errorf("GRC KPI record %d legacy policy is over-attested", index)
			}
		} else if record.Enforcement == (tuiGRCKPIEnforcement{}) || record.Catalog == (tuiGRCKPICatalog{}) {
			return fmt.Errorf("GRC KPI record %d verified policy is incomplete", index)
		}
		if record.MetricQuality == "attested" && record.PolicyQuality != "attested" ||
			record.MetricQuality == "recorded-unverified" && record.PolicyQuality != "recorded-unverified" ||
			record.MetricQuality == "legacy-estimate" && record.PolicyQuality != "legacy-estimate" {
			return fmt.Errorf("GRC KPI record %d metric and policy quality conflict", index)
		}
		recordPhysicalHits := uint64(record.PhysicalHits)
		if recordPhysicalHits > admittedEvents || physicalHits > admittedEvents-recordPhysicalHits {
			return fmt.Errorf("GRC KPI physical-hit total exceeds admitted events")
		}
		physicalHits += recordPhysicalHits
		if firstWindow.IsZero() || first.Before(firstWindow) {
			firstWindow = first
		}
		if lastWindow.IsZero() || last.After(lastWindow) {
			lastWindow = last
		}
		if record.MetricQuality != "attested" || record.PolicyQuality != "attested" || record.HitQuality != "measured" ||
			record.DegradedHits != 0 || record.EnforcementState == "unknown" || record.Catalog != envelope.Catalog {
			allRecordsComplete = false
		}
	}
	if len(envelope.Records) == 0 {
		if envelope.Window.First != "" || envelope.Window.Last != "" {
			return fmt.Errorf("empty GRC KPI records have a non-empty window")
		}
	} else if envelope.Window.First != firstWindow.UTC().Format(time.RFC3339Nano) || envelope.Window.Last != lastWindow.UTC().Format(time.RFC3339Nano) {
		return fmt.Errorf("GRC KPI record window is inconsistent")
	}
	if envelope.Evidence.RecordsTruncated == 0 {
		if physicalHits != admittedEvents {
			return fmt.Errorf("GRC KPI physical-hit total is inconsistent")
		}
	} else if len(envelope.Records) != 512 || physicalHits >= admittedEvents ||
		admittedEvents-physicalHits < uint64(envelope.Evidence.RecordsTruncated) {
		return fmt.Errorf("GRC KPI truncation evidence is inconsistent")
	}
	if envelope.Status == "complete" && (!envelope.Window.Complete || envelope.Catalog.Version == "" ||
		envelope.Evidence.JournalDecodeErrors != 0 || envelope.Evidence.RejectedEvents != 0 || envelope.Evidence.RecordsTruncated != 0 ||
		!envelope.Lifecycle.RuntimeStateLinked || !envelope.Lifecycle.RuntimeSnapshotComplete ||
		envelope.Lifecycle.RuntimeSnapshotTruncated || envelope.Lifecycle.RuntimeCoordination != "healthy" ||
		envelope.Lifecycle.RuntimePeerCheckpointSHA256 != envelope.Lifecycle.RuntimeCheckpointSHA256 || !allRecordsComplete) {
		return fmt.Errorf("GRC KPI document over-declares complete evidence")
	}
	return nil
}

func requireTUIJSONObjectKeys(raw []byte, label string, required, optional []string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("GRC KPI %s is not an object", label)
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = struct{}{}
		if _, present := object[key]; !present {
			return nil, fmt.Errorf("GRC KPI %s is missing %s", label, key)
		}
	}
	for _, key := range optional {
		allowed[key] = struct{}{}
	}
	for key := range object {
		if _, permitted := allowed[key]; !permitted {
			return nil, fmt.Errorf("GRC KPI %s has unknown key %s", label, key)
		}
	}
	return object, nil
}

func validateTUIGRCLifecycle(lifecycle tuiGRCKPILifecycle) error {
	if lifecycle.DeletionRecords < 0 || lifecycle.ExpiryRecords < 0 || lifecycle.TombstoneRecords < 0 {
		return fmt.Errorf("GRC KPI lifecycle counters are invalid")
	}
	if !lifecycle.RuntimeStateLinked {
		if lifecycle.Scope != "observed-telemetry-records-only" || lifecycle.RuntimeSnapshotComplete || lifecycle.RuntimeSnapshotTruncated ||
			lifecycle.RuntimeClusterID != "" || lifecycle.RuntimeEpoch != 0 || lifecycle.RuntimeNodeID != "" || lifecycle.RuntimeRole != "" ||
			lifecycle.RuntimeCoordination != "" || lifecycle.RuntimeModelSHA256 != "" || lifecycle.RuntimeCheckpointSHA256 != "" ||
			lifecycle.RuntimePeerCheckpointSHA256 != "" || lifecycle.RuntimeCheckpointAt != "" || lifecycle.RuntimeCapturedAt != "" ||
			lifecycle.ActiveClaims != 0 || lifecycle.ExpiredClaims != 0 || lifecycle.DeletedClaims != 0 || lifecycle.TombstonedClaims != 0 {
			return fmt.Errorf("unlinked GRC KPI lifecycle is invalid")
		}
		return nil
	}
	if lifecycle.Scope != "ha-v2-runtime-snapshot" || lifecycle.RuntimeSnapshotComplete == lifecycle.RuntimeSnapshotTruncated ||
		!validTUIRuntimeID(lifecycle.RuntimeClusterID) || lifecycle.RuntimeEpoch == 0 || !validTUIRuntimeID(lifecycle.RuntimeNodeID) ||
		lifecycle.RuntimeRole != "writer" && lifecycle.RuntimeRole != "standby" ||
		lifecycle.RuntimeCoordination != "healthy" && lifecycle.RuntimeCoordination != "degraded" &&
			lifecycle.RuntimeCoordination != "fenced" && lifecycle.RuntimeCoordination != "recovering" ||
		!validTUIHexDigest(lifecycle.RuntimeModelSHA256) || !validTUIHexDigest(lifecycle.RuntimeCheckpointSHA256) ||
		lifecycle.RuntimePeerCheckpointSHA256 != "" && !validTUIHexDigest(lifecycle.RuntimePeerCheckpointSHA256) {
		return fmt.Errorf("linked GRC KPI lifecycle is invalid")
	}
	if lifecycle.RuntimeCoordination == "healthy" && lifecycle.RuntimePeerCheckpointSHA256 != lifecycle.RuntimeCheckpointSHA256 {
		return fmt.Errorf("healthy GRC KPI checkpoints diverge")
	}
	checkpointAt, err := parseCanonicalTUITimestamp(lifecycle.RuntimeCheckpointAt)
	if err != nil {
		return fmt.Errorf("linked GRC KPI checkpoint time is invalid")
	}
	capturedAt, err := parseCanonicalTUITimestamp(lifecycle.RuntimeCapturedAt)
	if err != nil {
		return fmt.Errorf("linked GRC KPI lifecycle timestamp is invalid")
	}
	if checkpointAt.After(capturedAt.Add(tuiRuntimeCheckpointTimeTolerance)) ||
		lifecycle.RuntimeCoordination == "healthy" && checkpointAt.Before(capturedAt.Add(-tuiRuntimeCheckpointTimeTolerance)) {
		return fmt.Errorf("linked GRC KPI checkpoint timing is invalid")
	}
	claimCounts := []int{lifecycle.ActiveClaims, lifecycle.ExpiredClaims, lifecycle.DeletedClaims, lifecycle.TombstonedClaims}
	total := 0
	for _, count := range claimCounts {
		if count < 0 || count > 16384 || total > 16384-count {
			return fmt.Errorf("linked GRC KPI claim counters are invalid")
		}
		total += count
	}
	return nil
}

func validTUIGRCCatalog(catalog tuiGRCKPICatalog, allowEmpty bool) bool {
	if catalog == (tuiGRCKPICatalog{}) {
		return allowEmpty
	}
	return validTUIPrintableASCII(catalog.Version, 128) && validTUIHexDigest(catalog.SHA256) && catalog.RiskModelVersion == "sw-risk-v1"
}

func validTUIHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func parseCanonicalTUITimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("timestamp is not canonical UTC")
	}
	return parsed, nil
}

func validTUIPrintableASCII(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < '!' || character > '~' {
			return false
		}
	}
	return true
}

func validTUIEnforcementState(value string) bool {
	switch value {
	case "active", "expired", "deleted", "tombstoned", "absent", "unknown":
		return true
	default:
		return false
	}
}

func validTUIRiskCategory(value string) bool {
	switch value {
	case "exploit", "brute_force", "reconnaissance", "denial_of_service", "abuse":
		return true
	default:
		return false
	}
}

func validTUIRuleAction(value string) bool {
	return value == "ban" || value == "detect" || value == "track"
}

func validTUIGRCMetricQuality(value string) bool {
	return value == "attested" || value == "recorded-unverified" || value == "mixed" || value == "legacy-estimate"
}

func validTUIGRCPolicyQuality(value string) bool {
	return value == "attested" || value == "recorded-unverified" || value == "legacy-estimate"
}

func validTUIGRCHitQuality(value string) bool {
	return value == "measured" || value == "degraded" || value == "mixed" || value == "legacy-estimate"
}

func validTUIGRCHitEvidence(value string) bool {
	switch value {
	case "collector-content-window-v1", "collector-content-window-degraded-v1",
		"kernel-log-observation-v1", "kernel-log-observation-degraded-v1",
		"mixed", "legacy-estimate":
		return true
	default:
		return false
	}
}

func validateTUIGRCQualityConsistency(record tuiGRCKPIRecord) error {
	switch record.HitQuality {
	case "measured":
		if record.DegradedHits != 0 || record.HitEvidence == "legacy-estimate" || strings.Contains(record.HitEvidence, "degraded") {
			return fmt.Errorf("measured hits carry degraded evidence")
		}
	case "degraded":
		if record.DegradedHits == 0 || record.HitEvidence != "mixed" && !strings.Contains(record.HitEvidence, "degraded") {
			return fmt.Errorf("degraded hits lack degraded evidence")
		}
	case "mixed":
		if record.HitEvidence != "mixed" {
			return fmt.Errorf("mixed hit quality lacks mixed evidence")
		}
	case "legacy-estimate":
		if record.DegradedHits != 0 || record.HitEvidence != "legacy-estimate" {
			return fmt.Errorf("legacy hit quality conflicts with evidence")
		}
	}
	return nil
}

func validateTUIGRCPolicyEvidence(record tuiGRCKPIRecord) error {
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
	if record.SeverityScore != tuiGRCRiskScore(record) {
		return fmt.Errorf("severity score does not match policy evidence")
	}
	return nil
}

func tuiGRCRiskScore(record tuiGRCKPIRecord) int {
	base := map[string]int{
		"exploit": 50, "brute_force": 20, "reconnaissance": 20,
		"denial_of_service": 40, "abuse": 10,
	}[record.RiskCategory]
	score := base
	switch record.PolicyAction {
	case "ban":
		score += 20 + 10*min(record.PolicyHits, 4)
	case "detect":
		score += 10 + 10*min(record.PolicyHits, 4)
	case "track":
		effectivePeak := record.PeakWindowHits
		if record.ThresholdReached && effectivePeak < record.EffectiveThreshold {
			effectivePeak = record.EffectiveThreshold
		}
		score += (40*min(effectivePeak, record.EffectiveThreshold) + record.EffectiveThreshold - 1) / record.EffectiveThreshold
		if record.PeakWindowHits >= record.EffectiveThreshold || record.ThresholdReached {
			score += 20
		}
	}
	return min(score, 100)
}

func tuiSeverityLabel(score int) string {
	if score >= 80 {
		return "Critical"
	}
	if score >= 50 {
		return "High Risk"
	}
	return "Suspicious"
}

func validTUIRuntimeID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		alphaNumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alphaNumeric && (index == 0 || character != '.' && character != '_' && character != '-') {
			return false
		}
	}
	return true
}

func optionalKPIInt(value *int) string {
	if value == nil {
		return "unavailable"
	}
	return strconv.Itoa(*value)
}

func optionalKPIInt64(value *int64) string {
	if value == nil {
		return "unavailable"
	}
	return strconv.FormatInt(*value, 10)
}

func optionalKPIBool(value *bool) string {
	if value == nil {
		return "unavailable"
	}
	return strconv.FormatBool(*value)
}

func waapKPIEvidenceSummary(waf WAF) string {
	quality := strings.TrimSpace(waf.KPIEvidenceQuality)
	if quality == "" {
		quality = "unavailable"
	}
	return fmt.Sprintf("quality=%s journal_complete=%s scan_bytes=%s/%s decode_errors=%s rejected_events=%s grc=%s",
		quality,
		optionalKPIBool(waf.JournalScanComplete),
		optionalKPIInt64(waf.JournalBytesScanned),
		optionalKPIInt64(waf.JournalBytesTotal),
		optionalKPIInt(waf.JournalDecodeErrors),
		optionalKPIInt(waf.MetricRejectedEvents),
		grcKPIEvidenceSummary(waf.GRCKPI),
	)
}

func bannedRegistryState(entry BannedIP) string {
	if entry.EnforcementState == "active" {
		return "BAN"
	}
	return "UNKNOWN"
}

func topAttackersKPIEvidenceTitle(waf WAF) string {
	if kpiEvidenceDegradedOrUnavailable(waf) {
		return topAttackersTitleDegraded
	}
	return topAttackersTitleNormal
}

var (
	app            *tview.Application
	data           DashboardData
	mu             sync.Mutex
	headerText     *tview.TextView
	l3Text         *tview.TextView
	vectorsText    *tview.TextView
	trustedText    *tview.TextView
	portsTable     *tview.Table
	sparklineText  *tview.TextView
	attackersTable *tview.Table
	bannedTable    *tview.Table

	recentlyUnbanned   = make(map[string]time.Time)
	recentlyUnbannedMu sync.Mutex

	fetchError error
)

func main() {
	removalInProgress, err := inspectTUIRemovalTombstone(tuiRemovalTombstonePath, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[SYSWARDEN-TUI] Refusing startup while removal state is unsafe: %v\n", err)
		os.Exit(1)
	}
	if removalInProgress {
		fmt.Fprintf(os.Stderr, "[SYSWARDEN-TUI] Refusing startup while %s is present\n", tuiRemovalTombstonePath)
		os.Exit(1)
	}
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		printDashboardText()
		return
	}

	app = tview.NewApplication()

	// 1. Header (System Info)
	headerText = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(true)
	headerText.SetBorder(true).
		SetTitle(fmt.Sprintf(" [white::b]SYSWARDEN %s[-:-:-] ", SysWardenVersion)).
		SetTitleColor(tcell.ColorAqua).
		SetBorderColor(tcell.ColorBlue)

	// 2. L3 Blocks
	l3Text = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	l3Text.SetBorder(true).SetTitle(" [cyan]❖ L3 KERNEL BLOCKS (GLOBAL)[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 3. Risk Vectors
	vectorsText = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	vectorsText.SetBorder(true).SetTitle(" [white]❖ GLOBAL RISK VECTORS[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 4. Trusted Hosts
	trustedText = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	trustedText.SetBorder(true).SetTitle(" [green]❖ TRUSTED HOSTS (WHITELIST)[-] ").SetBorderColor(tcell.ColorDarkGray)

	metricsFlex := tview.NewFlex().
		AddItem(l3Text, 0, 1, false).
		AddItem(vectorsText, 0, 2, false).
		AddItem(trustedText, 0, 1, false)

	// 5. Ports Table
	portsTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	portsTable.SetBorder(true).SetTitle(" [white]❖ TOP TARGETED PORTS[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 5b. Sparkline
	sparklineText = tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetTextAlign(tview.AlignLeft)
	sparklineText.SetBorder(true).SetTitle(" [white]❖ WAF L7 BANS (24H)[-] ").SetBorderColor(tcell.ColorDarkGray)

	// 6. Top Attackers Table
	attackersTable = tview.NewTable().SetBorders(false).SetSelectable(false, false)
	attackersTable.SetBorder(true).SetTitle(topAttackersTitleDegraded).SetBorderColor(tcell.ColorDarkGray)

	midFlex := tview.NewFlex().
		AddItem(portsTable, 0, 3, false).
		AddItem(attackersTable, 0, 5, false)

	// 7. Banned IPs Table
	bannedTable = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0)
	bannedTable.SetBorder(true).
		SetTitle(" [white]❖ WAF ALLOWED/BANNED IP REGISTRY (L4/L7)[-] ").
		SetBorderColor(tcell.ColorBlue)

	// Layout Setup
	mainFlex := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(headerText, 8, 1, false).
		AddItem(metricsFlex, 6, 1, false).
		AddItem(midFlex, 8, 1, false).
		AddItem(sparklineText, 10, 1, false).
		AddItem(bannedTable, 0, 3, true)

	bannedTable.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'u' || event.Rune() == 'U' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				if cell != nil {
					ip := cell.Text
					if ip != "" && ip != emptyRegistryMessage {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to delete / unban IP %s from the list?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									go func(targetIP string) {
										if err := runSyswardenIPAction("unblock", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "unblock", targetIP, err)
											return
										}
										recentlyUnbannedMu.Lock()
										recentlyUnbanned[targetIP] = time.Now()
										recentlyUnbannedMu.Unlock()
										readDataAndUpdate()
									}(ip)
								}
								app.SetRoot(mainFlex, true)
							})
						app.SetRoot(modal, false)
					}
				}
			}
		} else if event.Rune() == 'w' || event.Rune() == 'W' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				if cell != nil {
					ip := cell.Text
					if ip != "" {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to permanently WHITELIST IP %s?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									go func(targetIP string) {
										if err := runSyswardenIPAction("whitelist", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "whitelist", targetIP, err)
											return
										}
										readDataAndUpdate()
									}(ip)
								}
								app.SetRoot(mainFlex, true)
							})
						app.SetRoot(modal, false)
					}
				}
			}
		} else if event.Rune() == 'b' || event.Rune() == 'B' {
			row, _ := bannedTable.GetSelection()
			if row > 0 {
				cell := bannedTable.GetCell(row, 0)
				stateCell := bannedTable.GetCell(row, 3)
				if cell != nil && stateCell != nil {
					ip := cell.Text
					state := stateCell.Text
					if ip != "" && state == "DETECT" {
						modal := tview.NewModal().
							SetText(fmt.Sprintf("[white]Do you want to permanently BAN IP %s?[-]", ip)).
							AddButtons([]string{"y", "n"}).
							SetDoneFunc(func(buttonIndex int, buttonLabel string) {
								if buttonLabel == "y" {
									go func(targetIP string) {
										if err := runSyswardenIPAction("block", targetIP); err != nil {
											showTUIActionError(app, mainFlex, "block", targetIP, err)
											return
										}
										readDataAndUpdate()
									}(ip)
								}
								app.SetRoot(mainFlex, true)
							})
						app.SetRoot(modal, false)
					}
				}
			}
		}
		return event
	})

	// Ensure safe exiting via Q/Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 'q' || event.Rune() == 'Q' || event.Key() == tcell.KeyCtrlC {
			cancel()
			app.EnableMouse(false)
			time.Sleep(50 * time.Millisecond)
			app.Stop()
			return nil
		}
		if event.Key() == tcell.KeyEscape {
			showP2PMenu(mainFlex)
			return nil
		}
		return event
	})

	// Background Poller
	go func() {
		// First read immediately
		readDataAndUpdate()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				readDataAndUpdate()
			}
		}
	}()

	runErr := app.SetRoot(mainFlex, true).EnableMouse(true).Run()
	cancel()
	if exitCode := reportTUIRunResult(runErr, os.Stderr); exitCode != 0 {
		os.Exit(exitCode)
	}
}

func reportTUIRunResult(err error, output io.Writer) int {
	if err == nil {
		return 0
	}
	if output != nil {
		_, _ = fmt.Fprintf(output, "[SYSWARDEN-TUI] Terminal application failed: %v\n", err)
	}
	return 1
}

func escapeTUIDynamicValue(value string) string {
	return tview.Escape(value)
}

func showTUIActionError(app *tview.Application, mainFlex *tview.Flex, action, target string, err error) {
	app.QueueUpdateDraw(func() {
		modal := tview.NewModal().
			SetText(fmt.Sprintf("[red]SysWarden %s failed for %s: %s[-]",
				escapeTUIDynamicValue(action), escapeTUIDynamicValue(target), escapeTUIDynamicValue(err.Error()))).
			AddButtons([]string{"ok"}).
			SetDoneFunc(func(int, string) { app.SetRoot(mainFlex, true) })
		app.SetRoot(modal, false)
	})
}

// --- P2P MESH TUI LOGIC ---

type tuiHAConfig struct {
	Enabled  bool
	PeerIPs  []string
	PeerPort string
	Token    string
}

func getHAPeers() []string {
	cfg, err := loadTUIHAConfig(haModularConfigDirectory, haLegacyConfigFile)
	haRuntimeConfigMu.Lock()
	defer haRuntimeConfigMu.Unlock()
	haRuntimeConfigErr = err
	if err != nil || !cfg.Enabled {
		haBearerToken = ""
		return nil
	}
	haPeerPort = cfg.PeerPort
	haBearerToken = cfg.Token
	return dialableTUIHAPeers(cfg.PeerIPs)
}

func loadTUIHAConfig(modularDirectory, legacyFile string) (tuiHAConfig, error) {
	info, err := os.Lstat(modularDirectory)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return tuiHAConfig{}, fmt.Errorf("modular HA config must be a real directory")
		}
		cfg := tuiHAConfig{PeerPort: "62026"}
		files := make([]string, 0)
		master := filepath.Join(modularDirectory, "config.toml")
		if _, statErr := os.Lstat(master); statErr == nil {
			files = append(files, master)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return tuiHAConfig{}, fmt.Errorf("inspect modular HA master config: %w", statErr)
		}
		modules := filepath.Join(modularDirectory, "modules")
		if moduleInfo, statErr := os.Lstat(modules); statErr == nil {
			if moduleInfo.Mode()&os.ModeSymlink != 0 || !moduleInfo.IsDir() {
				return tuiHAConfig{}, fmt.Errorf("modular HA modules path must be a real directory")
			}
			entries, readErr := os.ReadDir(modules)
			if readErr != nil {
				return tuiHAConfig{}, fmt.Errorf("read modular HA modules: %w", readErr)
			}
			moduleFiles := make([]string, 0)
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".toml") {
					moduleFiles = append(moduleFiles, filepath.Join(modules, entry.Name()))
				}
			}
			sort.Strings(moduleFiles)
			files = append(files, moduleFiles...)
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return tuiHAConfig{}, fmt.Errorf("inspect modular HA modules: %w", statErr)
		}
		for _, file := range files {
			wire, readErr := readTUIConfigFile(file)
			if readErr != nil {
				return tuiHAConfig{}, readErr
			}
			if err := mergeTUIHATOML(&cfg, wire); err != nil {
				return tuiHAConfig{}, fmt.Errorf("parse modular HA configuration: %w", err)
			}
		}
		return validateTUIHAConfig(cfg)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return tuiHAConfig{}, fmt.Errorf("inspect modular HA configuration: %w", err)
	}
	wire, err := readTUIConfigFile(legacyFile)
	if err != nil {
		return tuiHAConfig{}, fmt.Errorf("read legacy HA configuration: %w", err)
	}
	cfg, err := parseTUILegacyHAConfig(wire)
	if err != nil {
		return tuiHAConfig{}, err
	}
	return validateTUIHAConfig(cfg)
}

func readTUIConfigFile(path string) ([]byte, error) {
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("HA configuration file must be regular")
	}
	if info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("HA configuration file must not be group/world writable")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := root.Lstat(filepath.Base(path))
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() ||
		!os.SameFile(info, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("HA configuration file changed while opening")
	}
	const maxConfigBytes = 1024 * 1024
	wire, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(wire) > maxConfigBytes {
		return nil, fmt.Errorf("HA configuration file is too large")
	}
	return wire, nil
}

func mergeTUIHATOML(cfg *tuiHAConfig, wire []byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(wire)))
	section := ""
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(stripTUIConfigComment(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("invalid TOML section")
			}
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		if section != "integrations.ha" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid HA TOML assignment")
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate HA TOML key")
		}
		seen[key] = struct{}{}
		switch key {
		case "enabled":
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}
			cfg.Enabled = parsed
		case "peer_ips":
			values, err := parseTUIStringArray(value)
			if err != nil {
				return err
			}
			cfg.PeerIPs = values
		case "peer_port":
			cfg.PeerPort = strings.Trim(value, "\"'")
		case "token":
			parsed, err := parseTUIQuotedString(value)
			if err != nil {
				return err
			}
			cfg.Token = parsed
		}
	}
	return scanner.Err()
}

func stripTUIConfigComment(line string) string {
	var quote rune
	escaped := false
	for index, character := range line {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote == '"' {
			escaped = true
			continue
		}
		if character == '\'' || character == '"' {
			if quote == 0 {
				quote = character
			} else if quote == character {
				quote = 0
			}
			continue
		}
		if character == '#' && quote == 0 {
			return line[:index]
		}
	}
	return line
}

func parseTUIQuotedString(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 {
		return "", fmt.Errorf("HA TOML value must be quoted")
	}
	if value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1], nil
	}
	if value[0] != '"' || value[len(value)-1] != '"' {
		return "", fmt.Errorf("HA TOML value must be quoted")
	}
	return strconv.Unquote(value)
}

func parseTUIStringArray(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != '[' || value[len(value)-1] != ']' {
		return nil, fmt.Errorf("HA peer_ips must be a string array")
	}
	inner := strings.TrimSpace(value[1 : len(value)-1])
	if inner == "" {
		return []string{}, nil
	}
	parts := strings.Split(inner, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		parsed, err := parseTUIQuotedString(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		result = append(result, parsed)
	}
	return result, nil
}

func parseTUILegacyHAConfig(wire []byte) (tuiHAConfig, error) {
	cfg := tuiHAConfig{PeerPort: "62026"}
	scanner := bufio.NewScanner(strings.NewReader(string(wire)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		switch strings.TrimSpace(parts[0]) {
		case "SYSWARDEN_HA_ENABLED":
			cfg.Enabled = value == "y" || value == "1" || strings.EqualFold(value, "true")
		case "SYSWARDEN_HA_PEER_IP":
			cfg.PeerIPs = strings.Fields(strings.ReplaceAll(value, ",", " "))
		case "SYSWARDEN_HA_PEER_PORT":
			cfg.PeerPort = value
		case "SYSWARDEN_HA_TOKEN":
			cfg.Token = value
		}
	}
	return cfg, scanner.Err()
}

func validateTUIHAConfig(cfg tuiHAConfig) (tuiHAConfig, error) {
	if cfg.PeerPort == "" {
		cfg.PeerPort = "62026"
	}
	port, err := strconv.Atoi(cfg.PeerPort)
	if err != nil || port < 1 || port > 65535 {
		return tuiHAConfig{}, fmt.Errorf("invalid HA peer port")
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	if cfg.Token == "" || strings.TrimSpace(cfg.Token) != cfg.Token {
		return tuiHAConfig{}, fmt.Errorf("HA bearer token is required; configure integrations.ha.token and upgrade legacy HA clients")
	}
	if len(cfg.PeerIPs) == 0 {
		return tuiHAConfig{}, fmt.Errorf("HA peer_ips is required")
	}
	for _, peer := range cfg.PeerIPs {
		if strings.Contains(peer, "/") {
			prefix, err := netip.ParsePrefix(peer)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Masked().Addr() {
				return tuiHAConfig{}, fmt.Errorf("invalid HA peer CIDR")
			}
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return tuiHAConfig{}, fmt.Errorf("invalid exact HA peer")
		}
	}
	return cfg, nil
}

func dialableTUIHAPeers(configured []string) []string {
	peers := make([]string, 0, len(configured))
	seen := make(map[string]struct{}, len(configured))
	for _, peer := range configured {
		if strings.Contains(peer, "/") {
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			continue
		}
		canonical := address.String()
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		peers = append(peers, canonical)
	}
	return peers
}

func showP2PMenu(mainFlex *tview.Flex) {
	list := tview.NewList().
		AddItem("ACTUAL NODE", "Supervise local telemetry", '1', func() {
			activeNode.selectNode("local")
			app.SetRoot(mainFlex, true)
			go readDataAndUpdate()
		}).
		AddItem("NODES HA-CLUSTERS", "Explore and supervise HA peer nodes", '2', func() {
			showNodesList(mainFlex)
		}).
		AddItem("HOTKEYS", "Show functional hotkeys", '3', func() {
			showHotkeysMenu(mainFlex)
		}).
		AddItem("EXIT", "Quit SysWarden TUI", '4', func() {
			app.EnableMouse(false)
			time.Sleep(50 * time.Millisecond)
			app.Stop()
		})

	list.SetBorder(true).
		SetTitle(" [white]❖ P2P HA-CLUSTER MESH MENU[-] ").
		SetBorderColor(tcell.ColorBlue)

	app.SetRoot(list, true)
}

func showHotkeysMenu(mainFlex *tview.Flex) {
	modal := tview.NewModal().
		SetText("[white]P2P TUI HOTKEYS[-]\n\n[yellow]Esc[-]    : Open P2P HA-Cluster Menu\n[yellow]Ctrl+C[-] : Force exit TUI\n[yellow]q / Q[-]  : Quit TUI\n[yellow]u / U[-]  : Unban IP (when in ALLOWED/BANNED table)\n[yellow]Tab[-]    : Switch focus between panels\n[yellow]Enter[-]  : Select Node in HA-Cluster Explorer").
		AddButtons([]string{"Back"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			showP2PMenu(mainFlex)
		})
	app.SetRoot(modal, false)
}

func showNodesList(mainFlex *tview.Flex) {
	peers := getHAPeers()

	table := tview.NewTable().
		SetBorders(true).
		SetSelectable(true, false).
		SetFixed(1, 0)

	table.SetBorder(true).
		SetTitle(" [white]❖ HA-CLUSTER NODES EXPLORER[-] ").
		SetBorderColor(tcell.ColorBlue)

	table.SetCell(0, 0, tview.NewTableCell("Hostname").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 1, tview.NewTableCell("IP").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 2, tview.NewTableCell("OS").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 3, tview.NewTableCell("Status").SetTextColor(tcell.ColorYellow).SetSelectable(false))
	table.SetCell(0, 4, tview.NewTableCell("Version").SetTextColor(tcell.ColorYellow).SetSelectable(false))

	if len(peers) == 0 {
		table.SetCell(1, 0, tview.NewTableCell("No dialable exact HA peers configured").SetTextColor(tcell.ColorGray))
	} else {
		for i, ip := range peers {
			row := i + 1
			table.SetCell(row, 0, tview.NewTableCell("Probing...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 1, tview.NewTableCell(ip).SetTextColor(tcell.ColorWhite))
			table.SetCell(row, 2, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 3, tview.NewTableCell("[gray]WAITING[-]").SetTextColor(tcell.ColorGray))
			table.SetCell(row, 4, tview.NewTableCell("...").SetTextColor(tcell.ColorGray))

			go func(ip string, r int) {
				endpoint, endpointErr := haPeerURL(ip, "/ha/status")
				var resp *http.Response
				err := endpointErr
				if err == nil {
					resp, err = haGet(endpoint)
				}

				app.QueueUpdateDraw(func() {
					if err != nil {
						table.SetCell(r, 0, tview.NewTableCell("Unknown").SetTextColor(tcell.ColorDarkGray))
						table.SetCell(r, 2, tview.NewTableCell("Unknown").SetTextColor(tcell.ColorDarkGray))
						table.SetCell(r, 3, tview.NewTableCell("OFFLINE").SetTextColor(tcell.ColorRed))
						table.SetCell(r, 4, tview.NewTableCell("-").SetTextColor(tcell.ColorDarkGray))
						return
					}
					defer func() { _ = resp.Body.Close() }()

					if resp.StatusCode == 200 {
						var status struct {
							Hostname string `json:"hostname"`
							OS       string `json:"os"`
							Version  string `json:"version"`
							Status   string `json:"status"`
						}
						_ = json.NewDecoder(resp.Body).Decode(&status)
						table.SetCell(r, 0, tview.NewTableCell(tview.Escape(status.Hostname)).SetTextColor(tcell.ColorWhite))
						table.SetCell(r, 2, tview.NewTableCell(tview.Escape(status.OS)).SetTextColor(tcell.ColorWhite))
						table.SetCell(r, 3, tview.NewTableCell("ONLINE").SetTextColor(tcell.ColorGreen))
						table.SetCell(r, 4, tview.NewTableCell(tview.Escape(status.Version)).SetTextColor(tcell.ColorWhite))
					} else {
						table.SetCell(r, 3, tview.NewTableCell("OFFLINE").SetTextColor(tcell.ColorRed))
					}
				})
			}(ip, row)
		}
	}

	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			showP2PMenu(mainFlex)
			return nil
		}
		if event.Key() == tcell.KeyEnter {
			row, _ := table.GetSelection()
			if row > 0 {
				cell := table.GetCell(row, 1)
				if cell != nil && cell.Text != "" {
					activeNode.selectNode(cell.Text)
					app.SetRoot(mainFlex, true)
					go readDataAndUpdate()
				}
			}
			return nil
		}
		return event
	})

	app.SetRoot(table, true)
}

func readDataAndUpdate() {
	dashboardFetchMu.Lock()
	defer dashboardFetchMu.Unlock()

	targetNode, generation := activeNode.snapshot()
	var bytes []byte
	var err error

	if targetNode == "local" {
		bytes, err = readTUIDashboardFile(DataFile)
	} else {
		endpoint, reqErr := haPeerURL(targetNode, "/ha/telemetry")
		var resp *http.Response
		if reqErr == nil {
			resp, reqErr = haGet(endpoint)
		}
		if reqErr != nil {
			err = reqErr
		} else {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode == 200 {
				bytes, err = io.ReadAll(resp.Body)
			} else {
				err = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}
	}

	var newData DashboardData
	if err == nil {
		if decoded, decodeErr := decodeTUIDashboardData(bytes); decodeErr != nil {
			err = decodeErr
		} else {
			newData = decoded
		}
	}
	if !applyDashboardFetchResult(&activeNode, targetNode, generation, newData, err) {
		return
	}

	app.QueueUpdateDraw(func() {
		refreshUI()
	})
}

func applyDashboardFetchResult(
	selection *tuiNodeSelection,
	targetNode string,
	generation uint64,
	newData DashboardData,
	fetchErr error,
) bool {
	return selection.ifCurrent(targetNode, generation, func() {
		mu.Lock()
		defer mu.Unlock()
		if fetchErr != nil {
			if targetNode == "local" {
				fetchError = fmt.Errorf("data unreadable: %w", fetchErr)
			} else {
				fetchError = fmt.Errorf("node %s unreachable: %w", targetNode, fetchErr)
			}
			return
		}
		fetchError = nil
		data = newData
		for i, j := 0, len(data.WAF.BannedIPs)-1; i < j; i, j = i+1, j-1 {
			data.WAF.BannedIPs[i], data.WAF.BannedIPs[j] = data.WAF.BannedIPs[j], data.WAF.BannedIPs[i]
		}
		sort.Slice(data.WAF.SignaturesData, func(i, j int) bool {
			return data.WAF.SignaturesData[i].Count > data.WAF.SignaturesData[j].Count
		})
	})
}

func buildProgressBar(used, total int, label string, color string) string {
	if total <= 0 || used <= 0 {
		return fmt.Sprintf("[gray][%s 0%%][-]", label)
	}
	pct := float64(used) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}

	barsCount := 20
	filled := int(pct * float64(barsCount))
	if filled > barsCount {
		filled = barsCount
	}

	barStr := strings.Repeat("█", filled) + strings.Repeat("░", barsCount-filled)
	c := color
	if pct > 0.85 {
		c = "red"
	} else if pct > 0.60 {
		c = "yellow"
	}

	return fmt.Sprintf("[%s]%s %.1f%% %s[-]", c, label, pct*100, barStr)
}

func TranslateAllowedPayload(service, payload, ip, timestamp string) string {
	ts := timestamp
	if ts == "" {
		ts = time.Now().Format("2006-01-02 15:04:05")
	}
	if service == "sshd" {
		user := "unknown"
		var authMethod string
		keyInfo := ""

		if strings.Contains(payload, "Accepted publickey for ") {
			authMethod = "public key"
			parts := strings.Split(payload, "Accepted publickey for ")
			if len(parts) > 1 {
				subParts := strings.Split(parts[1], " from ")
				if len(subParts) > 0 {
					user = subParts[0]
				}
			}
			if idx := strings.Index(payload, "ssh2: "); idx != -1 {
				keyInfo = strings.TrimSpace(payload[idx+6:])
			}
		} else if strings.Contains(payload, "Accepted password for ") {
			authMethod = "password"
			parts := strings.Split(payload, "Accepted password for ")
			if len(parts) > 1 {
				subParts := strings.Split(parts[1], " from ")
				if len(subParts) > 0 {
					user = subParts[0]
				}
			}
		} else {
			return fmt.Sprintf("[%s] Access granted for IP %s", ts, ip)
		}

		if keyInfo != "" {
			return fmt.Sprintf("[%s] Access granted for user '%s' via %s (%s) from IP %s", ts, user, authMethod, keyInfo, ip)
		}
		return fmt.Sprintf("[%s] Access granted for user '%s' via %s from IP %s", ts, user, authMethod, ip)
	}

	return fmt.Sprintf("[%s] Access granted for IP %s", ts, ip)
}

func TranslatePayload(jail, payload, ip, timestamp string) string {
	ts := timestamp
	if ts == "" {
		ts = time.Now().Format("2006-01-02 15:04:05")
	}
	j := strings.ToLower(jail)
	url := fmt.Sprintf("(https://www.abuseipdb.com/check/%s)", ip)

	if strings.Contains(j, "ssh") || strings.Contains(j, "bruteforce") || strings.Contains(j, "auth") {
		port := "22"
		if idx := strings.Index(payload, "port "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				port = strings.Trim(parts[0], ":")
			}
		} else if idx := strings.Index(payload, "DPT="); idx != -1 {
			pStr := payload[idx+4:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		}
		return fmt.Sprintf("[%s] Attempted SSH brute-force on port %s by IP %s %s", ts, port, ip, url)
	}

	if strings.Contains(j, "scan") || strings.Contains(j, "zero-trust") || strings.Contains(j, "catch-all") {
		port := ""
		if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			pStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		} else if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			pStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
				port = pStr[:spaceIdx]
			}
		}

		if port == "" {
			return fmt.Sprintf("[%s] Attempted network scan by IP %s %s", ts, ip, url)
		}

		if port == "ICMP" || port == "ICMPv6" || port == "IGMP" || port == "GRE" || port == "IPSEC" || port == "IPIP" {
			return fmt.Sprintf("[%s] Attempted network sweep (Protocol: %s) by IP %s %s", ts, port, ip, url)
		}

		return fmt.Sprintf("[%s] Attempted port scan on port %s by IP %s %s", ts, port, ip, url)
	}

	if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") {
		uri := "/"
		if idx := strings.Index(payload, "GET "); idx != -1 {
			parts := strings.Split(payload[idx+4:], " ")
			if len(parts) > 0 {
				uri = parts[0]
			}
		} else if idx := strings.Index(payload, "POST "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				uri = parts[0]
			}
		}
		return fmt.Sprintf("[%s] Attempted Web exploit (%s) on URI '%s' by IP %s %s", ts, strings.ToUpper(jail), uri, ip, url)
	}

	return fmt.Sprintf("[%s] Attempted attack (%s) by IP %s %s", ts, strings.ToUpper(jail), ip, url)
}

func refreshUI() {
	mu.Lock()
	d := data
	currentErr := fetchError
	mu.Unlock()

	// --- Header Calculation ---
	ghStars, ghRelease := d.GithubStars, d.GithubRelease
	if ghStars == "" {
		ghStars = "--"
	}
	if ghRelease == "" {
		ghRelease = "--"
	}

	load1Str := "0.00"
	if parts := strings.Split(d.System.LoadAverage, ","); len(parts) > 0 {
		load1Str = strings.TrimSpace(parts[0])
	}
	loadVal, _ := strconv.ParseFloat(load1Str, 64)
	cLoad := "green"
	if loadVal >= 0.75 {
		cLoad = "red"
	} else if loadVal >= 0.50 {
		cLoad = "yellow"
	}

	var servicesStr []string
	for _, s := range d.System.Services {
		n := strings.ToUpper(s.Name)
		st := strings.ToUpper(s.Status)
		cSt := "red"
		switch st {
		case "ACTIVE", "ONLINE":
			cSt = "green"
		case "SKIPPED":
			cSt = "yellow"
		case "INACTIVE":
			cSt = "red"
		}
		if strings.Contains(st, ":") {
			cSt = "cyan"
		}
		servicesStr = append(servicesStr, fmt.Sprintf("[white]%s[-]:[%s]%s[-]",
			escapeTUIDynamicValue(n), cSt, escapeTUIDynamicValue(st)))
	}

	var portsStr []string
	for _, p := range d.System.Ports {
		portsStr = append(portsStr, fmt.Sprintf("%s:%s", escapeTUIDynamicValue(p.Protocol), escapeTUIDynamicValue(p.Port)))
	}
	pStr := strings.Join(portsStr, " │ ")
	if len(portsStr) == 0 {
		pStr = "No external ports exposed. Locked down."
	}

	ramBar := buildProgressBar(d.System.RamUsedMb, d.System.RamTotalMb, "MEM", "green")
	diskBar := buildProgressBar(d.System.DiskUsedMb, d.System.DiskTotalMb, "DSK", "cyan")

	errState := " [green]ONLINE[-]"
	if currentErr != nil {
		errState = " [red]OFFLINE (Telemetry Error)[-]"
	} else if d.Projection != nil && d.Projection.Quality == "degraded" {
		errState = " [yellow]DEGRADED (Display Projection)[-]"
	}

	profileStr := ""
	if d.ProfileName != "" {
		profileStr = fmt.Sprintf(" │ [gray]Profile:[-] [yellow]%s[-]", escapeTUIDynamicValue(d.ProfileName))
	}

	headerLines := fmt.Sprintf(
		" [gray]IP:[-] [green]%s[-] │ [gray]Stars:[-] [yellow]%s[-] │ [gray]Release:[-] [cyan]%s[-]%s │ [gray]NODE:[-] [white]%s[-]%s\n\n"+
			" [gray]Cores:[-] [white]%s[-] │ [gray]Arch:[-] [white]%s[-] │ [gray]OS:[-] [white]%s[-] │ [gray]CPU:[-] [white]%s[-]\n"+
			" [gray]Uptime:[-] [cyan]%s[-] │ [gray]Load:[-] [%s]%s[-] │ %s │ %s\n"+
			" [gray]Services:[-] %s\n"+
			" [gray]Ports:[-] [blue]%s[-]",
		escapeTUIDynamicValue(d.System.ServerIP), escapeTUIDynamicValue(ghStars), escapeTUIDynamicValue(ghRelease), profileStr,
		escapeTUIDynamicValue(d.System.Hostname), errState,
		escapeTUIDynamicValue(d.System.Cores), escapeTUIDynamicValue(d.System.Arch), escapeTUIDynamicValue(d.System.Os), escapeTUIDynamicValue(d.System.CpuModel),
		escapeTUIDynamicValue(d.System.Uptime), cLoad, escapeTUIDynamicValue(d.System.LoadAverage), ramBar, diskBar,
		strings.Join(servicesStr, " │ "),
		pStr,
	)
	headerText.SetText(headerLines)

	// --- L3 Metrics ---
	globalBlockedStr := fmt.Sprintf("%d", d.Layer3.GlobalBlocked)
	if d.Layer3.ZeroTrustMode {
		globalBlockedStr = fmt.Sprintf("%d (Zero-Trust)", d.Layer3.GlobalBlocked)
	}
	feedIPv4, feedIPv6 := threatFeedStatusSummaries(d.Layer3.ThreatFeeds, true)
	l3Lines := fmt.Sprintf(" [gray]Value:[-] [white]%s[-] [gray](L7/HA: %d)[-]\n [gray]GeoIP:[-] [white]%d[-] │ [gray]ASN:[-] [white]%d[-]\n %s\n %s",
		globalBlockedStr, d.Layer3.L7Banned, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked, feedIPv4, feedIPv6)
	l3Text.SetText(l3Lines)

	// --- Risk Vectors ---
	re, rb, rr, rd, ra := 0, 0, 0, 0, 0
	if len(d.WAF.RiskRadar) >= 5 {
		re, rb, rr, rd, ra = d.WAF.RiskRadar[0], d.WAF.RiskRadar[1], d.WAF.RiskRadar[2], d.WAF.RiskRadar[3], d.WAF.RiskRadar[4]
	}
	vecLines := fmt.Sprintf(" [gray]WAF L7 Bans:[-] [white]%d[-] │ [gray]Detected:[-] [yellow]%d[-]\n [gray]Active Signatures:[-] [white]%d[-]\n\n [red]Exploits:[-] %d │ [yellow]Brute-Force:[-] %d │ [blue]Recon:[-] %d │ [gray]DDoS:[-] %d │ [yellow]Abuse/Spam:[-] %d",
		d.WAF.TotalBanned, d.WAF.TotalDetected, d.WAF.ActiveSignatures, re, rb, rr, rd, ra)
	vectorsText.SetText(vecLines)

	// --- Trusted ---
	wlIps := "None"
	if len(d.Whitelist.IPs) > 0 {
		escapedIPs := make([]string, len(d.Whitelist.IPs))
		for index, ip := range d.Whitelist.IPs {
			escapedIPs[index] = escapeTUIDynamicValue(ip)
		}
		if len(d.Whitelist.IPs) > 3 {
			wlIps = strings.Join(escapedIPs[:3], ", ") + ", ..."
		} else {
			wlIps = strings.Join(escapedIPs, ", ")
		}
	}
	truLines := fmt.Sprintf(" [gray]Active IPs:[-] [white]%d[-]\n [gray]IPs:[-] [green]%s[-]", d.Whitelist.ActiveIPs, wlIps)
	trustedText.SetText(truLines)

	// --- Ports Table ---
	portsTable.Clear()
	portsTable.SetCell(0, 0, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 1, tview.NewTableCell("SERVICE").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 2, tview.NewTableCell("HITS").SetTextColor(tcell.ColorGray))
	portsTable.SetCell(0, 3, tview.NewTableCell("UNIQUE IPS").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TargetedPorts); i++ {
		p := d.WAF.TargetedPorts[i]
		portsTable.SetCell(i+1, 0, tview.NewTableCell(tview.Escape(p.Port)).SetTextColor(tcell.ColorAqua))
		portsTable.SetCell(i+1, 1, tview.NewTableCell(tview.Escape(p.Service)).SetTextColor(tcell.ColorWhite))
		portsTable.SetCell(i+1, 2, tview.NewTableCell(fmt.Sprintf("%d", p.Hits)).SetTextColor(tcell.ColorYellow))
		portsTable.SetCell(i+1, 3, tview.NewTableCell(fmt.Sprintf("%d", p.UniqueIPs)).SetTextColor(tcell.ColorBlue))
	}

	// --- Sparkline (ASCII Multi-line Graph) ---
	_, _, graphWidth, _ := sparklineText.GetInnerRect()
	if graphWidth < 50 {
		graphWidth = 72 // fallback minimum
	}

	maxBans := 1
	for _, v := range d.WAF.Sparkline24h {
		if v > maxBans {
			maxBans = v
		}
	}
	halfMax := maxBans / 2
	if halfMax == 0 {
		halfMax = 1
	}

	wPerPoint := (graphWidth - 12) / 24
	if wPerPoint < 1 {
		wPerPoint = 1
	}

	var line3, line2, line1, line0 strings.Builder
	for _, v := range d.WAF.Sparkline24h {
		blockStr := strings.Repeat("█", wPerPoint-1) + " "
		emptyStr := strings.Repeat(" ", wPerPoint)

		if v == 0 {
			line0.WriteString(emptyStr)
			line1.WriteString(emptyStr)
			line2.WriteString(emptyStr)
			line3.WriteString(emptyStr)
		} else {
			pct := float64(v) / float64(maxBans)
			if pct >= 0.75 {
				line0.WriteString(blockStr)
				line1.WriteString(blockStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else if pct >= 0.50 {
				line0.WriteString(emptyStr)
				line1.WriteString(blockStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else if pct >= 0.25 {
				line0.WriteString(emptyStr)
				line1.WriteString(emptyStr)
				line2.WriteString(blockStr)
				line3.WriteString(blockStr)
			} else {
				line0.WriteString(emptyStr)
				line1.WriteString(emptyStr)
				line2.WriteString(emptyStr)
				line3.WriteString(blockStr)
			}
		}
	}

	xAxis := "     └─"
	for i := 0; i < 24; i++ {
		seg := strings.Repeat("─", wPerPoint/2) + "┴" + strings.Repeat("─", wPerPoint-(wPerPoint/2)-1)
		xAxis += seg
	}
	xAxis += strings.Repeat("─", wPerPoint/2) + "┴─┐"

	nowTime := time.Now()
	xLabels := strings.Repeat(" ", 6+(wPerPoint/2))
	for i := 0; i <= 24; i += 3 {
		tickTime := nowTime.Add(time.Duration(i-23) * time.Hour)
		xLabels += fmt.Sprintf("%sh", tickTime.Format("15"))
		if i < 24 {
			spaceCount := (3 * wPerPoint) - 3
			if spaceCount > 0 {
				xLabels += strings.Repeat(" ", spaceCount)
			}
		}
	}

	graph := fmt.Sprintf(" [gray]%4d ┤[-] [white]%s[-]\n", maxBans, line0.String())
	graph += fmt.Sprintf(" [gray]     │[-] [white]%s[-]\n", line1.String())
	graph += fmt.Sprintf(" [gray]%4d ┤[-] [white]%s[-]\n", halfMax, line2.String())
	graph += fmt.Sprintf(" [gray]   0 ┤[-] [white]%s[-]\n", line3.String())
	graph += fmt.Sprintf(" [gray]%s[-]\n", xAxis)
	graph += fmt.Sprintf(" [gray]%s[-]\n", xLabels)

	sparklineText.SetText("\n" + graph)

	// --- Top Attackers ---
	attackersTable.Clear()
	attackersTable.SetTitle(topAttackersKPIEvidenceTitle(d.WAF))
	attackersTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 1, tview.NewTableCell("HITS").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 2, tview.NewTableCell("LAST SEEN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 3, tview.NewTableCell("SEVERITY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 4, tview.NewTableCell("PORT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 5, tview.NewTableCell("COUNTRY").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 6, tview.NewTableCell("ASN").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 7, tview.NewTableCell("THREAT").SetTextColor(tcell.ColorGray))
	attackersTable.SetCell(0, 8, tview.NewTableCell("ORG").SetTextColor(tcell.ColorGray))
	for i := 0; i < 5 && i < len(d.WAF.TopAttackers); i++ {
		t := d.WAF.TopAttackers[i]
		attackersTable.SetCell(i+1, 0, tview.NewTableCell(tview.Escape(t.IP)).SetTextColor(tcell.ColorRed))
		hits := fmt.Sprintf("%d", t.Hits)
		if t.HitQuality == "legacy-estimate" {
			hits += " est."
		} else if t.HitQuality == "mixed" {
			hits += " mixed"
		} else if t.HitQuality == "degraded" {
			hits += " degraded"
		}
		attackersTable.SetCell(i+1, 1, tview.NewTableCell(hits).SetTextColor(tcell.ColorYellow))
		ls := t.LastSeen
		if len(ls) >= 19 {
			ls = ls[11:19]
		}
		attackersTable.SetCell(i+1, 2, tview.NewTableCell(tview.Escape(ls)).SetTextColor(tcell.ColorGray))
		attackersTable.SetCell(i+1, 3, tview.NewTableCell(tview.Escape(t.Severity)).SetTextColor(tcell.ColorFuchsia))
		attackersTable.SetCell(i+1, 4, tview.NewTableCell(tview.Escape(t.Port)).SetTextColor(tcell.ColorYellow))
		attackersTable.SetCell(i+1, 5, tview.NewTableCell(tview.Escape(t.Country)).SetTextColor(tcell.ColorWhite))
		attackersTable.SetCell(i+1, 6, tview.NewTableCell(tview.Escape(t.ASN)).SetTextColor(tcell.ColorAqua))
		attackersTable.SetCell(i+1, 7, tview.NewTableCell(tview.Escape(t.Threat)).SetTextColor(tcell.ColorOrange))
		attackersTable.SetCell(i+1, 8, tview.NewTableCell(tview.Escape(t.Org)).SetTextColor(tcell.ColorWhite))
	}

	// --- Banned Table ---
	// Preserve selection
	r, c := bannedTable.GetSelection()
	bannedTable.Clear()
	bannedTable.SetCell(0, 0, tview.NewTableCell("IP ADDRESS").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 1, tview.NewTableCell("TRIGGERING").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 2, tview.NewTableCell("MITRE ATT&CK / TYPE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 3, tview.NewTableCell("STATE").SetTextColor(tcell.ColorGray).SetSelectable(false))
	bannedTable.SetCell(0, 4, tview.NewTableCell("REASON (ATTEMPTED ATTACK)").SetTextColor(tcell.ColorGray).SetSelectable(false))

	recentlyUnbannedMu.Lock()
	now := time.Now()
	var filteredBanned []BannedIP
	for _, b := range d.WAF.BannedIPs {
		if unbanTime, exists := recentlyUnbanned[b.IP]; exists {
			if now.Sub(unbanTime) < 15*time.Second {
				continue
			} else {
				delete(recentlyUnbanned, b.IP)
			}
		}
		filteredBanned = append(filteredBanned, b)
	}
	recentlyUnbannedMu.Unlock()
	d.WAF.BannedIPs = filteredBanned

	if len(d.WAF.BannedIPs) == 0 && len(d.WAF.AllowedEvents) == 0 {
		bannedTable.SetCell(1, 0, tview.NewTableCell(emptyRegistryMessage).SetTextColor(tcell.ColorGreen).SetSelectable(false))
	} else {
		row := 1
		for _, a := range d.WAF.AllowedEvents {
			bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(a.IP)).SetTextColor(tcell.ColorWhite))
			bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape(a.Service)).SetTextColor(tcell.ColorYellow))
			bannedTable.SetCell(row, 2, tview.NewTableCell("-").SetTextColor(tcell.ColorGray))
			bannedTable.SetCell(row, 3, tview.NewTableCell("ALLOW").SetTextColor(tcell.ColorGreen))
			bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(TranslateAllowedPayload(a.Service, a.Payload, a.IP, a.Timestamp))).SetTextColor(tcell.ColorGray))
			row++
		}
		for _, b := range d.WAF.BannedIPs {
			mitre := strings.Split(b.Mitre, ":")[0]
			payload := strings.ReplaceAll(strings.ReplaceAll(b.Payload, "\n", ""), "\r", "")

			var cVec tcell.Color
			j := strings.ToLower(b.Jail)
			if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") || strings.Contains(j, "revshell") || strings.Contains(j, "webshell") || strings.Contains(j, "ssti") || strings.Contains(j, "ssrf") || strings.Contains(j, "jndi") || strings.Contains(j, "modsec") {
				cVec = tcell.ColorRed
			} else if strings.Contains(j, "ssh") || strings.Contains(j, "auth") || strings.Contains(j, "privesc") || strings.Contains(j, "prestashop") {
				cVec = tcell.ColorYellow
			} else if strings.Contains(j, "scan") || strings.Contains(j, "bot") || strings.Contains(j, "mapper") || strings.Contains(j, "enum") || strings.Contains(j, "hunter") || strings.Contains(j, "tls") || strings.Contains(j, "honeypot") || strings.Contains(j, "honeyport") {
				cVec = tcell.ColorBlue
			} else if strings.Contains(j, "flood") || strings.Contains(j, "slowloris") || strings.Contains(j, "dos") {
				cVec = tcell.ColorDarkGray
			} else {
				cVec = tcell.ColorYellow
			}

			switch b.Action {
			case "SIMULATED-BAN":
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape("DRY-RUN: "+b.Jail)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 2, tview.NewTableCell(tview.Escape(mitre)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 3, tview.NewTableCell("AUDIT").SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp))).SetTextColor(tcell.ColorYellow))
			case "COMPLIANCE-DRIFT":
				ts := b.Timestamp
				if ts == "" {
					ts = time.Now().Format("2006-01-02 15:04:05")
				}
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape(b.Jail)).SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 2, tview.NewTableCell("TA0005").SetTextColor(tcell.ColorRed)) // Defense Evasion
				bannedTable.SetCell(row, 3, tview.NewTableCell("DRIFT").SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(fmt.Sprintf("[%s] %s", ts, b.Payload))).SetTextColor(tcell.ColorWhite))
			case "COMPLIANCE-OK":
				ts := b.Timestamp
				if ts == "" {
					ts = time.Now().Format("2006-01-02 15:04:05")
				}
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape(b.Jail)).SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 2, tview.NewTableCell("-").SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 3, tview.NewTableCell("OK").SetTextColor(tcell.ColorGreen))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(fmt.Sprintf("[%s] %s", ts, b.Payload))).SetTextColor(tcell.ColorGray))
			case "SHADOW-ALERT":
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape("SHADOW-ALERT: "+b.Jail)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 2, tview.NewTableCell(tview.Escape(mitre)).SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 3, tview.NewTableCell("DETECT").SetTextColor(tcell.ColorOrange))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp))).SetTextColor(tcell.ColorYellow))
			case "DETECTED":
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape("DETECTED: "+b.Jail)).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 2, tview.NewTableCell(tview.Escape(mitre)).SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 3, tview.NewTableCell("DETECT").SetTextColor(tcell.ColorYellow))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp))).SetTextColor(tcell.ColorYellow))
			default:
				state := bannedRegistryState(b)
				bannedTable.SetCell(row, 0, tview.NewTableCell(tview.Escape(b.IP)).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 1, tview.NewTableCell(tview.Escape(b.Jail)).SetTextColor(cVec))
				bannedTable.SetCell(row, 2, tview.NewTableCell(tview.Escape(mitre)).SetTextColor(tcell.ColorWhite))
				bannedTable.SetCell(row, 3, tview.NewTableCell(tview.Escape(state)).SetTextColor(tcell.ColorRed))
				bannedTable.SetCell(row, 4, tview.NewTableCell(tview.Escape(TranslatePayload(b.Jail, payload, b.IP, b.Timestamp))).SetTextColor(tcell.ColorWhite))
			}
			row++
		}
	}
	bannedTable.Select(r, c)
}

func printDashboardText() {
	bytes, err := readTUIDashboardFile(DataFile)
	if err != nil {
		fmt.Printf("=== %s ===\n[ERROR] Telemetry data unreadable: %v\n", dashboardSnapshotTitle, err)
		return
	}

	d, err := decodeTUIDashboardData(bytes)
	if err != nil {
		fmt.Printf("=== %s ===\n[ERROR] Invalid telemetry snapshot: %v\n", dashboardSnapshotTitle, err)
		return
	}

	load1Str := "0.00"
	if parts := strings.Split(d.System.LoadAverage, ","); len(parts) > 0 {
		load1Str = strings.TrimSpace(parts[0])
	}

	fmt.Printf("=== %s ===\n", dashboardSnapshotTitle)
	fmt.Printf("[SYSTEM] NODE: %s | Uptime: %s | Load: %s\n", d.System.Hostname, d.System.Uptime, load1Str)
	fmt.Printf("[L3 FIREWALL] Global Blocks: %d (GeoIP: %d | ASN: %d)\n", d.Layer3.GlobalBlocked, d.Layer3.GeoIPBlocked, d.Layer3.ASNBlocked)
	feedIPv4, feedIPv6 := threatFeedStatusSummaries(d.Layer3.ThreatFeeds, false)
	fmt.Printf("[THREAT FEEDS] %s | %s\n", feedIPv4, feedIPv6)
	fmt.Printf("[WAAP L7] Active Bans: %d\n", d.WAF.TotalBanned)
	fmt.Printf("[WAAP KPI] Evidence: %s\n", waapKPIEvidenceSummary(d.WAF))
	if d.Projection != nil {
		fmt.Printf("[DASHBOARD PROJECTION] Quality: %s | Reason: %s | Payloads projected: %d\n",
			d.Projection.Quality, d.Projection.Reason, d.Projection.PayloadsProjected)
	}

	// Format Jails
	var jails []string
	for i := 0; i < len(d.WAF.SignaturesData); i++ {
		jails = append(jails, fmt.Sprintf("%s (%d)", d.WAF.SignaturesData[i].Name, d.WAF.SignaturesData[i].Count))
	}
	if len(jails) > 0 {
		fmt.Printf("[WAAP JAILS] %s\n", strings.Join(jails, ", "))
	} else {
		fmt.Println("[WAAP JAILS] None")
	}

	fmt.Println("[TOP ATTACKERS]")
	if len(d.WAF.TopAttackers) == 0 {
		fmt.Println(" - None")
	} else {
		for i := 0; i < len(d.WAF.TopAttackers); i++ {
			a := d.WAF.TopAttackers[i]
			fmt.Printf(" - %s | hits=%d | severity=%s | jail=%s | enforcement=%s/%s | enforcement_state=%s | policy_quality=%s | metric_quality=%s | hit_quality=%s | evidence=%s | %s / %s / %s\n",
				a.IP, a.Hits, a.Severity, a.PrimaryJail, a.EnforcementJail, a.EnforcementAction, a.EnforcementState, a.SelectedPolicyQuality, a.MetricQuality, a.HitQuality, a.HitEvidence, a.Country, a.ASN, a.Org)
		}
	}
}

func threatFeedStatusSummaries(feeds []ThreatFeedStatus, colors bool) (string, string) {
	summaries := map[string]string{
		"ipv4": threatFeedSummary(ThreatFeedStatus{AddressFamily: "ipv4"}, colors),
		"ipv6": threatFeedSummary(ThreatFeedStatus{AddressFamily: "ipv6"}, colors),
	}
	for _, feed := range feeds {
		if feed.AddressFamily != "ipv4" && feed.AddressFamily != "ipv6" {
			continue
		}
		summaries[feed.AddressFamily] = threatFeedSummary(feed, colors)
	}
	return summaries["ipv4"], summaries["ipv6"]
}

func threatFeedSummary(feed ThreatFeedStatus, colors bool) string {
	label := "IPv4"
	if feed.AddressFamily == "ipv6" {
		label = "IPv6"
	}
	freshness := feed.Freshness
	attestation := feed.Attestation
	quality := feed.EvidenceQuality
	if freshness == "" {
		freshness = "not-reported"
	}
	if attestation == "" {
		attestation = "not-reported"
	}
	if quality == "" {
		quality = attestation
	}
	summary := fmt.Sprintf("%s %s/%s", label, freshness, quality)
	if !colors {
		return summary
	}
	color := "yellow"
	if attestation == "verified" && freshness == "current" {
		color = "green"
	} else if attestation == "rejected" {
		color = "red"
	} else if attestation == "not-reported" || attestation == "missing" {
		color = "gray"
	}
	return fmt.Sprintf("[gray]%s:[-] [%s]%s[-]", label, color,
		escapeTUIDynamicValue(strings.TrimPrefix(summary, label+" ")))
}
