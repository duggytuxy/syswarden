package logger

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"syswarden-core/telemetry"
	"syswarden-core/utils"
	"syswarden-core/webhook"
)

const (
	persistentBlacklistIPv4File = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	persistentBlacklistIPv6File = "/etc/syswarden/lists/syswarden_blacklist.ipv6"
	maxPersistentBlocklistBytes = 1024 * 1024
	maxTelemetryLogBytes        = 16 * 1024 * 1024

	// InternalLogMarker identifies process-log records owned by SysWarden. Log
	// ingestion boundaries must reject records carrying this marker so an event
	// cannot be detected again after journald or rsyslog persists it.
	InternalLogMarker = "[SYSWARDEN-INTERNAL]"
)

var errTelemetryRecordExceedsRotationLimit = errors.New("telemetry record exceeds rotation limit")

const (
	internalLogTimestampPattern       = `[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} `
	internalSyslogTimestampPattern    = `[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} `
	internalSyslogHostnamePattern     = `[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?`
	internalLogCanonicalFieldsPattern = `action=[A-Z][A-Z0-9-]{0,63} ip=(?:[0-9A-Fa-f:.]+|invalid-[0-9a-f]{16}) scope=[A-Za-z0-9._:/%-]{1,128} payload_sha256=[0-9a-f]{64} payload_bytes=[0-9]{1,20}`
	internalLogRecordPattern          = `\[SYSWARDEN-INTERNAL\] (` + internalLogCanonicalFieldsPattern + `) auth=([0-9a-f]{64})`
)

var (
	internalProcessHMACKey  = newInternalProcessHMACKey()
	internalLogRecordLine   = regexp.MustCompile(`^` + internalLogRecordPattern + `$`)
	directInternalLogPrefix = regexp.MustCompile(`^` + internalLogTimestampPattern + `$`)
	systemInternalLogPrefix = regexp.MustCompile(`^(?:` + internalSyslogTimestampPattern + internalSyslogHostnamePattern + ` )?syswarden-core(?:\[[0-9]+\])?: +(?:` + internalLogTimestampPattern + `)?$`)
)

func newInternalProcessHMACKey() []byte {
	random := make([]byte, 32)
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Sprintf("generate internal log HMAC key: %v", err))
	}
	return random
}

// persistBanToDisk writes WAF/WAAP bans synchronously. The production paths
// are fixed; UpdatePersistentBlocklist provides the shared HA/WAAP atomic RMW
// primitive while retaining strict rooted-path validation.
func persistBanToDisk(entry string) error {
	canonical, ipv6, err := canonicalPersistentBlocklistEntry(entry)
	if err != nil {
		return err
	}
	path := persistentBlacklistIPv4File
	if ipv6 {
		path = persistentBlacklistIPv6File
	}
	return UpdatePersistentBlocklist(path, canonical, true)
}

// UpdatePersistentBlocklist atomically adds or removes one canonical IP/CIDR.
// It is shared by the HA API and the WAAP logger so both processes coordinate
// on the same parent-directory flock and cannot lose each other's updates.
func UpdatePersistentBlocklist(path, entry string, present bool) error {
	canonical, _, err := canonicalPersistentBlocklistEntry(entry)
	if err != nil {
		return err
	}
	cleanPath := filepath.Clean(path)
	if !filepath.IsAbs(cleanPath) || cleanPath != path {
		return fmt.Errorf("persistent blocklist path must be absolute and canonical")
	}
	name := filepath.Base(cleanPath)
	if name == "." || name == string(filepath.Separator) || filepath.Base(name) != name {
		return fmt.Errorf("invalid persistent blocklist file name")
	}
	root, err := openPersistentBlocklistDirectory(filepath.Dir(cleanPath))
	if err != nil {
		return err
	}
	defer root.Close()
	lockFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open persistent blocklist directory lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("lock persistent blocklist directory: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
		_ = lockFile.Close()
	}()

	stored, err := readPersistentBlocklist(root, name)
	if err != nil {
		return err
	}
	_, exists := stored[canonical]
	if exists == present {
		return nil
	}
	if present {
		stored[canonical] = struct{}{}
	} else {
		delete(stored, canonical)
	}
	entries := make([]string, 0, len(stored))
	for storedEntry := range stored {
		entries = append(entries, storedEntry)
	}
	sort.Strings(entries)
	content := []byte(nil)
	if len(entries) > 0 {
		content = []byte(strings.Join(entries, "\n") + "\n")
	}
	if len(content) > maxPersistentBlocklistBytes {
		return fmt.Errorf("persistent blocklist exceeds %d bytes", maxPersistentBlocklistBytes)
	}
	return publishPersistentBlocklist(root, name, content)
}

func openPersistentBlocklistDirectory(path string) (*os.Root, error) {
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for persistent blocklist: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(filepath.ToSlash(path), "/"), "/")
	for _, component := range components {
		if component == "" {
			continue
		}
		info, err := current.Lstat(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("inspect persistent blocklist parent component %q: %w", component, err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return nil, fmt.Errorf("persistent blocklist parent component %q must be a real directory", component)
		}
		next, err := current.OpenRoot(component)
		if err != nil {
			_ = current.Close()
			return nil, fmt.Errorf("open persistent blocklist parent component %q: %w", component, err)
		}
		opened, err := next.Stat(".")
		if err != nil || !opened.IsDir() || !os.SameFile(info, opened) {
			_ = next.Close()
			_ = current.Close()
			return nil, fmt.Errorf("persistent blocklist parent component %q changed while opening", component)
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func canonicalPersistentBlocklistEntry(entry string) (string, bool, error) {
	entry = strings.TrimSpace(entry)
	if address, err := netip.ParseAddr(entry); err == nil {
		if address.Is4In6() || address.Zone() != "" {
			return "", false, fmt.Errorf("invalid persistent blocklist address")
		}
		return address.String(), address.Is6(), nil
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return "", false, fmt.Errorf("invalid persistent blocklist address")
	}
	prefix = prefix.Masked()
	return prefix.String(), prefix.Addr().Is6(), nil
}

func readPersistentBlocklist(root *os.Root, name string) (map[string]struct{}, error) {
	stored := make(map[string]struct{})
	before, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return stored, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect persistent blocklist: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("persistent blocklist must be a regular 0600 file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open persistent blocklist: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened persistent blocklist: %w", err)
	}
	current, err := root.Lstat(name)
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return nil, fmt.Errorf("persistent blocklist changed while opening")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxPersistentBlocklistBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read persistent blocklist: %w", err)
	}
	if len(wire) > maxPersistentBlocklistBytes {
		return nil, fmt.Errorf("persistent blocklist exceeds %d bytes", maxPersistentBlocklistBytes)
	}
	for lineNumber, line := range strings.Split(string(wire), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		canonical, _, err := canonicalPersistentBlocklistEntry(line)
		if err != nil || canonical != line {
			return nil, fmt.Errorf("persistent blocklist contains an invalid entry at line %d", lineNumber+1)
		}
		stored[canonical] = struct{}{}
	}
	return stored, nil
}

func createPersistentBlocklistStagingFile(root *os.Root, name string) (*os.File, string, error) {
	for range 128 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate persistent blocklist staging name: %w", err)
		}
		stagingName := "." + name + ".syswarden-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(stagingName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create persistent blocklist staging file: %w", err)
		}
		return file, stagingName, nil
	}
	return nil, "", fmt.Errorf("create persistent blocklist staging file: too many collisions")
}

func publishPersistentBlocklist(root *os.Root, name string, content []byte) (resultErr error) {
	destinationInfo, destinationErr := root.Lstat(name)
	destinationExists := destinationErr == nil
	if destinationErr != nil && !errors.Is(destinationErr, fs.ErrNotExist) {
		return destinationErr
	}
	if destinationExists && (!destinationInfo.Mode().IsRegular() || destinationInfo.Mode().Perm() != 0600) {
		return fmt.Errorf("persistent blocklist destination must be a regular 0600 file")
	}
	file, stagingName, err := createPersistentBlocklistStagingFile(root, name)
	if err != nil {
		return err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if stagingName != "" {
			_ = root.Remove(stagingName)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("restrict persistent blocklist staging file: %w", err)
	}
	if written, err := file.Write(content); err != nil {
		return fmt.Errorf("write persistent blocklist staging file: %w", err)
	} else if written != len(content) {
		return fmt.Errorf("write persistent blocklist staging file: %w", io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync persistent blocklist staging file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close persistent blocklist staging file: %w", err)
	}
	file = nil

	currentInfo, currentErr := root.Lstat(name)
	if destinationExists {
		if currentErr != nil || !currentInfo.Mode().IsRegular() || currentInfo.Mode().Perm() != 0600 ||
			!os.SameFile(destinationInfo, currentInfo) {
			return fmt.Errorf("persistent blocklist destination changed before publication")
		}
	} else if !errors.Is(currentErr, fs.ErrNotExist) {
		if currentErr == nil {
			return fmt.Errorf("persistent blocklist destination appeared before publication")
		}
		return currentErr
	}
	if err := root.Rename(stagingName, name); err != nil {
		return fmt.Errorf("publish persistent blocklist atomically: %w", err)
	}
	stagingName = ""
	directoryFile, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open persistent blocklist directory for sync: %w", err)
	}
	if err := directoryFile.Sync(); err != nil {
		_ = directoryFile.Close()
		return fmt.Errorf("sync persistent blocklist directory: %w", err)
	}
	if err := directoryFile.Close(); err != nil {
		return fmt.Errorf("close persistent blocklist directory: %w", err)
	}
	return nil
}

type Logger struct {
	file                   *os.File
	logPath                string
	rotationLimit          int64
	createRotationLogFile  func(string) (*os.File, error)
	compactRotationLogFile func(string, int64) error
	mu                     sync.Mutex
	lifecycleMu            sync.Mutex
	asyncWG                sync.WaitGroup
	closed                 bool
}

func (l *Logger) runAsync(operation func()) {
	if operation == nil {
		return
	}
	l.lifecycleMu.Lock()
	if l.closed {
		l.lifecycleMu.Unlock()
		return
	}
	l.asyncWG.Add(1)
	l.lifecycleMu.Unlock()
	go func() {
		defer l.asyncWG.Done()
		operation()
	}()
}

// TelemetryEvent represents a banned or allowed IP event
type TelemetryEvent struct {
	Action                        string `json:"action,omitempty"`
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

// RuleContext attests the exact rule metadata used when an event was
// evaluated. Legacy and synthetic callers may leave it empty; consumers can
// then report an estimate instead of presenting reconstructed policy as fact.
type RuleContext struct {
	RuleID                        string
	RiskCategory                  string
	RuleAction                    string
	EffectiveThreshold            int
	EffectiveWindowSeconds        int
	RiskAttributionRuleID         string
	RiskAttributionCategory       string
	RiskAttributionAction         string
	RiskAttributionThreshold      int
	RiskAttributionWindowSeconds  int
	RiskAttributionMetricEligible bool
	SignatureCatalogVersion       string
	SignatureCatalogSHA256        string
	RiskModelVersion              string
	MetricEligible                bool
	ObservedAt                    time.Time
	ObservationModel              string
	ObservationDisposition        string
}

func newTelemetryEvent(action, ip, jail, payload string, severity int, rule *RuleContext) TelemetryEvent {
	observedAt := time.Now().UTC()
	event := TelemetryEvent{
		Action:    action,
		Timestamp: observedAt.Format(time.RFC3339Nano),
		IP:        ip,
		Jail:      jail,
		Payload:   payload,
		Severity:  severity,
	}
	if rule == nil || emptyRuleContext(rule) {
		return event
	}
	if !validRuleContextForEvent(action, jail, rule) {
		event.RuleAttestationStatus = "invalid"
		return event
	}
	if !rule.ObservedAt.IsZero() {
		event.Timestamp = rule.ObservedAt.UTC().Format(time.RFC3339Nano)
	}
	eligible := rule.MetricEligible
	window := rule.EffectiveWindowSeconds
	event.RuleID = rule.RuleID
	event.RiskCategory = rule.RiskCategory
	event.RuleAction = rule.RuleAction
	event.EffectiveThreshold = rule.EffectiveThreshold
	event.EffectiveWindowSeconds = &window
	if rule.RiskAttributionRuleID != "" {
		attributionWindow := rule.RiskAttributionWindowSeconds
		attributionEligible := rule.RiskAttributionMetricEligible
		event.RiskAttributionRuleID = rule.RiskAttributionRuleID
		event.RiskAttributionCategory = rule.RiskAttributionCategory
		event.RiskAttributionAction = rule.RiskAttributionAction
		event.RiskAttributionThreshold = rule.RiskAttributionThreshold
		event.RiskAttributionWindowSeconds = &attributionWindow
		event.RiskAttributionMetricEligible = &attributionEligible
	}
	event.SignatureCatalogVersion = rule.SignatureCatalogVersion
	event.SignatureCatalogSHA256 = rule.SignatureCatalogSHA256
	event.RiskModelVersion = rule.RiskModelVersion
	event.MetricEligible = &eligible
	event.ObservationModel = rule.ObservationModel
	event.ObservationDisposition = rule.ObservationDisposition
	event.RuleAttestationStatus = "attested"
	return event
}

func emptyRuleContext(rule *RuleContext) bool {
	return rule == nil || rule.RuleID == "" && rule.RiskCategory == "" && rule.RuleAction == "" &&
		rule.EffectiveThreshold == 0 && rule.EffectiveWindowSeconds == 0 &&
		emptyRiskAttributionContext(rule) &&
		rule.SignatureCatalogVersion == "" && rule.SignatureCatalogSHA256 == "" &&
		rule.RiskModelVersion == "" && !rule.MetricEligible && rule.ObservedAt.IsZero() && rule.ObservationModel == "" &&
		rule.ObservationDisposition == ""
}

func validRuleContextForEvent(eventAction, jail string, rule *RuleContext) bool {
	if rule == nil || rule.RuleID == "" || rule.RuleID != jail || !validRuleContextCategory(rule.RiskCategory) ||
		!validRuleContextPolicy(rule.RuleAction, rule.EffectiveThreshold, rule.EffectiveWindowSeconds) ||
		!validRiskAttributionContext(rule) ||
		rule.SignatureCatalogVersion == "" || len(rule.SignatureCatalogSHA256) != sha256.Size*2 ||
		rule.RiskModelVersion != "sw-risk-v1" || !validObservationModel(rule.ObservationModel) {
		return false
	}
	if _, err := hex.DecodeString(rule.SignatureCatalogSHA256); err != nil {
		return false
	}
	if rule.ObservationDisposition != "" &&
		(rule.ObservationDisposition != "kernel-packet-dropped" || eventAction != "DETECTED" ||
			rule.RuleID != "L2-ARP-FLOOD" || !strings.HasPrefix(rule.ObservationModel, "kernel-log-observation")) {
		return false
	}
	switch eventAction {
	case "BANNED", "SIMULATED-BAN", "SHADOW-ALERT":
		return rule.RuleAction == "ban" || rule.RuleAction == "track"
	case "DETECTED":
		return rule.RuleAction == "ban" || rule.RuleAction == "track" || rule.RuleAction == "detect"
	default:
		return false
	}
}

func emptyRiskAttributionContext(rule *RuleContext) bool {
	return rule == nil || rule.RiskAttributionRuleID == "" && rule.RiskAttributionCategory == "" &&
		rule.RiskAttributionAction == "" && rule.RiskAttributionThreshold == 0 &&
		rule.RiskAttributionWindowSeconds == 0 && !rule.RiskAttributionMetricEligible
}

func validRiskAttributionContext(rule *RuleContext) bool {
	if emptyRiskAttributionContext(rule) {
		return true
	}
	return rule != nil && rule.RiskAttributionRuleID != "" && rule.RiskAttributionRuleID != rule.RuleID &&
		validRuleContextCategory(rule.RiskAttributionCategory) &&
		validRuleContextPolicy(rule.RiskAttributionAction, rule.RiskAttributionThreshold, rule.RiskAttributionWindowSeconds)
}

func validObservationModel(model string) bool {
	switch model {
	case "collector-content-window-v1", "collector-content-window-degraded-v1", "kernel-log-observation-v1", "kernel-log-observation-degraded-v1":
		return true
	default:
		return false
	}
}

func validRuleContextCategory(category string) bool {
	switch category {
	case "exploit", "brute_force", "reconnaissance", "denial_of_service", "abuse":
		return true
	default:
		return false
	}
}

func validRuleContextPolicy(action string, threshold, window int) bool {
	switch action {
	case "track":
		return threshold > 0 && window > 0
	case "ban", "detect":
		return threshold == 1 && window == 0
	default:
		return false
	}
}

func (l *Logger) writeTelemetry(event TelemetryEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		l.Error("Failed to marshal telemetry event", err)
		return
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	if err := l.rotateBeforeWriteLocked(int64(len(data))); err != nil {
		log.Printf("[Logger] Warning: telemetry log rotation failed: %v", err)
		if errors.Is(err, errTelemetryRecordExceedsRotationLimit) {
			return
		}
	}
	if l.file == nil {
		return
	}
	if written, err := l.file.Write(data); err != nil {
		log.Printf("[Logger] Error writing telemetry data: %v", err)
	} else if written != len(data) {
		log.Printf("[Logger] Error writing telemetry data: %v", io.ErrShortWrite)
	}
}

func (l *Logger) rotateBeforeWriteLocked(pendingBytes int64) error {
	if l.file == nil || l.logPath == "" || l.rotationLimit <= 0 || pendingBytes < 0 {
		return nil
	}
	if pendingBytes > l.rotationLimit {
		return fmt.Errorf("%w: record=%d limit=%d", errTelemetryRecordExceedsRotationLimit, pendingBytes, l.rotationLimit)
	}
	openedInfo, err := l.file.Stat()
	if err != nil {
		return fmt.Errorf("inspect active telemetry log: %w", err)
	}
	pathInfo, err := os.Lstat(l.logPath)
	if err != nil {
		return fmt.Errorf("inspect telemetry log path: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("active telemetry log path no longer identifies the opened regular file")
	}
	if openedInfo.Size() == 0 ||
		(openedInfo.Size() <= l.rotationLimit && pendingBytes <= l.rotationLimit-openedInfo.Size()) {
		return nil
	}
	return l.rotateLocked()
}

func createExclusiveTelemetryLog(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- path is the configured telemetry journal
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return nil, fmt.Errorf("set telemetry log mode: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect new telemetry log: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("new telemetry log is not a regular 0600 file")
	}
	cleanup = false
	return file, nil
}

func reopenTelemetryLog(path string) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("telemetry log path is not a regular file")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0) // #nosec G304 -- path was bound to a regular file above
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("telemetry log changed while reopening")
	}
	return file, nil
}

func syncTelemetryLogDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path)) // #nosec G304 -- directory contains the configured telemetry journal
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return err
	}
	return nil
}

// compactTelemetryGenerationTail replaces an oversized retained generation
// with its newest complete NDJSON records. The original path remains untouched
// until the bounded 0600 staging file is durable and ready for an atomic rename.
func compactTelemetryGenerationTail(path string, limit int64) error {
	return compactTelemetryGenerationTailWithSync(path, limit, syncTelemetryLogDirectory)
}

func compactTelemetryGenerationTailWithSync(path string, limit int64, syncDirectory func(string) error) error {
	if path == "" || limit <= 0 || syncDirectory == nil {
		return fmt.Errorf("invalid telemetry generation compaction request")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect retained telemetry generation: %w", err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Size() < 0 {
		return fmt.Errorf("retained telemetry generation must be a regular file")
	}
	if pathInfo.Size() <= limit {
		return nil
	}

	source, err := os.Open(path) // #nosec G304 -- path is the configured retained telemetry generation
	if err != nil {
		return fmt.Errorf("open retained telemetry generation: %w", err)
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			_ = source.Close()
		}
	}()
	sourceInfo, err := source.Stat()
	if err != nil || !sourceInfo.Mode().IsRegular() || !os.SameFile(pathInfo, sourceInfo) || sourceInfo.Size() != pathInfo.Size() {
		if err == nil {
			err = fmt.Errorf("retained telemetry generation changed while opening")
		}
		return err
	}

	start := sourceInfo.Size() - limit
	tail := make([]byte, int(limit))
	if _, err := io.ReadFull(io.NewSectionReader(source, start, limit), tail); err != nil {
		return fmt.Errorf("read retained telemetry generation tail: %w", err)
	}
	var previous [1]byte
	if _, err := source.ReadAt(previous[:], start-1); err != nil {
		return fmt.Errorf("inspect retained telemetry generation boundary: %w", err)
	}
	if previous[0] != '\n' {
		if boundary := bytes.IndexByte(tail, '\n'); boundary >= 0 {
			tail = tail[boundary+1:]
		} else {
			tail = tail[:0]
		}
	}
	if len(tail) > 0 && tail[len(tail)-1] != '\n' {
		if boundary := bytes.LastIndexByte(tail, '\n'); boundary >= 0 {
			tail = tail[:boundary+1]
		} else {
			tail = tail[:0]
		}
	}

	if err := source.Close(); err != nil {
		return fmt.Errorf("close retained telemetry generation: %w", err)
	}
	sourceOpen = false

	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+"-tail-*.tmp")
	if err != nil {
		return fmt.Errorf("create retained telemetry tail staging file: %w", err)
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
		return fmt.Errorf("protect retained telemetry tail staging file: %w", err)
	}
	if written, err := temporary.Write(tail); err != nil {
		return fmt.Errorf("write retained telemetry tail staging file: %w", err)
	} else if written != len(tail) {
		return fmt.Errorf("write retained telemetry tail staging file: %w", io.ErrShortWrite)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync retained telemetry tail staging file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close retained telemetry tail staging file: %w", err)
	}
	currentInfo, err := os.Lstat(path)
	if err != nil || !currentInfo.Mode().IsRegular() || !os.SameFile(pathInfo, currentInfo) || currentInfo.Size() != pathInfo.Size() {
		if err == nil {
			err = fmt.Errorf("retained telemetry generation changed before publication")
		}
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish bounded retained telemetry generation: %w", err)
	}
	published = true
	if err := syncDirectory(path); err != nil {
		return fmt.Errorf("sync telemetry log directory after generation compaction: %w", err)
	}
	return nil
}

func (l *Logger) reopenAfterRotationFailureLocked(rotationErr error) error {
	reopened, reopenErr := reopenTelemetryLog(l.logPath)
	if reopenErr != nil {
		l.file = nil
		return errors.Join(rotationErr, fmt.Errorf("reopen active telemetry log: %w", reopenErr))
	}
	l.file = reopened
	return rotationErr
}

func (l *Logger) rollbackRotatedTelemetryLogLocked(rotatedPath string, rotationErr error) error {
	if err := os.Rename(rotatedPath, l.logPath); err != nil {
		l.file = nil
		return errors.Join(rotationErr, fmt.Errorf("restore previous active telemetry log: %w", err))
	}
	if err := syncTelemetryLogDirectory(l.logPath); err != nil {
		rotationErr = errors.Join(rotationErr, fmt.Errorf("sync telemetry log directory after rollback: %w", err))
	}
	return l.reopenAfterRotationFailureLocked(rotationErr)
}

func (l *Logger) rotateLocked() error {
	if l.file == nil {
		return nil
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("sync active telemetry log before rotation: %w", err)
	}
	if err := l.file.Close(); err != nil {
		l.file = nil
		return l.reopenAfterRotationFailureLocked(fmt.Errorf("close active telemetry log before rotation: %w", err))
	}
	l.file = nil

	rotatedPath := l.logPath + ".1"
	if err := os.Rename(l.logPath, rotatedPath); err != nil {
		return l.reopenAfterRotationFailureLocked(fmt.Errorf("rename active telemetry log to generation .1: %w", err))
	}
	compactLogFile := l.compactRotationLogFile
	if compactLogFile == nil {
		compactLogFile = compactTelemetryGenerationTail
	}
	if err := compactLogFile(rotatedPath, l.rotationLimit); err != nil {
		return l.rollbackRotatedTelemetryLogLocked(
			rotatedPath,
			fmt.Errorf("bound retained telemetry generation: %w", err),
		)
	}

	createLogFile := l.createRotationLogFile
	if createLogFile == nil {
		createLogFile = createExclusiveTelemetryLog
	}
	newFile, createErr := createLogFile(l.logPath)
	if createErr != nil {
		return l.rollbackRotatedTelemetryLogLocked(
			rotatedPath,
			fmt.Errorf("create new active telemetry log: %w", createErr),
		)
	}
	l.file = newFile
	if err := syncTelemetryLogDirectory(l.logPath); err != nil {
		return fmt.Errorf("sync telemetry log directory after rotation: %w", err)
	}
	return nil
}

// IsInternalLogLine reports whether a line was emitted by SysWarden's event
// logger and must therefore be excluded from every detection input.
func IsInternalLogLine(line string) bool {
	return isInternalLogLineForKey(line, internalProcessHMACKey)
}

func isInternalLogLineForKey(line string, key []byte) bool {
	if !strings.Contains(line, InternalLogMarker) {
		return false
	}
	markerIndex := strings.Index(line, InternalLogMarker)
	if markerIndex < 0 {
		return false
	}
	matches := internalLogRecordLine.FindStringSubmatch(line[markerIndex:])
	if len(matches) != 3 {
		return false
	}
	providedMAC, err := hex.DecodeString(matches[2])
	if err != nil {
		return false
	}
	expectedMAC := hmac.New(sha256.New, key)
	_, _ = expectedMAC.Write([]byte(matches[1]))
	if !hmac.Equal(providedMAC, expectedMAC.Sum(nil)) {
		return false
	}
	prefix := line[:markerIndex]
	return directInternalLogPrefix.MatchString(prefix) || systemInternalLogPrefix.MatchString(prefix)
}

// internalSecurityEventLine deliberately represents the untrusted payload by
// digest and length only. The full payload remains available in the protected
// NDJSON telemetry file, but is never copied into a rematchable process log.
func internalSecurityEventLine(action, ip, scope, payload string) string {
	return internalSecurityEventLineForKey(internalProcessHMACKey, action, ip, scope, payload)
}

func internalSecurityEventLineForKey(key []byte, action, ip, scope, payload string) string {
	digest := sha256.Sum256([]byte(payload))
	canonicalFields := fmt.Sprintf(
		"action=%s ip=%s scope=%s payload_sha256=%x payload_bytes=%d",
		internalLogAction(action),
		internalLogIP(ip),
		internalLogScope(scope),
		digest,
		len(payload),
	)
	authenticator := hmac.New(sha256.New, key)
	_, _ = authenticator.Write([]byte(canonicalFields))
	return fmt.Sprintf("%s %s auth=%x", InternalLogMarker, canonicalFields, authenticator.Sum(nil))
}

func internalLogAction(action string) string {
	if len(action) == 0 || len(action) > 64 {
		return "INVALID"
	}
	for _, character := range action {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
			return "INVALID"
		}
	}
	return action
}

func internalLogIP(raw string) string {
	address, err := netip.ParseAddr(raw)
	if err == nil && address.Zone() == "" {
		return address.Unmap().String()
	}
	digest := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("invalid-%x", digest[:8])
}

func internalLogScope(raw string) string {
	if len(raw) > 0 && len(raw) <= 128 {
		safe := true
		for _, character := range raw {
			if (character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				!strings.ContainsRune("._:/%-", character) {
				safe = false
				break
			}
		}
		if safe {
			return raw
		}
	}
	digest := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("sha256-%x", digest)
}

func newLoggerWithRotationLimit(logPath string, rotationLimit int64) *Logger {
	logger := &Logger{
		logPath:                logPath,
		rotationLimit:          rotationLimit,
		createRotationLogFile:  createExclusiveTelemetryLog,
		compactRotationLogFile: compactTelemetryGenerationTail,
	}
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("[Logger] Warning: failed to create log dir: %v", err)
	}
	if rotationLimit > 0 {
		if err := compactTelemetryGenerationTail(logPath+".1", rotationLimit); err != nil {
			log.Printf("[Logger] Warning: failed to bound retained telemetry generation %s: %v", logPath+".1", err)
			return logger
		}
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err != nil {
		log.Printf("[Logger] Warning: failed to open log file %s: %v", logPath, err)
		return logger
	}
	logger.file = file
	return logger
}

func NewLogger(logPath string) *Logger {
	return newLoggerWithRotationLimit(logPath, maxTelemetryLogBytes)
}

func (l *Logger) Info(msg string) {
	log.Printf("[INFO] %s", msg)
}

func (l *Logger) Error(msg string, err error) {
	log.Printf("[ERROR] %s: %v", msg, err)
}

// LogBan writes a JSON telemetry event when an IP is banned
func (l *Logger) LogBan(ip, jail, payload string) {
	l.LogBanWithRule(ip, jail, payload, RuleContext{})
}

// LogBanWithRule records a ban together with the exact rule policy used.
func (l *Logger) LogBanWithRule(ip, jail, payload string, rule RuleContext) {
	event := newTelemetryEvent("BANNED", ip, jail, payload, 10, &rule)
	telemetry.ReportAbuseAsync(ip, jail, payload)
	l.runAsync(func() { webhook.SendBanAlert(ip, jail, "WAF Drop (L7)") })
	if err := persistBanToDisk(ip); err != nil {
		log.Printf("[Logger] Failed to persist WAF ban: %v", err)
	}

	l.writeTelemetry(event)

	log.Print(internalSecurityEventLine("BANNED", ip, jail, payload))
}

// LogAllowed writes a JSON telemetry event when an IP is successfully allowed (e.g. login)
func (l *Logger) LogAllowed(ip, service, payload string) {
	l.runAsync(func() { webhook.SendAllowAlert(ip, service) })
	event := newTelemetryEvent("ALLOWED", ip, service, payload, 3, nil)
	l.writeTelemetry(event)

	log.Print(internalSecurityEventLine("ALLOWED", ip, service, payload))
}

// LogDetected writes a JSON telemetry event when an IP is detected but not banned
func (l *Logger) LogDetected(ip, jail, payload string) {
	l.LogDetectedWithRule(ip, jail, payload, RuleContext{})
}

// LogDetectedWithRule records a detection together with the exact rule policy used.
func (l *Logger) LogDetectedWithRule(ip, jail, payload string, rule RuleContext) {
	event := newTelemetryEvent("DETECTED", ip, jail, payload, 7, &rule)
	description := "Detection Only (No Drop)"
	if event.ObservationDisposition == "kernel-packet-dropped" {
		description = "Kernel Packet Dropped (No Source Ban)"
	}
	l.runAsync(func() { webhook.SendDetectedAlert(ip, jail, description) })
	l.writeTelemetry(event)

	log.Print(internalSecurityEventLine("DETECTED", ip, jail, payload))
}

// LogShadowAlert writes a JSON telemetry event when an internal threat is detected but not banned
func (l *Logger) LogShadowAlert(ip, jail, payload string) {
	l.LogShadowAlertWithRule(ip, jail, payload, RuleContext{})
}

// LogShadowAlertWithRule records a threshold observation with its exact rule policy.
func (l *Logger) LogShadowAlertWithRule(ip, jail, payload string, rule RuleContext) {
	l.runAsync(func() { webhook.SendShadowAlert(ip, jail) })
	event := newTelemetryEvent("SHADOW-ALERT", ip, jail, payload, 8, &rule)
	l.writeTelemetry(event)

	action := "SHADOW-ALERT"
	if utils.IsWhitelisted(ip) {
		action = "SHADOW-ALERT-WHITELISTED"
	}
	log.Print(internalSecurityEventLine(action, ip, jail, payload))
}

// LogSimulatedBan logs an IP that would have been banned but was bypassed due to Audit mode.
func (l *Logger) LogSimulatedBan(ip, jail, payload string) {
	l.LogSimulatedBanWithRule(ip, jail, payload, RuleContext{})
}

// LogSimulatedBanWithRule records an audit-mode enforcement decision with its exact rule policy.
func (l *Logger) LogSimulatedBanWithRule(ip, jail, payload string, rule RuleContext) {
	if payload == "" {
		payload = "No payload"
	}
	event := newTelemetryEvent("SIMULATED-BAN", ip, jail, payload, 0, &rule)
	l.writeTelemetry(event)

	log.Print(internalSecurityEventLine("SIMULATED-BAN", ip, jail, payload))
}

// LogComplianceDrift logs a deviation found by a selected local check. The
// retained method and structured identifiers preserve consumer compatibility;
// the payload makes no compliance claim.
func (l *Logger) LogComplianceDrift(msg string) {
	event := newTelemetryEvent("COMPLIANCE-DRIFT", "127.0.0.1", "NIS2-AUDIT", msg, 0, nil)
	l.writeTelemetry(event)

	l.runAsync(func() { webhook.SendComplianceAlert(msg, "DRIFT") })

	log.Print(internalSecurityEventLine("LOCAL-CHECK-DRIFT", "127.0.0.1", "NIS2-AUDIT", msg))
}

// LogComplianceOK logs that the selected local checks did not find a
// deviation. The retained method and structured identifiers preserve consumer
// compatibility; the payload makes no compliance claim.
func (l *Logger) LogComplianceOK(msg string) {
	event := newTelemetryEvent("COMPLIANCE-OK", "127.0.0.1", "NIS2-AUDIT", msg, 0, nil)
	l.writeTelemetry(event)

	l.runAsync(func() { webhook.SendComplianceAlert(msg, "OK") })

	log.Print(internalSecurityEventLine("LOCAL-CHECK-OK", "127.0.0.1", "NIS2-AUDIT", msg))
}

func (l *Logger) Close() {
	l.lifecycleMu.Lock()
	if l.closed {
		l.lifecycleMu.Unlock()
		return
	}
	l.closed = true
	l.lifecycleMu.Unlock()

	l.asyncWG.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		if err := l.file.Sync(); err != nil {
			log.Printf("[Logger] Warning: failed to sync telemetry log during close: %v", err)
		}
		if err := l.file.Close(); err != nil {
			log.Printf("[Logger] Warning: failed to close telemetry log: %v", err)
		}
		l.file = nil
	}
}
