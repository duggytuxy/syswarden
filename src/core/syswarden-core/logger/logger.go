package logger

import (
	"crypto/rand"
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
)

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
	file *os.File
	mu   sync.Mutex
}

// TelemetryEvent represents a banned or allowed IP event
type TelemetryEvent struct {
	Action    string `json:"action,omitempty"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
	Severity  int    `json:"severity,omitempty"`
}

func NewLogger(logPath string) *Logger {
	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("[Logger] Warning: failed to create log dir: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err != nil {
		log.Printf("[Logger] Warning: failed to open log file %s: %v", logPath, err)
		return &Logger{}
	}

	return &Logger{file: file}
}

func (l *Logger) Info(msg string) {
	log.Printf("[INFO] %s", msg)
}

func (l *Logger) Error(msg string, err error) {
	log.Printf("[ERROR] %s: %v", msg, err)
}

// LogBan writes a JSON telemetry event when an IP is banned
func (l *Logger) LogBan(ip, jail, payload string) {
	telemetry.ReportAbuseAsync(ip, jail, payload)
	go webhook.SendBanAlert(ip, jail, "WAF Drop (L7)")
	if err := persistBanToDisk(ip); err != nil {
		log.Printf("[Logger] Failed to persist WAF ban: %v", err)
	}

	if l.file == nil {
		return
	}

	event := TelemetryEvent{
		Action:    "BANNED",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Jail:      jail,
		Payload:   payload,
		Severity:  10,
	}

	data, err := json.Marshal(event)
	if err != nil {
		l.Error("Failed to marshal telemetry event", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(data); err != nil {
		log.Printf("[Logger] Error writing telemetry data: %v", err)
	}
	if _, err := l.file.Write([]byte("\n")); err != nil {
		log.Printf("[Logger] Error writing newline: %v", err)
	}

	log.Printf("[SYSWARDEN-BLOCK] IP=%s Jail=%s Payload=%s", ip, jail, payload)
}

// LogAllowed writes a JSON telemetry event when an IP is successfully allowed (e.g. login)
func (l *Logger) LogAllowed(ip, service, payload string) {
	go webhook.SendAllowAlert(ip, service)
	if l.file == nil {
		return
	}

	event := TelemetryEvent{
		Action:    "ALLOWED",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Jail:      service, // Store service in the Jail field for simplicity
		Payload:   payload,
		Severity:  3,
	}

	data, err := json.Marshal(event)
	if err != nil {
		l.Error("Failed to marshal telemetry event", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(data); err != nil {
		log.Printf("[Logger] Error writing telemetry data: %v", err)
	}
	if _, err := l.file.Write([]byte("\n")); err != nil {
		log.Printf("[Logger] Error writing newline: %v", err)
	}

	log.Printf("[SYSWARDEN-ALLOWED] Legitimate access IP=%s Service=%s", ip, service)
}

// LogDetected writes a JSON telemetry event when an IP is detected but not banned
func (l *Logger) LogDetected(ip, jail, payload string) {
	go webhook.SendDetectedAlert(ip, jail, "Detection Only (No Drop)")
	if l.file == nil {
		return
	}

	event := TelemetryEvent{
		Action:    "DETECTED",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Jail:      jail,
		Payload:   payload,
		Severity:  7,
	}

	data, err := json.Marshal(event)
	if err != nil {
		l.Error("Failed to marshal telemetry event", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(data); err != nil {
		log.Printf("[Logger] Error writing telemetry data: %v", err)
	}
	if _, err := l.file.Write([]byte("\n")); err != nil {
		log.Printf("[Logger] Error writing newline: %v", err)
	}

	log.Printf("[SYSWARDEN-DETECTED] Threat detected without ban IP=%s Jail=%s Payload=%s", ip, jail, payload)
}

// LogShadowAlert writes a JSON telemetry event when an internal threat is detected but not banned
func (l *Logger) LogShadowAlert(ip, jail, payload string) {
	go webhook.SendShadowAlert(ip, jail)
	if l.file == nil {
		return
	}

	event := TelemetryEvent{
		Action:    "SHADOW-ALERT",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Jail:      jail,
		Payload:   payload,
		Severity:  8,
	}

	data, err := json.Marshal(event)
	if err != nil {
		l.Error("Failed to marshal telemetry event", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(data); err != nil {
		log.Printf("[Logger] Error writing telemetry data: %v", err)
	}
	if _, err := l.file.Write([]byte("\n")); err != nil {
		log.Printf("[Logger] Error writing newline: %v", err)
	}

	if utils.IsWhitelisted(ip) {
		log.Printf("[SOC-ALERT] INSIDER THREAT DETECTED FROM WHITELISTED IP: %s (Vector: %s)", ip, jail)
	} else {
		log.Printf("[SOC-ALERT] HIGH RISK THREAT TRACKING (PRE-BAN): %s (Vector: %s)", ip, jail)
	}
}

// LogSimulatedBan logs an IP that would have been banned but was bypassed due to Audit mode.
func (l *Logger) LogSimulatedBan(ip, jail, payload string) {
	if payload == "" {
		payload = "No payload"
	}

	event := TelemetryEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Action:    "SHADOW-ALERT", // Use SHADOW-ALERT but we will change TUI to parse SIMULATED-BAN, wait, I can just use SIMULATED-BAN
		Jail:      jail,
		Payload:   payload,
	}
	event.Action = "SIMULATED-BAN"

	data, err := json.Marshal(event)
	if err == nil && l.file != nil {
		l.mu.Lock()
		_, _ = l.file.Write(data)
		_, _ = l.file.Write([]byte("\n"))
		l.mu.Unlock()
	}

	log.Printf("[SYSWARDEN-SIMULATED-BAN] IP=%s JAIL=%s PAYLOAD=%s\n", ip, jail, payload)
}

// LogComplianceDrift logs a deviation found by a selected local check. The
// retained method and structured identifiers preserve consumer compatibility;
// the payload makes no compliance claim.
func (l *Logger) LogComplianceDrift(msg string) {
	event := TelemetryEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        "127.0.0.1",
		Action:    "COMPLIANCE-DRIFT",
		Jail:      "NIS2-AUDIT",
		Payload:   msg,
	}

	data, err := json.Marshal(event)
	if err == nil && l.file != nil {
		l.mu.Lock()
		_, _ = l.file.Write(data)
		_, _ = l.file.Write([]byte("\n"))
		l.mu.Unlock()
	}

	go webhook.SendComplianceAlert(msg, "DRIFT")

	log.Printf("[SYSWARDEN-LOCAL-CHECK-DRIFT] MSG=%s\n", msg)
}

// LogComplianceOK logs that the selected local checks did not find a
// deviation. The retained method and structured identifiers preserve consumer
// compatibility; the payload makes no compliance claim.
func (l *Logger) LogComplianceOK(msg string) {
	event := TelemetryEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        "127.0.0.1",
		Action:    "COMPLIANCE-OK",
		Jail:      "NIS2-AUDIT",
		Payload:   msg,
	}

	data, err := json.Marshal(event)
	if err == nil && l.file != nil {
		l.mu.Lock()
		_, _ = l.file.Write(data)
		_, _ = l.file.Write([]byte("\n"))
		l.mu.Unlock()
	}

	go webhook.SendComplianceAlert(msg, "OK")

	log.Printf("[SYSWARDEN-LOCAL-CHECK-OK] MSG=%s\n", msg)
}

func (l *Logger) Close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}
