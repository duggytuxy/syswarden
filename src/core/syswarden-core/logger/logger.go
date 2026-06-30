package logger

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"syswarden-core/telemetry"
	"syswarden-core/webhook"
)

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
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[Logger] Warning: failed to create log dir: %v", err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
	telemetry.ReportAbuseAsync(ip, jail)
	go webhook.SendBanAlert(ip, jail, "WAF Drop (L7)")
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

	log.Printf("[SysWarden-BLOCK] IP=%s Jail=%s Payload=%s", ip, jail, payload)
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

	log.Printf("[SysWarden-ALLOWED] Legitimate access IP=%s Service=%s", ip, service)
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

	log.Printf("[SysWarden-DETECTED] Threat detected without ban IP=%s Jail=%s Payload=%s", ip, jail, payload)
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

	log.Printf("[SOC-ALERT] INSIDER THREAT DETECTED FROM WHITELISTED IP: %s (Vector: %s)", ip, jail)
}

func (l *Logger) Close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}
