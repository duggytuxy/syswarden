package network

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nxadm/tail"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/utils"
)

type WAAPConfig struct {
	Logs      []string
	Threshold int
	Window    time.Duration
}

type WAAPEngine struct {
	config WAAPConfig
	fw     firewall.Manager
	logger *logger.Logger

	// Track IPs: map[IP][]timestamps
	tracker sync.Map
}

func loadWAAPConfig() WAAPConfig {
	cfg := WAAPConfig{
		Threshold: 5,
		Window:    60 * time.Second,
	}

	file, err := os.Open("/opt/syswarden/syswarden-auto.conf")
	if err != nil {
		return cfg
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")

		// Keeping the BRUTEFORCE variable names to prevent breaking existing confs
		switch key {
		case "SYSWARDEN_BRUTEFORCE_LOGS":
			if val != "" {
				if strings.ToLower(val) == "auto" {
					cfg.Logs = discoverLogs()
				} else {
					cfg.Logs = strings.Fields(val)
				}
			}
		case "SYSWARDEN_BRUTEFORCE_THRESHOLD":
			if t, err := strconv.Atoi(val); err == nil && t > 0 {
				cfg.Threshold = t
			}
		case "SYSWARDEN_BRUTEFORCE_WINDOW":
			if w, err := strconv.Atoi(val); err == nil && w > 0 {
				cfg.Window = time.Duration(w) * time.Second
			}
		}
	}
	return cfg
}

func discoverLogs() []string {
	var discovered []string

	// Map of parent directories to log patterns
	autoPaths := map[string][]string{
		"/var/log/nginx":    {"/var/log/nginx/access.log", "/var/log/nginx/*.log"},
		"/var/log/apache2":  {"/var/log/apache2/access.log", "/var/log/apache2/*.log"},
		"/var/log/httpd":    {"/var/log/httpd/access_log", "/var/log/httpd/*_log"},
		"/var/log/caddy":    {"/var/log/caddy/access.log", "/var/log/caddy/*.log"},
		"/var/log/traefik":  {"/var/log/traefik/access.log", "/var/log/traefik/*.log"},
		"/var/log/lighttpd": {"/var/log/lighttpd/access.log"},
	}

	for dir, patterns := range autoPaths {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			discovered = append(discovered, patterns...)
		}
	}
	return discovered
}

func NewWAAPEngine(fw firewall.Manager, l *logger.Logger) *WAAPEngine {
	cfg := loadWAAPConfig()
	return &WAAPEngine{
		config: cfg,
		fw:     fw,
		logger: l,
	}
}

func (w *WAAPEngine) Start() {
	if len(w.config.Logs) == 0 {
		log.Println("[WAAP Engine] Disabled (No logs configured).")
		return
	}

	log.Printf("[WAAP Engine] Initializing L7 Analysis. Monitoring %d patterns (Threshold: %d, Window: %v)", len(w.config.Logs), w.config.Threshold, w.config.Window)

	// Expand wildcards
	var filesToTail []string
	for _, pattern := range w.config.Logs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			filesToTail = append(filesToTail, matches...)
		} else {
			// fallback in case it's an exact file that doesn't exist yet
			filesToTail = append(filesToTail, pattern)
		}
	}

	for _, file := range filesToTail {
		go w.tailFile(file)
	}

	// Start Garbage Collector
	go w.garbageCollector()
}

func (w *WAAPEngine) tailFile(filepath string) {
	// Attempt to touch file if it doesn't exist to prevent tail from immediately failing if created later
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		_ = os.WriteFile(filepath, []byte{}, 0640)
	}

	t, err := tail.TailFile(filepath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Location:  &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		log.Printf("[WAAP Engine] Failed to tail %s: %v", filepath, err)
		return
	}

	log.Printf("[WAAP Engine] Actively tailing %s", filepath)

	// A simple but fast regex for IPv4 extraction
	ipRegex := regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`)

	// Signatures mappings (Zero-overhead substring matching)
	// Keys are the substring to look for, values are the Jail Name
	sigSQLi := []string{"union select", "select * from", "waitfor delay", "1=1--", "%27", "pg_sleep", "xp_cmdshell"}
	sigXSS := []string{"<script", "javascript:", "onerror=", "eval(", "onload="}
	sigLFI := []string{"../../../", "..%2f", "/etc/passwd", "c:\\windows", "%c0%af", "php://filter", "php://input"}
	sigRCE := []string{"${jndi:", ";\\wget ", "|curl ", "${lower:jndi}", "/bin/sh -c"}
	sigSSRF := []string{"169.254.169.254", "metadata.google.internal", "/metadata/instance"}
	sigNoSQL := []string{"$where", "$gt:", "$ne:"}
	sigAPI := []string{"__schema", "/swagger-ui", "/openapi.json"}
	sigScanners := []string{"nikto", "sqlmap", "zgrab", "nuclei", "masscan", "kiterunner", "ffuf"}

	for line := range t.Lines {
		text := line.Text
		match := ipRegex.FindStringSubmatch(text)
		if len(match) < 2 {
			continue // No IP found, skip
		}
		ip := match[1]

		lowerText := strings.ToLower(text)
		matchedJail := ""

		// 1. Analyze high-severity signatures (Deterministic -> Immediate Ban)
		for _, sig := range sigSQLi {
			if strings.Contains(lowerText, sig) {
				matchedJail = "l7-sqli"
				break
			}
		}
		if matchedJail == "" {
			for _, sig := range sigXSS {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-xss"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigLFI {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-lfi"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigRCE {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-rce"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigScanners {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-scanner"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigSSRF {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-ssrf"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigNoSQL {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-nosql"
					break
				}
			}
		}
		if matchedJail == "" {
			for _, sig := range sigAPI {
				if strings.Contains(lowerText, sig) {
					matchedJail = "l7-api"
					break
				}
			}
		}

		if matchedJail != "" {
			w.enforceImmediateBan(ip, matchedJail, text)
			continue
		}

		// 2. Fallback to heuristic analysis (401, 403, 404 thresholds)
		if strings.Contains(text, "\" 401 ") || strings.Contains(text, "\" 403 ") || strings.Contains(text, "\" 404 ") {
			w.recordFailure(ip, text)
		}
	}
}

func (w *WAAPEngine) enforceImmediateBan(ip, jail, logLine string) {
	if utils.IsWhitelisted(ip) {
		return // Immunity for Admin IPs and Local Loop
	}

	log.Printf("[WAAP Engine] Critical L7 Signature detected (%s) for %s! Enforcing immediate ban.", jail, ip)

	// Enforce Ban
	if err := w.fw.Ban(ip); err != nil {
		w.logger.Error(fmt.Sprintf("Failed to ban L7 attacker %s", ip), err)
		return
	}

	w.logger.LogBan(ip, jail, logLine)
}

func (w *WAAPEngine) recordFailure(ip, logLine string) {
	if utils.IsWhitelisted(ip) {
		return // Immunity for Admin IPs and Local Loop
	}

	now := time.Now()

	var timestamps []time.Time
	if val, ok := w.tracker.Load(ip); ok {
		timestamps = val.([]time.Time)
	}

	// Clean old timestamps for this specific IP
	var validTimestamps []time.Time
	for _, t := range timestamps {
		if now.Sub(t) <= w.config.Window {
			validTimestamps = append(validTimestamps, t)
		}
	}

	validTimestamps = append(validTimestamps, now)
	w.tracker.Store(ip, validTimestamps)

	if len(validTimestamps) >= w.config.Threshold {
		log.Printf("[WAAP Engine] Threshold exceeded for %s! Banning at L3.", ip)

		// Clear tracker to prevent spamming bans
		w.tracker.Delete(ip)

		// Enforce Ban
		if err := w.fw.Ban(ip); err != nil {
			w.logger.Error(fmt.Sprintf("Failed to ban bruteforcer %s", ip), err)
			return
		}

		w.logger.LogBan(ip, "l7-bruteforce", logLine)
	}
}

func (w *WAAPEngine) garbageCollector() {
	ticker := time.NewTicker(w.config.Window)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		w.tracker.Range(func(key, value interface{}) bool {
			timestamps := value.([]time.Time)
			var valid []time.Time
			for _, t := range timestamps {
				if now.Sub(t) <= w.config.Window {
					valid = append(valid, t)
				}
			}

			if len(valid) == 0 {
				w.tracker.Delete(key) // Memory freed
			} else {
				w.tracker.Store(key, valid)
			}
			return true
		})
	}
}
