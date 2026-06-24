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
)

type BruteforceConfig struct {
	Logs      []string
	Threshold int
	Window    time.Duration
}

type BruteforceEngine struct {
	config BruteforceConfig
	fw     firewall.Manager
	logger *logger.Logger

	// Track IPs: map[IP][]timestamps
	tracker sync.Map
}

func loadBruteforceConfig() BruteforceConfig {
	cfg := BruteforceConfig{
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

		switch key {
		case "SYSWARDEN_BRUTEFORCE_LOGS":
			if val != "" {
				cfg.Logs = strings.Fields(val)
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

func NewBruteforceEngine(fw firewall.Manager, l *logger.Logger) *BruteforceEngine {
	cfg := loadBruteforceConfig()
	return &BruteforceEngine{
		config: cfg,
		fw:     fw,
		logger: l,
	}
}

func (b *BruteforceEngine) Start() {
	if len(b.config.Logs) == 0 {
		log.Println("[BruteForce Engine] Disabled (No logs configured).")
		return
	}

	log.Printf("[BruteForce Engine] Initializing L7 Analysis. Monitoring %d patterns (Threshold: %d, Window: %v)", len(b.config.Logs), b.config.Threshold, b.config.Window)

	// Expand wildcards
	var filesToTail []string
	for _, pattern := range b.config.Logs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			filesToTail = append(filesToTail, matches...)
		} else {
			// fallback in case it's an exact file that doesn't exist yet
			filesToTail = append(filesToTail, pattern)
		}
	}

	for _, file := range filesToTail {
		go b.tailFile(file)
	}

	// Start Garbage Collector
	go b.garbageCollector()
}

func (b *BruteforceEngine) tailFile(filepath string) {
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
		log.Printf("[BruteForce Engine] Failed to tail %s: %v", filepath, err)
		return
	}

	log.Printf("[BruteForce Engine] Actively tailing %s", filepath)

	// Regex to extract IP and detect 401, 403, 404
	// Assumes standard Nginx/Apache/Traefik access log: "1.2.3.4 ... \"GET / HTTP...\" 401 ..."
	// A simple but fast regex for IPv4
	ipRegex := regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`)

	for line := range t.Lines {
		text := line.Text
		if strings.Contains(text, "\" 401 ") || strings.Contains(text, "\" 403 ") || strings.Contains(text, "\" 404 ") {
			match := ipRegex.FindStringSubmatch(text)
			if len(match) > 1 {
				ip := match[1]
				b.recordFailure(ip, text)
			}
		}
	}
}

func (b *BruteforceEngine) recordFailure(ip, logLine string) {
	now := time.Now()

	var timestamps []time.Time
	if val, ok := b.tracker.Load(ip); ok {
		timestamps = val.([]time.Time)
	}

	// Clean old timestamps for this specific IP
	var validTimestamps []time.Time
	for _, t := range timestamps {
		if now.Sub(t) <= b.config.Window {
			validTimestamps = append(validTimestamps, t)
		}
	}

	validTimestamps = append(validTimestamps, now)
	b.tracker.Store(ip, validTimestamps)

	if len(validTimestamps) >= b.config.Threshold {
		log.Printf("[BruteForce Engine] Threshold exceeded for %s! Banning at L3.", ip)

		// Clear tracker to prevent spamming bans
		b.tracker.Delete(ip)

		// Enforce Ban
		if err := b.fw.Ban(ip); err != nil {
			b.logger.Error(fmt.Sprintf("Failed to ban bruteforcer %s", ip), err)
			return
		}

		b.logger.LogBan(ip, "l7-bruteforce", logLine)
	}
}

func (b *BruteforceEngine) garbageCollector() {
	ticker := time.NewTicker(b.config.Window)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		b.tracker.Range(func(key, value interface{}) bool {
			timestamps := value.([]time.Time)
			var valid []time.Time
			for _, t := range timestamps {
				if now.Sub(t) <= b.config.Window {
					valid = append(valid, t)
				}
			}

			if len(valid) == 0 {
				b.tracker.Delete(key) // Memory freed
			} else {
				b.tracker.Store(key, valid)
			}
			return true
		})
	}
}
