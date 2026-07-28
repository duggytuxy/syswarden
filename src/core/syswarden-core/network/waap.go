package network

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/utils"

	"github.com/nxadm/tail"
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
	engine *engine.Engine
}

func loadWAAPConfig() WAAPConfig {
	cfg := WAAPConfig{
		Threshold: 5,
		Window:    60 * time.Second,
	}

	file, err := os.Open("/opt/syswarden/syswarden-auto.conf") // #nosec
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
		case "SYSWARDEN_BRUTEFORCE_LOGS", "SYSWARDEN_MODSEC_LOGS":
			if val != "" {
				if strings.ToLower(val) == "auto" {
					cfg.Logs = append(cfg.Logs, discoverLogs()...)
				} else {
					cfg.Logs = append(cfg.Logs, strings.Fields(val)...)
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
	autoPaths := map[string][]string{
		"/var/log/nginx":    {"/var/log/nginx/access.log", "/var/log/nginx/*.log"},
		"/var/log/apache2":  {"/var/log/apache2/access.log", "/var/log/apache2/*.log"},
		"/var/log/httpd":    {"/var/log/httpd/access_log", "/var/log/httpd/*_log"},
		"/var/log/caddy":    {"/var/log/caddy/access.log", "/var/log/caddy/*.log"},
		"/var/log/traefik":  {"/var/log/traefik/access.log", "/var/log/traefik/*.log"},
		"/var/log/lighttpd": {"/var/log/lighttpd/access.log"},
		"/var/log":          {"/var/log/secure", "/var/log/auth.log", "/var/log/messages"},
	}

	for dir, patterns := range autoPaths {
		if stat, err := os.Stat(dir); err == nil && stat.IsDir() {
			discovered = append(discovered, patterns...)
		}
	}
	return discovered
}

func NewWAAPEngine(fw firewall.Manager, l *logger.Logger, e *engine.Engine) *WAAPEngine {
	cfg := loadWAAPConfig()
	return &WAAPEngine{
		config: cfg,
		fw:     fw,
		logger: l,
		engine: e,
	}
}

func (w *WAAPEngine) Start() {
	if len(w.config.Logs) == 0 {
		log.Println("[WAAP Engine] Disabled (No logs configured).")
		return
	}

	log.Printf("[WAAP Engine] Initializing Log Collector forwarding to Engine. Monitoring %d patterns", len(w.config.Logs))

	var filesToTail []string
	for _, pattern := range w.config.Logs {
		matches, err := filepath.Glob(pattern)
		if err == nil && len(matches) > 0 {
			filesToTail = append(filesToTail, matches...)
		} else {
			filesToTail = append(filesToTail, pattern)
		}
	}

	// Deduplicate
	dedup := make(map[string]bool)
	var uniqueFiles []string
	for _, f := range filesToTail {
		if !dedup[f] {
			dedup[f] = true
			uniqueFiles = append(uniqueFiles, f)
		}
	}

	for _, file := range uniqueFiles {
		go w.tailFile(file)
	}
}

func (w *WAAPEngine) tailFile(filepath string) {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		_ = os.WriteFile(filepath, []byte{}, 0600)
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

	for line := range t.Lines {
		text := line.Text

		match := w.engine.Scan(text)
		if match != nil {
			ip := engine.ExtractIP(text)
			if ip != "" {
				if match.Action == "detect" {
					w.logger.LogDetected(ip, match.RuleID, text)
				} else {
					shouldBan := true
					if match.Action == "track" {
						shouldBan = w.engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
						if !shouldBan {
							w.logger.LogShadowAlert(ip, match.RuleID, text)
						}
					}

					if shouldBan {
						if utils.IsWhitelisted(ip) {
							w.logger.LogShadowAlert(ip, match.RuleID, text)
							continue
						}
						err := w.fw.Ban(ip)
						if err != nil {
							w.logger.Error("Failed to ban IP, logging as DETECTED", err)
							w.logger.LogDetected(ip, match.RuleID, text)
						} else {
							w.logger.LogBan(ip, match.RuleID, text)
						}
					}
				}
			}
		}
	}
}

// LoadWAAPConfig is exported to allow retrieving the default thresholds
func LoadWAAPConfig() WAAPConfig {
	return loadWAAPConfig()
}
