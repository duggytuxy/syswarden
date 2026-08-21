package network

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"syswarden-core/engine"
	"syswarden-core/firewall"
	"syswarden-core/logger"
	"syswarden-core/utils"

	"github.com/spf13/viper"
)

type WAAPConfig struct {
	Logs      []string
	Threshold int
	Window    time.Duration
	Mode      string
}

type WAAPEngine struct {
	config WAAPConfig
	fw     firewall.Manager
	logger *logger.Logger
	engine *engine.Engine
	wg     sync.WaitGroup
}

func loadWAAPConfig() WAAPConfig {
	cfg := WAAPConfig{
		Threshold: 5,
		Window:    60 * time.Second,
		Mode:      "enforcing",
	}

	mode := viper.GetString("waap.enforcement_mode")
	if mode != "" {
		cfg.Mode = mode
	}

	threshold := viper.GetInt("waap.bruteforce_threshold")
	if threshold > 0 {
		cfg.Threshold = threshold
	}

	window := viper.GetInt("waap.bruteforce_window_seconds")
	if window > 0 {
		cfg.Window = time.Duration(window) * time.Second
	}

	bfLogs := viper.GetString("waap.bruteforce_logs")
	modLogs := viper.GetString("waap.modsec_logs")

	if bfLogs != "" {
		if strings.ToLower(bfLogs) == "auto" {
			cfg.Logs = append(cfg.Logs, discoverLogs()...)
		} else {
			cfg.Logs = append(cfg.Logs, strings.Fields(bfLogs)...)
		}
	}
	if modLogs != "" {
		if strings.ToLower(modLogs) == "auto" {
			cfg.Logs = append(cfg.Logs, discoverLogs()...)
		} else {
			cfg.Logs = append(cfg.Logs, strings.Fields(modLogs)...)
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

// StartContext starts the log followers and stops them when ctx is cancelled.
func (w *WAAPEngine) StartContext(ctx context.Context) {
	if ctx == nil {
		log.Println("[WAAP Engine] Disabled (No lifecycle context provided).")
		return
	}
	if len(w.config.Logs) == 0 {
		log.Println("[WAAP Engine] Disabled (No logs configured).")
		return
	}

	uniqueFiles, rejected := resolveWAAPLogFiles(w.config.Logs)
	for _, err := range rejected {
		log.Printf("[WAAP Engine] Rejecting log input: %v", err)
	}
	if len(uniqueFiles) == 0 {
		log.Println("[WAAP Engine] Disabled (No configured pattern resolved to a real regular file).")
		return
	}
	log.Printf("[WAAP Engine] Initializing Log Collector forwarding to Engine. Monitoring %d verified files", len(uniqueFiles))

	for _, file := range uniqueFiles {
		w.wg.Add(1)
		go func(path string) {
			defer w.wg.Done()
			w.tailFile(ctx, path)
		}(file)
	}
}

// Wait blocks until all log followers have observed cancellation and exited.
func (w *WAAPEngine) Wait() {
	w.wg.Wait()
}

func resolveWAAPLogFiles(patterns []string) ([]string, []error) {
	files := make(map[string]struct{})
	var rejected []error
	for _, pattern := range patterns {
		if !filepath.IsAbs(pattern) || filepath.Clean(pattern) != pattern || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
			rejected = append(rejected, fmt.Errorf("pattern %q is not an absolute canonical path", pattern))
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			rejected = append(rejected, fmt.Errorf("pattern %q is invalid: %w", pattern, err))
			continue
		}
		if len(matches) == 0 {
			rejected = append(rejected, fmt.Errorf("pattern %q has no existing match", pattern))
			continue
		}
		for _, match := range matches {
			if err := verifyWAAPLogFile(match); err != nil {
				rejected = append(rejected, err)
				continue
			}
			files[match] = struct{}{}
		}
	}
	resolved := make([]string, 0, len(files))
	for file := range files {
		resolved = append(resolved, file)
	}
	sort.Strings(resolved)
	return resolved, rejected
}

func verifyWAAPLogFile(path string) error {
	follower, err := newSecureWAAPLogFollower(path, false)
	if err != nil {
		return err
	}
	if closeErr := follower.Close(); closeErr != nil {
		return fmt.Errorf("close WAAP log %q: %w", path, closeErr)
	}
	return nil
}

func (w *WAAPEngine) tailFile(ctx context.Context, path string) {
	follower, err := newSecureWAAPLogFollower(path, true)
	if err != nil {
		log.Printf("[WAAP Engine] Refusing to tail unverified log: %v", err)
		return
	}
	defer func() {
		if err := follower.Close(); err != nil {
			log.Printf("[WAAP Engine] Failed to close %s: %v", path, err)
		}
	}()

	log.Printf("[WAAP Engine] Actively tailing %s", path)

	for {
		text, err := follower.Next(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Printf("[WAAP Engine] Stopped tailing %s: %v", path, err)
			}
			return
		}

		// Prevent recursive scanning of our own logs (infinite loops on Rocky Linux /var/log/messages)
		if strings.Contains(text, "[SYSWARDEN-BLOCK] IP=") ||
			strings.Contains(text, "[SYSWARDEN-DETECT] IP=") ||
			strings.Contains(text, "[SYSWARDEN-SHADOW-ALERT] IP=") {
			continue
		}

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

						if w.config.Mode == "audit" {
							w.logger.LogSimulatedBan(ip, match.RuleID, text)
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
