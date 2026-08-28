package network

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
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

const maxWAAPLogLineBytes = 1 << 20

type WAAPEngine struct {
	config                  WAAPConfig
	fw                      firewall.Manager
	logger                  *logger.Logger
	engine                  *engine.Engine
	localInterfaceAddresses func() ([]netip.Addr, error)
	protectedHAPeers        func() ([]netip.Prefix, error)
	isWhitelisted           func(string) (bool, error)
	wg                      sync.WaitGroup
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
		config:                  cfg,
		fw:                      fw,
		logger:                  l,
		engine:                  e,
		localInterfaceAddresses: utils.LocalInterfaceAddresses,
		protectedHAPeers:        configuredHAPeerPrefixes,
		isWhitelisted:           utils.IsWhitelistedStrict,
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

		w.processLogLine(text)
	}
}

func (w *WAAPEngine) processLogLine(text string) {
	// Process logs carrying this marker are product output, never new input.
	if logger.IsInternalLogLine(text) {
		return
	}

	if w.engine == nil {
		return
	}
	match := w.engine.ScanIngress(engine.IngressSourceDirect, text)
	if match == nil {
		return
	}
	if !match.Host.IsValid() {
		return
	}
	ip := match.Host.String()
	if match.Action == "detect" {
		w.logDetected(ip, match, match.Payload)
		return
	}

	shouldBan := true
	if match.Action == "track" {
		shouldBan = w.engine.EvaluateThreshold(ip, match.RuleID, match.Threshold, match.Window)
		if !shouldBan {
			w.logShadow(ip, match, match.Payload)
		}
	}
	if !shouldBan {
		return
	}
	canonical, err := w.canonicalWAAPFirewallTarget(ip)
	if err != nil {
		if errors.Is(err, utils.ErrProtectedFirewallTarget) {
			w.logShadow(ip, match, match.Payload)
		} else {
			w.logError("WAAP firewall target policy failed closed", err)
			w.logDetected(ip, match, match.Payload)
		}
		return
	}
	switch w.config.Mode {
	case "audit":
		w.logSimulatedBan(canonical, match, match.Payload)
		return
	case "enforcing":
		// Continue to the only firewall mutation below.
	default:
		w.logError("WAAP enforcement mode is invalid", errors.New("unsupported enforcement mode"))
		w.logDetected(canonical, match, match.Payload)
		return
	}
	if w.fw == nil {
		w.logError("WAAP firewall is unavailable", errors.New("missing firewall manager"))
		w.logDetected(canonical, match, match.Payload)
		return
	}
	if err := w.fw.Ban(canonical); err != nil {
		w.logError("Failed to ban IP, logging as DETECTED", err)
		w.logDetected(canonical, match, match.Payload)
		return
	}
	w.logBan(canonical, match, match.Payload)
}

func (w *WAAPEngine) canonicalWAAPFirewallTarget(value string) (string, error) {
	if w.localInterfaceAddresses == nil || w.protectedHAPeers == nil || w.isWhitelisted == nil {
		return "", fmt.Errorf("WAAP firewall target policy is unavailable")
	}
	localAddresses, err := w.localInterfaceAddresses()
	if err != nil {
		return "", fmt.Errorf("load local interface addresses: %w", err)
	}
	peers, err := w.protectedHAPeers()
	if err != nil {
		return "", err
	}
	return utils.CanonicalFirewallMutationTarget(value, utils.FirewallTargetPolicy{
		LocalAddresses:    localAddresses,
		ProtectedPrefixes: peers,
		IsWhitelisted:     w.isWhitelisted,
	})
}

func (w *WAAPEngine) logDetected(ip string, match *engine.Match, line string) {
	if w.logger != nil {
		w.logger.LogDetectedWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (w *WAAPEngine) logShadow(ip string, match *engine.Match, line string) {
	if w.logger != nil {
		w.logger.LogShadowAlertWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (w *WAAPEngine) logSimulatedBan(ip string, match *engine.Match, line string) {
	if w.logger != nil {
		w.logger.LogSimulatedBanWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (w *WAAPEngine) logBan(ip string, match *engine.Match, line string) {
	if w.logger != nil {
		w.logger.LogBanWithRule(ip, match.RuleID, line, loggerRuleContext(match))
	}
}

func (w *WAAPEngine) logError(message string, err error) {
	if w.logger != nil {
		w.logger.Error(message, err)
	}
}

// LoadWAAPConfig is exported to allow retrieving the default thresholds
func LoadWAAPConfig() WAAPConfig {
	return loadWAAPConfig()
}
