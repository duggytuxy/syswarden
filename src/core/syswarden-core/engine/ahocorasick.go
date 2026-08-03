package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	goahocorasick "github.com/duggytuxy/ahocorasick"
)

type RuleDef struct {
	ID        string   `json:"id"`
	Type      string   `json:"type"`
	Pattern   string   `json:"pattern,omitempty"`
	Patterns  []string `json:"patterns,omitempty"`
	Service   string   `json:"service"`
	Action    string   `json:"action,omitempty"` // "ban" (default), "detect", or "track"
	Threshold int      `json:"threshold,omitempty"`
	Window    int      `json:"window,omitempty"`
}

type Config struct {
	Rules []RuleDef `json:"rules"`
}

type Engine struct {
	ahoMachine    *goahocorasick.Automaton
	patternToRule map[string]RuleDef
	regexRules    []compiledRegex

	ahoCount         int
	defaultThreshold int
	defaultWindow    int
	tracker          sync.Map
}

type compiledRegex struct {
	def RuleDef
	re  *regexp.Regexp
}

type Match struct {
	RuleID    string
	Payload   string
	Service   string
	Action    string
	Threshold int
	Window    int
}

func NewEngine(configFile string, defaultThreshold, defaultWindow int) (*Engine, error) {
	data, err := os.ReadFile(configFile) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read signatures: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse signatures JSON: %w", err)
	}

	e := &Engine{
		patternToRule:    make(map[string]RuleDef),
		defaultThreshold: defaultThreshold,
		defaultWindow:    defaultWindow,
	}

	ahoBuilder := goahocorasick.NewBuilder()

	for _, rule := range config.Rules {
		switch rule.Type {
		case "aho-corasick":
			for _, pat := range rule.Patterns {
				ahoBuilder.AddPattern([]byte(pat))
				e.patternToRule[pat] = rule
				e.ahoCount++
			}
		case "regex":
			strictHostRegex := `(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)`
			safePattern := strings.ReplaceAll(rule.Pattern, "<HOST>", strictHostRegex)
			re, err := regexp.Compile("(?i)" + safePattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for rule %s: %w", rule.ID, err)
			}
			e.regexRules = append(e.regexRules, compiledRegex{def: rule, re: re})
		}
	}

	if e.ahoCount > 0 {
		machine, err := ahoBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build aho-corasick machine: %w", err)
		}
		e.ahoMachine = machine
	}

	// Start garbage collector for tracker
	go e.GarbageCollector()

	return e, nil
}

func (e *Engine) RuleCount() int {
	return e.ahoCount + len(e.regexRules)
}

func (e *Engine) Scan(logLine string) *Match {
	for _, rr := range e.regexRules {
		if match := rr.re.FindStringSubmatch(logLine); match != nil {
			hostIdx := rr.re.SubexpIndex("host")
			if hostIdx >= 0 && hostIdx < len(match) {
				matchedHost := match[hostIdx]
				if matchedHost != "" && net.ParseIP(matchedHost) == nil {
					continue
				}
			}

			return &Match{
				RuleID:    rr.def.ID,
				Payload:   logLine,
				Service:   rr.def.Service,
				Action:    rr.def.Action,
				Threshold: rr.def.Threshold,
				Window:    rr.def.Window,
			}
		}
	}

	if e.ahoMachine != nil {
		// Scan raw line
		if match, found := e.ahoMachine.Find([]byte(logLine), 0); found {
			if rule, ok := e.patternToRule[string(e.ahoMachine.Pattern(match.PatternID))]; ok {
				return &Match{
					RuleID:    rule.ID,
					Payload:   logLine,
					Service:   rule.Service,
					Action:    rule.Action,
					Threshold: rule.Threshold,
					Window:    rule.Window,
				}
			}
		}

		// Decode URL if possible to catch obfuscated payloads
		decodedLine, err := url.QueryUnescape(logLine)
		if err == nil && decodedLine != logLine {
			if match, found := e.ahoMachine.Find([]byte(decodedLine), 0); found {
				if rule, ok := e.patternToRule[string(e.ahoMachine.Pattern(match.PatternID))]; ok {
					return &Match{
						RuleID:    rule.ID,
						Payload:   logLine,
						Service:   rule.Service,
						Action:    rule.Action,
						Threshold: rule.Threshold,
						Window:    rule.Window,
					}
				}
			}
		}
	}

	return nil
}

// EvaluateThreshold returns true if the IP has reached the limit and should be banned
func (e *Engine) EvaluateThreshold(ip string, ruleID string, customThreshold, customWindow int) bool {
	threshold := customThreshold
	window := customWindow

	if threshold <= 0 {
		threshold = e.defaultThreshold
	}
	if window <= 0 {
		window = e.defaultWindow
	}
	if threshold <= 1 {
		return true // Instant ban if threshold is 1 or less
	}

	key := ip + ":" + ruleID
	now := time.Now().Unix()

	var timestamps []int64
	if val, ok := e.tracker.Load(key); ok {
		timestamps = val.([]int64)
	}

	// Filter valid timestamps within window
	var valid []int64
	windowStart := now - int64(window)
	for _, t := range timestamps {
		if t >= windowStart {
			valid = append(valid, t)
		}
	}

	valid = append(valid, now)

	if len(valid) >= threshold {
		e.tracker.Delete(key)
		return true
	}

	e.tracker.Store(key, valid)
	return false
}

func (e *Engine) GarbageCollector() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().Unix()
		e.tracker.Range(func(key, value interface{}) bool {
			timestamps := value.([]int64)
			var valid []int64
			// Get window safely from default, exact GC for specific custom windows is complex so we do a general cleanup
			// Using 1 hour as max TTL for cleanup to ensure memory safety
			windowStart := now - 3600
			for _, t := range timestamps {
				if t >= windowStart {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				e.tracker.Delete(key)
			} else {
				e.tracker.Store(key, valid)
			}
			return true
		})
	}
}

var standardIpRegex = regexp.MustCompile(`^(?i)(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9:]+:[a-f0-9:]+)`)
var jsonIpRegex = regexp.MustCompile(`\"(?:ClientHost|remote_ip|client_ip|ClientAddr)\"\s*:\s*\"(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9:]+:[a-f0-9:]+)\"`)

func ExtractIP(logLine string) string {
	logLine = strings.TrimSpace(logLine)
	
	// 1. Try standard JSON log format matching Traefik/Caddy
	if strings.Contains(logLine, "{") && strings.Contains(logLine, "}") {
		matches := jsonIpRegex.FindStringSubmatch(logLine)
		if len(matches) > 1 {
			return validateIPStr(matches[1])
		}
	}

	// 2. Try standard Apache/Nginx format (IP at the very beginning of the line)
	matches := standardIpRegex.FindStringSubmatch(logLine)
	if len(matches) > 1 {
		return validateIPStr(matches[1])
	}

	return ""
}

func validateIPStr(ipStr string) string {
	// Ignore unroutable loopback and generic bind addresses from internal logs
	if ipStr == "0.0.0.0" || ipStr == "127.0.0.1" || ipStr == "::1" || ipStr == "::" {
		return ""
	}
	if net.ParseIP(ipStr) != nil {
		return ipStr
	}
	return ""
}
