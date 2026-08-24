package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	goahocorasick "github.com/duggytuxy/ahocorasick"
)

type RuleDef struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Pattern            string   `json:"pattern,omitempty"`
	Patterns           []string `json:"patterns,omitempty"`
	Service            string   `json:"service"`
	Action             string   `json:"action,omitempty"` // "ban" (default), "detect", or "track"
	Threshold          int      `json:"threshold,omitempty"`
	Window             int      `json:"window,omitempty"`
	TrustedHostCapture bool     `json:"trusted_host_capture,omitempty"`
}

type Config struct {
	Rules []RuleDef `json:"rules"`
}

type Engine struct {
	ahoMachine    *goahocorasick.Automaton
	patternToRule map[string][]RuleDef
	regexRules    []compiledRegex

	ahoCount         int
	defaultThreshold int
	defaultWindow    int
	tracker          sync.Map
	trackerMu        sync.Mutex
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
	Host      netip.Addr
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
		patternToRule:    make(map[string][]RuleDef),
		defaultThreshold: defaultThreshold,
		defaultWindow:    defaultWindow,
	}

	ahoBuilder := goahocorasick.NewBuilder()

	for _, rule := range config.Rules {
		switch rule.Type {
		case "aho-corasick":
			if rule.TrustedHostCapture {
				return nil, fmt.Errorf("rule %s cannot trust a host capture without a regex placeholder", rule.ID)
			}
			for _, pat := range rule.Patterns {
				ahoBuilder.AddPattern([]byte(pat))
				e.patternToRule[pat] = append(e.patternToRule[pat], rule)
				e.ahoCount++
			}
		case "regex":
			if rule.TrustedHostCapture && (strings.Count(rule.Pattern, "<HOST>") != 1 || !strings.HasPrefix(rule.Pattern, "^")) {
				return nil, fmt.Errorf("rule %s must be anchored and contain exactly one <HOST> placeholder for a trusted capture", rule.ID)
			}
			strictHostRegex := `(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-fA-F0-9:]+:[a-fA-F0-9:]+)`
			safePattern := strings.ReplaceAll(rule.Pattern, "<HOST>", strictHostRegex)
			re, err := regexp.Compile("(?i)" + safePattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for rule %s: %w", rule.ID, err)
			}
			if rule.TrustedHostCapture {
				hostCaptureCount := 0
				for _, name := range re.SubexpNames() {
					if name == "host" {
						hostCaptureCount++
					}
				}
				if hostCaptureCount != 1 {
					return nil, fmt.Errorf("rule %s must compile to exactly one trusted host capture", rule.ID)
				}
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
	structuralHost := authoritativeRecordHost(logLine)
	type regexCandidate struct {
		match *Match
		start int
	}
	regexCandidates := make([]regexCandidate, 0, len(e.regexRules))
	for _, rr := range e.regexRules {
		if indexes := rr.re.FindStringSubmatchIndex(logLine); indexes != nil {
			hostIdx := rr.re.SubexpIndex("host")
			host := structuralHost
			if !host.IsValid() && hostIdx >= 0 && rr.def.TrustedHostCapture {
				indexOffset := 2 * hostIdx
				if indexOffset+1 >= len(indexes) || indexes[indexOffset] < 0 || indexes[indexOffset+1] < 0 {
					continue
				}
				var ok bool
				host, ok = canonicalSourceAddr(logLine[indexes[indexOffset]:indexes[indexOffset+1]])
				if !ok {
					continue
				}
			}

			regexCandidates = append(regexCandidates, regexCandidate{match: &Match{
				RuleID:    rr.def.ID,
				Payload:   logLine,
				Service:   rr.def.Service,
				Action:    rr.def.Action,
				Threshold: rr.def.Threshold,
				Window:    rr.def.Window,
				Host:      host,
			}, start: indexes[0]})
		}
	}

	// A syslog record does not have a structural leading or JSON address. In
	// that case, bind the record to the host captured by the earliest matching
	// signature. Later attacker-controlled text may match another service's
	// signature, but it cannot replace that record-level authority.
	var capturedAuthority netip.Addr
	if !structuralHost.IsValid() {
		authorityStart := len(logLine) + 1
		for _, candidate := range regexCandidates {
			if candidate.match.Host.IsValid() && candidate.start < authorityStart {
				capturedAuthority = candidate.match.Host
				authorityStart = candidate.start
			}
		}
	}

	var best *Match
	for _, candidate := range regexCandidates {
		if capturedAuthority.IsValid() && candidate.match.Host.IsValid() && candidate.match.Host != capturedAuthority {
			continue
		}
		best = preferHigherImpactMatch(best, candidate.match)
	}

	if e.ahoMachine != nil {
		addMatches := func(content []byte) {
			for _, ahoMatch := range e.ahoMachine.FindAllOverlapping(content) {
				for _, rule := range e.patternToRule[string(e.ahoMachine.Pattern(ahoMatch.PatternID))] {
					best = preferHigherImpactMatch(best, &Match{
						RuleID:    rule.ID,
						Payload:   logLine,
						Service:   rule.Service,
						Action:    rule.Action,
						Threshold: rule.Threshold,
						Window:    rule.Window,
						Host:      structuralHost,
					})
				}
			}
		}

		addMatches([]byte(logLine))
		decodedLine, err := url.QueryUnescape(logLine)
		if err == nil && decodedLine != logLine {
			addMatches([]byte(decodedLine))
		}
	}

	return best
}

func preferHigherImpactMatch(current, candidate *Match) *Match {
	if current == nil {
		return candidate
	}
	if candidate.Host.IsValid() != current.Host.IsValid() {
		if candidate.Host.IsValid() {
			return candidate
		}
		return current
	}
	if matchImpact(candidate.Action) > matchImpact(current.Action) {
		return candidate
	}
	return current
}

func matchImpact(action string) int {
	switch action {
	case "detect":
		return 1
	case "track":
		return 2
	default:
		return 3
	}
}

func authoritativeRecordHost(logLine string) netip.Addr {
	value := ExtractIP(logLine)
	if value == "" {
		return netip.Addr{}
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return address.Unmap()
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
	e.trackerMu.Lock()
	defer e.trackerMu.Unlock()

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
		e.trackerMu.Lock()
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
		e.trackerMu.Unlock()
	}
}

var jsonIPFieldNames = map[string]struct{}{
	"ClientHost": {},
	"remote_ip":  {},
	"remoteAddr": {},
	"client_ip":  {},
	"ClientAddr": {},
}

func ExtractIP(logLine string) string {
	logLine = strings.TrimSpace(logLine)
	if logLine == "" {
		return ""
	}

	// A leading address is authoritative for conventional access logs. Checking it
	// first prevents attacker-controlled text later in the record from replacing it.
	leadingEnd := strings.IndexAny(logLine, " \t\r\n")
	if leadingEnd < 0 {
		leadingEnd = len(logLine)
	}
	if addr, ok := canonicalSourceAddr(logLine[:leadingEnd]); ok {
		return addr.String()
	}

	// Structured logs are accepted only when the complete record is one JSON
	// object and an unambiguous supported field exists at its top level.
	if addr, ok := extractTopLevelJSONAddr(logLine); ok {
		return addr.String()
	}

	return ""
}

func extractTopLevelJSONAddr(logLine string) (netip.Addr, bool) {
	decoder := json.NewDecoder(strings.NewReader(logLine))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return netip.Addr{}, false
	}

	seen := make(map[string]struct{})
	var candidate netip.Addr
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return netip.Addr{}, false
		}
		key, ok := keyToken.(string)
		if !ok {
			return netip.Addr{}, false
		}
		if _, duplicate := seen[key]; duplicate {
			return netip.Addr{}, false
		}
		seen[key] = struct{}{}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return netip.Addr{}, false
		}
		if _, supported := jsonIPFieldNames[key]; !supported {
			continue
		}

		var encodedAddr string
		if err := json.Unmarshal(value, &encodedAddr); err != nil {
			return netip.Addr{}, false
		}
		addr, valid := canonicalSourceAddr(encodedAddr)
		if !valid {
			return netip.Addr{}, false
		}
		if candidate.IsValid() && candidate != addr {
			return netip.Addr{}, false
		}
		candidate = addr
	}

	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return netip.Addr{}, false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return netip.Addr{}, false
	}
	return candidate, candidate.IsValid()
}

func canonicalSourceAddr(raw string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr.IsLoopback() {
		return netip.Addr{}, false
	}
	return addr, true
}
