package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/cloudflare/ahocorasick"
)

type RuleDef struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Pattern  string   `json:"pattern,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
	Service  string   `json:"service"`
	Action   string   `json:"action,omitempty"` // "ban" (default) or "detect"
}

type Config struct {
	Rules []RuleDef `json:"rules"`
}

type Engine struct {
	ahoMatcher *ahocorasick.Matcher
	ahoDict    []string
	ahoRules   map[int]RuleDef
	regexRules []compiledRegex
}

type compiledRegex struct {
	def RuleDef
	re  *regexp.Regexp
}

type Match struct {
	RuleID  string
	Payload string
	Service string
	Action  string
}

func NewEngine(configFile string) (*Engine, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read signatures: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse signatures JSON: %w", err)
	}

	e := &Engine{
		ahoRules: make(map[int]RuleDef),
	}

	for _, rule := range config.Rules {
		switch rule.Type {
		case "aho-corasick":
			for _, pat := range rule.Patterns {
				e.ahoDict = append(e.ahoDict, pat)
				e.ahoRules[len(e.ahoDict)-1] = rule
			}
		case "regex":
			// Convert <HOST> to regex capture group for IP extraction (Strict matching to prevent timestamp False Positives)
			strictHostRegex := `(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7})`
			safePattern := strings.ReplaceAll(rule.Pattern, "<HOST>", strictHostRegex)
			re, err := regexp.Compile(safePattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex for rule %s: %w", rule.ID, err)
			}
			e.regexRules = append(e.regexRules, compiledRegex{def: rule, re: re})
		}
	}

	if len(e.ahoDict) > 0 {
		e.ahoMatcher = ahocorasick.NewStringMatcher(e.ahoDict)
	}

	return e, nil
}

func (e *Engine) RuleCount() int {
	return len(e.ahoDict) + len(e.regexRules)
}

// Scan processes a log line. It first attempts RE2 regex extraction, then Aho-Corasick.
func (e *Engine) Scan(logLine string) *Match {
	// 1. Fast Linear Regex Matching (O(N) RE2)
	for _, rr := range e.regexRules {
		if match := rr.re.FindStringSubmatch(logLine); match != nil {
			return &Match{
				RuleID:  rr.def.ID,
				Payload: logLine,
				Service: rr.def.Service,
				Action:  rr.def.Action,
			}
		}
	}

	// 2. Aho-Corasick O(N) Substring Match
	if e.ahoMatcher != nil {
		matches := e.ahoMatcher.Match([]byte(logLine))
		if len(matches) > 0 {
			// First match is sufficient
			idx := matches[0]
			rule := e.ahoRules[idx]
			return &Match{
				RuleID:  rule.ID,
				Payload: logLine,
				Service: rule.Service,
				Action:  rule.Action,
			}
		}
	}

	return nil
}

// ExtractIP acts as a fast fallback to extract IP if Aho-Corasick matches but the IP isn't explicitly known.
var ipRegex = regexp.MustCompile(`(?i)(?P<host>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-f0-9:]+:[a-f0-9:]+)`)

func ExtractIP(logLine string) string {
	matches := ipRegex.FindAllStringSubmatch(logLine, -1)
	for _, match := range matches {
		if len(match) > 1 {
			if net.ParseIP(match[1]) != nil {
				return match[1]
			}
		}
	}
	return ""
}
