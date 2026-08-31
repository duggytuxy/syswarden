package engine

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newRequestTargetScopeTestEngine(t *testing.T) *Engine {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "signatures.json")
	config := `{
  "rules": [
    {
      "id": "sqli",
      "type": "aho-corasick",
      "patterns": ["UNION SELECT", "SLEEP("],
      "service": "http",
      "match_scope": "request-target"
    },
    {
      "id": "lfi-advanced",
      "type": "aho-corasick",
      "patterns": ["/etc/passwd", "php://filter"],
      "service": "http",
      "match_scope": "request-target"
    },
    {
      "id": "scoped-regex",
      "type": "regex",
      "pattern": "WAITFOR DELAY",
      "service": "http",
      "match_scope": "request-target",
      "action": "detect"
    },
    {
      "id": "header-oriented",
      "type": "aho-corasick",
      "patterns": ["HeaderCanary"],
      "service": "http",
      "action": "detect"
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := NewEngine(configPath, 5, 60)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return detector
}

func TestRequestTargetScopeExcludesCombinedLogHeaders(t *testing.T) {
	detector := newRequestTargetScopeTestEngine(t)
	tests := []struct {
		name string
		line string
	}{
		{
			name: "SQLi in Referer",
			line: `198.51.100.40 - - [31/Aug/2026:08:00:00 +0200] "GET /safe HTTP/1.1" 200 123 "https://example.test/?q=UNION+SELECT" "Mozilla/5.0"`,
		},
		{
			name: "SQLi in User-Agent",
			line: `198.51.100.41 - - [31/Aug/2026:08:00:01 +0200] "GET /safe HTTP/1.1" 200 123 "-" "scanner SLEEP(5)"`,
		},
		{
			name: "LFI in Referer",
			line: `198.51.100.42 - - [31/Aug/2026:08:00:02 +0200] "GET /safe HTTP/1.1" 200 123 "https://example.test/%2Fetc%2Fpasswd" "Mozilla/5.0"`,
		},
		{
			name: "LFI in User-Agent",
			line: `198.51.100.43 - - [31/Aug/2026:08:00:03 +0200] "GET /safe HTTP/1.1" 200 123 "-" "php://filter/convert.base64-encode"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if match := detector.Scan(test.line); match != nil {
				t.Fatalf("header-only attack matched scoped rule: %#v", match)
			}
		})
	}
}

func TestRequestTargetScopeMatchesRawAndDecodedTargets(t *testing.T) {
	detector := newRequestTargetScopeTestEngine(t)
	tests := []struct {
		name     string
		line     string
		wantRule string
	}{
		{
			name:     "Apache raw SQLi",
			line:     `198.51.100.50 - - [31/Aug/2026:08:10:00 +0200] "GET /search?q=SLEEP(5) HTTP/1.1" 403 12`,
			wantRule: "sqli",
		},
		{
			name:     "Nginx percent-encoded SQLi",
			line:     `198.51.100.51 - - [31/Aug/2026:08:10:01 +0200] "GET /search?q=UNION%20SELECT HTTP/1.1" 403 12 "-" "curl/8"`,
			wantRule: "sqli",
		},
		{
			name:     "Nginx form-encoded SQLi",
			line:     `198.51.100.52 - - [31/Aug/2026:08:10:02 +0200] "GET /search?q=UNION+SELECT HTTP/2.0" 403 12 "-" "curl/8"`,
			wantRule: "sqli",
		},
		{
			name:     "Apache raw LFI",
			line:     `198.51.100.53 - - [31/Aug/2026:08:10:03 +0200] "GET /../../etc/passwd HTTP/1.0" 404 0`,
			wantRule: "lfi-advanced",
		},
		{
			name:     "Apache percent-encoded LFI",
			line:     `198.51.100.54 - - [31/Aug/2026:08:10:04 +0200] "GET /..%2F..%2Fetc%2Fpasswd HTTP/1.1" 404 0`,
			wantRule: "lfi-advanced",
		},
		{
			name:     "scoped regex decoded target",
			line:     `198.51.100.55 - - [31/Aug/2026:08:10:05 +0200] "GET /search?q=WAITFOR+DELAY HTTP/1.1" 403 0`,
			wantRule: "scoped-regex",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := detector.Scan(test.line)
			if match == nil || match.RuleID != test.wantRule {
				t.Fatalf("Scan() match = %#v, want rule %q", match, test.wantRule)
			}
			if match.Payload != test.line {
				t.Fatalf("Match.Payload = %q, want complete original record", match.Payload)
			}
			if match.Host != netip.MustParseAddr(strings.Fields(test.line)[0]) {
				t.Fatalf("Match.Host = %v, want access-log source", match.Host)
			}
		})
	}
}

func TestRequestTargetScopeSupportsUnambiguousTopLevelJSON(t *testing.T) {
	detector := newRequestTargetScopeTestEngine(t)
	tests := []struct {
		name     string
		line     string
		wantRule string
	}{
		{
			name:     "path raw SQLi",
			line:     `{"client_ip":"198.51.100.60","path":"/search?q=SLEEP(5)","user_agent":"safe"}`,
			wantRule: "sqli",
		},
		{
			name:     "path encoded SQLi",
			line:     `{"remote_ip":"198.51.100.61","path":"/search?q=UNION%20SELECT","referer":"safe"}`,
			wantRule: "sqli",
		},
		{
			name:     "request URI encoded LFI",
			line:     `{"ClientHost":"198.51.100.62","request_uri":"/..%2F..%2Fetc%2Fpasswd"}`,
			wantRule: "lfi-advanced",
		},
		{
			name:     "full request line",
			line:     `{"ClientAddr":"198.51.100.63","request":"GET /search?q=SLEEP(5) HTTP/3"}`,
			wantRule: "sqli",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match := detector.Scan(test.line)
			if match == nil || match.RuleID != test.wantRule || !match.Host.IsValid() {
				t.Fatalf("Scan() match = %#v, want %q with authoritative JSON host", match, test.wantRule)
			}
		})
	}
}

func TestRequestTargetScopeRejectsMissingMalformedAndAmbiguousTargets(t *testing.T) {
	detector := newRequestTargetScopeTestEngine(t)
	oversizedTarget := "/" + strings.Repeat("a", maxRequestTargetBytes) + "SLEEP("
	tests := []struct {
		name string
		line string
	}{
		{
			name: "JSON target missing",
			line: `{"client_ip":"198.51.100.70","message":"User-Agent SLEEP(5)"}`,
		},
		{
			name: "JSON targets conflict",
			line: `{"client_ip":"198.51.100.71","path":"/safe","request_uri":"/search?q=SLEEP(5)"}`,
		},
		{
			name: "JSON duplicate target key",
			line: `{"client_ip":"198.51.100.72","path":"/safe","path":"/search?q=SLEEP(5)"}`,
		},
		{
			name: "JSON target has wrong type",
			line: `{"client_ip":"198.51.100.73","path":{"raw":"/search?q=SLEEP(5)"}}`,
		},
		{
			name: "JSON trailing text",
			line: `{"client_ip":"198.51.100.74","path":"/search?q=SLEEP(5)"} trailing`,
		},
		{
			name: "common log missing request",
			line: `198.51.100.75 - - [31/Aug/2026:08:20:00 +0200] "-" 400 0 "SLEEP(5)" "safe"`,
		},
		{
			name: "common log malformed request spacing",
			line: `198.51.100.76 - - [31/Aug/2026:08:20:01 +0200] "GET  /search?q=SLEEP(5) HTTP/1.1" 400 0`,
		},
		{
			name: "common log malformed status",
			line: `198.51.100.77 - - [31/Aug/2026:08:20:02 +0200] "GET /search?q=SLEEP(5) HTTP/1.1" nope 0`,
		},
		{
			name: "request target exceeds bound",
			line: `198.51.100.78 GET ` + oversizedTarget + ` HTTP/1.1`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if match := detector.Scan(test.line); match != nil {
				t.Fatalf("malformed or ambiguous target matched: %#v", match)
			}
		})
	}
}

func TestRecordScopeRemainsBackwardCompatibleForHeaderRules(t *testing.T) {
	detector := newRequestTargetScopeTestEngine(t)
	line := `198.51.100.80 - - [31/Aug/2026:08:30:00 +0200] "GET /safe HTTP/1.1" 200 12 "-" "HeaderCanary"`
	match := detector.Scan(line)
	if match == nil || match.RuleID != "header-oriented" || match.Action != "detect" {
		t.Fatalf("record-scoped header rule did not retain legacy behavior: %#v", match)
	}
}

func TestProductionOverlappingSQLiAndLFIHeaderRulesAreScoped(t *testing.T) {
	detector := newProductionTestEngine(t)
	tests := []string{
		`198.51.100.81 - - [31/Aug/2026:08:31:00 +0200] "GET /safe HTTP/1.1" 200 12 "https://example.test/?q=UNION+ALL+SELECT" "safe"`,
		`198.51.100.82 - - [31/Aug/2026:08:31:01 +0200] "GET /safe HTTP/1.1" 200 12 "-" "scanner /etc/passwd"`,
	}
	for _, line := range tests {
		if match := detector.Scan(line); match != nil {
			t.Fatalf("production target-oriented rule matched an HTTP header: %#v", match)
		}
	}
}

func TestProductionHeaderOrientedRuleRetainsRecordScope(t *testing.T) {
	detector := newProductionTestEngine(t)
	line := `198.51.100.83 - - [31/Aug/2026:08:32:00 +0200] "GET /safe HTTP/1.1" 200 12 "-" "GPTBot"`
	match := detector.Scan(line)
	if match == nil || match.RuleID != "aibots" {
		t.Fatalf("production header-oriented rule lost record scope: %#v", match)
	}
}

func TestMatchScopeCatalogValidation(t *testing.T) {
	tests := []struct {
		name    string
		catalog string
	}{
		{
			name:    "unknown scope",
			catalog: `{"rules":[{"id":"bad","type":"aho-corasick","patterns":["x"],"service":"http","match_scope":"headers"}]}`,
		},
		{
			name:    "scoped trusted host capture",
			catalog: `{"rules":[{"id":"bad","type":"regex","pattern":"^GET / from <HOST>$","service":"http","match_scope":"request-target","trusted_host_capture":true}]}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signatures.json")
			if err := os.WriteFile(path, []byte(test.catalog), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewEngine(path, 5, 60); err == nil {
				t.Fatal("NewEngine() accepted an invalid match scope")
			}
		})
	}
}
