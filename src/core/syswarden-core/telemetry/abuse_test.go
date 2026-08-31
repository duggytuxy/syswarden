package telemetry

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type abuseRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn abuseRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestAbuseReportPayloadNeverPublishesRequestData_SW_KPI_001(t *testing.T) {
	now := time.Date(2026, time.August, 31, 2, 7, 26, 0, time.UTC)
	payloads := []struct {
		name    string
		payload string
		canary  string
	}{
		{name: "query", payload: `GET /login?token=QUERY-CANARY-901 HTTP/1.1`, canary: "QUERY-CANARY-901"},
		{name: "path segment", payload: `GET /reset/PATH-CANARY-902/confirm HTTP/1.1`, canary: "PATH-CANARY-902"},
		{name: "absolute URI userinfo", payload: `GET https://ABSOLUTE-CANARY-903@example.test/private HTTP/1.1`, canary: "ABSOLUTE-CANARY-903"},
		{name: "unicode", payload: `POST /account/UNICODE-CANARY-904-秘密 HTTP/1.1`, canary: "UNICODE-CANARY-904-秘密"},
		{name: "control characters", payload: "GET /control/CONTROL-CANARY-905\x00\x1f/private HTTP/1.1", canary: "CONTROL-CANARY-905"},
	}

	var firstJSON string
	for _, test := range payloads {
		t.Run(test.name, func(t *testing.T) {
			req, err := newAbuseReportRequest("192.0.2.44", "sqli", test.payload, "test-api-key", now)
			if err != nil {
				t.Fatalf("construct AbuseIPDB request: %v", err)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read final AbuseIPDB request body: %v", err)
			}
			bodyText := string(body)
			if strings.Contains(bodyText, test.canary) || strings.Contains(bodyText, test.payload) ||
				strings.Contains(bodyText, `\u0000`) || strings.Contains(bodyText, `\u001f`) ||
				strings.Contains(bodyText, "test-api-key") {
				t.Fatalf("final AbuseIPDB JSON leaked request data: %s", bodyText)
			}
			if strings.Contains(bodyText, "/login") || strings.Contains(bodyText, "/reset/") || strings.Contains(bodyText, "example.test") || strings.Contains(bodyText, "private") {
				t.Fatalf("final AbuseIPDB JSON leaked a request target fragment: %s", bodyText)
			}
			if req.Method != http.MethodPost || req.URL.String() != abuseReportURL {
				t.Fatalf("request target = %s %s", req.Method, req.URL)
			}
			if req.Header.Get("Key") != "test-api-key" || req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("request headers = %#v", req.Header)
			}

			var report abuseReportPayload
			if err := json.Unmarshal(body, &report); err != nil {
				t.Fatalf("decode final AbuseIPDB request body: %v", err)
			}
			if !strings.Contains(report.Comment, "request target redacted") {
				t.Fatalf("comment does not state the privacy boundary: %q", report.Comment)
			}
			if report.Categories != "16,21" {
				t.Fatalf("categories = %q, want 16,21", report.Categories)
			}
			if firstJSON == "" {
				firstJSON = bodyText
			} else if bodyText != firstJSON {
				t.Fatalf("request payload changed public JSON:\nfirst: %s\n  got: %s", firstJSON, bodyText)
			}
		})
	}
}

func TestReportedPortIsStrictAndBounded_SW_KPI_002(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		fallback string
		want     string
	}{
		{name: "ssh port", payload: "failed login on port 2222: user root", fallback: "22", want: "2222"},
		{name: "firewall destination", payload: "PROTO=TCP DPT=443 SYN", fallback: "unknown", want: "443"},
		{name: "canonicalizes leading zeroes", payload: "DPT=00443 ", fallback: "unknown", want: "443"},
		{name: "zero", payload: "DPT=0 ", fallback: "unknown", want: "unknown"},
		{name: "above maximum", payload: "DPT=65536 ", fallback: "unknown", want: "unknown"},
		{name: "negative", payload: "DPT=-1 ", fallback: "unknown", want: "unknown"},
		{name: "suffix injection", payload: "DPT=22;QUERY-CANARY ", fallback: "unknown", want: "unknown"},
		{name: "newline injection", payload: "port 2222\nQUERY-CANARY", fallback: "22", want: "2222"},
		{name: "unicode digits", payload: "DPT=４４３ ", fallback: "unknown", want: "unknown"},
		{name: "empty", payload: "DPT= ", fallback: "unknown", want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := reportedPort(test.payload, test.fallback); got != test.want {
				t.Fatalf("reportedPort(%q) = %q, want %q", test.payload, got, test.want)
			}
		})
	}
}

func TestAbuseCategoriesUseRealRuleIDs_SW_KPI_003(t *testing.T) {
	tests := map[string]string{
		"sqli":              "16,21",
		"l7-sqli":           "16,21",
		"lfi-advanced":      "21",
		"xss":               "21",
		"owasp-a03-xss":     "21",
		"rce":               "21",
		"php-rce-generic":   "21",
		"ssrf":              "21",
		"nosql":             "21",
		"apimapper":         "21",
		"nginx-scanner":     "19",
		"l7-bruteforce":     "18,21",
		"ssh-auth":          "18,22",
		"firewall-portscan": "14",
	}

	for jail, want := range tests {
		t.Run(jail, func(t *testing.T) {
			if got := abuseCategories(jail); got != want {
				t.Fatalf("abuseCategories(%q) = %q, want %q", jail, got, want)
			}
		})
	}
}

func TestAbuseHTTPClientDoesNotFollowRedirects_SW_KPI_004(t *testing.T) {
	requests := 0
	client := newAbuseHTTPClient()
	client.Transport = abuseRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if requests != 1 {
			t.Fatalf("HTTP client followed redirect to %s", req.URL)
		}
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"https://redirected.example.test/collect"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	resp, err := client.Post(abuseReportURL, "application/json", strings.NewReader(`{"ip":"192.0.2.44"}`))
	if err != nil {
		t.Fatalf("post redirecting endpoint: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}
	if requests != 1 {
		t.Fatalf("transport received %d requests, want 1", requests)
	}
	if err := client.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v", err)
	}
}
