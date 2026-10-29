package telemetry

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maximumAbuseReportsInFlight = 8
	maximumAbuseRecentReports   = 4096
	abuseReportInterval         = 15 * time.Minute
	abuseCleanupInterval        = time.Minute
	maximumAbuseResponseDrain   = 4096
	maximumAbuseRuleLabel       = 128
	maximumAbuseEventPreview    = 4096
)

type abuseReportLimiter struct {
	mu          sync.Mutex
	recent      map[string]time.Time
	active      int
	nextCleanup time.Time
}

// reserve bounds both live workers and duplicate-suppression memory. Cache
// pressure does not evict an unexpired cooldown to admit another report.
func (limiter *abuseReportLimiter) reserve(ip string, now time.Time) func() {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.active >= maximumAbuseReportsInFlight {
		return nil
	}
	if limiter.recent == nil {
		limiter.recent = make(map[string]time.Time)
	}
	if !now.Before(limiter.nextCleanup) {
		for address, last := range limiter.recent {
			if !now.Before(last.Add(abuseReportInterval)) {
				delete(limiter.recent, address)
			}
		}
		limiter.nextCleanup = now.Add(abuseCleanupInterval)
	}
	if last, exists := limiter.recent[ip]; exists {
		if now.Before(last.Add(abuseReportInterval)) {
			return nil
		}
	} else if len(limiter.recent) >= maximumAbuseRecentReports {
		return nil
	}
	limiter.recent[ip] = now
	limiter.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			limiter.mu.Lock()
			defer limiter.mu.Unlock()
			limiter.active--
		})
	}
}

// Rule identifiers may originate outside the compiled rule catalog. Never
// publish control characters, arbitrary prose or unbounded values as a label.
func safeAbuseRuleLabel(raw string) string {
	if len(raw) == 0 || len(raw) > maximumAbuseRuleLabel {
		return "unclassified"
	}
	for _, b := range []byte(raw) {
		if !(b >= 'a' && b <= 'z') && !(b >= 'A' && b <= 'Z') &&
			!(b >= '0' && b <= '9') && b != '-' && b != '_' && b != '.' {
			return "unclassified"
		}
	}
	return strings.ToLower(raw)
}

// deliverAbuseReport returns only fixed local diagnostics and a numeric status.
// Remote bodies, headers, redirects and transport errors are not log authority.
// A small bounded drain permits connection reuse for ordinary responses without
// allocating or retaining their contents. The production client bounds time.
func deliverAbuseReport(client *http.Client, request *http.Request) string {
	if client == nil || request == nil {
		return "[AbuseIPDB FAIL] Reporting request is unavailable"
	}
	response, err := client.Do(request)
	if err != nil {
		return "[AbuseIPDB FAIL] Reporting request failed"
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumAbuseResponseDrain))
	if response.StatusCode == http.StatusOK {
		return "[SUCCESS] AbuseIPDB returned HTTP 200"
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return "[API ERROR] AbuseIPDB returned an invalid HTTP status"
	}
	return fmt.Sprintf("[API ERROR] AbuseIPDB HTTP %d", response.StatusCode)
}
