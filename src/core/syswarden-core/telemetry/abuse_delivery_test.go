package telemetry

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAbuseLimiterCapsConcurrentWorkersAndReleasesOnce(t *testing.T) {
	var limiter abuseReportLimiter
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	permits := make(chan func(), 64)
	var attempts sync.WaitGroup
	for i := 0; i < 64; i++ {
		attempts.Add(1)
		go func(i int) {
			defer attempts.Done()
			if release := limiter.reserve(fmt.Sprintf("192.0.2.%d", i+1), now); release != nil {
				permits <- release
			}
		}(i)
	}
	attempts.Wait()
	close(permits)
	if len(permits) != maximumAbuseReportsInFlight || limiter.active != maximumAbuseReportsInFlight {
		t.Fatal("report worker cap was not exact")
	}
	first := <-permits
	first()
	first()
	if limiter.active != maximumAbuseReportsInFlight-1 {
		t.Fatal("repeated release returned another worker's permit")
	}
	replacement := limiter.reserve("198.51.100.1", now)
	if replacement == nil {
		t.Fatal("released worker slot was not reusable")
	}
	for release := range permits {
		release()
	}
	replacement()
	replacement()
	if limiter.active != 0 {
		t.Fatal("worker permits leaked")
	}
}

func TestAbuseLimiterBoundsMemoryWithoutEvictingCooldowns(t *testing.T) {
	var limiter abuseReportLimiter
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maximumAbuseRecentReports; i++ {
		release := limiter.reserve(fmt.Sprintf("2001:db8::%x", i+1), now)
		if release == nil {
			t.Fatal("cache filled before its bound")
		}
		release()
	}
	if release := limiter.reserve("198.51.100.1", now.Add(time.Second)); release != nil {
		release()
		t.Fatal("cache admitted another address past its bound")
	}
	if len(limiter.recent) != maximumAbuseRecentReports {
		t.Fatal("cache cap changed")
	}
	if release := limiter.reserve("2001:db8::1", now.Add(abuseReportInterval-time.Nanosecond)); release != nil {
		release()
		t.Fatal("cache pressure evicted an unexpired cooldown")
	}
	release := limiter.reserve("198.51.100.1", now.Add(abuseReportInterval+abuseCleanupInterval))
	if release == nil {
		t.Fatal("expired cache was not reclaimed")
	}
	release()
	if len(limiter.recent) != 1 {
		t.Fatal("expired entries were retained after cleanup")
	}
}

func TestAbuseLimiterKeepsCooldownAfterFailureAndClockRegression(t *testing.T) {
	var limiter abuseReportLimiter
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	release := limiter.reserve("192.0.2.1", now)
	if release == nil {
		t.Fatal("first report refused")
	}
	release()
	for _, at := range []time.Time{now.Add(-time.Hour), now, now.Add(abuseReportInterval - time.Nanosecond)} {
		if release := limiter.reserve("192.0.2.1", at); release != nil {
			release()
			t.Fatal("cooldown bypassed by retry or clock regression")
		}
	}
	release = limiter.reserve("192.0.2.1", now.Add(abuseReportInterval))
	if release == nil {
		t.Fatal("exact cooldown boundary refused")
	}
	release()
}

type abuseUnboundedBody struct {
	read, closed int
	fail         bool
}

func (body *abuseUnboundedBody) Read(data []byte) (int, error) {
	if body.fail {
		return 0, errors.New("PRIVATE-RESPONSE-ERROR")
	}
	for i := range data {
		data[i] = 'x'
	}
	body.read += len(data)
	return len(data), nil
}
func (body *abuseUnboundedBody) Close() error { body.closed++; return nil }

func TestAbuseDeliveryBoundsAndClosesRemoteResponses(t *testing.T) {
	for _, status := range []int{0, 200, 307, 401, 429, 500, 999} {
		for _, failedRead := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/read-error-%t", status, failedRead), func(t *testing.T) {
				body := &abuseUnboundedBody{fail: failedRead}
				client := newAbuseHTTPClient()
				requests := 0
				client.Transport = abuseRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					requests++
					return &http.Response{StatusCode: status, Status: "PRIVATE-STATUS", Header: http.Header{"Location": []string{"https://private.invalid/PRIVATE-REDIRECT"}, "Secret": []string{"PRIVATE-HEADER"}}, Body: body, Request: request}, nil
				})
				request, err := newAbuseReportRequest("192.0.2.1", "sqli", "PRIVATE-EVENT", "PRIVATE-KEY", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				defer request.Body.Close()
				message := deliverAbuseReport(client, request)
				if strings.Contains(message, "PRIVATE") || strings.Contains(message, "xxx") || requests != 1 || body.closed != 1 {
					t.Fatalf("remote text escaped or response leaked: %q", message)
				}
				if body.read > maximumAbuseResponseDrain || (!failedRead && body.read != maximumAbuseResponseDrain) {
					t.Fatal("response drain was not bounded")
				}
				want := fmt.Sprintf("[API ERROR] AbuseIPDB HTTP %d", status)
				if status == 200 {
					want = "[SUCCESS] AbuseIPDB returned HTTP 200"
				}
				if status < 100 || status > 599 {
					want = "[API ERROR] AbuseIPDB returned an invalid HTTP status"
				}
				if message != want {
					t.Fatalf("report outcome = %q, want %q", message, want)
				}
			})
		}
	}
}

func TestAbuseDeliveryNeverLogsTransportErrorsOrCredentials(t *testing.T) {
	client := newAbuseHTTPClient()
	client.Transport = abuseRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("PRIVATE-KEY https://private.invalid/PRIVATE-QUERY")
	})
	request, err := newAbuseReportRequest("192.0.2.1", "sqli", "PRIVATE-EVENT", "PRIVATE-KEY", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer request.Body.Close()
	if got := deliverAbuseReport(client, request); got != "[AbuseIPDB FAIL] Reporting request failed" {
		t.Fatalf("unsafe transport diagnostic: %q", got)
	}
	if got := deliverAbuseReport(nil, request); strings.Contains(got, "PRIVATE") {
		t.Fatal("nil client leaked private data")
	}
	if got := deliverAbuseReport(client, nil); strings.Contains(got, "PRIVATE") {
		t.Fatal("nil request leaked private data")
	}
	if client.Timeout != abuseReportTimeout {
		t.Fatal("report timeout changed")
	}
}

func TestAbuseRequestCanonicalizesAddressAndDoesNotExportRuleNames(t *testing.T) {
	for _, label := range []string{"PRIVATE-RULE-ID", "sqli-PRIVATE-RULE-ID", "ssh-PRIVATE-RULE-ID", "PRIVATE token=CANARY", "PRIVATE\nCANARY", strings.Repeat("x", maximumAbuseRuleLabel+1), "", "符号"} {
		request, err := newAbuseReportRequest("::ffff:192.0.2.1", label, "PRIVATE-EVENT", "PRIVATE-KEY", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(request.Body)
		_ = request.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "PRIVATE") || strings.Contains(string(data), "CANARY") || strings.Contains(string(data), "::ffff:") || !strings.Contains(string(data), `"ip":"192.0.2.1"`) {
			t.Fatal("outgoing report leaked event, rule, credentials or noncanonical address")
		}
	}
	for _, address := range []string{"", "192.0.2.1\nPRIVATE", "10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::", "::1", "fc00::1", "fe80::1", "fe80::1%eth0", "ff02::1"} {
		if request, err := newAbuseReportRequest(address, "sqli", "", "PRIVATE-KEY", time.Now()); err == nil || request != nil {
			t.Fatal("unsafe reporting address accepted")
		}
	}
}

func TestAbuseRuleAndPortParsingBounded(t *testing.T) {
	for _, label := range []string{"SQLI", "l7-XSS", "ssh-auth", "rule_1.2"} {
		if got := safeAbuseRuleLabel(label); got != strings.ToLower(label) {
			t.Fatal("ordinary bounded identifier refused")
		}
	}
	for _, label := range []string{"", "one two", "secret/key", "line\nnext", strings.Repeat("x", maximumAbuseRuleLabel+1)} {
		if got := safeAbuseRuleLabel(label); got != "unclassified" {
			t.Fatal("unsafe identifier accepted")
		}
	}
	if got := reportedPort("DPT=443 "+strings.Repeat("x", maximumAbuseEventPreview), "unknown"); got != "unknown" {
		t.Fatal("oversized event was inspected for public report")
	}
}
