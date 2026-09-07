package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLocalCheckWebhookPresentation_SW_DOC_001(t *testing.T) {
	for _, status := range []string{"OK", "DRIFT"} {
		title, _ := localCheckAlertPresentation(status)
		if !strings.Contains(title, "Local Check") || strings.Contains(title, "Compliance") {
			t.Fatalf("status %s produced unsupported title %q", status, title)
		}
	}
}

func TestKernelDropDetectionDoesNotClaimNoDrop_SW_KPI_001(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	var body []byte
	previousClient := webhookHTTPClient
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var err error
		body, err = io.ReadAll(io.LimitReader(request.Body, 64*1024))
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	t.Cleanup(func() { webhookHTTPClient = previousClient })
	viper.Set("integrations.webhooks.enabled", true)
	viper.Set("integrations.webhooks.discord_url", "https://webhook.invalid/discord/opaque-test-token")

	SendDetectedAlert("198.51.100.11", "L2-ARP-FLOOD", "Kernel Packet Dropped (No Source Ban)")

	var payload DiscordPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Embeds) != 1 || strings.Contains(payload.Embeds[0].Description, "NOT blocked") ||
		!strings.Contains(payload.Embeds[0].Description, "dropped the observed packet") {
		t.Fatalf("kernel detection description = %#v", payload.Embeds)
	}
}

type receivedWebhookRequest struct {
	contentType    string
	idempotencyKey string
	body           []byte
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestWebhookProviderDispatchAndPayloads_SW_INT_001(t *testing.T) {
	testCases := []struct {
		name          string
		send          func()
		wantTitle     string
		wantFactTitle string
		wantFactValue string
		wantSlackText string
	}{
		{
			name:          "ban",
			send:          func() { SendBanAlert("198.51.100.10", "sshd", "DROP") },
			wantTitle:     "🚨 SYSWARDEN Security Alert",
			wantFactTitle: "Action Taken",
			wantFactValue: "DROP",
			wantSlackText: "SYSWARDEN Security Alert",
		},
		{
			name:          "detected",
			send:          func() { SendDetectedAlert("198.51.100.11", "waap", "DETECTION") },
			wantTitle:     "⚠️ SYSWARDEN Threat Detected",
			wantFactTitle: "Action Taken",
			wantFactValue: "DETECTION",
			wantSlackText: "SYSWARDEN Threat Detected",
		},
		{
			name:          "allow",
			send:          func() { SendAllowAlert("198.51.100.12", "https") },
			wantTitle:     "✅ SYSWARDEN Access Granted",
			wantFactTitle: "Service Target",
			wantFactValue: "https",
			wantSlackText: "SYSWARDEN Access Granted",
		},
		{
			name:          "shadow",
			send:          func() { SendShadowAlert("127.0.0.1", "insider-rule") },
			wantTitle:     "⚠️ SYSWARDEN INSIDER THREAT ALERT",
			wantFactTitle: "Action Taken",
			wantFactValue: "SHADOW-ALERT (Not Banned)",
			wantSlackText: "SYSWARDEN INSIDER THREAT ALERT",
		},
		{
			name:          "local check drift",
			send:          func() { SendComplianceAlert("policy drift", "DRIFT") },
			wantTitle:     "❌ SYSWARDEN Local Check: Deviation Observed",
			wantFactTitle: "Status",
			wantFactValue: "DRIFT",
			wantSlackText: "SYSWARDEN Local Check: Deviation Observed",
		},
		{
			name:          "local check ok",
			send:          func() { SendComplianceAlert("no drift", "OK") },
			wantTitle:     "✅ SYSWARDEN Local Check: No Deviation Observed",
			wantFactTitle: "Status",
			wantFactValue: "OK",
			wantSlackText: "SYSWARDEN Local Check: No Deviation Observed",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			requests := make(map[string]receivedWebhookRequest)
			previousClient := webhookHTTPClient
			webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(io.LimitReader(request.Body, 64*1024))
				if err != nil {
					return nil, err
				}
				requests[request.URL.Path] = receivedWebhookRequest{
					contentType:    request.Header.Get("Content-Type"),
					idempotencyKey: request.Header.Get("Idempotency-Key"),
					body:           body,
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
					Header:     make(http.Header),
				}, nil
			})}
			t.Cleanup(func() { webhookHTTPClient = previousClient })

			// All providers deliberately use the same hostname. The configured field,
			// not URL hostname matching, must select the wire format.
			viper.Set("integrations.webhooks.enabled", true)
			viper.Set("integrations.webhooks.discord_url", "https://webhook.invalid/discord/opaque-test-token")
			viper.Set("integrations.webhooks.teams_url", "https://webhook.invalid/power-automate/opaque-test-token")
			viper.Set("integrations.webhooks.slack_url", "https://webhook.invalid/slack/opaque-test-token")

			testCase.send()

			if len(requests) != 3 {
				t.Fatalf("received %d webhook requests, want 3", len(requests))
			}
			providers := map[string]webhookProvider{
				"/discord/opaque-test-token":        providerDiscord,
				"/power-automate/opaque-test-token": providerTeams,
				"/slack/opaque-test-token":          providerSlack,
			}
			for path, provider := range providers {
				request := requests[path]
				wantKey := deliveryIdempotencyKey(provider, request.body)
				if request.idempotencyKey != wantKey || !strings.HasPrefix(request.idempotencyKey, webhookIdempotencyPrefix) {
					t.Fatalf("provider path %s idempotency key=%q want=%q", path, request.idempotencyKey, wantKey)
				}
			}

			assertDiscordRequest(t, requests["/discord/opaque-test-token"], testCase.wantTitle)
			assertTeamsRequest(t, requests["/power-automate/opaque-test-token"], testCase.wantTitle, testCase.wantFactTitle, testCase.wantFactValue)
			assertSlackRequest(t, requests["/slack/opaque-test-token"], testCase.wantSlackText)
		})
	}
}

func assertDiscordRequest(t *testing.T, request receivedWebhookRequest, wantTitle string) {
	t.Helper()
	if request.contentType != "application/json" {
		t.Fatalf("Discord Content-Type = %q, want application/json", request.contentType)
	}
	var payload DiscordPayload
	if err := json.Unmarshal(request.body, &payload); err != nil {
		t.Fatalf("decode Discord payload: %v", err)
	}
	if len(payload.Embeds) != 1 || payload.Embeds[0].Title != wantTitle {
		t.Fatalf("Discord embeds = %#v, want one embed titled %q", payload.Embeds, wantTitle)
	}
}

func assertTeamsRequest(t *testing.T, request receivedWebhookRequest, wantTitle, wantFactTitle, wantFactValue string) {
	t.Helper()
	if request.contentType != "application/json" {
		t.Fatalf("Teams Content-Type = %q, want application/json", request.contentType)
	}
	if strings.Contains(string(request.body), `"embeds"`) || strings.Contains(string(request.body), `"content":null`) {
		t.Fatalf("Teams endpoint received Discord-shaped JSON: %s", request.body)
	}
	if !strings.Contains(string(request.body), `"contentUrl":null`) {
		t.Fatalf("Teams envelope is missing the required null contentUrl: %s", request.body)
	}

	var payload teamsPayload
	if err := json.Unmarshal(request.body, &payload); err != nil {
		t.Fatalf("decode Teams payload: %v", err)
	}
	if payload.Type != "message" || len(payload.Attachments) != 1 {
		t.Fatalf("Teams envelope = %#v, want one message attachment", payload)
	}
	attachment := payload.Attachments[0]
	if attachment.ContentType != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("Teams content type = %q", attachment.ContentType)
	}
	if attachment.Content.Type != "AdaptiveCard" || attachment.Content.Version != "1.2" {
		t.Fatalf("Teams card identity = %#v", attachment.Content)
	}
	if attachment.Content.Schema != "http://adaptivecards.io/schemas/adaptive-card.json" {
		t.Fatalf("Teams card schema = %q", attachment.Content.Schema)
	}
	if len(attachment.Content.Body) == 0 || attachment.Content.Body[0].Text != wantTitle {
		t.Fatalf("Teams card title missing, want %q: %#v", wantTitle, attachment.Content.Body)
	}

	foundFact := false
	for _, element := range attachment.Content.Body {
		for _, fact := range element.Facts {
			if fact.Title == wantFactTitle && fact.Value == wantFactValue {
				foundFact = true
			}
		}
	}
	if !foundFact {
		t.Fatalf("Teams card missing fact %q=%q: %#v", wantFactTitle, wantFactValue, attachment.Content.Body)
	}
}

func assertSlackRequest(t *testing.T, request receivedWebhookRequest, wantText string) {
	t.Helper()
	if request.contentType != "application/json" {
		t.Fatalf("Slack Content-Type = %q, want application/json", request.contentType)
	}
	var payload slackPayload
	if err := json.Unmarshal(request.body, &payload); err != nil {
		t.Fatalf("decode Slack payload: %v", err)
	}
	if !strings.Contains(payload.Text, wantText) {
		t.Fatalf("Slack text = %q, want marker %q", payload.Text, wantText)
	}
}

func TestWebhookTransportFailureDoesNotLogCredential_SW_INT_001(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	previousClient := webhookHTTPClient
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network unavailable")
	})}
	t.Cleanup(func() { webhookHTTPClient = previousClient })

	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousLogOutput) })

	const credential = "private-test-credential"
	viper.Set("integrations.webhooks.enabled", true)
	viper.Set("integrations.webhooks.discord_url", "https://webhook.invalid/api/"+credential)

	SendBanAlert("198.51.100.20", "sshd", "DROP")

	if strings.Contains(logs.String(), credential) || strings.Contains(logs.String(), "webhook.invalid") {
		t.Fatalf("transport failure log exposed webhook credentials: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "provider=discord state=degraded") ||
		!strings.Contains(logs.String(), "reason=transport_ambiguous") {
		t.Fatalf("transport failure was not logged: %q", logs.String())
	}
}

func TestWebhookRetriesOnlyExplicitTransientResponses_SW_INT_002(t *testing.T) {
	previousClient := webhookHTTPClient
	previousSleep := webhookSleep
	previousJitter := webhookJitter
	t.Cleanup(func() {
		webhookHTTPClient = previousClient
		webhookSleep = previousSleep
		webhookJitter = previousJitter
	})

	attempts := 0
	var delays []time.Duration
	webhookSleep = func(_ context.Context, delay time.Duration) bool {
		delays = append(delays, delay)
		return true
	}
	webhookJitter = func(time.Duration) time.Duration { return 10 * time.Millisecond }
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		status := http.StatusTooManyRequests
		if attempts == 2 {
			status = http.StatusNoContent
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("response")), Header: make(http.Header)}, nil
	})}

	deliverAlert(webhookTarget{provider: providerSlack, url: "https://webhook.invalid/secret"}, []byte(`{"text":"alert"}`))
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(delays) != 1 || delays[0] != webhookBaseRetryDelay+10*time.Millisecond {
		t.Fatalf("retry delays = %v", delays)
	}
}

func TestWebhookRetryAfterIsParsedAndBounded_SW_INT_003(t *testing.T) {
	base := time.Date(2026, time.September, 3, 10, 0, 0, 0, time.UTC)
	if got := retryAfterDelay("3600", base); got != webhookMaxRetryDelay {
		t.Fatalf("large delta Retry-After = %v, want %v", got, webhookMaxRetryDelay)
	}
	if got := retryAfterDelay(base.Add(2*time.Second).Format(http.TimeFormat), base); got != 2*time.Second {
		t.Fatalf("date Retry-After = %v, want 2s", got)
	}
	for _, value := range []string{"invalid", "-1", base.Add(-time.Second).Format(http.TimeFormat)} {
		if got := retryAfterDelay(value, base); got != 0 {
			t.Fatalf("Retry-After %q = %v, want zero", value, got)
		}
	}
}

func TestWebhookPermanentResponseAndAmbiguousTransportAreNotRetried_SW_INT_004(t *testing.T) {
	testCases := []struct {
		name      string
		transport roundTripFunc
	}{
		{
			name: "permanent response",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("rejected")), Header: make(http.Header)}, nil
			},
		},
		{
			name: "ambiguous gateway response",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("ambiguous")), Header: make(http.Header)}, nil
			},
		},
		{name: "ambiguous transport", transport: func(*http.Request) (*http.Response, error) { return nil, errors.New("reset") }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			previousClient := webhookHTTPClient
			attempts := 0
			webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				attempts++
				return testCase.transport(request)
			})}
			t.Cleanup(func() { webhookHTTPClient = previousClient })
			deliverAlert(webhookTarget{provider: providerDiscord, url: "https://webhook.invalid/private"}, []byte(`{}`))
			if attempts != 1 {
				t.Fatalf("attempts = %d, want 1", attempts)
			}
		})
	}
}

type countingResponseBody struct {
	remaining int
	read      int
	closed    bool
}

func (body *countingResponseBody) Read(buffer []byte) (int, error) {
	if body.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if count > body.remaining {
		count = body.remaining
	}
	for index := 0; index < count; index++ {
		buffer[index] = 'x'
	}
	body.remaining -= count
	body.read += count
	return count, nil
}

func (body *countingResponseBody) Close() error {
	body.closed = true
	return nil
}

func TestWebhookResponseBodyDrainIsBoundedAndClosed_SW_INT_005(t *testing.T) {
	body := &countingResponseBody{remaining: webhookMaxResponseBytes * 2}
	drainAndCloseResponse(body)
	if body.read != webhookMaxResponseBytes {
		t.Fatalf("response bytes read = %d, want %d", body.read, webhookMaxResponseBytes)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
}

func TestWebhookDeliveryReportsStableStatesAndBoundsRequest_SW_INT_006(t *testing.T) {
	previousClient := webhookHTTPClient
	t.Cleanup(func() { webhookHTTPClient = previousClient })

	requests := 0
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Body:       io.NopCloser(strings.NewReader("rejected")),
			Header:     make(http.Header),
		}, nil
	})}

	report := deliverAlert(
		webhookTarget{provider: providerTeams, url: "https://webhook.invalid/private"},
		[]byte(`{"type":"message"}`),
	)
	if report.SchemaVersion != 1 || report.Provider != providerTeams ||
		report.State != deliveryDiscarded || report.Attempts != 1 ||
		report.HTTPStatus != http.StatusBadRequest || report.Reason != "provider_rejected" {
		t.Fatalf("permanent delivery report = %#v", report)
	}

	report = deliverAlert(
		webhookTarget{provider: providerSlack, url: "https://webhook.invalid/private"},
		make([]byte, webhookMaxRequestBytes+1),
	)
	if report.State != deliveryDiscarded || report.Attempts != 0 ||
		report.Reason != "request_body_size" || requests != 1 {
		t.Fatalf("oversize delivery report = %#v, requests=%d", report, requests)
	}
}

func TestWebhookRetryAndSuccessReportsAreDeterministic_SW_INT_007(t *testing.T) {
	previousClient := webhookHTTPClient
	previousSleep := webhookSleep
	previousJitter := webhookJitter
	t.Cleanup(func() {
		webhookHTTPClient = previousClient
		webhookSleep = previousSleep
		webhookJitter = previousJitter
	})
	webhookSleep = func(context.Context, time.Duration) bool { return true }
	webhookJitter = func(time.Duration) time.Duration { return 0 }
	attempts := 0
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts++
		status := http.StatusTooEarly
		if attempts == 2 {
			status = http.StatusNoContent
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}
	report := deliverAlert(
		webhookTarget{provider: providerDiscord, url: "https://webhook.invalid/private"},
		[]byte(`{}`),
	)
	if report.State != deliveryDelivered || report.Attempts != 2 ||
		report.HTTPStatus != http.StatusNoContent || report.Reason != "accepted" {
		t.Fatalf("retry delivery report = %#v", report)
	}
}

func TestWebhookRetriesReuseStableProviderScopedIdempotencyKey_SW_INT_008(t *testing.T) {
	previousClient := webhookHTTPClient
	previousSleep := webhookSleep
	t.Cleanup(func() {
		webhookHTTPClient = previousClient
		webhookSleep = previousSleep
	})
	webhookSleep = func(context.Context, time.Duration) bool { return true }

	payload := []byte(`{"text":"bounded alert"}`)
	var keys []string
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		status := http.StatusTooManyRequests
		if len(keys) == 2 {
			status = http.StatusNoContent
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
		}, nil
	})}

	target := webhookTarget{provider: providerSlack, url: "https://webhook.invalid/private-token-a"}
	report := deliverAlert(target, payload)
	if report.State != deliveryDelivered || len(keys) != 2 {
		t.Fatalf("delivery report=%#v keys=%v", report, keys)
	}
	want := deliveryIdempotencyKey(providerSlack, payload)
	if keys[0] != want || keys[1] != want || !strings.HasPrefix(want, webhookIdempotencyPrefix) {
		t.Fatalf("retry idempotency keys=%q want=%q", keys, want)
	}
	if strings.Contains(want, "private-token") {
		t.Fatalf("idempotency key exposed endpoint credentials: %q", want)
	}
	if got := deliveryIdempotencyKey(providerSlack, payload); got != want {
		t.Fatalf("same delivery generated unstable idempotency key %q, want %q", got, want)
	}
	if got := deliveryIdempotencyKey(providerDiscord, payload); got == want {
		t.Fatal("different providers shared an idempotency key")
	}
	if got := deliveryIdempotencyKey(providerSlack, []byte(`{"text":"different"}`)); got == want {
		t.Fatal("different payloads shared an idempotency key")
	}
}

func TestWebhookDeliveryCancellationInterruptsRequestAndRetryWait_SW_INT_009(t *testing.T) {
	t.Run("before request", func(t *testing.T) {
		previousClient := webhookHTTPClient
		defer func() { webhookHTTPClient = previousClient }()
		requests := 0
		webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests++
			return nil, errors.New("request must not start")
		})}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report := deliverAlertContext(ctx, webhookTarget{provider: providerDiscord, url: "https://webhook.invalid/private"}, []byte(`{}`))
		if report.State != deliveryDiscarded || report.Reason != "context_cancelled" || report.Attempts != 0 {
			t.Fatalf("pre-request cancellation report = %#v", report)
		}
		if requests != 0 {
			t.Fatalf("pre-request cancellation started %d requests", requests)
		}
	})

	t.Run("in flight request", func(t *testing.T) {
		previousClient := webhookHTTPClient
		defer func() { webhookHTTPClient = previousClient }()
		requestStarted := make(chan struct{})
		webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(requestStarted)
			<-request.Context().Done()
			return nil, request.Context().Err()
		})}
		ctx, cancel := context.WithCancel(context.Background())
		reportChannel := make(chan deliveryReport, 1)
		go func() {
			reportChannel <- deliverAlertContext(ctx, webhookTarget{provider: providerTeams, url: "https://webhook.invalid/private"}, []byte(`{}`))
		}()
		<-requestStarted
		cancel()
		select {
		case report := <-reportChannel:
			if report.State != deliveryDegraded || report.Reason != "transport_ambiguous" || report.Attempts != 1 {
				t.Fatalf("cancelled in-flight delivery report = %#v", report)
			}
		case <-time.After(time.Second):
			t.Fatal("cancelled in-flight delivery did not return")
		}
	})

	t.Run("retry wait", func(t *testing.T) {
		previousClient := webhookHTTPClient
		previousSleep := webhookSleep
		defer func() {
			webhookHTTPClient = previousClient
			webhookSleep = previousSleep
		}()
		waiting := make(chan struct{})
		webhookSleep = func(ctx context.Context, _ time.Duration) bool {
			close(waiting)
			<-ctx.Done()
			return false
		}
		webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		})}
		ctx, cancel := context.WithCancel(context.Background())
		reportChannel := make(chan deliveryReport, 1)
		go func() {
			reportChannel <- deliverAlertContext(ctx, webhookTarget{provider: providerSlack, url: "https://webhook.invalid/private"}, []byte(`{}`))
		}()
		<-waiting
		cancel()
		select {
		case report := <-reportChannel:
			if report.State != deliveryDiscarded || report.Reason != "context_cancelled" || report.Attempts != 1 {
				t.Fatalf("cancelled retry delivery report = %#v", report)
			}
		case <-time.After(time.Second):
			t.Fatal("cancelled retry wait did not return")
		}
	})
}

func TestWebhookRejectsOversizedInputBeforeNetworkAndWithoutDisclosure_SW_INT_009(t *testing.T) {
	previousClient := webhookHTTPClient
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		webhookHTTPClient = previousClient
		log.SetOutput(previousLogOutput)
	})

	requests := 0
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	const credential = "private-webhook-credential"
	cfg := Config{
		Enabled:    true,
		DiscordURL: "https://webhook.invalid/discord/" + credential,
		TeamsURL:   "https://webhook.invalid/teams/" + credential,
		SlackURL:   "https://webhook.invalid/slack/" + credential,
	}
	oversized := strings.Repeat("sensitive-marker", webhookMaxInputFieldBytes)
	sendAlert(cfg, DiscordPayload{Embeds: []DiscordEmbed{{Description: oversized}}}, oversized)

	if requests != 0 {
		t.Fatalf("oversized alert made %d network requests", requests)
	}
	if strings.Count(logs.String(), "reason=payload_bounds") != 3 {
		t.Fatalf("oversized alert did not report one discard per provider: %q", logs.String())
	}
	if strings.Contains(logs.String(), credential) || strings.Contains(logs.String(), "sensitive-marker") {
		t.Fatalf("oversized alert log disclosed protected input: %q", logs.String())
	}
}

func TestWebhookRejectsInvalidTargetsWithoutNetworkOrCredentialLogs_SW_INT_010(t *testing.T) {
	previousClient := webhookHTTPClient
	previousLogOutput := log.Writer()
	t.Cleanup(func() {
		webhookHTTPClient = previousClient
		log.SetOutput(previousLogOutput)
	})

	requests := 0
	webhookHTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	var logs bytes.Buffer
	log.SetOutput(&logs)
	const credential = "private-target-credential"
	for _, target := range []webhookTarget{
		{provider: providerDiscord, url: "http://webhook.invalid/" + credential},
		{provider: providerTeams, url: "https://user:" + credential + "@webhook.invalid/path"},
		{provider: webhookProvider("invalid\nprovider"), url: "https://webhook.invalid/" + credential},
	} {
		report := deliverAlert(target, []byte(`{}`))
		if report.State != deliveryDiscarded || report.Reason != "target_invalid" {
			t.Fatalf("invalid target report = %#v", report)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid targets made %d network requests", requests)
	}
	if strings.Contains(logs.String(), credential) || strings.Contains(logs.String(), "invalid\nprovider") {
		t.Fatalf("invalid target log disclosed untrusted data: %q", logs.String())
	}
}
