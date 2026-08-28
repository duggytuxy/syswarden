package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

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
	contentType string
	body        []byte
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
					contentType: request.Header.Get("Content-Type"),
					body:        body,
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
	if !strings.Contains(logs.String(), "Failed to send discord alert") {
		t.Fatalf("transport failure was not logged: %q", logs.String())
	}
}
