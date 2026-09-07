package integration

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"syswarden-cli/config"
)

type cliWebhookRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip cliWebhookRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

type cliWebhookTrackingBody struct {
	remaining int
	read      int
	closed    bool
}

func (body *cliWebhookTrackingBody) Read(buffer []byte) (int, error) {
	if body.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if count > body.remaining {
		count = body.remaining
	}
	body.remaining -= count
	body.read += count
	return count, nil
}

func (body *cliWebhookTrackingBody) Close() error {
	body.closed = true
	return nil
}

func cliWebhookTestClient(roundTrip cliWebhookRoundTripFunc) *http.Client {
	return &http.Client{
		Transport: roundTrip,
		Timeout:   250 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestCLIWebhookTargetAndInputValidation(t *testing.T) {
	for _, rawURL := range []string{
		"http://webhook.invalid/private",
		"https://user:password@webhook.invalid/private",
		"https://webhook.invalid/private#fragment",
		"/relative",
		strings.Repeat("x", cliWebhookMaxURLBytes+1),
	} {
		if validCLIWebhookTarget(rawURL) {
			t.Fatalf("unsafe webhook target %q was accepted", rawURL)
		}
	}
	if !validCLIWebhookTarget("https://webhook.invalid/private?sig=opaque") {
		t.Fatal("valid HTTPS webhook target was rejected")
	}

	for _, value := range []string{"", "not-an-address", "8.8.8.8\nforged", strings.Repeat("1", cliWebhookMaxInputFieldBytes+1)} {
		if _, err := canonicalCLIWebhookBlockTarget(value); !errors.Is(err, errCLIWebhookInputInvalid) {
			t.Fatalf("invalid manual block target was accepted")
		}
	}
	for value, want := range map[string]string{
		"8.8.8.8":      "8.8.8.8",
		"2001:4860::1": "2001:4860::1",
		"8.8.8.7/24":   "8.8.8.0/24",
	} {
		got, err := canonicalCLIWebhookBlockTarget(value)
		if err != nil || got != want {
			t.Fatalf("canonical block target %q = %q, %v, want %q", value, got, err, want)
		}
	}
}

func TestCLIWebhookPayloadCompatibilityAndStableSecretIndependentKey(t *testing.T) {
	payload, err := manualBlockCLIWebhookPayload(
		"8.8.8.8",
		"SYSWARDEN-NODE",
		time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	wirePayload, err := marshalCLIWebhookPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wirePayload, []byte(`"title":"🚨 SYSWARDEN Manual Block"`)) ||
		!bytes.Contains(wirePayload, []byte(`"name":"Target IP","value":"8.8.8.8"`)) ||
		!bytes.Contains(wirePayload, []byte(`"name":"Action","value":"Manual Kernel Drop"`)) {
		t.Fatalf("Discord wire compatibility changed: %s", wirePayload)
	}

	keys := make([]string, 0, 2)
	client := cliWebhookTestClient(func(request *http.Request) (*http.Response, error) {
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		if request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q", request.Header.Get("Content-Type"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	for _, rawURL := range []string{
		"https://webhook.invalid/first-secret",
		"https://webhook.invalid/second-secret",
	} {
		if _, err := deliverCLIWebhook(t.Context(), client, rawURL, wirePayload); err != nil {
			t.Fatal(err)
		}
	}
	want := cliWebhookIdempotencyKey(cliWebhookProviderDiscord, wirePayload)
	if len(keys) != 2 || keys[0] != want || keys[1] != want || !strings.HasPrefix(want, cliWebhookIdempotencyPrefix) {
		t.Fatalf("idempotency keys = %#v, want stable %q", keys, want)
	}
}

func TestCLIWebhookTransportErrorsNeverDiscloseCredentials(t *testing.T) {
	const secret = "private-webhook-credential"
	client := cliWebhookTestClient(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network failure involving " + secret)
	})
	_, err := deliverCLIWebhook(
		t.Context(),
		client,
		"https://webhook.invalid/api/"+secret,
		[]byte(`{"embeds":[{}]}`),
	)
	if !errors.Is(err, errCLIWebhookTransport) {
		t.Fatalf("transport error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "webhook.invalid") {
		t.Fatalf("transport error disclosed target credentials: %q", err)
	}
}

func TestCLIWebhookRedirectIsNotFollowedAndStatusIsSecretSafe(t *testing.T) {
	requests := 0
	body := &cliWebhookTrackingBody{remaining: 16}
	client := cliWebhookTestClient(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Body:       body,
			Header:     http.Header{"Location": []string{"https://other.invalid/captured"}},
		}, nil
	})
	const secret = "redirect-source-secret"
	status, err := deliverCLIWebhook(
		t.Context(), client, "https://webhook.invalid/"+secret, []byte(`{"embeds":[{}]}`),
	)
	if status != http.StatusTemporaryRedirect || err == nil || requests != 1 {
		t.Fatalf("redirect status=%d err=%v requests=%d", status, err, requests)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "webhook.invalid") {
		t.Fatalf("status error disclosed target credentials: %q", err)
	}
	if !body.closed {
		t.Fatal("redirect response body was not closed")
	}
}

func TestCLIWebhookTimeoutIsFiniteAndSecretSafe(t *testing.T) {
	client := cliWebhookTestClient(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	client.Timeout = 20 * time.Millisecond
	started := time.Now()
	_, err := deliverCLIWebhook(
		context.Background(), client, "https://webhook.invalid/timeout-secret", []byte(`{"embeds":[{}]}`),
	)
	if !errors.Is(err, errCLIWebhookTransport) {
		t.Fatalf("timeout error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("webhook timeout took %v", elapsed)
	}
	if strings.Contains(err.Error(), "timeout-secret") || strings.Contains(err.Error(), "webhook.invalid") {
		t.Fatalf("timeout error disclosed target credentials: %q", err)
	}
}

func TestCLIWebhookResponseDrainIsBoundedAndClosed(t *testing.T) {
	body := &cliWebhookTrackingBody{remaining: cliWebhookMaxResponseBytes * 2}
	client := cliWebhookTestClient(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: body, Header: make(http.Header)}, nil
	})
	if _, err := deliverCLIWebhook(
		t.Context(), client, "https://webhook.invalid/private", []byte(`{"embeds":[{}]}`),
	); err != nil {
		t.Fatal(err)
	}
	if body.read != cliWebhookMaxResponseBytes {
		t.Fatalf("response bytes read = %d, want %d", body.read, cliWebhookMaxResponseBytes)
	}
	if !body.closed {
		t.Fatal("response body was not closed")
	}
}

func TestCLIWebhookRequestAndPayloadBoundsRejectBeforeTransport(t *testing.T) {
	requests := 0
	client := cliWebhookTestClient(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if _, err := deliverCLIWebhook(
		t.Context(), client, "https://webhook.invalid/private", make([]byte, cliWebhookMaxRequestBytes+1),
	); !errors.Is(err, errCLIWebhookPayloadBounds) {
		t.Fatalf("oversize wire payload error = %v", err)
	}
	payload := DiscordPayload{Embeds: []DiscordEmbed{{Title: strings.Repeat("x", cliWebhookMaxInputFieldBytes+1)}}}
	if _, err := sendCLIWebhookPayload(t.Context(), client, "https://webhook.invalid/private", payload); !errors.Is(err, errCLIWebhookPayloadBounds) {
		t.Fatalf("oversize logical payload error = %v", err)
	}
	if requests != 0 {
		t.Fatalf("oversize inputs caused %d transport requests", requests)
	}
}

func TestCLIWebhookProductionClientHasFiniteTransportBounds(t *testing.T) {
	client := newCLIWebhookHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("CLI webhook client has an unexpected transport")
	}
	if client.Timeout <= 0 || transport.DialContext == nil || transport.TLSHandshakeTimeout <= 0 ||
		transport.ResponseHeaderTimeout <= 0 || transport.MaxResponseHeaderBytes <= 0 ||
		transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion == 0 || client.CheckRedirect == nil {
		t.Fatal("CLI webhook client lacks one or more finite transport bounds")
	}
}

func TestCLIWebhookCallersUseHardenedSecretSafeTransport(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousClient := cliWebhookHTTPClient
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		cliWebhookHTTPClient = previousClient
	})

	const secret = "caller-private-credential"
	requests := 0
	var idempotencyKey string
	cliWebhookHTTPClient = cliWebhookTestClient(func(request *http.Request) (*http.Response, error) {
		requests++
		idempotencyKey = request.Header.Get("Idempotency-Key")
		return nil, errors.New("transport error at " + request.URL.String())
	})
	config.GlobalConfig = config.NewFailSafeConfig()
	config.GlobalConfig.EnableWebhook = true
	config.GlobalConfig.WebhookURLDiscord = "https://webhook.invalid/" + secret

	err := SetupWebhooks()
	if !errors.Is(err, errCLIWebhookTransport) {
		t.Fatalf("SetupWebhooks transport error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "webhook.invalid") {
		t.Fatalf("SetupWebhooks disclosed target credentials: %q", err)
	}
	SendBanAlert("8.8.8.8")
	if requests != 2 {
		t.Fatalf("hardened caller requests = %d, want 2", requests)
	}
	if idempotencyKey == "" || !strings.HasPrefix(idempotencyKey, cliWebhookIdempotencyPrefix) {
		t.Fatalf("manual block request idempotency key = %q", idempotencyKey)
	}
}
