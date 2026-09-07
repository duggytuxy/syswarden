package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"syswarden-cli/config"
)

const (
	cliWebhookMaxRequestBytes    = 64 * 1024
	cliWebhookMaxResponseBytes   = 64 * 1024
	cliWebhookMaxInputFieldBytes = 4 * 1024
	cliWebhookMaxLogicalBytes    = 8 * 1024
	cliWebhookMaxURLBytes        = 8 * 1024
	cliWebhookIdempotencyPrefix  = "sw1-"
	cliWebhookProviderDiscord    = "discord"
)

var (
	errCLIWebhookTargetInvalid = errors.New("webhook target is invalid")
	errCLIWebhookInputInvalid  = errors.New("webhook input is invalid")
	errCLIWebhookPayloadBounds = errors.New("webhook payload exceeds accepted bounds")
	errCLIWebhookTransport     = errors.New("webhook transport failed")
	errCLIWebhookResponse      = errors.New("webhook response could not be consumed safely")
)

var cliWebhookHTTPClient = newCLIWebhookHTTPClient()

func newCLIWebhookHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:      true,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    2 * time.Second,
			ResponseHeaderTimeout:  3 * time.Second,
			ExpectContinueTimeout:  time.Second,
			IdleConnTimeout:        30 * time.Second,
			MaxIdleConns:           8,
			MaxIdleConnsPerHost:    2,
			MaxConnsPerHost:        4,
			MaxResponseHeaderBytes: 32 * 1024,
		},
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type EmbedFooter struct {
	Text string `json:"text"`
}

type DiscordEmbed struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Color       int          `json:"color"`
	Fields      []EmbedField `json:"fields"`
	Footer      EmbedFooter  `json:"footer"`
	Timestamp   string       `json:"timestamp,omitempty"`
}

type DiscordPayload struct {
	Content *string        `json:"content"`
	Embeds  []DiscordEmbed `json:"embeds"`
}

func validCLIWebhookTarget(rawURL string) bool {
	if rawURL == "" || len(rawURL) > cliWebhookMaxURLBytes || strings.ContainsAny(rawURL, "\r\n\t#") {
		return false
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	return true
}

func cliWebhookTextWithinBounds(values ...string) bool {
	total := 0
	for _, value := range values {
		if len(value) > cliWebhookMaxInputFieldBytes || len(value) > cliWebhookMaxLogicalBytes-total {
			return false
		}
		total += len(value)
	}
	return true
}

func canonicalCLIWebhookBlockTarget(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || !cliWebhookTextWithinBounds(value) ||
		strings.ContainsAny(value, "\r\n\x00") {
		return "", errCLIWebhookInputInvalid
	}
	if address, err := netip.ParseAddr(value); err == nil && address.Zone() == "" {
		return address.String(), nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Addr().Zone() == "" {
		return prefix.Masked().String(), nil
	}
	return "", errCLIWebhookInputInvalid
}

// cliWebhookIdempotencyKey is stable for the exact provider wire payload.
// The endpoint is excluded because webhook URLs commonly contain credentials.
func cliWebhookIdempotencyKey(provider string, wirePayload []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("syswarden-webhook-delivery-v1\x00"))
	_, _ = digest.Write([]byte(provider))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(wirePayload)
	return cliWebhookIdempotencyPrefix + hex.EncodeToString(digest.Sum(nil))
}

func cliWebhookPayloadWithinBounds(payload DiscordPayload) bool {
	if len(payload.Embeds) != 1 || payload.Content != nil {
		return false
	}
	embed := payload.Embeds[0]
	if len(embed.Fields) > 16 {
		return false
	}
	values := make([]string, 0, 4+len(embed.Fields)*2)
	values = append(values, embed.Title, embed.Description, embed.Footer.Text, embed.Timestamp)
	for _, field := range embed.Fields {
		values = append(values, field.Name, field.Value)
	}
	return cliWebhookTextWithinBounds(values...)
}

func marshalCLIWebhookPayload(payload DiscordPayload) ([]byte, error) {
	if !cliWebhookPayloadWithinBounds(payload) {
		return nil, errCLIWebhookPayloadBounds
	}
	data, err := json.Marshal(payload)
	if err != nil || len(data) == 0 || len(data) > cliWebhookMaxRequestBytes {
		return nil, errCLIWebhookPayloadBounds
	}
	return data, nil
}

func drainAndCloseCLIWebhookResponse(body io.ReadCloser) error {
	if body == nil {
		return errCLIWebhookResponse
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(body, cliWebhookMaxResponseBytes))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil {
		return errCLIWebhookResponse
	}
	return nil
}

func deliverCLIWebhook(ctx context.Context, client *http.Client, rawURL string, wirePayload []byte) (int, error) {
	if ctx == nil || client == nil || !validCLIWebhookTarget(rawURL) {
		return 0, errCLIWebhookTargetInvalid
	}
	if len(wirePayload) == 0 || len(wirePayload) > cliWebhookMaxRequestBytes {
		return 0, errCLIWebhookPayloadBounds
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(wirePayload))
	if err != nil {
		return 0, errCLIWebhookTargetInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", cliWebhookIdempotencyKey(cliWebhookProviderDiscord, wirePayload))
	response, err := client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = drainAndCloseCLIWebhookResponse(response.Body)
		}
		// A failed POST is ambiguous. Do not retry and do not expose the URL from
		// net/http's error, since its path or query may contain credentials.
		return 0, errCLIWebhookTransport
	}
	if response == nil {
		return 0, errCLIWebhookResponse
	}
	status := response.StatusCode
	if err := drainAndCloseCLIWebhookResponse(response.Body); err != nil {
		return status, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return status, fmt.Errorf("webhook provider rejected request with HTTP status %d", status)
	}
	return status, nil
}

func sendCLIWebhookPayload(ctx context.Context, client *http.Client, rawURL string, payload DiscordPayload) (int, error) {
	wirePayload, err := marshalCLIWebhookPayload(payload)
	if err != nil {
		return 0, err
	}
	return deliverCLIWebhook(ctx, client, rawURL, wirePayload)
}

// SetupWebhooks installs and verifies webhook integrations natively
func SetupWebhooks() error {
	fmt.Println("[INFO] Configuring Alert Webhooks...")

	if !config.GlobalConfig.EnableWebhook {
		fmt.Println("[INFO] Webhooks are disabled in configuration.")
		return nil
	}

	if discordURL := config.GlobalConfig.WebhookURLDiscord; discordURL != "" {
		fmt.Println("[INFO] Verifying Discord Webhook connectivity...")
		if !validCLIWebhookTarget(discordURL) {
			return errors.New("Discord webhook connectivity verification failed: invalid HTTPS target")
		}

		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "SYSWARDEN-NODE"
		}
		payload, err := setupCLIWebhookPayload(hostname, time.Now().UTC())
		if err != nil {
			return errors.New("Discord webhook connectivity verification failed: local payload rejected")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		_, err = sendCLIWebhookPayload(ctx, cliWebhookHTTPClient, discordURL, payload)
		cancel()
		if err != nil {
			return fmt.Errorf("Discord webhook connectivity verification failed: %w", err)
		}
		fmt.Println("[+] Discord Webhook is active.")
	}

	return nil
}

func SendBanAlert(ip string) {
	if !config.GlobalConfig.EnableWebhook {
		return
	}
	discordURL := config.GlobalConfig.WebhookURLDiscord
	if discordURL == "" {
		return
	}
	canonicalTarget, err := canonicalCLIWebhookBlockTarget(ip)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "[WARNING] Manual block webhook alert discarded: invalid target.")
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}
	payload, err := manualBlockCLIWebhookPayload(canonicalTarget, hostname, time.Now().UTC())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "[WARNING] Manual block webhook alert discarded: local payload rejected.")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	_, err = sendCLIWebhookPayload(ctx, cliWebhookHTTPClient, discordURL, payload)
	cancel()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[WARNING] Manual block webhook delivery failed: %v.\n", err)
	}
}

func setupCLIWebhookPayload(hostname string, timestamp time.Time) (DiscordPayload, error) {
	if hostname == "" || !cliWebhookTextWithinBounds(hostname) || strings.ContainsAny(hostname, "\r\n\x00") {
		return DiscordPayload{}, errCLIWebhookInputInvalid
	}
	return DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "🟢 SYSWARDEN Integration Successful",
				Description: "Native Go Webhook integration established.",
				Color:       3066993,
				Fields: []EmbedField{
					{Name: "Version", Value: "v4.10.0", Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
					{Name: "Status", Value: "Active", Inline: true},
				},
				Footer:    EmbedFooter{Text: "SYSWARDEN Advanced Agentic Defense"},
				Timestamp: timestamp.UTC().Format(time.RFC3339),
			},
		},
	}, nil
}

func manualBlockCLIWebhookPayload(ip, hostname string, timestamp time.Time) (DiscordPayload, error) {
	if !cliWebhookTextWithinBounds(ip, hostname) || hostname == "" || strings.ContainsAny(hostname, "\r\n\x00") {
		return DiscordPayload{}, errCLIWebhookInputInvalid
	}
	return DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "🚨 SYSWARDEN Manual Block",
				Description: "An IP was manually blocked by an Administrator via CLI.",
				Color:       16753920, // Orange
				Fields: []EmbedField{
					{Name: "Target IP", Value: ip, Inline: true},
					{Name: "Action", Value: "Manual Kernel Drop", Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer:    EmbedFooter{Text: "SYSWARDEN Advanced Agentic Defense"},
				Timestamp: timestamp.UTC().Format(time.RFC3339),
			},
		},
	}, nil
}
