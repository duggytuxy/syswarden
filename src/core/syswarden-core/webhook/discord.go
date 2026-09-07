package webhook

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"syswarden-core/utils"

	"github.com/spf13/viper"
)

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

type slackPayload struct {
	Text string `json:"text"`
}

type teamsPayload struct {
	Type        string            `json:"type"`
	Attachments []teamsAttachment `json:"attachments"`
}

type teamsAttachment struct {
	ContentType string            `json:"contentType"`
	ContentURL  *string           `json:"contentUrl"`
	Content     teamsAdaptiveCard `json:"content"`
}

type teamsAdaptiveCard struct {
	Schema  string             `json:"$schema"`
	Type    string             `json:"type"`
	Version string             `json:"version"`
	Body    []teamsCardElement `json:"body"`
}

type teamsCardElement struct {
	Type     string      `json:"type"`
	Text     string      `json:"text,omitempty"`
	Weight   string      `json:"weight,omitempty"`
	Size     string      `json:"size,omitempty"`
	IsSubtle bool        `json:"isSubtle,omitempty"`
	Wrap     bool        `json:"wrap,omitempty"`
	Facts    []teamsFact `json:"facts,omitempty"`
}

type teamsFact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

type webhookProvider string

const (
	providerDiscord webhookProvider = "discord"
	providerTeams   webhookProvider = "teams"
	providerSlack   webhookProvider = "slack"
)

type webhookTarget struct {
	provider webhookProvider
	url      string
}

var webhookHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    2 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 32 * 1024,
	},
	Timeout: 5 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const (
	webhookMaxAttempts        = 3
	webhookMaxRequestBytes    = 64 * 1024
	webhookMaxResponseBytes   = 64 * 1024
	webhookMaxInputFieldBytes = 4 * 1024
	webhookMaxLogicalBytes    = 8 * 1024
	webhookMaxURLBytes        = 8 * 1024
	webhookMaxEmbeds          = 1
	webhookMaxEmbedFields     = 16
	webhookMaxRetryDelay      = 5 * time.Second
	webhookBaseRetryDelay     = 250 * time.Millisecond
	webhookRetryJitterDivisor = 4
	webhookIdempotencyPrefix  = "sw1-"
)

type deliveryState string

const (
	deliveryDelivered deliveryState = "delivered"
	deliveryRetrying  deliveryState = "retrying"
	deliveryDiscarded deliveryState = "discarded"
	deliveryDegraded  deliveryState = "degraded"
)

type deliveryReport struct {
	SchemaVersion int
	Provider      webhookProvider
	State         deliveryState
	Attempts      int
	HTTPStatus    int
	RetryDelay    time.Duration
	Reason        string
}

var (
	webhookSleep = func(ctx context.Context, delay time.Duration) bool {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			return true
		case <-ctx.Done():
			return false
		}
	}
	webhookNow    = time.Now
	webhookJitter = func(upper time.Duration) time.Duration {
		if upper <= 0 {
			return 0
		}
		var random [8]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return 0
		}
		return time.Duration(binary.LittleEndian.Uint64(random[:]) % uint64(upper))
	}
)

type Config struct {
	Enabled    bool
	DiscordURL string
	TeamsURL   string
	SlackURL   string
}

func loadConfig() Config {
	return Config{
		Enabled:    viper.GetBool("integrations.webhooks.enabled"),
		DiscordURL: viper.GetString("integrations.webhooks.discord_url"),
		TeamsURL:   viper.GetString("integrations.webhooks.teams_url"),
		SlackURL:   viper.GetString("integrations.webhooks.slack_url"),
	}
}

func configuredTargets(cfg Config) []webhookTarget {
	return []webhookTarget{
		{provider: providerDiscord, url: cfg.DiscordURL},
		{provider: providerTeams, url: cfg.TeamsURL},
		{provider: providerSlack, url: cfg.SlackURL},
	}
}

func supportedWebhookProvider(provider webhookProvider) bool {
	switch provider {
	case providerDiscord, providerTeams, providerSlack:
		return true
	default:
		return false
	}
}

func validWebhookTarget(target webhookTarget) bool {
	if !supportedWebhookProvider(target.provider) || len(target.url) == 0 || len(target.url) > webhookMaxURLBytes {
		return false
	}
	parsed, err := url.ParseRequestURI(target.url)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	return true
}

func webhookTextWithinBounds(values ...string) bool {
	total := 0
	for _, value := range values {
		if len(value) > webhookMaxInputFieldBytes || len(value) > webhookMaxLogicalBytes-total {
			return false
		}
		total += len(value)
	}
	return true
}

func webhookPayloadWithinBounds(payload DiscordPayload, slackText string) bool {
	if len(payload.Embeds) == 0 || len(payload.Embeds) > webhookMaxEmbeds ||
		len(slackText) > webhookMaxLogicalBytes {
		return false
	}
	values := make([]string, 0, 5+webhookMaxEmbedFields*2)
	if payload.Content != nil {
		values = append(values, *payload.Content)
	}
	for _, embed := range payload.Embeds {
		if len(embed.Fields) > webhookMaxEmbedFields {
			return false
		}
		values = append(values, embed.Title, embed.Description, embed.Footer.Text, embed.Timestamp)
		for _, field := range embed.Fields {
			values = append(values, field.Name, field.Value)
		}
	}
	return webhookTextWithinBounds(values...) && webhookTextWithinBounds(slackText)
}

func reportConfiguredDiscard(cfg Config, reason string) {
	for _, target := range configuredTargets(cfg) {
		if target.url == "" {
			continue
		}
		reportDelivery(deliveryReport{
			SchemaVersion: 1,
			Provider:      target.provider,
			State:         deliveryDiscarded,
			Reason:        reason,
		})
	}
}

func acceptWebhookInputs(cfg Config, values ...string) bool {
	if webhookTextWithinBounds(values...) {
		return true
	}
	reportConfiguredDiscard(cfg, "input_bounds")
	return false
}

// deliveryIdempotencyKey is stable for every retry of the same provider wire
// payload. The endpoint URL is deliberately excluded because it commonly
// contains credentials and must not influence diagnostics or request identity.
func deliveryIdempotencyKey(provider webhookProvider, data []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("syswarden-webhook-delivery-v1\x00"))
	_, _ = digest.Write([]byte(provider))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(data)
	return webhookIdempotencyPrefix + hex.EncodeToString(digest.Sum(nil))
}

func newTeamsPayload(embed DiscordEmbed) teamsPayload {
	body := []teamsCardElement{
		{
			Type:   "TextBlock",
			Text:   embed.Title,
			Weight: "Bolder",
			Size:   "Medium",
			Wrap:   true,
		},
	}
	if embed.Description != "" {
		body = append(body, teamsCardElement{
			Type: "TextBlock",
			Text: embed.Description,
			Wrap: true,
		})
	}
	if len(embed.Fields) != 0 {
		facts := make([]teamsFact, 0, len(embed.Fields))
		for _, field := range embed.Fields {
			facts = append(facts, teamsFact{Title: field.Name, Value: field.Value})
		}
		body = append(body, teamsCardElement{Type: "FactSet", Facts: facts})
	}
	if embed.Footer.Text != "" {
		body = append(body, teamsCardElement{
			Type:     "TextBlock",
			Text:     embed.Footer.Text,
			IsSubtle: true,
			Wrap:     true,
		})
	}
	if embed.Timestamp != "" {
		body = append(body, teamsCardElement{
			Type:     "TextBlock",
			Text:     embed.Timestamp,
			IsSubtle: true,
			Wrap:     true,
		})
	}

	return teamsPayload{
		Type: "message",
		Attachments: []teamsAttachment{
			{
				ContentType: "application/vnd.microsoft.card.adaptive",
				Content: teamsAdaptiveCard{
					Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
					Type:    "AdaptiveCard",
					Version: "1.2",
					Body:    body,
				},
			},
		},
	}
}

func sendAlert(cfg Config, payload DiscordPayload, slackText string) {
	sendAlertContext(context.Background(), cfg, payload, slackText)
}

func sendAlertContext(ctx context.Context, cfg Config, payload DiscordPayload, slackText string) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Bound attacker-influenced text before JSON encoding can allocate an
	// expanded representation. Runtime telemetry remains authoritative when a
	// best-effort external notification is discarded.
	if !webhookPayloadWithinBounds(payload, slackText) {
		reportConfiguredDiscard(cfg, "payload_bounds")
		return
	}
	discordData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal Discord payload: %v", err)
		return
	}

	for _, target := range configuredTargets(cfg) {
		if target.url == "" {
			continue
		}

		var (
			finalData  []byte
			marshalErr error
		)
		switch target.provider {
		case providerDiscord:
			finalData = discordData
		case providerTeams:
			if len(payload.Embeds) == 0 {
				log.Printf("[Webhook] Refusing to send an empty Teams alert")
				continue
			}
			finalData, marshalErr = json.Marshal(newTeamsPayload(payload.Embeds[0]))
		case providerSlack:
			finalData, marshalErr = json.Marshal(slackPayload{Text: slackText})
		default:
			continue
		}
		if marshalErr != nil {
			log.Printf("[Webhook] Failed to marshal %s payload: %v", target.provider, marshalErr)
			continue
		}

		deliverAlertContext(ctx, target, finalData)
	}
}

func deliverAlert(target webhookTarget, data []byte) deliveryReport {
	return deliverAlertContext(context.Background(), target, data)
}

func deliverAlertContext(ctx context.Context, target webhookTarget, data []byte) deliveryReport {
	if ctx == nil {
		ctx = context.Background()
	}
	if !validWebhookTarget(target) {
		provider := target.provider
		if !supportedWebhookProvider(provider) {
			provider = "unknown"
		}
		return reportDelivery(deliveryReport{
			SchemaVersion: 1,
			Provider:      provider,
			State:         deliveryDiscarded,
			Reason:        "target_invalid",
		})
	}
	if len(data) == 0 || len(data) > webhookMaxRequestBytes {
		return reportDelivery(deliveryReport{
			SchemaVersion: 1,
			Provider:      target.provider,
			State:         deliveryDiscarded,
			Reason:        "request_body_size",
		})
	}
	idempotencyKey := deliveryIdempotencyKey(target.provider, data)
	for attempt := 1; attempt <= webhookMaxAttempts; attempt++ {
		if ctx.Err() != nil {
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         deliveryDiscarded,
				Attempts:      attempt - 1,
				Reason:        "context_cancelled",
			})
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.url, bytes.NewReader(data))
		if err != nil {
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         deliveryDiscarded,
				Attempts:      attempt,
				Reason:        "request_invalid",
			})
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", idempotencyKey)

		response, err := webhookHTTPClient.Do(request)
		if err != nil {
			// Once Do starts a POST, every transport result is ambiguous, including
			// cancellation: the provider may have accepted the request before the
			// client observed the error. Retrying would risk a duplicate alert.
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         deliveryDegraded,
				Attempts:      attempt,
				Reason:        "transport_ambiguous",
			})
		}
		drainAndCloseResponse(response.Body)
		if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         deliveryDelivered,
				Attempts:      attempt,
				HTTPStatus:    response.StatusCode,
				Reason:        "accepted",
			})
		}
		if !retryableWebhookStatus(response.StatusCode) || attempt == webhookMaxAttempts {
			state := deliveryDiscarded
			reason := "provider_rejected"
			if response.StatusCode >= http.StatusInternalServerError {
				state = deliveryDegraded
				reason = "provider_result_ambiguous"
			} else if retryableWebhookStatus(response.StatusCode) {
				reason = "retry_exhausted"
			}
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         state,
				Attempts:      attempt,
				HTTPStatus:    response.StatusCode,
				Reason:        reason,
			})
		}

		delay := retryAfterDelay(response.Header.Get("Retry-After"), webhookNow())
		if delay <= 0 {
			base := webhookBaseRetryDelay << (attempt - 1)
			jitterLimit := base / webhookRetryJitterDivisor
			delay = base + webhookJitter(jitterLimit)
		}
		if delay > webhookMaxRetryDelay {
			delay = webhookMaxRetryDelay
		}
		reportDelivery(deliveryReport{
			SchemaVersion: 1,
			Provider:      target.provider,
			State:         deliveryRetrying,
			Attempts:      attempt,
			HTTPStatus:    response.StatusCode,
			RetryDelay:    delay,
			Reason:        "provider_retry_later",
		})
		if !webhookSleep(ctx, delay) {
			return reportDelivery(deliveryReport{
				SchemaVersion: 1,
				Provider:      target.provider,
				State:         deliveryDiscarded,
				Attempts:      attempt,
				HTTPStatus:    response.StatusCode,
				Reason:        "context_cancelled",
			})
		}
	}
	return reportDelivery(deliveryReport{
		SchemaVersion: 1,
		Provider:      target.provider,
		State:         deliveryDegraded,
		Attempts:      webhookMaxAttempts,
		Reason:        "internal_state",
	})
}

func reportDelivery(report deliveryReport) deliveryReport {
	log.Printf(
		"[WebhookDelivery] schema=%d provider=%s state=%s attempts=%d http_status=%d retry_delay_ms=%d reason=%s",
		report.SchemaVersion,
		report.Provider,
		report.State,
		report.Attempts,
		report.HTTPStatus,
		report.RetryDelay.Milliseconds(),
		report.Reason,
	)
	return report
}

func retryableWebhookStatus(status int) bool {
	switch status {
	// Retry only responses which explicitly refuse processing until later.
	// Service, timeout, gateway and generic server failures remain ambiguous for
	// POST without a provider idempotency contract and could duplicate an alert.
	case http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	default:
		return false
	}
}

func retryAfterDelay(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.ParseUint(value, 10, 31); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > webhookMaxRetryDelay {
			return webhookMaxRetryDelay
		}
		return delay
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	delay := when.Sub(now)
	if delay > webhookMaxRetryDelay {
		return webhookMaxRetryDelay
	}
	return delay
}

func drainAndCloseResponse(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, webhookMaxResponseBytes)
	_ = body.Close()
}

func SendBanAlert(ip, jail, action string) {
	SendBanAlertContext(context.Background(), ip, jail, action)
}

func SendBanAlertContext(ctx context.Context, ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}
	if !acceptWebhookInputs(cfg, ip, jail, action) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "🚨 SYSWARDEN Security Alert",
				Description: "An intrusion attempt was detected and automatically mitigated by the native firewall engine.",
				Color:       15158332,
				Fields: []EmbedField{
					{Name: "Attacker IP", Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: action, Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN v4.10.0 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlertContext(ctx, cfg, payload, "🚨 **SYSWARDEN Security Alert**\nAttacker IP: "+ip+"\nThreat Vector: "+jail+"\nNODE: "+hostname)
}

func SendDetectedAlert(ip, jail, action string) {
	SendDetectedAlertContext(context.Background(), ip, jail, action)
}

func SendDetectedAlertContext(ctx context.Context, ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}
	if !acceptWebhookInputs(cfg, ip, jail, action) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	description := "An intrusion attempt was detected but NOT blocked (Alert-Only mode or firewall failure)."
	if action == "Kernel Packet Dropped (No Source Ban)" {
		description = "A kernel-level rule dropped the observed packet; no durable source ban was claimed."
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "⚠️ SYSWARDEN Threat Detected",
				Description: description,
				Color:       16753920, // Orange
				Fields: []EmbedField{
					{Name: "Attacker IP", Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: action, Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN v4.10.0 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlertContext(ctx, cfg, payload, "⚠️ **SYSWARDEN Threat Detected**\nAttacker IP: "+ip+"\nThreat Vector: "+jail+"\nNODE: "+hostname)
}

func SendAllowAlert(ip, service string) {
	SendAllowAlertContext(context.Background(), ip, service)
}

func SendAllowAlertContext(ctx context.Context, ip, service string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}
	if !acceptWebhookInputs(cfg, ip, service) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "✅ SYSWARDEN Access Granted",
				Description: "A legitimate connection was authorized by the firewall.",
				Color:       3066993, // Green color
				Fields: []EmbedField{
					{Name: "Allowed IP", Value: ip, Inline: true},
					{Name: "Service Target", Value: service, Inline: true},
					{Name: "Action Taken", Value: "ALLOWED", Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN - Zero-Trust Telemetry",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlertContext(ctx, cfg, payload, "✅ **SYSWARDEN Access Granted**\nAllowed IP: "+ip+"\nService: "+service+"\nNODE: "+hostname)
}

func SendShadowAlert(ip, jail string) {
	SendShadowAlertContext(context.Background(), ip, jail)
}

func SendShadowAlertContext(ctx context.Context, ip, jail string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}
	if !acceptWebhookInputs(cfg, ip, jail) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	isInsider := utils.IsWhitelisted(ip)

	title := "⚠️ SYSWARDEN HIGH RISK THREAT TRACKING"
	desc := "An external IP triggered a tracked security rule."
	ipLabel := "Attacker IP"
	color := 16753920 // Orange

	if isInsider {
		title = "⚠️ SYSWARDEN INSIDER THREAT ALERT"
		desc = "A Whitelisted IP triggered a malicious signature (Shadow Mode)."
		ipLabel = "Insider IP"
		color = 16711680 // Red
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       title,
				Description: desc,
				Color:       color,
				Fields: []EmbedField{
					{Name: ipLabel, Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: "SHADOW-ALERT (Not Banned)", Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN - Zero-Trust Telemetry",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlertContext(ctx, cfg, payload, title+"\n"+ipLabel+": "+ip+"\nThreat Vector: "+jail+"\nAction: SHADOW-ALERT (Not Banned)\nNODE: "+hostname)
}

func SendComplianceAlert(msg, status string) {
	SendComplianceAlertContext(context.Background(), msg, status)
}

func SendComplianceAlertContext(ctx context.Context, msg, status string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}
	if !acceptWebhookInputs(cfg, msg, status) {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	title, color := localCheckAlertPresentation(status)

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       title,
				Description: msg,
				Color:       color,
				Fields: []EmbedField{
					{Name: "Node", Value: hostname, Inline: true},
					{Name: "Status", Value: status, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN v4.10.0 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlertContext(ctx, cfg, payload, title+"\nMessage: "+msg+"\nNODE: "+hostname)
}

func localCheckAlertPresentation(status string) (string, int) {
	if status == "OK" {
		return "✅ SYSWARDEN Local Check: No Deviation Observed", 3066993
	}
	return "❌ SYSWARDEN Local Check: Deviation Observed", 15158332
}
