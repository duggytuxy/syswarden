package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
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

var webhookHTTPClient = &http.Client{Timeout: 5 * time.Second}

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

		resp, postErr := webhookHTTPClient.Post(target.url, "application/json", bytes.NewReader(finalData))
		if postErr != nil {
			// Webhook URLs normally contain credentials. Do not include them in logs.
			log.Printf("[Webhook] Failed to send %s alert", target.provider)
			continue
		}
		_ = resp.Body.Close()
	}
}

func SendBanAlert(ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled {
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
					Text: "SYSWARDEN v4.03.3 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlert(cfg, payload, "🚨 **SYSWARDEN Security Alert**\nAttacker IP: "+ip+"\nThreat Vector: "+jail+"\nNODE: "+hostname)
}

func SendDetectedAlert(ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled {
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
				Title:       "⚠️ SYSWARDEN Threat Detected",
				Description: "An intrusion attempt was detected but NOT blocked (Alert-Only mode or firewall failure).",
				Color:       16753920, // Orange
				Fields: []EmbedField{
					{Name: "Attacker IP", Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: action, Inline: true},
					{Name: "NODE", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SYSWARDEN v4.03.3 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlert(cfg, payload, "⚠️ **SYSWARDEN Threat Detected**\nAttacker IP: "+ip+"\nThreat Vector: "+jail+"\nNODE: "+hostname)
}

func SendAllowAlert(ip, service string) {
	cfg := loadConfig()
	if !cfg.Enabled {
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

	sendAlert(cfg, payload, "✅ **SYSWARDEN Access Granted**\nAllowed IP: "+ip+"\nService: "+service+"\nNODE: "+hostname)
}

func SendShadowAlert(ip, jail string) {
	cfg := loadConfig()
	if !cfg.Enabled {
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

	sendAlert(cfg, payload, title+"\n"+ipLabel+": "+ip+"\nThreat Vector: "+jail+"\nAction: SHADOW-ALERT (Not Banned)\nNODE: "+hostname)
}

func SendComplianceAlert(msg, status string) {
	cfg := loadConfig()
	if !cfg.Enabled {
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
					Text: "SYSWARDEN v4.03.3 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	sendAlert(cfg, payload, title+"\nMessage: "+msg+"\nNODE: "+hostname)
}

func localCheckAlertPresentation(status string) (string, int) {
	if status == "OK" {
		return "✅ SYSWARDEN Local Check: No Deviation Observed", 3066993
	}
	return "❌ SYSWARDEN Local Check: Deviation Observed", 15158332
}
