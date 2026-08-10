package webhook

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
					Text: "SYSWARDEN v3.91.1 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal payload: %v", err)
		return
	}

	urls := []string{cfg.DiscordURL, cfg.TeamsURL, cfg.SlackURL}
	for _, u := range urls {
		if u == "" {
			continue
		}

		// For Slack, we send a simple text payload to be universally compatible
		finalData := data
		if strings.Contains(u, "hooks.slack.com") {
			slackPayload := map[string]string{
				"text": "🚨 **SYSWARDEN Security Alert**\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "🚨 SYSWARDEN Security Alert\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(teamsPayload)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(u, "application/json", bytes.NewBuffer(finalData))
		if err != nil {
			log.Printf("[Webhook] Failed to send alert: %v", err)
			continue
		}
		_ = resp.Body.Close()
	}
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
					Text: "SYSWARDEN v3.91.1 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal payload: %v", err)
		return
	}

	urls := []string{cfg.DiscordURL, cfg.TeamsURL, cfg.SlackURL}
	for _, u := range urls {
		if u == "" {
			continue
		}

		finalData := data
		if strings.Contains(u, "hooks.slack.com") {
			slackPayload := map[string]string{
				"text": "⚠️ **SYSWARDEN Threat Detected**\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "⚠️ SYSWARDEN Threat Detected\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(teamsPayload)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(u, "application/json", bytes.NewBuffer(finalData))
		if err != nil {
			log.Printf("[Webhook] Failed to send detected alert: %v", err)
			continue
		}
		_ = resp.Body.Close()
	}
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

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal payload: %v", err)
		return
	}

	urls := []string{cfg.DiscordURL, cfg.TeamsURL, cfg.SlackURL}
	for _, u := range urls {
		if u == "" {
			continue
		}

		finalData := data
		if strings.Contains(u, "hooks.slack.com") {
			slackPayload := map[string]string{
				"text": "✅ **SYSWARDEN Access Granted**\nAllowed IP: " + ip + "\nService: " + service + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "✅ SYSWARDEN Access Granted\nAllowed IP: " + ip + "\nService: " + service + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(teamsPayload)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(u, "application/json", bytes.NewBuffer(finalData))
		if err != nil {
			log.Printf("[Webhook] Failed to send alert: %v", err)
			continue
		}
		_ = resp.Body.Close()
	}
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

	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	urls := []string{cfg.DiscordURL, cfg.TeamsURL, cfg.SlackURL}
	for _, u := range urls {
		if u == "" {
			continue
		}

		finalData := data
		if strings.Contains(u, "hooks.slack.com") {
			slackPayload := map[string]string{
				"text": title + "\n" + ipLabel + ": " + ip + "\nThreat Vector: " + jail + "\nAction: SHADOW-ALERT (Not Banned)\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": title + "\n" + ipLabel + ": " + ip + "\nThreat Vector: " + jail + "\nAction: SHADOW-ALERT (Not Banned)\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(teamsPayload)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(u, "application/json", bytes.NewBuffer(finalData))
		if err == nil {
			_ = resp.Body.Close()
		}
	}
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

	title := "✅ SYSWARDEN Compliance OK"
	color := 3066993 // Green
	if status != "OK" {
		title = "❌ SYSWARDEN Compliance Drift"
		color = 15158332 // Red
	}

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
					Text: "SYSWARDEN v3.91.1 - Advanced Agentic Defense",
				},
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[Webhook] Failed to marshal compliance payload: %v", err)
		return
	}

	urls := []string{cfg.DiscordURL, cfg.TeamsURL, cfg.SlackURL}
	for _, u := range urls {
		if u == "" {
			continue
		}

		finalData := data
		if strings.Contains(u, "hooks.slack.com") {
			slackPayload := map[string]string{
				"text": title + "\nMessage: " + msg + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": title + "\nMessage: " + msg + "\nNODE: " + hostname,
			}
			finalData, _ = json.Marshal(teamsPayload)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Post(u, "application/json", bytes.NewBuffer(finalData))
		if err != nil {
			log.Printf("[Webhook] Failed to send compliance alert: %v", err)
			continue
		}
		_ = resp.Body.Close()
	}
}
