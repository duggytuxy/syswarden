package webhook

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
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
	c := Config{}
	file, err := os.Open("/opt/syswarden/syswarden-auto.conf")
	if err != nil {
		return c
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_ENABLE_WEBHOOK=") {
			val := strings.Trim(strings.SplitN(line, "=", 2)[1], "\"'")
			if strings.ToLower(val) == "y" {
				c.Enabled = true
			}
		}
		if strings.HasPrefix(line, "SYSWARDEN_WEBHOOK_URL_DISCORD=") {
			c.DiscordURL = strings.Trim(strings.SplitN(line, "=", 2)[1], "\"'")
		}
		if strings.HasPrefix(line, "SYSWARDEN_WEBHOOK_URL_TEAMS=") {
			c.TeamsURL = strings.Trim(strings.SplitN(line, "=", 2)[1], "\"'")
		}
		if strings.HasPrefix(line, "SYSWARDEN_WEBHOOK_URL_SLACK=") {
			c.SlackURL = strings.Trim(strings.SplitN(line, "=", 2)[1], "\"'")
		}
	}
	return c
}

func SendBanAlert(ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SysWarden-Node"
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "🚨 SysWarden Security Alert",
				Description: "An intrusion attempt was detected and automatically mitigated by the native firewall engine.",
				Color:       15158332,
				Fields: []EmbedField{
					{Name: "Attacker IP", Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: action, Inline: true},
					{Name: "Node", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SysWarden v3.31.1 - Advanced Agentic Defense",
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
				"text": "🚨 **SysWarden Security Alert**\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNode: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "🚨 SysWarden Security Alert\nAttacker IP: " + ip + "\nThreat Vector: " + jail + "\nNode: " + hostname,
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

func SendAllowAlert(ip, service string) {
	cfg := loadConfig()
	if !cfg.Enabled {
		return
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SysWarden-Node"
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "✅ SysWarden Access Granted",
				Description: "A legitimate connection was authorized by the firewall.",
				Color:       3066993, // Green color
				Fields: []EmbedField{
					{Name: "Allowed IP", Value: ip, Inline: true},
					{Name: "Service Target", Value: service, Inline: true},
					{Name: "Action Taken", Value: "ALLOWED", Inline: true},
					{Name: "Node", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SysWarden - Zero-Trust Telemetry",
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
				"text": "✅ **SysWarden Access Granted**\nAllowed IP: " + ip + "\nService: " + service + "\nNode: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "✅ SysWarden Access Granted\nAllowed IP: " + ip + "\nService: " + service + "\nNode: " + hostname,
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
		hostname = "SysWarden-Node"
	}

	payload := DiscordPayload{
		Content: nil,
		Embeds: []DiscordEmbed{
			{
				Title:       "⚠️ SysWarden INSIDER THREAT ALERT",
				Description: "A Whitelisted IP triggered a malicious signature (Shadow Mode).",
				Color:       16753920, // Orange color
				Fields: []EmbedField{
					{Name: "Insider IP", Value: ip, Inline: true},
					{Name: "Threat Vector", Value: jail, Inline: true},
					{Name: "Action Taken", Value: "SHADOW-ALERT (Not Banned)", Inline: true},
					{Name: "Node", Value: hostname, Inline: true},
				},
				Footer: EmbedFooter{
					Text: "SysWarden - Zero-Trust Telemetry",
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
				"text": "⚠️ **SysWarden INSIDER THREAT ALERT**\nInsider IP: " + ip + "\nThreat Vector: " + jail + "\nAction: SHADOW-ALERT (Not Banned)\nNode: " + hostname,
			}
			finalData, _ = json.Marshal(slackPayload)
		} else if strings.Contains(u, "webhook.office.com") {
			teamsPayload := map[string]string{
				"text": "⚠️ SysWarden INSIDER THREAT ALERT\nInsider IP: " + ip + "\nThreat Vector: " + jail + "\nAction: SHADOW-ALERT (Not Banned)\nNode: " + hostname,
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
