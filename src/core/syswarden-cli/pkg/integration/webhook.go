package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"syswarden-cli/config"
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

// SetupWebhooks installs and verifies webhook integrations natively
func SetupWebhooks() error {
	fmt.Println("[INFO] Configuring Alert Webhooks...")

	if !config.GlobalConfig.EnableWebhook {
		fmt.Println("[INFO] Webhooks are disabled in configuration.")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if discordURL := config.GlobalConfig.WebhookURLDiscord; discordURL != "" {
		fmt.Println("[INFO] Verifying Discord Webhook connectivity...")

		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "SYSWARDEN-NODE"
		}

		payload := DiscordPayload{
			Content: nil,
			Embeds: []DiscordEmbed{
				{
					Title:       "🟢 SYSWARDEN Integration Successful",
					Description: "Native Go Webhook integration established.",
					Color:       3066993, // Green
					Fields: []EmbedField{
						{Name: "Version", Value: "v3.75.5", Inline: true},
						{Name: "NODE", Value: hostname, Inline: true},
						{Name: "Status", Value: "Active", Inline: true},
					},
					Footer:    EmbedFooter{Text: "SYSWARDEN Advanced Agentic Defense"},
					Timestamp: time.Now().UTC().Format(time.RFC3339),
				},
			},
		}
		data, _ := json.Marshal(payload)

		req, _ := http.NewRequestWithContext(ctx, "POST", discordURL, bytes.NewBuffer(data))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to reach Discord webhook: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			fmt.Println("[+] Discord Webhook is active.")
		} else {
			fmt.Printf("[-] Discord Webhook returned HTTP %d\n", resp.StatusCode)
		}
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

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "SYSWARDEN-NODE"
	}

	payload := DiscordPayload{
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
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	data, _ := json.Marshal(payload)
	_, _ = http.Post(discordURL, "application/json", bytes.NewBuffer(data)) // #nosec
}
