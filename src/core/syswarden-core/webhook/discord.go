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
	Enabled bool
	URL     string
}

func loadConfig() Config {
	c := Config{}
	file, err := os.Open("/opt/syswarden/syswarden-auto.conf")
	if err != nil {
		return c
	}
 defer func() { _ = file.Close()
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
			c.URL = strings.Trim(strings.SplitN(line, "=", 2)[1], "\"'")
		}
	}
	return c
}

func SendBanAlert(ip, jail, action string) {
	cfg := loadConfig()
	if !cfg.Enabled || cfg.URL == "" {
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
					Text: "SysWarden v2.01.8 - Advanced Agentic Defense",
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

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(cfg.URL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[Webhook] Failed to send alert: %v", err)
		return
	}
 defer func() { _ = resp.Body.Close()
 }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[Webhook] Successfully sent ban alert for IP %s", ip)
	} else {
		log.Printf("[Webhook] Failed to send alert, HTTP status: %d", resp.StatusCode)
	}
}
