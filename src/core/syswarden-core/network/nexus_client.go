package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// Config matches the CLI enroll prototype
type NexusConfig struct {
	NexusURL string `json:"nexus_url"`
	NodeID   string `json:"node_id"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
}

const nexusConfigPath = "/opt/syswarden/nexus.conf"

// StartNexusSleepyAgent initiates the Sleepy Agent pattern.
// It checks for /opt/syswarden/nexus.conf. If it exists, it wakes up and starts reporting.
// If it does not exist, it remains dormant but checks periodically (e.g. every minute)
// in case it gets enrolled dynamically without a daemon restart.
func StartNexusSleepyAgent(ctx context.Context) {
	go func() {
		log.Println("[NEXUS] Sleepy Agent initialized. Awaiting configuration...")

		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Sleepy check
				if _, err := os.Stat(nexusConfigPath); err == nil {
					// Configuration exists, wake up and run the loop
					log.Println("[NEXUS] Configuration detected. Waking up Sleepy Agent...")
					err := runNexusClientLoop(ctx)
					if err != nil && err != context.Canceled {
						log.Printf("[NEXUS] Client loop exited with error: %v. Returning to sleep.", err)
					} else if err == context.Canceled {
						return
					}
				}

				// Sleep for 60 seconds before checking again if not enrolled,
				// or if the loop crashed/exited.
				select {
				case <-time.After(60 * time.Second):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
}

func runNexusClientLoop(ctx context.Context) error {
	// Parse config
	data, err := os.ReadFile(nexusConfigPath)
	if err != nil {
		return err
	}

	var conf NexusConfig
	if err := json.Unmarshal(data, &conf); err != nil {
		return err
	}

	log.Printf("[NEXUS] Successfully loaded configuration for Node ID: %s", conf.NodeID)
	log.Printf("[NEXUS] Connecting to Nexus API at %s via mTLS...", conf.NexusURL)

	// Configure mTLS Client
	var client *http.Client
	if conf.CertPEM != "" && conf.KeyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(conf.CertPEM), []byte(conf.KeyPEM))
		if err != nil {
			log.Printf("[NEXUS] Warning: Could not load mTLS keypair: %v. Falling back to TLS without client auth.", err)
			client = &http.Client{Timeout: 10 * time.Second}
		} else {
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				// Note: In strict prod, InsecureSkipVerify must be false and RootCAs properly populated
				InsecureSkipVerify: true,
			}
			client = &http.Client{
				Transport: &http.Transport{TLSClientConfig: tlsConfig},
				Timeout:   10 * time.Second,
			}
		}
	} else {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	// Telemetry Loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-ticker.C:
			// 1. Gather RiskRadar telemetry
			// Here we simulate an alert payload to push
			payload := map[string]interface{}{
				"node_id":    conf.NodeID,
				"source_ip":  "192.168.x.x",
				"alert_type": "L7_WAF_BLOCK",
				"reason":     "Simulated Agent Alert",
				"payload":    "GET /?id=1' OR '1'='1",
			}
			
			body, _ := json.Marshal(payload)
			resp, err := client.Post(conf.NexusURL+"/api/v1/telemetry", "application/json", bytes.NewBuffer(body))
			if err != nil {
				log.Printf("[NEXUS-SYNC] Failed to send telemetry: %v", err)
				continue
			}
			resp.Body.Close()
			
			if resp.StatusCode == 200 {
				log.Println("[NEXUS-SYNC] Telemetry successfully pushed to Nexus API.")
			} else {
				log.Printf("[NEXUS-SYNC] Nexus API rejected telemetry (Status: %d)", resp.StatusCode)
			}
		}
	}
}
