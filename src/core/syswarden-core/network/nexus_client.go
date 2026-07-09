package network

import (
	"context"
	"encoding/json"
	"log"
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

	// Mock Telemetry Loop
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Canceled
		case <-ticker.C:
			// 1. Gather RiskRadar telemetry
			// 2. Send via mTLS POST request to NexusURL/api/v1/telemetry
			// 3. Pull global policies from NexusURL/api/v1/policies
			log.Println("[NEXUS-SYNC] Heartbeat and telemetry sent to Nexus API (Mock)")
		}
	}
}
