package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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
			// Read the real telemetry data.json
			dataJSON, err := os.ReadFile("/var/lib/syswarden/ui/data.json")
			if err != nil {
				log.Printf("[NEXUS-SYNC] Warning: Could not read data.json: %v", err)
				continue
			}

			req, err := http.NewRequest("POST", conf.NexusURL+"/api/v1/telemetry/full", bytes.NewBuffer(dataJSON))
			if err != nil {
				log.Printf("[NEXUS-SYNC] Failed to create telemetry request: %v", err)
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Node-ID", conf.NodeID)

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[NEXUS-SYNC] Failed to send full telemetry: %v", err)
				continue
			}
			if resp.StatusCode == 200 {
				log.Println("[NEXUS-SYNC] Full telemetry successfully pushed to Nexus API.")
				bodyBytes, _ := io.ReadAll(resp.Body)

				var nexusResp struct {
					Status  string `json:"status"`
					Command struct {
						ID     uint   `json:"id"`
						Action string `json:"action"`
					} `json:"command"`
				}

				if err := json.Unmarshal(bodyBytes, &nexusResp); err == nil && nexusResp.Command.ID > 0 {
					log.Printf("[NEXUS-SYNC] Received C2 Command: %s (ID: %d)", nexusResp.Command.Action, nexusResp.Command.ID)
					go executeNexusCommand(ctx, conf, client, nexusResp.Command.ID, nexusResp.Command.Action)
				}
			} else {
				log.Printf("[NEXUS-SYNC] Nexus API rejected full telemetry (Status: %d)", resp.StatusCode)
			}
			_ = resp.Body.Close()
		}
	}
}

func executeNexusCommand(ctx context.Context, conf NexusConfig, client *http.Client, cmdID uint, action string) {
	var result string
	status := "completed"

	switch action {
	case "read_config":
		data, err := os.ReadFile("/opt/syswarden/syswarden-auto.conf")
		if err != nil {
			status = "failed"
			result = "Error reading config: " + err.Error()
		} else {
			result = string(data)
		}
	case "update_package":
		if os.Getuid() == 0 {
			cmd := exec.CommandContext(ctx, "syswarden", "update")
			out, err := cmd.CombinedOutput()
			if err != nil {
				status = "failed"
				result = "Update failed: " + err.Error() + "\n" + string(out)
			} else {
				result = "Update successful.\n" + string(out)
			}
		} else {
			cmd := exec.CommandContext(ctx, "sudo", "syswarden", "update")
			out, err := cmd.CombinedOutput()
			if err != nil {
				status = "failed"
				result = "Update failed: " + err.Error() + "\n" + string(out)
			} else {
				result = "Update successful.\n" + string(out)
			}
		}
	default:
		status = "failed"
		result = "Unknown command action"
	}

	payload := map[string]interface{}{
		"command_id": cmdID,
		"status":     status,
		"result":     result,
	}
	payloadBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", conf.NexusURL+"/api/v1/telemetry/response", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-ID", conf.NodeID)

	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	} else {
		log.Printf("[NEXUS-SYNC] Failed to send command response: %v", err)
	}
}
