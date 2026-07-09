package nexus

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Config represents the nexus.conf structure
type Config struct {
	NexusURL string `json:"nexus_url"`
	NodeID   string `json:"node_id"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
}

type TokenPayload struct {
	URL string `json:"url"`
	Key string `json:"key"`
}

type EnrollRequest struct {
	Hostname string `json:"hostname"`
	Key      string `json:"key"`
}

type EnrollResponse struct {
	NodeID  string `json:"node_id"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

const configPath = "/opt/syswarden/nexus.conf"

func EnrollNode(tokenB64 string) error {
	// For prototyping, the token could be a simple base64 JSON
	// echo -n '{"url":"https://nexus.syswarden.io", "key":"secret-key"}' | base64
	// Decode token
	/*
		decoded, err := base64.StdEncoding.DecodeString(tokenB64)
		if err != nil {
			return fmt.Errorf("invalid token format: %v", err)
		}
		var tokenPayload TokenPayload
		if err := json.Unmarshal(decoded, &tokenPayload); err != nil {
			return fmt.Errorf("invalid token payload: %v", err)
		}
	*/

	// Prototyping mock: In reality, we'd do an HTTP POST to tokenPayload.URL + "/api/v1/enroll"
	// with the tokenPayload.Key to retrieve the mTLS certs.
	// For now, since the API doesn't exist yet, we will generate a dummy config.
	fmt.Println(" -> Connecting to Nexus API (Prototyping Mode)...")
	time.Sleep(1 * time.Second)

	fmt.Println(" -> Exchanging bootstrap key for mTLS certificates...")
	time.Sleep(1 * time.Second)

	dummyConfig := Config{
		NexusURL: "https://nexus.syswarden.io",
		NodeID:   "node-mock-1234",
		CertPEM:  "-----BEGIN CERTIFICATE-----\nMOCK_CERT...\n-----END CERTIFICATE-----",
		KeyPEM:   "-----BEGIN PRIVATE KEY-----\nMOCK_KEY...\n-----END PRIVATE KEY-----",
	}

	configBytes, err := json.MarshalIndent(dummyConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	if err := os.WriteFile(configPath, configBytes, 0600); err != nil {
		return fmt.Errorf("failed to write nexus.conf: %v", err)
	}

	fmt.Printf(" -> Successfully provisioned %s\n", configPath)

	// Trigger core reload to wake up the Sleepy Agent
	fmt.Println(" -> Reloading SysWarden core daemon...")
	// system.ReloadDaemon() // Assuming we use pkg/system later

	return nil
}

// DoEnrollHTTP is a helper to actually make the HTTP call once the API is ready.
// Exported to prevent linter unused warnings during prototyping.
func DoEnrollHTTP(url, key string) (*EnrollResponse, error) {
	hostname, _ := os.Hostname()
	reqBody := EnrollRequest{
		Hostname: hostname,
		Key:      key,
	}

	bodyBytes, _ := json.Marshal(reqBody)

	// Skip verification ONLY if strictly required during prototyping
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Post(url+"/api/v1/enroll", "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status: %d", resp.StatusCode)
	}

	var enrollResp EnrollResponse
	respBytes, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(respBytes, &enrollResp); err != nil {
		return nil, err
	}

	return &enrollResp, nil
}
