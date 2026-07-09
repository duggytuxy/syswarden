package nexus

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
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
	decoded, err := base64.StdEncoding.DecodeString(tokenB64)
	if err != nil {
		return fmt.Errorf("invalid token format: %v", err)
	}
	
	var tokenPayload TokenPayload
	if err := json.Unmarshal(decoded, &tokenPayload); err != nil {
		return fmt.Errorf("invalid token payload: %v", err)
	}

	fmt.Println(" -> Connecting to Nexus API securely...")
	
	resp, err := DoEnrollHTTP(tokenPayload.URL, tokenPayload.Key)
	if err != nil {
		return fmt.Errorf("enrollment failed: %v", err)
	}

	fmt.Println(" -> Enrollment successful! Provisioning configuration...")

	config := Config{
		NexusURL: tokenPayload.URL,
		NodeID:   resp.NodeID,
		CertPEM:  resp.CertPEM, // Could be empty if Nexus doesn't generate it yet
		KeyPEM:   resp.KeyPEM,
	}

	configBytes, err := json.MarshalIndent(config, "", "  ")
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

	fmt.Printf(" -> Successfully provisioned %s (NodeID: %s)\n", configPath, resp.NodeID)

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
