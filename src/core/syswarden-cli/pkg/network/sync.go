package network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syswarden-cli/config"
)

type HASyncPayload struct {
	IPs []string `json:"ips"`
}

func getLocalBlocklist(file string) ([]string, error) {
	content, err := os.ReadFile(file)
	if err != nil {
		return []string{}, nil
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var ips []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			ips = append(ips, l)
		}
	}
	return ips, nil
}

func SyncHAPeer() error {
	if !config.GlobalConfig.HAEnabled {
		fmt.Println("[INFO] HA Sync is disabled in configuration.")
		return nil
	}

	peerIPsStr := strings.ReplaceAll(config.GlobalConfig.HAPeerIP, ",", " ")
	peerIPs := strings.Fields(peerIPsStr)
	peerPort := config.GlobalConfig.HAPeerPort
	if len(peerIPs) == 0 {
		return fmt.Errorf("HA Cluster enabled but no Peer IPs configured")
	}

	// InsecureSkipVerify is required because HA API uses auto-generated self-signed certs
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	for _, peerIP := range peerIPs {
		fmt.Printf("[INFO] Starting HA Sync to Peer %s:%s...\n", peerIP, peerPort)
		
		apiUrl := fmt.Sprintf("https://%s:%s/ha/sync", peerIP, peerPort)

		// 1. Get remote blocklist
		resp, err := client.Get(apiUrl)
		if err != nil {
			fmt.Printf("[ERROR] HA Peer unreachable at %s:%s: %v\n", peerIP, peerPort, err)
			continue
		}
		
		if resp.StatusCode != http.StatusOK {
			fmt.Printf("[ERROR] HA Peer rejected the connection. HTTP Status: %d\n", resp.StatusCode)
			_ = resp.Body.Close()
			continue
		}

		var remoteData HASyncPayload
		if err := json.NewDecoder(resp.Body).Decode(&remoteData); err != nil {
			fmt.Printf("[ERROR] Failed to decode remote HA list: %v\n", err)
			_ = resp.Body.Close()
			continue
		}
		_ = resp.Body.Close()

		remoteIPs := make(map[string]bool)
		for _, ip := range remoteData.IPs {
			remoteIPs[ip] = true
		}

		// 2. Get local blocklists
		var localIPs []string
		v4, _ := getLocalBlocklist("/etc/syswarden/lists/syswarden_blacklist.ipv4")
		v6, _ := getLocalBlocklist("/etc/syswarden/lists/syswarden_blacklist.ipv6")
		localIPs = append(localIPs, v4...)
		localIPs = append(localIPs, v6...)

		// 3. Find IPs to push
		var toPush []string
		for _, ip := range localIPs {
			if !remoteIPs[ip] {
				toPush = append(toPush, ip)
			}
		}

		if len(toPush) == 0 {
			fmt.Printf("[INFO] Peer %s is already up to date. No new IPs to push.\n", peerIP)
			continue
		}

		fmt.Printf("[INFO] Found %d new IPs to push to peer %s. Synchronizing...\n", len(toPush), peerIP)

		// 4. Push all missing IPs
		payload := HASyncPayload{IPs: toPush}
		jsonData, err := json.Marshal(payload)
		if err != nil {
			fmt.Printf("[ERROR] Failed to marshal HA payload: %v\n", err)
			continue
		}

		postResp, err := client.Post(apiUrl, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			fmt.Printf("[ERROR] Failed to push to HA Peer %s: %v\n", peerIP, err)
			continue
		}

		if postResp.StatusCode != http.StatusOK {
			fmt.Printf("[ERROR] HA Peer %s rejected the push. HTTP Status: %d\n", peerIP, postResp.StatusCode)
			_ = postResp.Body.Close()
			continue
		}
		_ = postResp.Body.Close()

		fmt.Printf("[+] Successfully synchronized %d IPs to Peer %s.\n", len(toPush), peerIP)
	}

	return nil
}
