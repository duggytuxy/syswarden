package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	abuseCache     = make(map[string]time.Time)
	abuseCacheLock sync.Mutex
	abuseAPIKey    string
	abuseEnabled   bool
	abuseOnce      sync.Once
)

func initAbuse() {
	content, err := os.ReadFile("/etc/syswarden/secrets.env") // #nosec
	if err != nil {
		return
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SYSWARDEN_ENABLE_ABUSE=") {
			val := strings.Trim(strings.TrimPrefix(line, "SYSWARDEN_ENABLE_ABUSE="), `"'`)
			if val == "y" || val == "Y" {
				abuseEnabled = true
			}
		}
		if strings.HasPrefix(line, "SYSWARDEN_ABUSE_API_KEY=") {
			abuseAPIKey = strings.Trim(strings.TrimPrefix(line, "SYSWARDEN_ABUSE_API_KEY="), `"'`)
		}
	}
}

// ReportAbuseAsync asynchronously reports a banned IP to AbuseIPDB
func ReportAbuseAsync(ip string, jail string) {
	abuseOnce.Do(initAbuse)
	if !abuseEnabled || abuseAPIKey == "" {
		return
	}

	abuseCacheLock.Lock()
	lastReport, exists := abuseCache[ip]
	if exists && time.Since(lastReport) < 15*time.Minute {
		abuseCacheLock.Unlock()
		return
	}
	abuseCache[ip] = time.Now()
	abuseCacheLock.Unlock()

	go func() {
		hostname, _ := os.Hostname()
		comment := fmt.Sprintf("[%s] Banned by SYSWARDEN Firewall (Jail: %s)", hostname, jail)

		// Map jails to categories
		categories := "14,15,18,21"
		jailLower := strings.ToLower(jail)
		if strings.Contains(jailLower, "portscan") || strings.Contains(jailLower, "catch") {
			categories = "14"
		} else if strings.Contains(jailLower, "ssh") {
			categories = "18,22"
		} else if strings.Contains(jailLower, "geo") || strings.Contains(jailLower, "asn") {
			categories = "14,15"
		} else if strings.Contains(jailLower, "l7-sqli") {
			categories = "16,21"
		} else if strings.Contains(jailLower, "l7-xss") || strings.Contains(jailLower, "l7-lfi") || strings.Contains(jailLower, "l7-rce") || strings.Contains(jailLower, "l7-ssrf") || strings.Contains(jailLower, "l7-nosql") || strings.Contains(jailLower, "l7-api") {
			categories = "21"
		} else if strings.Contains(jailLower, "l7-scanner") {
			categories = "19"
		} else if strings.Contains(jailLower, "l7-bruteforce") {
			categories = "18,21"
		}

		url := "https://api.abuseipdb.com/api/v2/report"
		reqBody, _ := json.Marshal(map[string]string{
			"ip":         ip,
			"categories": categories,
			"comment":    comment,
		})

		req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
		if err != nil {
			return
		}
		req.Header.Set("Key", abuseAPIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[AbuseIPDB FAIL] Error: %v", err)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()

		if resp.StatusCode == 200 {
			log.Printf("[SUCCESS] Reported %s to AbuseIPDB (Jail: %s)", ip, jail)
		} else {
			bodyBytes, _ := io.ReadAll(resp.Body)
			log.Printf("[API ERROR] AbuseIPDB HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}
	}()
}
