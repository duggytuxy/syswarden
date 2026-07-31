package telemetry

import (
	"bufio"
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

// isKnownIP checks if the IP is already in our threat intel or blacklist files.
func isKnownIP(ip string) bool {
	files := []string{
		"/etc/syswarden/lists/syswarden_blacklist.ipv4",
		"/etc/syswarden/lists/syswarden_blacklist.ipv6",
		"/etc/syswarden/lists/syswarden_threatintel.ipv4",
		"/etc/syswarden/lists/syswarden_threatintel.ipv6",
	}

	for _, path := range files {
		f, err := os.Open(path) // #nosec
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == ip {
				_ = f.Close()
				return true
			}
		}
		_ = f.Close()
	}
	return false
}

// ReportAbuseAsync asynchronously reports a banned IP to AbuseIPDB
func ReportAbuseAsync(ip, jail, payload string) {
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

	if isKnownIP(ip) {
		return
	}

	go func() {
		ts := time.Now().Format("2006-01-02 15:04:05")
		j := strings.ToLower(jail)
		var comment string

		if strings.Contains(j, "ssh") || strings.Contains(j, "bruteforce") || strings.Contains(j, "auth") {
			port := "22"
			if idx := strings.Index(payload, "port "); idx != -1 {
				parts := strings.Split(payload[idx+5:], " ")
				if len(parts) > 0 {
					port = strings.Trim(parts[0], ":")
				}
			} else if idx := strings.Index(payload, "DPT="); idx != -1 {
				pStr := payload[idx+4:]
				if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
					port = pStr[:spaceIdx]
				}
			}
			comment = fmt.Sprintf("[%s] Attempted SSH brute-force on port %s by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, port, ip)
		} else if strings.Contains(j, "scan") || strings.Contains(j, "zero-trust") || strings.Contains(j, "catch-all") {
			port := "unknown"
			if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
				pStr := payload[dptIdx+4:]
				if spaceIdx := strings.Index(pStr, " "); spaceIdx != -1 {
					port = pStr[:spaceIdx]
				}
			}
			comment = fmt.Sprintf("[%s] Attempted port scan on port %s by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, port, ip)
		} else if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") {
			uri := "/"
			if idx := strings.Index(payload, "GET "); idx != -1 {
				parts := strings.Split(payload[idx+4:], " ")
				if len(parts) > 0 {
					uri = parts[0]
				}
			} else if idx := strings.Index(payload, "POST "); idx != -1 {
				parts := strings.Split(payload[idx+5:], " ")
				if len(parts) > 0 {
					uri = parts[0]
				}
			}
			comment = fmt.Sprintf("[%s] Attempted Web exploit (%s) on URI '%s' by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, strings.ToUpper(jail), uri, ip)
		} else {
			comment = fmt.Sprintf("[%s] Attempted attack (%s) by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, strings.ToUpper(jail), ip)
		}

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
