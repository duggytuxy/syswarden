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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/viper"
)

var (
	abuseCache     = make(map[string]time.Time)
	abuseCacheLock sync.Mutex
	abuseAPIKey    string
	abuseEnabled   bool
	abuseOnce      sync.Once
)

const (
	abuseReportURL     = "https://api.abuseipdb.com/api/v2/report"
	abuseReportTimeout = 10 * time.Second
)

type abuseReportPayload struct {
	IP         string `json:"ip"`
	Categories string `json:"categories"`
	Comment    string `json:"comment"`
}

func initAbuse() {
	abuseEnabled = viper.GetBool("integrations.abuseipdb.enabled")
	abuseAPIKey = viper.GetString("integrations.abuseipdb.api_key")
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

func normalizedJail(jail string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(jail)), "l7-")
}

func isL7ExploitJail(jail string) bool {
	jail = normalizedJail(jail)
	for _, marker := range []string{
		"sqli", "injection", "xss", "lfi", "path-traversal", "rce", "cmd-exec",
		"ssrf", "nosql", "ssti", "jndi", "webshell", "deserialization", "exploit", "api",
	} {
		if strings.Contains(jail, marker) {
			return true
		}
	}
	return false
}

// reportedPort returns only a canonical decimal TCP/UDP port. The payload is
// otherwise untrusted and must never be copied into a public AbuseIPDB comment.
func reportedPort(payload, fallback string) string {
	for _, marker := range []string{"port ", "DPT="} {
		searchFrom := 0
		for {
			idx := strings.Index(payload[searchFrom:], marker)
			if idx == -1 {
				break
			}
			idx += searchFrom + len(marker)
			fields := strings.Fields(payload[idx:])
			if len(fields) != 0 {
				candidate := fields[0]
				if marker == "port " {
					candidate = strings.TrimSuffix(candidate, ":")
				}
				if port, ok := canonicalPort(candidate); ok {
					return port
				}
			}
			searchFrom = idx
			if searchFrom >= len(payload) {
				break
			}
		}
	}
	return fallback
}

func canonicalPort(candidate string) (string, bool) {
	if candidate == "" || len(candidate) > 5 {
		return "", false
	}
	for _, char := range candidate {
		if char < '0' || char > '9' {
			return "", false
		}
	}
	port, err := strconv.Atoi(candidate)
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	return strconv.Itoa(port), true
}

func abuseCategories(jail string) string {
	jail = normalizedJail(jail)
	switch {
	case jail == "sqli":
		return "16,21"
	case jail == "xss", jail == "lfi", jail == "lfi-advanced", jail == "rce",
		jail == "ssrf", jail == "nosql", jail == "api", jail == "apimapper":
		return "21"
	case strings.Contains(jail, "scanner"):
		return "19"
	case strings.Contains(jail, "bruteforce"):
		return "18,21"
	case strings.Contains(jail, "portscan") || strings.Contains(jail, "catch"):
		return "14"
	case strings.Contains(jail, "ssh"):
		return "18,22"
	case strings.Contains(jail, "geo") || strings.Contains(jail, "asn"):
		return "14,15"
	case isL7ExploitJail(jail):
		return "21"
	default:
		return "14,15,18,21"
	}
}

func newAbuseReportPayload(ip, jail, payload string, now time.Time) abuseReportPayload {
	ts := now.Format("2006-01-02 15:04:05")
	jailLower := strings.ToLower(jail)
	var comment string

	switch {
	case strings.Contains(jailLower, "ssh") || strings.Contains(jailLower, "bruteforce") || strings.Contains(jailLower, "auth"):
		port := reportedPort(payload, "22")
		comment = fmt.Sprintf("[%s] Attempted SSH brute-force on port %s by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, port, ip)
	case strings.Contains(jailLower, "scan") || strings.Contains(jailLower, "zero-trust") || strings.Contains(jailLower, "catch-all"):
		port := reportedPort(payload, "unknown")
		comment = fmt.Sprintf("[%s] Attempted port scan on port %s by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, port, ip)
	case isL7ExploitJail(jail):
		comment = fmt.Sprintf("[%s] Attempted web exploit (%s; request target redacted) by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, strings.ToUpper(jail), ip)
	default:
		comment = fmt.Sprintf("[%s] Attempted attack (%s) by IP %s (Reported by SysWarden https://github.com/duggytuxy/syswarden)", ts, strings.ToUpper(jail), ip)
	}

	return abuseReportPayload{
		IP:         ip,
		Categories: abuseCategories(jail),
		Comment:    comment,
	}
}

func newAbuseHTTPClient() *http.Client {
	return &http.Client{
		Timeout: abuseReportTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newAbuseReportRequest(ip, jail, payload, apiKey string, now time.Time) (*http.Request, error) {
	report := newAbuseReportPayload(ip, jail, payload, now)
	reqBody, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, abuseReportURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	return req, nil
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
		req, err := newAbuseReportRequest(ip, jail, payload, abuseAPIKey, time.Now())
		if err != nil {
			return
		}

		client := newAbuseHTTPClient()
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
