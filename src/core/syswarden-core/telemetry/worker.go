package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"syswarden-core/internal/runtimepaths"
	"syswarden-core/utils"

	"github.com/spf13/viper"
)

type FirewallManager interface {
	Ban(ip string) error
}

type Service struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Status string `json:"status"`
}

type Port struct {
	IP       string `json:"ip"`
	State    string `json:"state"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type SystemData struct {
	Hostname    string    `json:"hostname"`
	Uptime      string    `json:"uptime"`
	LoadAverage string    `json:"load_average"`
	RamUsedMb   int       `json:"ram_used_mb"`
	RamTotalMb  int       `json:"ram_total_mb"`
	DiskUsedMb  int       `json:"disk_used_mb"`
	DiskTotalMb int       `json:"disk_total_mb"`
	Cores       string    `json:"cores"`
	Arch        string    `json:"arch"`
	Os          string    `json:"os"`
	CpuModel    string    `json:"cpu_model"`
	ServerIP    string    `json:"server_ip"`
	Services    []Service `json:"services"`
	Ports       []Port    `json:"ports"`
}

type platformSystemStats struct {
	Uptime      string
	LoadAverage string
	RamUsedMb   int
	RamTotalMb  int
	CpuModel    string
}

type Layer3 struct {
	GlobalBlocked int  `json:"global_blocked"`
	GeoIPBlocked  int  `json:"geoip_blocked"`
	ASNBlocked    int  `json:"asn_blocked"`
	L7Banned      int  `json:"l7_banned"`
	ZeroTrustMode bool `json:"zero_trust_mode"`
}

type JailData struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Mitre string `json:"mitre"`
}

type AllowedEvent struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Service   string `json:"service"`
	Payload   string `json:"payload"`
}

type BannedIP struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
	Mitre     string `json:"mitre"`
	Action    string `json:"action"`
}

type Attacker struct {
	IP       string `json:"ip"`
	Severity string `json:"severity"`
	Port     string `json:"port"`
	Country  string `json:"country"`
	ASN      string `json:"asn"`
	Threat   string `json:"threat"`
	Org      string `json:"org"`
	Hits     int    `json:"hits"`
	LastSeen string `json:"last_seen"`
}

type TargetedPort struct {
	Port      string `json:"port"`
	Service   string `json:"service"`
	Hits      int    `json:"hits"`
	UniqueIPs int    `json:"unique_ips"`
}

type WAF struct {
	TotalBanned      int            `json:"total_banned"`
	TotalDetected    int            `json:"total_detected"`
	ActiveSignatures int            `json:"active_signatures"`
	SignaturesData   []JailData     `json:"signatures_data"`
	TargetedPorts    []TargetedPort `json:"targeted_ports"`
	BannedIPs        []BannedIP     `json:"banned_ips"`
	TopAttackers     []Attacker     `json:"top_attackers"`
	RiskRadar        []int          `json:"risk_radar"`
	Sparkline24h     [24]int        `json:"sparkline_24h"`
	AllowedEvents    []AllowedEvent `json:"allowed_events"`
}

type Whitelist struct {
	ActiveIPs int      `json:"active_ips"`
	IPs       []string `json:"ips"`
}

type DashboardData struct {
	Timestamp     string       `json:"timestamp"`
	GithubStars   string       `json:"github_stars"`
	GithubRelease string       `json:"github_release"`
	ProfileName   string       `json:"profile_name"`
	System        SystemData   `json:"system"`
	Layer3        Layer3       `json:"layer3"`
	WAF           WAF          `json:"waf"`
	Whitelist     Whitelist    `json:"whitelist"`
	HA            *HATelemetry `json:"ha,omitempty"`
}

// TelemetryEvent parses lines from waf.json
type TelemetryEvent struct {
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Jail      string `json:"jail"`
	Payload   string `json:"payload"`
	Severity  int    `json:"severity,omitempty"`
}

// StartWorker launches the background telemetry generator replacing the cron bash script
func StartWorker(ctx context.Context, wg *sync.WaitGroup, fwManager FirewallManager, logAllowed func(ip, service, payload string), logBan func(ip, jail, payload string), logShadowAlert func(ip, jail, payload string)) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("[Telemetry Worker] Started background worker (eliminating cron)")

		// Refresh every 5 seconds to provide near real-time TUI updates
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		generateTelemetry()

		for {
			select {
			case <-ctx.Done():
				log.Println("[Telemetry Worker] Shutting down gracefully...")
				return
			case <-ticker.C:
				generateTelemetry()
			}
		}
	}()

	// Start ALLOWED events monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorAllowedEvents(ctx, logAllowed)
	}()

	// Start ARP Flood & Portscan monitor
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorKernelDrops(ctx, fwManager, logBan, logShadowAlert)
	}()
}

func monitorAllowedEvents(ctx context.Context, logAllowed func(ip, service, payload string)) {
	if logAllowed == nil {
		return
	}

	cmd := allowedEventsCommand(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[Telemetry Worker] Failed to start tail for ALLOWED events: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse SSH (Debian/Ubuntu auth.log or RHEL secure)
		if strings.Contains(line, "sshd") && (strings.Contains(line, "Accepted password for") || strings.Contains(line, "Accepted publickey for")) {
			parts := strings.Fields(line)
			for i, p := range parts {
				if p == "from" && i+1 < len(parts) {
					ip := parts[i+1]
					logAllowed(ip, "sshd", line)
					break
				}
			}
		} else if strings.Contains(line, "HTTP/1.") || strings.Contains(line, "HTTP/2.") {
			// Nginx / Apache access log format
			// 1.2.3.4 - - [date] "GET / HTTP/1.1" 200 ...
			if strings.Contains(line, "\" 200 ") || strings.Contains(line, "\" 201 ") || strings.Contains(line, "\" 204 ") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					ip := parts[0]
					logAllowed(ip, "nginx/apache2", line)
				}
			}
		}
	}
	_ = cmd.Wait()
}

func monitorKernelDrops(ctx context.Context, fwManager FirewallManager, logBan func(ip, jail, payload string), logShadowAlert func(ip, jail, payload string)) {
	if logBan == nil {
		return
	}

	cmd := kernelDropsCommand(ctx)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[Telemetry Worker] Failed to start tail for kernel drop events: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}

	strikeMap := make(map[string]int)
	var strikeMu sync.Mutex

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// 1. Parse CATCH-ALL Drops for L3 Portscanners (Fail2ban Parity)
		if strings.Contains(line, "[CATCH-ALL]") {
			ip := extractField(line, "SRC=")
			if ip != "" {
				if utils.IsWhitelisted(ip) {
					continue // Absolute immunity for Infra IPs
				}

				strikeMu.Lock()
				strikeMap[ip]++
				hits := strikeMap[ip]
				strikeMu.Unlock()

				if hits == 3 {
					// 3 strikes: Permanently Ban IP using Firewall Manager
					if fwManager == nil {
						log.Printf("[Telemetry Worker] Firewall unavailable; refusing to report a port-scan ban for %s", ip)
						continue
					}
					if err := fwManager.Ban(ip); err != nil {
						log.Printf("[Telemetry Worker] Firewall rejected port-scan ban for %s: %v", ip, err)
						continue
					}
					logBan(ip, "L3-PORTSCAN", line)
				}
			}
		} else if strings.Contains(line, "[SYSWARDEN-HONEYPORT]") {
			ip := extractField(line, "SRC=")
			if ip != "" {
				if utils.IsWhitelisted(ip) {
					if logShadowAlert != nil {
						logShadowAlert(ip, "L3-HONEYPORT-SCAN", line)
					}
					continue
				}

				strikeMu.Lock()
				strikeMap[ip]++
				hits := strikeMap[ip]
				strikeMu.Unlock()

				if hits == 1 {
					// 1 strike is enough for Honeyport
					if fwManager == nil {
						log.Printf("[Telemetry Worker] Firewall unavailable; refusing to report a honeyport ban for %s", ip)
						continue
					}
					if err := fwManager.Ban(ip); err != nil {
						log.Printf("[Telemetry Worker] Firewall rejected honeyport ban for %s: %v", ip, err)
						continue
					}
					logBan(ip, "L3-HONEYPORT-SCAN", line)
				}
			}
		} else if strings.Contains(line, "[SYSWARDEN-ARP-FLOOD]") {
			ip := extractField(line, "SRC=")
			if ip == "" {
				ip = extractField(line, "MAC=") // Fallback to MAC if SRC IP is missing
			}
			if ip == "" {
				ip = "Unknown-ARP-Attacker"
			}
			logBan(ip, "L2-ARP-FLOOD", line)
		}
	}
	_ = cmd.Wait()
}

func extractField(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx != -1 {
		parts := strings.Fields(line[idx:])
		if len(parts) > 0 {
			return strings.TrimPrefix(parts[0], prefix)
		}
	}
	return ""
}

func generateTelemetry() {
	data := DashboardData{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		GithubStars:   getGithubStars(),
		GithubRelease: getGithubRelease(),
		ProfileName:   viper.GetString("user.profile_name"),
		System:        getSystemStats(),
		Layer3:        getLayer3Stats(),
		WAF:           getWAFStats(),
		Whitelist:     getWhitelistStats(),
		HA:            getHATelemetry(),
	}

	uiDir := "/var/lib/syswarden/ui"
	_ = os.MkdirAll(uiDir, 0750)
	dataFile := filepath.Join(uiDir, "data.json")

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("[Telemetry Worker] Error marshaling telemetry data: %v", err)
		return
	}

	// Write atomically using a tmp file
	tmpFile := dataFile + ".tmp"
	if err := os.WriteFile(tmpFile, jsonData, 0600); err != nil {
		log.Printf("[Telemetry Worker] Error writing telemetry data: %v", err)
		return
	}

	if err := os.Rename(tmpFile, dataFile); err != nil {
		log.Printf("[Telemetry Worker] Error moving telemetry data: %v", err)
	}
}

var cachedSys SystemData
var lastSysFetch time.Time

func GetOutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer func() {
		_ = conn.Close()
	}()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getSystemStats() SystemData {
	if time.Since(lastSysFetch) < 60*time.Second && cachedSys.Hostname != "" {
		return cachedSys
	}

	sys := SystemData{
		Hostname: "Unknown",
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Cores:    fmt.Sprintf("%d", runtime.NumCPU()),
	}
	if h, err := os.Hostname(); err == nil {
		sys.Hostname = h
	}
	sys.ServerIP = GetOutboundIP()

	platformStats := collectPlatformSystemStats()
	sys.Uptime = platformStats.Uptime
	sys.LoadAverage = platformStats.LoadAverage
	sys.CpuModel = platformStats.CpuModel
	sys.RamTotalMb = platformStats.RamTotalMb
	sys.RamUsedMb = platformStats.RamUsedMb

	// Disk Space
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		sys.DiskTotalMb = int((stat.Blocks * uint64(stat.Bsize)) / 1024 / 1024)               // #nosec G115
		sys.DiskUsedMb = int(((stat.Blocks - stat.Bfree) * uint64(stat.Bsize)) / 1024 / 1024) // #nosec G115
	}

	osName := runtime.GOOS
	if b, err := os.ReadFile("/etc/os-release"); err == nil { // #nosec
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}
	sys.Os = osName

	sys.Services = collectPlatformServices()
	sys.Ports = collectPlatformPorts()
	if sys.Ports == nil {
		sys.Ports = make([]Port, 0)
	}

	// --- Virtual Service: SYSWARDEN-HA-CLUSTER ---
	haStatus := "SKIPPED"
	haEnabled := false
	haPort := "62026"

	if viper.GetBool("integrations.ha.enabled") {
		haEnabled = true
		if p := viper.GetInt("integrations.ha.peer_port"); p > 0 {
			haPort = strconv.Itoa(p)
		} else if ps := viper.GetString("integrations.ha.peer_port"); ps != "" {
			haPort = ps
		}
	}
	if haEnabled {
		haStatus = "INACTIVE"
		for _, p := range sys.Ports {
			if p.Port == haPort && p.State == "LISTEN" {
				haStatus = "ACTIVE"
				break
			}
		}
	}
	sys.Services = append(sys.Services, Service{
		Name:   "SYSWARDEN-HA-CLUSTER",
		Status: haStatus,
	})

	// --- Virtual Service: SYSWARDEN-UPDATE-FEEDS ---
	feedsTimer := "SKIPPED"
	outFeeds, errFeeds := exec.Command("crontab", "-l").Output() // #nosec
	if errFeeds == nil {
		lines := strings.Split(string(outFeeds), "\n")
		for _, line := range lines {
			if strings.Contains(line, "syswarden-cli update-feeds") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					minute, errMin := strconv.Atoi(parts[0])
					if errMin == nil {
						now := time.Now()
						nextRun := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), minute, 0, 0, now.Location())
						if now.After(nextRun) {
							nextRun = nextRun.Add(time.Hour)
						}
						diff := nextRun.Sub(now)
						h := int(diff.Hours())
						m := int(diff.Minutes()) % 60
						s := int(diff.Seconds()) % 60
						feedsTimer = fmt.Sprintf("%02d:%02d:%02d", h, m, s)
					}
				}
			}
		}
	}
	sys.Services = append(sys.Services, Service{
		Name:   "SYSWARDEN-UPDATE-FEEDS",
		Status: feedsTimer,
	})

	cachedSys = sys
	lastSysFetch = time.Now()
	return sys
}

var cachedL3 Layer3
var lastL3Fetch time.Time

func countLinesInFile(path string) int {
	file, err := os.Open(path) // #nosec
	if err != nil {
		return 0
	}
	defer func() {
		_ = file.Close()
	}()
	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		count++
	}
	return count
}

func getLayer3Stats() Layer3 {
	if time.Since(lastL3Fetch) < 2*time.Minute && cachedL3.GlobalBlocked > 0 {
		return cachedL3
	}

	var l3 Layer3

	if len(viper.GetStringSlice("network.geo.allowed_countries")) > 0 {
		l3.ZeroTrustMode = true
	}
	if len(viper.GetStringSlice("network.asn.allowed_asns")) > 0 {
		l3.ZeroTrustMode = true
	}

	l3.L7Banned = countLinesInFile("/etc/syswarden/lists/syswarden_blacklist.ipv4") + countLinesInFile("/etc/syswarden/lists/syswarden_blacklist.ipv6")
	l3.GlobalBlocked = l3.L7Banned + countLinesInFile("/etc/syswarden/lists/syswarden_threatintel.ipv4") + countLinesInFile("/etc/syswarden/lists/syswarden_threatintel.ipv6")

	if matches, err := filepath.Glob("/etc/syswarden/lists/AS*.ipv*"); err == nil {
		for _, m := range matches {
			l3.ASNBlocked += countLinesInFile(m)
		}
	}

	if matches, err := filepath.Glob("/etc/syswarden/lists/??.ipv*"); err == nil {
		for _, m := range matches {
			l3.GeoIPBlocked += countLinesInFile(m)
		}
	}

	cachedL3 = l3
	lastL3Fetch = time.Now()
	return l3
}

type IPAPIResponse struct {
	CountryCode string `json:"country_code"`
	Asn         string `json:"asn"`
	Org         string `json:"org"`
	Threat      string `json:"threat"`
}

var osintCache = make(map[string]Attacker)
var osintMu sync.Mutex
var osintCacheOnce sync.Once

func loadOSINTCache() {
	b, err := os.ReadFile("/var/lib/syswarden/ui/osint_cache.json") // #nosec
	if err == nil {
		_ = json.Unmarshal(b, &osintCache)
	}
}

func saveOSINTCache() {
	b, err := json.Marshal(osintCache)
	if err == nil {
		_ = os.WriteFile("/var/lib/syswarden/ui/osint_cache.json", b, 0600) // #nosec
	}
}

func getActiveSSHPort() string {
	// Dynamically query sshd for its effective configuration
	if out, err := exec.Command("sh", "-c", "sshd -T 2>/dev/null | grep -i '^port '").Output(); err == nil && len(out) > 0 { // #nosec
		fields := strings.Fields(string(out))
		if len(fields) >= 2 {
			if parsed, err := strconv.Atoi(fields[1]); err == nil && parsed > 0 && parsed <= 65535 {
				return strconv.Itoa(parsed)
			}
		}
	}
	return getConfiguredSSHPort()
}

var customSSHPort string
var sshPortMu sync.Mutex

func getConfiguredSSHPort() string {
	sshPortMu.Lock()
	defer sshPortMu.Unlock()
	if customSSHPort != "" {
		return customSSHPort
	}

	if p := viper.GetString("core.ssh_port"); p != "" {
		customSSHPort = p
		return customSSHPort
	}
	customSSHPort = "22"
	return customSSHPort
}

func getServiceName(port string) string {
	services := map[string]string{
		"21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS",
		"80": "HTTP", "110": "POP3", "143": "IMAP", "443": "HTTPS", "445": "SMB",
		"3306": "MySQL", "3389": "RDP", "5432": "PostgreSQL", "6379": "Redis",
		"8080": "HTTP-Alt", "8443": "HTTPS-Alt",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return "Port " + port
}

func extractPort(payload string) string {
	port := "MULTI"
	if payload != "" {
		if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			protoStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(protoStr, " "); spaceIdx != -1 {
				protoStr = protoStr[:spaceIdx]
			}

			if protoStr == "ICMP" || protoStr == "ICMPv6" || protoStr == "IGMP" || protoStr == "GRE" || protoStr == "IPSEC" || protoStr == "IPIP" {
				port = protoStr
			} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
				dptStr := payload[dptIdx+4:]
				if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
					dptStr = dptStr[:spaceIdx]
				}
				port = dptStr
			} else {
				port = protoStr
			}
		} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			dptStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
				dptStr = dptStr[:spaceIdx]
			}
			port = dptStr
		} else if idx := strings.Index(payload, "port "); idx != -1 {
			parts := strings.Split(payload[idx+5:], " ")
			if len(parts) > 0 {
				port = parts[0]
			}
		} else if strings.Contains(strings.ToLower(payload), "http") || strings.Contains(strings.ToLower(payload), "nginx") || strings.Contains(strings.ToLower(payload), "apache") {
			port = "80/443"
		}
	}
	return port
}

func enrichOSINT(ip string, payload string, jail string) Attacker {
	osintCacheOnce.Do(func() {
		osintMu.Lock()
		loadOSINTCache()
		osintMu.Unlock()
	})

	var att Attacker
	osintMu.Lock()
	if cached, ok := osintCache[ip]; ok {
		att = cached
		osintMu.Unlock()
	} else {
		osintMu.Unlock()
		att = Attacker{
			IP:      ip,
			Country: "N/A",
			ASN:     "N/A",
			Org:     "N/A",
		}

		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("https://ip.wiredalter.com/json?ip=" + ip)
		if err == nil {
			defer func() {
				_ = resp.Body.Close()
			}()
			var res IPAPIResponse
			if json.NewDecoder(resp.Body).Decode(&res) == nil {
				if res.CountryCode != "" {
					att.Country = res.CountryCode
				}
				if res.Asn != "" {
					att.ASN = res.Asn
				}
				if res.Org != "" {
					att.Org = res.Org
				}
				if res.Threat != "" {
					att.Threat = res.Threat
				}
			}
		}

		// Save to memory and cache (whether N/A or actual data to avoid spamming the API)
		osintMu.Lock()
		osintCache[ip] = att
		saveOSINTCache()
		osintMu.Unlock()
	}

	// Extract port or protocol from payload dynamically
	port := "MULTI"
	if payload != "" {
		if protoIdx := strings.Index(payload, "PROTO="); protoIdx != -1 {
			protoStr := payload[protoIdx+6:]
			if spaceIdx := strings.Index(protoStr, " "); spaceIdx != -1 {
				protoStr = protoStr[:spaceIdx]
			}

			if protoStr == "ICMP" || protoStr == "ICMPv6" || protoStr == "IGMP" || protoStr == "GRE" || protoStr == "IPSEC" || protoStr == "IPIP" {
				port = protoStr
			} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
				dptStr := payload[dptIdx+4:]
				if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
					dptStr = dptStr[:spaceIdx]
				}
				port = dptStr
			} else {
				port = protoStr
			}
		} else if dptIdx := strings.Index(payload, "DPT="); dptIdx != -1 {
			dptStr := payload[dptIdx+4:]
			if spaceIdx := strings.Index(dptStr, " "); spaceIdx != -1 {
				dptStr = dptStr[:spaceIdx]
			}
			port = dptStr
		}
	}

	if port == "MULTI" {
		j := strings.ToLower(jail)
		if strings.Contains(j, "ssh") || strings.Contains(j, "bruteforce") {
			port = getActiveSSHPort()
		}
	}

	att.Port = port

	return att
}

var cachedStars string = "260"
var lastStarFetch time.Time

func getGithubStars() string {
	if time.Since(lastStarFetch) < 1*time.Hour && cachedStars != "N/A" {
		return cachedStars
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/duggytuxy/syswarden", nil)
	if err != nil {
		return cachedStars
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err == nil {
		defer func() {
			_ = resp.Body.Close()
		}()
		if resp.StatusCode == 200 {
			var res struct {
				StargazersCount int `json:"stargazers_count"`
			}
			if json.NewDecoder(resp.Body).Decode(&res) == nil {
				cachedStars = fmt.Sprintf("%d", res.StargazersCount)
				lastStarFetch = time.Now()
			}
		}
	}
	return cachedStars
}

var cachedRelease string = "Unknown"
var lastReleaseFetch time.Time

func getGithubRelease() string {
	if time.Since(lastReleaseFetch) < 1*time.Hour && cachedRelease != "Unknown" {
		return cachedRelease
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/duggytuxy/syswarden/releases/latest", nil)
	if err != nil {
		return cachedRelease
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == 200 {
			var res struct {
				TagName string `json:"tag_name"`
			}
			if json.NewDecoder(resp.Body).Decode(&res) == nil {
				cachedRelease = res.TagName
				lastReleaseFetch = time.Now()
			}
		}
	}
	return cachedRelease
}

var cachedWAF WAF
var lastWAFFetch time.Time

func getMitreTag(jail string) string {
	j := strings.ToLower(jail)
	if strings.Contains(j, "bruteforce") || strings.Contains(j, "ssh") || strings.Contains(j, "auth") || strings.Contains(j, "login") {
		return "T1110: Brute Force"
	} else if strings.Contains(j, "scan") || strings.Contains(j, "recon") {
		return "T1595: Active Scanning"
	} else if strings.Contains(j, "sqli") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "rce") || strings.Contains(j, "exploit") || strings.Contains(j, "waap") {
		return "T1190: Exploit Public-Facing Application"
	} else if strings.Contains(j, "flood") || strings.Contains(j, "dos") {
		return "T1498: Network Denial of Service"
	}
	return "T1190: Exploit Public-Facing Application"
}

func getWAFStats() WAF {
	if time.Since(lastWAFFetch) < 15*time.Second && cachedWAF.TotalBanned > 0 {
		return cachedWAF
	}

	var waf WAF
	waf.BannedIPs = []BannedIP{}
	waf.TopAttackers = []Attacker{}
	waf.SignaturesData = []JailData{}

	// Read signatures.json for active signatures count
	if b, err := runtimepaths.ReadSignatures(); err == nil {
		var sigs struct {
			Rules []interface{} `json:"rules"`
		}
		if err := json.Unmarshal(b, &sigs); err == nil {
			waf.ActiveSignatures = len(sigs.Rules)
		}
	}

	// Parse /var/log/syswarden/waf.json
	file, err := os.Open("/var/log/syswarden/waf.json") // #nosec
	if err != nil {
		return waf
	}
	defer func() {
		_ = file.Close()
	}()

	jailCounts := make(map[string]int)
	var allBans []BannedIP
	var allAllowed []AllowedEvent

	activeBans := make(map[string]bool)
	if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4"); err == nil { // #nosec
		for _, line := range strings.Split(string(content), "\n") {
			if ip := strings.TrimSpace(line); ip != "" {
				activeBans[ip] = true
			}
		}
	}
	if content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv6"); err == nil { // #nosec
		for _, line := range strings.Split(string(content), "\n") {
			if ip := strings.TrimSpace(line); ip != "" {
				activeBans[ip] = true
			}
		}
	}
	waf.TotalBanned = len(activeBans)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event TelemetryEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			if event.Action != "ALLOWED" && activeBans[event.IP] {
				event.Action = "BANNED"
			}
			switch event.Action {
			case "ALLOWED":
				allAllowed = append(allAllowed, AllowedEvent{
					Timestamp: event.Timestamp,
					IP:        event.IP,
					Service:   event.Jail,
					Payload:   event.Payload,
				})
			case "SHADOW-ALERT":
				waf.TotalDetected++
				jailCounts[event.Jail]++
				allBans = append(allBans, BannedIP{
					Timestamp: event.Timestamp,
					IP:        event.IP,
					Jail:      event.Jail,
					Payload:   event.Payload,
					Mitre:     getMitreTag(event.Jail),
					Action:    "SHADOW-ALERT",
				})
			case "DETECTED":
				waf.TotalDetected++
				jailCounts[event.Jail]++
				allBans = append(allBans, BannedIP{
					Timestamp: event.Timestamp,
					IP:        event.IP,
					Jail:      event.Jail,
					Payload:   event.Payload,
					Mitre:     getMitreTag(event.Jail),
					Action:    "DETECTED",
				})
			case "COMPLIANCE-OK", "COMPLIANCE-DRIFT", "SIMULATED-BAN":
				allBans = append(allBans, BannedIP{
					Timestamp: event.Timestamp,
					IP:        event.IP,
					Jail:      event.Jail,
					Payload:   event.Payload,
					Mitre:     getMitreTag(event.Jail),
					Action:    event.Action,
				})
			default:
				if !activeBans[event.IP] {
					continue
				}
				jailCounts[event.Jail]++

				allBans = append(allBans, BannedIP{
					Timestamp: event.Timestamp,
					IP:        event.IP,
					Jail:      event.Jail,
					Payload:   event.Payload,
					Mitre:     getMitreTag(event.Jail),
					Action:    "BANNED",
				})
			}
		}
	}

	// Get last 50 allowed IPs for display
	startA := 0
	if len(allAllowed) > 50 {
		startA = len(allAllowed) - 50
	}
	for i := len(allAllowed) - 1; i >= startA; i-- {
		waf.AllowedEvents = append(waf.AllowedEvents, allAllowed[i])
	}

	// Get last 50 unique banned/detected IPs for display (newest first)
	seenIPs := make(map[string]bool)
	hitCounts := make(map[string]int)
	currentStrikes := make(map[string]int)
	for _, b := range allBans {
		if b.Action == "COMPLIANCE-OK" || b.Action == "COMPLIANCE-DRIFT" {
			continue
		}
		currentStrikes[b.IP]++
		if b.Action == "BANNED" {
			hitCounts[b.IP] = currentStrikes[b.IP]
			currentStrikes[b.IP] = 0 // Reset after a ban
		}
	}
	// Fallback for attackers not yet banned
	for ip, strikes := range currentStrikes {
		if strikes > 0 && hitCounts[ip] == 0 {
			hitCounts[ip] = strikes
		}
	}
	for i := len(allBans) - 1; i >= 0; i-- {
		if len(waf.BannedIPs) >= 50 {
			break
		}
		if seenIPs[allBans[i].IP] {
			continue
		}
		seenIPs[allBans[i].IP] = true
		waf.BannedIPs = append(waf.BannedIPs, allBans[i])

		if allBans[i].Action != "COMPLIANCE-OK" && allBans[i].Action != "COMPLIANCE-DRIFT" {
			// Quick TopAttacker populate with OSINT and Severity
			att := enrichOSINT(allBans[i].IP, allBans[i].Payload, allBans[i].Jail)
			hits := hitCounts[allBans[i].IP]
			att.Hits = hits
			att.LastSeen = allBans[i].Timestamp
			score := hits * 10
			j := strings.ToLower(allBans[i].Jail)
			if strings.Contains(j, "sqli") || strings.Contains(j, "rce") || strings.Contains(j, "xss") || strings.Contains(j, "lfi") || strings.Contains(j, "bruteforce") || strings.Contains(j, "ssh") || strings.Contains(j, "auth") {
				score += 20
			}
			if score > 100 {
				score = 100
			}
			level := "Suspicious"
			if score >= 80 {
				level = "Critical"
			} else if score >= 50 {
				level = "High Risk"
			}
			att.Severity = fmt.Sprintf("%d/100 (%s)", score, level)
			waf.TopAttackers = append(waf.TopAttackers, att)
		}
	}

	for jail, count := range jailCounts {
		waf.SignaturesData = append(waf.SignaturesData, JailData{
			Name:  jail,
			Count: count,
			Mitre: getMitreTag(jail),
		})
	}

	// Targeted Ports
	portCounts := make(map[string]int)
	portIPs := make(map[string]map[string]bool)
	for _, b := range allBans {
		if b.Action == "BANNED" || b.Action == "DETECTED" || b.Action == "SHADOW-ALERT" {
			p := extractPort(b.Payload)
			portCounts[p]++
			if portIPs[p] == nil {
				portIPs[p] = make(map[string]bool)
			}
			portIPs[p][b.IP] = true
		}
	}
	for p, count := range portCounts {
		waf.TargetedPorts = append(waf.TargetedPorts, TargetedPort{
			Port:      p,
			Service:   getServiceName(p),
			Hits:      count,
			UniqueIPs: len(portIPs[p]),
		})
	}
	sort.Slice(waf.TargetedPorts, func(i, j int) bool {
		return waf.TargetedPorts[i].Hits > waf.TargetedPorts[j].Hits
	})
	if len(waf.TargetedPorts) > 5 {
		waf.TargetedPorts = waf.TargetedPorts[:5]
	}

	// Sparkline 24h
	sparkCache := make(map[string]int)
	metricsFile := "/var/lib/syswarden/ui/metrics_24h.json"
	if b, err := os.ReadFile(metricsFile); err == nil { // #nosec
		_ = json.Unmarshal(b, &sparkCache)
	}

	currentHourCounts := make(map[string]int)
	for _, b := range allBans {
		if b.Action == "BANNED" || b.Action == "DETECTED" {
			if t, err := time.Parse(time.RFC3339, b.Timestamp); err == nil {
				key := t.UTC().Format("2006-01-02-15")
				currentHourCounts[key]++
			}
		}
	}

	for k, v := range currentHourCounts {
		if v > sparkCache[k] {
			sparkCache[k] = v
		}
	}

	now := time.Now().UTC()
	var spark [24]int
	for i := 0; i < 24; i++ {
		t := now.Add(time.Duration(-i) * time.Hour)
		key := t.Format("2006-01-02-15")
		spark[23-i] = sparkCache[key]
	}

	for k := range sparkCache {
		if t, err := time.Parse("2006-01-02-15", k); err == nil && now.Sub(t) > 25*time.Hour {
			delete(sparkCache, k)
		}
	}

	if b, err := json.Marshal(sparkCache); err == nil {
		_ = os.WriteFile(metricsFile, b, 0600) // #nosec
	}

	waf.Sparkline24h = spark

	var cExploit, cBrute, cRecon, cDdos, cAbuse int
	for jail, count := range jailCounts {
		j := strings.ToLower(jail)
		if strings.Contains(j, "bruteforce") || strings.Contains(j, "ssh") || strings.Contains(j, "auth") || strings.Contains(j, "login") {
			cBrute += count
		} else if strings.Contains(j, "scan") || strings.Contains(j, "recon") {
			cRecon += count
		} else if strings.Contains(j, "flood") || strings.Contains(j, "dos") || strings.Contains(j, "ddos") {
			cDdos += count
		} else if strings.Contains(j, "spam") || strings.Contains(j, "abuse") || strings.Contains(j, "bot") || strings.Contains(j, "crawler") {
			cAbuse += count
		} else {
			cExploit += count
		}
	}
	waf.RiskRadar = []int{cExploit, cBrute, cRecon, cDdos, cAbuse}

	cachedWAF = waf
	lastWAFFetch = time.Now()
	return waf
}

func getWhitelistStats() Whitelist {
	var wl Whitelist
	wl.IPs = []string{}

	files := []string{"/etc/syswarden/lists/syswarden_whitelist.ipv4", "/etc/syswarden/lists/syswarden_whitelist.ipv6"}
	for _, file := range files {
		if content, err := os.ReadFile(file); err == nil { // #nosec
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				ip := strings.TrimSpace(line)
				if ip != "" && !strings.HasPrefix(ip, "#") {
					wl.IPs = append(wl.IPs, ip)
				}
			}
		}
	}
	wl.ActiveIPs = len(wl.IPs)
	return wl
}
