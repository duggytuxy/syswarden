package network

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"syswarden-core/logger"
)

// SaasMonitorDownloader runs in the background and periodically downloads SaaS monitor IPs
type SaasMonitorDownloader struct {
	logger *logger.Logger
}

func NewSaasMonitorDownloader(l *logger.Logger) *SaasMonitorDownloader {
	return &SaasMonitorDownloader{logger: l}
}

func (s *SaasMonitorDownloader) Start() {
	if !s.isSaasAllowed() {
		s.logger.Info("SaaS Monitors Auto-Whitelist is disabled. Skipping downloader.")
		return
	}

	s.logger.Info("Starting SaaS Monitors Downloader (BetterStack) in background...")

	// Initial fetch
	s.fetchMonitors()

	// Periodic fetch every 1 hour
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			s.fetchMonitors()
		}
	}()
}

func (s *SaasMonitorDownloader) isSaasAllowed() bool {
	file, err := os.Open("/opt/syswarden/syswarden-auto.conf") // #nosec
	if err != nil {
		return true // Default to true for safety
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_ALLOW_SAAS_MONITORS=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				if strings.ToLower(val) == "n" {
					return false
				}
			}
		}
	}
	return true
}

func (s *SaasMonitorDownloader) fetchMonitors() {
	urls := []string{
		"https://uptime.betterstack.com/ips.txt",
		// Additional SaaS monitor IP lists can be added here
	}

	var allIps []string

	for _, u := range urls {
		ips, err := s.downloadList(u)
		if err != nil {
			s.logger.Error("Failed to fetch SaaS IPs from: "+u, err)
			continue
		}
		allIps = append(allIps, ips...)
	}

	if len(allIps) == 0 {
		return
	}

	var ipv4List, ipv6List []string
	for _, ip := range allIps {
		if strings.Contains(ip, ":") {
			ipv6List = append(ipv6List, ip)
		} else {
			ipv4List = append(ipv4List, ip)
		}
	}

	// Write IPv4
	targetFileV4 := "/etc/syswarden/lists/syswarden_saas_monitors.ipv4"
	err := os.WriteFile(targetFileV4, []byte(strings.Join(ipv4List, "\n")), 0600)
	if err != nil {
		s.logger.Error("Failed to write SaaS monitors IPv4 list", err)
	}

	// Write IPv6
	if len(ipv6List) > 0 {
		targetFileV6 := "/etc/syswarden/lists/syswarden_saas_monitors.ipv6"
		err = os.WriteFile(targetFileV6, []byte(strings.Join(ipv6List, "\n")), 0600)
		if err != nil {
			s.logger.Error("Failed to write SaaS monitors IPv6 list", err)
		}
	}
}

func (s *SaasMonitorDownloader) downloadList(url string) ([]string, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, nil
}
