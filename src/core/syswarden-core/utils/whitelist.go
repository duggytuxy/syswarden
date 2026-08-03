package utils

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	whitelistCache     map[string]bool
	whitelistCIDRCache []*net.IPNet
	cacheMutex         sync.RWMutex
	lastLoad           time.Time
)

// IsWhitelisted checks if an IP belongs to the Infra Whitelist or Local Loop.
// The result is cached in memory to prevent disk I/O bottlenecks.
// Cache is automatically refreshed every 60 seconds if accessed.
func IsWhitelisted(ip string) bool {
	// Hardcoded Immunity for Local Loopback
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	// Strip port from incoming IP if present
	if net.ParseIP(ip) == nil {
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
	}

	cacheMutex.RLock()
	needsRefresh := time.Since(lastLoad) > 60*time.Second
	cacheMutex.RUnlock()

	if needsRefresh || whitelistCache == nil {
		refreshCache()
	}

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	if whitelistCache[ip] {
		return true
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for _, cidrnet := range whitelistCIDRCache {
			if cidrnet.Contains(parsedIP) {
				return true
			}
		}
	}

	return false
}

func refreshCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if time.Since(lastLoad) <= 60*time.Second && whitelistCache != nil {
		return // Another goroutine already refreshed it
	}

	newCache := make(map[string]bool)
	var newCIDRCache []*net.IPNet

	files := []string{
		"/etc/syswarden/lists/syswarden_whitelist.ipv4",
		"/etc/syswarden/lists/syswarden_whitelist.ipv6",
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv4",
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv6",
	}

	for _, file := range files {
		f, err := os.Open(file) // #nosec
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				ipPart := line
				if !strings.Contains(ipPart, "/") {
					if net.ParseIP(ipPart) == nil {
						if host, _, err := net.SplitHostPort(ipPart); err == nil {
							ipPart = host
						}
					}
				}

				if strings.Contains(ipPart, "/") {
					_, cidrnet, err := net.ParseCIDR(ipPart)
					if err == nil {
						newCIDRCache = append(newCIDRCache, cidrnet)
					}
				} else {
					newCache[ipPart] = true
				}
			}
		}
		_ = f.Close()
	}

	whitelistCache = newCache
	whitelistCIDRCache = newCIDRCache
	lastLoad = time.Now()
}
