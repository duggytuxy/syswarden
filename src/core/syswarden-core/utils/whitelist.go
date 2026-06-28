package utils

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	whitelistCache map[string]bool
	cacheMutex     sync.RWMutex
	lastLoad       time.Time
)

// IsWhitelisted checks if an IP belongs to the Infra Whitelist or Local Loop.
// The result is cached in memory to prevent disk I/O bottlenecks.
// Cache is automatically refreshed every 60 seconds if accessed.
func IsWhitelisted(ip string) bool {
	// Hardcoded Immunity for Local Loopback
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	cacheMutex.RLock()
	needsRefresh := time.Since(lastLoad) > 60*time.Second
	cacheMutex.RUnlock()

	if needsRefresh || whitelistCache == nil {
		refreshCache()
	}

	cacheMutex.RLock()
	defer cacheMutex.RUnlock()
	return whitelistCache[ip]
}

func refreshCache() {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if time.Since(lastLoad) <= 60*time.Second && whitelistCache != nil {
		return // Another goroutine already refreshed it
	}

	newCache := make(map[string]bool)

	files := []string{
		"/etc/syswarden/lists/syswarden_whitelist.ipv4",
		"/etc/syswarden/lists/syswarden_whitelist.ipv6",
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				newCache[line] = true
			}
		}
		_ = f.Close()
	}

	whitelistCache = newCache
	lastLoad = time.Now()
}
