package system

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

var StandardMirrors = map[string]string{
	"GitHub":   "https://raw.githubusercontent.com/",
	"Codeberg": "https://codeberg.org/",
}

// SelectFastestMirror benchmarks mirrors and selects the fastest one
func SelectFastestMirror() (string, error) {
	fmt.Println("[INFO] Benchmarking mirrors...")

	fastestTime := time.Hour
	fastestURL := StandardMirrors["Codeberg"] // Default fallback

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for name, url := range StandardMirrors {
		fmt.Printf("Connecting to %s... ", name)

		start := time.Now()
		req, _ := http.NewRequestWithContext(context.Background(), "HEAD", url, nil)
		resp, err := client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			duration := time.Since(start)
			fmt.Printf("%d ms\n", duration.Milliseconds())
			if duration < fastestTime {
				fastestTime = duration
				fastestURL = url
			}
		} else {
			fmt.Println("FAIL")
		}
	}

	fmt.Printf("[INFO] Selected Mirror: %s\n", fastestURL)
	return fastestURL, nil
}

// MirrorResult holds the benchmark result for a mirror
type MirrorResult struct {
	URL      string
	Duration time.Duration
}

// SelectFastestThreatIntelMirror benchmarks Threat Intel mirrors and returns an ordered list (fastest first)
func SelectFastestThreatIntelMirror(listChoice string) []string {
	var mirrors []string
	if listChoice == "2" {
		mirrors = []string{
			"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
			"https://gitlab.com/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt?ref_type=heads",
			"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
			"https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt",
			"https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt",
		}
	} else {
		mirrors = []string{
			"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
			"https://gitlab.com/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt?ref_type=heads",
			"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
			"https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt",
			"https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt",
		}
	}

	fmt.Println("[INFO] Benchmarking Threat Intel mirrors for optimal latency...")

	var results []MirrorResult
	client := &http.Client{Timeout: 5 * time.Second}

	for _, urlStr := range mirrors {
		start := time.Now()
		req, _ := http.NewRequestWithContext(context.Background(), "HEAD", urlStr, nil)
		resp, err := client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			duration := time.Since(start)
			results = append(results, MirrorResult{URL: urlStr, Duration: duration})
		}
	}

	// Sort by fastest
	sort.Slice(results, func(i, j int) bool {
		return results[i].Duration < results[j].Duration
	})

	var ordered []string
	for i, r := range results {
		host := r.URL
		u, err := url.Parse(r.URL)
		if err == nil {
			host = u.Host
		}
		fmt.Printf("  #%d: %s (%d ms)\n", i+1, host, r.Duration.Milliseconds())
		ordered = append(ordered, r.URL)
	}

	// If all failed, return original order for aggressive sequential fallback
	if len(ordered) == 0 {
		fmt.Println("[WARN] All mirrors failed HEAD latency check. Retaining default sequential failover.")
		return mirrors
	}

	return ordered
}

// SelectFastestThreatIntelMirrorV6 benchmarks Threat Intel IPv6 mirrors and returns an ordered list (fastest first)
func SelectFastestThreatIntelMirrorV6(listChoice string) []string {
	var mirrors []string
	if listChoice == "2" {
		mirrors = []string{
			"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv6_Blocklist/refs/heads/main/prod_critical_data-shield_ipv6_blocklist.txt",
			"https://gitlab.com/duggytuxy/Data-Shield-IPv6-Blocklist/-/raw/main/prod_critical_data-shield_ipv6_blocklist.txt?ref_type=heads",
			"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv6_Blocklist@refs/heads/main/prod_critical_data-shield_ipv6_blocklist.txt",
			"https://bitbucket.org/duggytuxy/data-shield-ipv6-blocklist/raw/HEAD/prod_critical_data-shield_ipv6_blocklist.txt",
			"https://codeberg.org/duggytuxy21/Data-Shield_IPv6_Blocklist/raw/branch/main/prod_critical_data-shield_ipv6_blocklist.txt",
		}
	} else {
		mirrors = []string{
			"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv6_Blocklist/refs/heads/main/prod_data-shield_ipv6_blocklist.txt",
			"https://gitlab.com/duggytuxy/Data-Shield-IPv6-Blocklist/-/raw/main/prod_data-shield_ipv6_blocklist.txt?ref_type=heads",
			"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv6_Blocklist@refs/heads/main/prod_data-shield_ipv6_blocklist.txt",
			"https://bitbucket.org/duggytuxy/data-shield-ipv6-blocklist/raw/HEAD/prod_data-shield_ipv6_blocklist.txt",
			"https://codeberg.org/duggytuxy21/Data-Shield_IPv6_Blocklist/raw/branch/main/prod_data-shield_ipv6_blocklist.txt",
		}
	}

	fmt.Println("[INFO] Benchmarking Threat Intel IPv6 mirrors for optimal latency...")

	var results []MirrorResult
	client := &http.Client{Timeout: 5 * time.Second}

	for _, urlStr := range mirrors {
		start := time.Now()
		req, _ := http.NewRequestWithContext(context.Background(), "HEAD", urlStr, nil)
		resp, err := client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			duration := time.Since(start)
			results = append(results, MirrorResult{URL: urlStr, Duration: duration})
		}
	}

	// Sort by fastest
	sort.Slice(results, func(i, j int) bool {
		return results[i].Duration < results[j].Duration
	})

	var ordered []string
	for i, r := range results {
		host := r.URL
		u, err := url.Parse(r.URL)
		if err == nil {
			host = u.Host
		}
		fmt.Printf("  #%d: %s (%d ms)\n", i+1, host, r.Duration.Milliseconds())
		ordered = append(ordered, r.URL)
	}

	// If all failed, return original order for aggressive sequential fallback
	if len(ordered) == 0 {
		fmt.Println("[WARN] All IPv6 mirrors failed HEAD latency check. Retaining default sequential failover.")
		return mirrors
	}

	return ordered
}
