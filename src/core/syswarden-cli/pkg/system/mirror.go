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

var threatIntelMirrors = map[string][]string{
	"critical": {
		"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
		"https://gitlab.com/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt?ref_type=heads",
		"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt",
		"https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt",
		"https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt",
	},
	"standard": {
		"https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
		"https://gitlab.com/duggytuxy/Data-Shield-IPv4-Blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt?ref_type=heads",
		"https://cdn.jsdelivr.net/gh/duggytuxy/Data-Shield_IPv4_Blocklist@refs/heads/main/prod_data-shield_ipv4_blocklist.txt",
		"https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt",
		"https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt",
	},
}

func mirrorHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func approvedHTTPSMirror(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Opaque == "" && parsed.Fragment == ""
}

// ThreatIntelMirrors returns a copy of the independently hosted built-in mirror set.
func ThreatIntelMirrors(listChoice string) []string {
	key := "standard"
	if listChoice == "2" {
		key = "critical"
	}
	return append([]string(nil), threatIntelMirrors[key]...)
}

// SelectFastestMirror benchmarks mirrors and selects the fastest one
func SelectFastestMirror() (string, error) {
	fmt.Println("[INFO] Benchmarking mirrors...")

	fastestTime := time.Hour
	fastestURL := StandardMirrors["Codeberg"] // Default fallback

	client := mirrorHTTPClient()

	for name, rawURL := range StandardMirrors {
		fmt.Printf("Connecting to %s... ", name)
		if !approvedHTTPSMirror(rawURL) {
			fmt.Println("FAIL")
			continue
		}

		start := time.Now()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, rawURL, nil)
		if err != nil {
			fmt.Println("FAIL")
			continue
		}
		resp, err := client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			duration := time.Since(start)
			fmt.Printf("%d ms\n", duration.Milliseconds())
			if duration < fastestTime {
				fastestTime = duration
				fastestURL = rawURL
			}
		} else {
			if resp != nil {
				_ = resp.Body.Close()
			}
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
	mirrors := ThreatIntelMirrors(listChoice)

	fmt.Println("[INFO] Benchmarking Threat Intel mirrors for optimal latency...")

	var results []MirrorResult
	client := mirrorHTTPClient()

	for _, urlStr := range mirrors {
		if !approvedHTTPSMirror(urlStr) {
			continue
		}
		start := time.Now()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, urlStr, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)

		if err == nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			duration := time.Since(start)
			results = append(results, MirrorResult{URL: urlStr, Duration: duration})
		} else if resp != nil {
			_ = resp.Body.Close()
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
