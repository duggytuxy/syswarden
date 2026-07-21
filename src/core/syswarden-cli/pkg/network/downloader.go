package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syswarden-cli/pkg/system"
	"time"
)

// SecureDownloader downloads files with strict timeouts and resource limits
func SecureDownloader(ctx context.Context, url string, destPath string) error {
	var resp *http.Response
	var err error
	client := &http.Client{Timeout: 30 * time.Second}

	for retries := 0; retries < 3; retries++ {
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(2 * time.Second) // Wait before retry
	}

	if err != nil {
		return fmt.Errorf("download failed for %s after 3 retries: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code %d for %s after 3 retries", resp.StatusCode, url)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600) // #nosec
	if err != nil {
		return fmt.Errorf("failed to open destination file %s: %w", destPath, err)
	}
	defer func() { _ = out.Close() }()

	// Use io.Copy to stream data safely
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}

	return CleanCIDRList(destPath)
}

// CleanCIDRList ensures CWE-20 compliance by stripping any malformed IPs
func CleanCIDRList(filepath string) error {
	content, err := os.ReadFile(filepath) // #nosec
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var validCIDRs []string
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Validate CIDR format
		if !strings.Contains(line, "/") {
			line = line + "/32"
		}

		ip, _, err := net.ParseCIDR(line)
		if err == nil {
			// Strictly enforce IPv4 to prevent Nftables chunk crash
			if ip.To4() != nil {
				if !seen[line] {
					seen[line] = true
					validCIDRs = append(validCIDRs, line)
				}
			}
		}
	}

	return os.WriteFile(filepath, []byte(strings.Join(validCIDRs, "\n")+"\n"), 0600)
}

// CleanCIDRListV6 ensures CWE-20 compliance for IPv6 lists
func CleanCIDRListV6(filepath string) error {
	content, err := os.ReadFile(filepath) // #nosec
	if err != nil {
		return err // file might not exist if no IPv6 routes were found, that's okay
	}

	lines := strings.Split(string(content), "\n")
	var validCIDRs []string
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "/") {
			line = line + "/128"
		}

		ip, _, err := net.ParseCIDR(line)
		if err == nil {
			if ip.To4() == nil && ip.To16() != nil {
				if !seen[line] {
					seen[line] = true
					validCIDRs = append(validCIDRs, line)
				}
			}
		}
	}

	return os.WriteFile(filepath, []byte(strings.Join(validCIDRs, "\n")+"\n"), 0600)
}

// DownloadFeeds manages the download of GeoIP, ASN, and OSINT feeds
func DownloadFeeds(mirrorURL, customURLIPv6, listChoice, geoCodes, asnList, geoAllowed, asnAllowed string, lanMode, useSpamhaus bool) error {
	fmt.Println("[INFO] Initializing Network Intelligence Feeds...")

	if lanMode {
		fmt.Println("[INFO] LAN Mode is ENABLED. Skipping public Data-Shield, GeoIP, ASN, and OSINT feeds to conserve local resources.")
		return nil
	}

	// Increased global context timeout to 15 minutes to allow full mirror failover rotation
	// without hitting "context deadline exceeded" prematurely.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	if geoCodes != "" {
		codes := strings.Split(geoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			// Download IPv4
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP [%s] (IPv4)... ", code)
			if err := SecureDownloader(ctx, url, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}

			// Download IPv6
			urlV6 := fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/countries/%s.zone", strings.ToLower(code))
			destV6 := fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP [%s] (IPv6)... ", code)
			if err := SecureDownloader(ctx, urlV6, destV6); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}

	// Build the deduplicated list of ASNs to drop
	asnSet := make(map[string]bool)
	var asnsToDrop []string

	if asnList != "" {
		asns := strings.Split(asnList, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn == "" || asn == "none" || asn == "auto" {
				continue
			}
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			asn = strings.ToUpper(asn)
			if !asnSet[asn] {
				asnSet[asn] = true
				asnsToDrop = append(asnsToDrop, asn)
			}
		}
	}

	if useSpamhaus {
		fmt.Printf("Fetching Spamhaus ASN-DROP list... ")
		spamhausASNs, err := FetchSpamhausASNs(ctx)
		if err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Printf("OK (%d ASNs found)\n", len(spamhausASNs))
			for _, asn := range spamhausASNs {
				asn = strings.ToUpper(asn)
				if !asnSet[asn] {
					asnSet[asn] = true
					asnsToDrop = append(asnsToDrop, asn)
				}
			}
		}
	}

	for i, asn := range asnsToDrop {
		dest := fmt.Sprintf("/etc/syswarden/lists/%s", asn)
		fmt.Printf("Downloading ASN [%s]... ", asn)
		if err := FetchASNWhois(asn, dest); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
		// Rate limit RADB queries to prevent blacklisting
		if i < len(asnsToDrop)-1 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Download GeoIP ALLOW lists (Zero-Trust Mode)
	if geoAllowed != "" {
		codes := strings.Split(geoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			// Download IPv4
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv4)... ", code)
			if err := SecureDownloader(ctx, url, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}

			// Download IPv6
			urlV6 := fmt.Sprintf("https://www.ipdeny.com/ipv6/ipaddresses/blocks/countries/%s.zone", strings.ToLower(code))
			destV6 := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv6", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP ALLOW [%s] (IPv6)... ", code)
			if err := SecureDownloader(ctx, urlV6, destV6); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}

	// Download ASN ALLOW lists (Zero-Trust Mode)
	if asnAllowed != "" {
		asns := strings.Split(asnAllowed, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn == "" || asn == "none" || asn == "auto" {
				continue
			}
			if !strings.HasPrefix(asn, "AS") {
				asn = "AS" + asn
			}
			dest := fmt.Sprintf("/etc/syswarden/lists/allowed_%s", strings.ToUpper(asn))
			fmt.Printf("Downloading ASN ALLOW [%s]... ", asn)
			if err := FetchASNWhois(asn, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
			time.Sleep(500 * time.Millisecond) // Parity: Prevent RADB rate limiting
		}
	}

	// Download IPv6 Custom Blocklist if configured
	if listChoice == "3" && customURLIPv6 != "" {
		fmt.Printf("Downloading Custom IPv6 Blocklist... ")
		if err := SecureDownloader(ctx, customURLIPv6, "/etc/syswarden/lists/syswarden_threatintel.ipv6"); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	}

	// Download Threat Intel Blocklist
	switch listChoice {
	case "4":
		fmt.Println("Downloading Threat Intel IPv4 Blocklist... SKIPPED (Option 4 'none')")
		// Clean up existing threat intel files to ensure Zero-Trust or 'none' posture is strictly enforced
		_ = os.Remove("/etc/syswarden/lists/syswarden_threatintel.ipv4")
		_ = os.Remove("/etc/syswarden/lists/syswarden_threatintel.ipv6")
	case "3":
		fmt.Printf("Downloading Custom Threat Intel IPv4 Blocklist... ")
		dataShieldUrl := strings.TrimRight(mirrorURL, "/")
		if err := SecureDownloader(ctx, dataShieldUrl, "/etc/syswarden/lists/syswarden_threatintel.ipv4"); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	default:
		fmt.Printf("Downloading Threat Intel IPv4 Blocklist... ")
		var success bool
		mirrors := system.SelectFastestThreatIntelMirror(listChoice)

		var lastErr error
		for _, url := range mirrors {
			if err := SecureDownloader(ctx, url, "/etc/syswarden/lists/syswarden_threatintel.ipv4"); err == nil {
				fmt.Println("OK")
				success = true
				break
			} else {
				lastErr = err
			}
		}
		if !success {
			fmt.Printf("FAILED (%v)\n", lastErr)
		}

		fmt.Printf("Downloading Threat Intel IPv6 Blocklist... ")
		success = false
		mirrorsV6 := system.SelectFastestThreatIntelMirrorV6(listChoice)

		for _, url := range mirrorsV6 {
			if err := SecureDownloader(ctx, url, "/etc/syswarden/lists/syswarden_threatintel.ipv6"); err == nil {
				fmt.Println("OK")
				success = true
				break
			} else {
				lastErr = err
			}
		}
		if !success {
			fmt.Printf("FAILED (%v)\n", lastErr)
		}
	}

	// Download OSINT Feeds (CINS Army & Blocklist.de)
	switch listChoice {
	case "4", "3":
		fmt.Println("Downloading Free OSINT Feeds (CINS & Blocklist.de)... SKIPPED")
	default:
		fmt.Printf("Downloading Free OSINT Feeds (CINS & Blocklist.de)... ")
		if err := DownloadOSINT(ctx, "/etc/syswarden/lists/syswarden_threatintel"); err != nil {
			fmt.Printf("FAILED (%v)\n", err)
		} else {
			fmt.Println("OK")
		}
	}

	return nil
}

// DownloadOSINT downloads free OSINT threat feeds and appends them to the destination files
func DownloadOSINT(ctx context.Context, destBase string) error {
	urls := []string{
		"https://cinsscore.com/list/ci-badguys.txt",
		"https://lists.blocklist.de/lists/all.txt",
	}

	f4, err := os.OpenFile(destBase+".ipv4", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err != nil {
		return err
	}
	defer func() { _ = f4.Close() }()

	f6, err := os.OpenFile(destBase+".ipv6", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err != nil {
		return err
	}
	defer func() { _ = f6.Close() }()

	for _, url := range urls {
		client := &http.Client{Timeout: 30 * time.Second}
		var resp *http.Response
		for retries := 0; retries < 3; retries++ {
			req, reqErr := http.NewRequestWithContext(ctx, "GET", url, nil)
			if reqErr != nil {
				continue
			}
			resp, err = client.Do(req)
			if err == nil && resp.StatusCode == http.StatusOK {
				break
			}
			if resp != nil {
				_ = resp.Body.Close()
			}
			time.Sleep(2 * time.Second)
		}
		if resp != nil && resp.StatusCode == http.StatusOK {
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, ":") {
					_, _ = f6.WriteString(line + "\n")
				} else {
					_, _ = f4.WriteString(line + "\n")
				}
			}
			_ = resp.Body.Close()
		}
	}

	_ = f4.Close() // Close before cleaning
	_ = f6.Close() // Close before cleaning

	_ = CleanCIDRListV6(destBase + ".ipv6")
	return CleanCIDRList(destBase + ".ipv4")
}

// SetupFeedsCron configures a root cron job to update feeds hourly at a random minute
func SetupFeedsCron() error {
	fmt.Println("[INFO] Setting up automatic hourly updates for Threat Intelligence...")

	// Generate a random minute (1-59) to prevent "Thundering Herd" API collisions
	randomMinute := rand.Intn(59) + 1 // #nosec

	cronJob := fmt.Sprintf("%d * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1", randomMinute)

	// Add to crontab natively
	out, _ := exec.Command("crontab", "-l").Output() // #nosec
	lines := strings.Split(string(out), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli update-feeds") {
			newLines = append(newLines, line)
		}
	}
	newLines = append(newLines, cronJob)

	newCron := strings.Join(newLines, "\n") + "\n"
	cmd := exec.Command("crontab", "-") // #nosec
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to inject feeds cron job: %w", err)
	}
	fmt.Printf("[+] Background Threat Feeds updater injected successfully (Hourly at minute %d).\n", randomMinute)

	return nil
}

// FetchASNWhois retrieves IPv4 and IPv6 prefixes for an ASN natively via TCP WHOIS
func FetchASNWhois(asn, destBase string) error {
	conn, err := net.DialTimeout("tcp", "whois.radb.net:43", 5*time.Second)
	if err != nil {
		return fmt.Errorf("whois connection failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	query := fmt.Sprintf("-i origin %s\r\n", asn)
	if _, err := conn.Write([]byte(query)); err != nil {
		return fmt.Errorf("whois query failed: %w", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("whois read failed: %w", err)
	}

	// Extract IPv4 and IPv6 routes
	reV4 := regexp.MustCompile(`(?m)^route:\s+([0-9]{1,3}\.([0-9]{1,3}\.){2}[0-9]{1,3}/[0-9]{1,2})`)
	reV6 := regexp.MustCompile(`(?m)^route6:\s+([0-9a-fA-F:]+/[0-9]{1,3})`)

	matchesV4 := reV4.FindAllStringSubmatch(string(data), -1)
	matchesV6 := reV6.FindAllStringSubmatch(string(data), -1)

	if err := os.MkdirAll(filepath.Dir(destBase), 0750); err != nil {
		return err
	}

	var cidrsV4 []string
	for _, m := range matchesV4 {
		if len(m) > 1 {
			cidrsV4 = append(cidrsV4, m[1])
		}
	}

	var cidrsV6 []string
	for _, m := range matchesV6 {
		if len(m) > 1 {
			cidrsV6 = append(cidrsV6, m[1])
		}
	}

	outV4 := strings.Join(cidrsV4, "\n") + "\n"
	if err := os.WriteFile(destBase+".ipv4", []byte(outV4), 0600); err != nil {
		return err
	}

	if len(cidrsV6) > 0 {
		outV6 := strings.Join(cidrsV6, "\n") + "\n"
		if err := os.WriteFile(destBase+".ipv6", []byte(outV6), 0600); err != nil {
			return err
		}
	}

	_ = CleanCIDRList(destBase + ".ipv4")
	_ = CleanCIDRListV6(destBase + ".ipv6")

	return nil
}

// FetchSpamhausASNs retrieves the latest ASNs from the Spamhaus DROP JSON list
func FetchSpamhausASNs(ctx context.Context) ([]string, error) {
	url := "https://www.spamhaus.org/drop/asndrop.json"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	var resp *http.Response
	for retries := 0; retries < 3; retries++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	var asns []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		var record struct {
			ASN int `json:"asn"`
		}
		if err := json.Unmarshal([]byte(line), &record); err == nil && record.ASN > 0 {
			asns = append(asns, fmt.Sprintf("AS%d", record.ASN))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	return asns, nil
}
