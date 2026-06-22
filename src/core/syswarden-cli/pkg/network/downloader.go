package network

import (
	"context"
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
			resp.Body.Close()
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

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
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
	content, err := os.ReadFile(filepath)
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

	return os.WriteFile(filepath, []byte(strings.Join(validCIDRs, "\n")+"\n"), 0640)
}

// DownloadFeeds manages the download of GeoIP, ASN, and OSINT feeds
func DownloadFeeds(mirrorURL, geoCodes, asnList string) error {
	fmt.Println("[INFO] Initializing Network Intelligence Feeds...")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if geoCodes != "" {
		codes := strings.Split(geoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code == "" || code == "none" {
				continue
			}
			url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", strings.ToLower(code))
			dest := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code))
			fmt.Printf("Downloading GeoIP [%s]... ", code)
			if err := SecureDownloader(ctx, url, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
		}
	}

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
			dest := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToUpper(asn))
			fmt.Printf("Downloading ASN [%s]... ", asn)
			if err := FetchASNWhois(asn, dest); err != nil {
				fmt.Printf("FAILED (%v)\n", err)
			} else {
				fmt.Println("OK")
			}
			time.Sleep(500 * time.Millisecond) // Parity: Prevent RADB rate limiting
		}
	}

	// Download Data-Shield
	dataShieldUrl := fmt.Sprintf("%s/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt", strings.TrimRight(mirrorURL, "/"))
	fmt.Printf("Downloading Data-Shield IPv4 Blocklist... ")
	if err := SecureDownloader(ctx, dataShieldUrl, "/etc/syswarden/lists/syswarden_threatintel.ipv4"); err != nil {
		fmt.Printf("FAILED (%v)\n", err)
	} else {
		fmt.Println("OK")
	}

	// Download OSINT Feeds (CINS Army & Blocklist.de)
	fmt.Printf("Downloading Free OSINT Feeds (CINS & Blocklist.de)... ")
	if err := DownloadOSINT(ctx, "/etc/syswarden/lists/syswarden_threatintel.ipv4"); err != nil {
		fmt.Printf("FAILED (%v)\n", err)
	} else {
		fmt.Println("OK")
	}

	return nil
}

// DownloadOSINT downloads free OSINT threat feeds and appends them to the destination file
func DownloadOSINT(ctx context.Context, destFile string) error {
	urls := []string{
		"https://cinsscore.com/list/ci-badguys.txt",
		"https://lists.blocklist.de/lists/all.txt",
	}

	f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}

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
				resp.Body.Close()
			}
			time.Sleep(2 * time.Second)
		}
		if resp != nil && resp.StatusCode == http.StatusOK {
			_, _ = io.Copy(f, resp.Body)
			_, _ = f.WriteString("\n")
			resp.Body.Close()
		}
	}
	_ = f.Close() // Close before cleaning

	// Clean and deduplicate the newly merged file
	return CleanCIDRList(destFile)
}

// SetupFeedsCron configures a root cron job to update feeds hourly at a random minute
func SetupFeedsCron() error {
	fmt.Println("[INFO] Setting up automatic hourly updates for Threat Intelligence...")

	// Generate a random minute (1-59) to prevent "Thundering Herd" API collisions
	randomMinute := rand.Intn(59) + 1
	
	cronJob := fmt.Sprintf("%d * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1", randomMinute)

	// Add to crontab securely
	out, _ := exec.Command("crontab", "-l").Output()
	currentCron := string(out)

	// Remove old if exists
	_ = exec.Command("sh", "-c", "crontab -l | grep -v 'syswarden-cli update-feeds' | crontab -").Run()

	if !strings.Contains(currentCron, "syswarden-cli update-feeds") {
		newCron := currentCron
		if newCron != "" && !strings.HasSuffix(newCron, "\n") {
			newCron += "\n"
		}
		newCron += cronJob + "\n"
		
		cmd := exec.Command("crontab", "-")
		cmd.Stdin = strings.NewReader(newCron)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to inject feeds cron job: %w", err)
		}
		fmt.Printf("[+] Background Threat Feeds updater injected successfully (Hourly at minute %d).\n", randomMinute)
	}

	return nil
}

// FetchASNWhois retrieves IPv4 prefixes for an ASN natively via TCP WHOIS
func FetchASNWhois(asn, destPath string) error {
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

	re := regexp.MustCompile(`(?m)^route:\s+([0-9]{1,3}\.([0-9]{1,3}\.){2}[0-9]{1,3}/[0-9]{1,2})`)
	matches := re.FindAllStringSubmatch(string(data), -1)

	if err := os.MkdirAll(filepath.Dir(destPath), 0750); err != nil {
		return err
	}

	var cidrs []string
	for _, m := range matches {
		if len(m) > 1 {
			cidrs = append(cidrs, m[1])
		}
	}

	out := strings.Join(cidrs, "\n") + "\n"
	if err := os.WriteFile(destPath, []byte(out), 0640); err != nil {
		return err
	}

	return CleanCIDRList(destPath)
}
