package firewall

import (
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"
)

// AutoWhitelistAdminAndInfra detects and safely whitelists the admin IP and critical infra IPs
func AutoWhitelistAdminAndInfra() error {
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before automatic whitelist mutation: %w", err)
	}
	if _, err := retireLegacyMetadataWhitelistEntry(); err != nil {
		return fmt.Errorf("retire legacy metadata whitelist entry: %w", err)
	}
	fmt.Println("[INFO] Scanning and auto-whitelisting critical infrastructure & Admin IP...")

	_ = os.MkdirAll("/etc/syswarden/lists", 0750)
	whitelistFile := "/etc/syswarden/lists/syswarden_whitelist.ipv4"

	// Read existing
	content, _ := os.ReadFile(whitelistFile) // #nosec
	existing := string(content)

	// 1. Admin IP Detection
	adminIP := ""
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		adminIP = strings.Split(sshConn, " ")[0]
	} else {
		sshClient := os.Getenv("SSH_CLIENT")
		if sshClient != "" {
			adminIP = strings.Split(sshClient, " ")[0]
		}
	}

	if adminIP == "" || adminIP == "127.0.0.1" {
		fmt.Println("[WARN] Could not safely determine Admin IP from environment.")
	}

	// 2. Infra IPs (DNS, gateway, and local interface addresses)
	var discoveredInfraIPs []string
	if config.GlobalConfig.WhitelistInfra {
		infraIPs, err := infraIPv4Candidates()
		if err != nil {
			return err
		}
		discoveredInfraIPs = infraIPs
	}

	// 3. User-Defined Config IPs
	whitelistFileV6 := "/etc/syswarden/lists/syswarden_whitelist.ipv6"
	contentV6, _ := os.ReadFile(whitelistFileV6) // #nosec
	existingV6 := string(contentV6)

	ipsToAdd, ipsToAddV6 := automaticWhitelistCandidates(
		adminIP,
		config.GlobalConfig.WhitelistInfra,
		discoveredInfraIPs,
		strings.Fields(config.GlobalConfig.WhitelistIPs),
	)
	canonicalAdminIP := ""
	if entry, err := parseCanonicalListEntry(adminIP, false); err == nil && entry.isIPv4 {
		canonicalAdminIP = entry.network
	}

	// Append to IPv4 file safely
	f, err := os.OpenFile(whitelistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	addedCount := 0
	for _, ip := range ipsToAdd {
		if !strings.Contains(existing, ip) {
			_, _ = f.WriteString(ip + "\n")
			existing += ip + "\n"
			addedCount++
			if ip == canonicalAdminIP {
				fmt.Printf(" -> Auto-whitelisting Admin SSH IP: %s\n", ip)
			} else {
				fmt.Printf(" -> Auto-whitelisting Infra IPv4: %s\n", ip)
			}
		}
	}

	// Append to IPv6 file safely
	f6, err6 := os.OpenFile(whitelistFileV6, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec
	if err6 != nil {
		return err6
	}
	defer func() { _ = f6.Close() }()

	for _, ip := range ipsToAddV6 {
		if !strings.Contains(existingV6, ip) {
			_, _ = f6.WriteString(ip + "\n")
			existingV6 += ip + "\n"
			addedCount++
			fmt.Printf(" -> Auto-whitelisting Infra IPv6: %s\n", ip)
		}
	}

	if addedCount > 0 {
		fmt.Printf("[+] Safely added %d IPs to the absolute whitelist.\n", addedCount)
	}

	return nil
}

func automaticWhitelistCandidates(adminIP string, includeInfra bool, infraIPs, configuredIPs []string) ([]string, []string) {
	candidates := make([]string, 0, 1+len(infraIPs)+len(configuredIPs))
	if adminIP != "" && adminIP != "127.0.0.1" {
		candidates = append(candidates, adminIP)
	}
	if includeInfra {
		candidates = append(candidates, infraIPs...)
	}
	candidates = append(candidates, configuredIPs...)
	return canonicalWhitelistCandidates(candidates...)
}
