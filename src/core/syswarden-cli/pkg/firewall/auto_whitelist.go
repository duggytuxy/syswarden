package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

// AutoWhitelistAdminAndInfra detects and safely whitelists the admin IP and critical infra IPs
func AutoWhitelistAdminAndInfra() error {
	fmt.Println("[INFO] Scanning and auto-whitelisting critical infrastructure & Admin IP...")

	_ = os.MkdirAll("/etc/syswarden/lists", 0755)
	whitelistFile := "/etc/syswarden/lists/syswarden_whitelist.ipv4"

	// Read existing
	content, _ := os.ReadFile(whitelistFile)
	existing := string(content)

	var ipsToAdd []string

	// 1. Admin IP Detection
	adminIP := ""
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		adminIP = strings.Split(sshConn, " ")[0]
	} else {
		sshClient := os.Getenv("SSH_CLIENT")
		if sshClient != "" {
			adminIP = strings.Split(sshClient, " ")[0]
		} else {
			// Fallback: active SSH session from ss
			out, err := exec.Command("sh", "-c", "ss -tnp 2>/dev/null | grep -E 'sshd|ssh' | grep 'ESTAB' | awk '{print $5}' | cut -d: -f1 | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | head -n 1").Output()
			if err == nil {
				adminIP = strings.TrimSpace(string(out))
			}
		}
	}

	if adminIP != "" && adminIP != "127.0.0.1" {
		if valid, isIPv4 := IsValidIP(adminIP); valid && isIPv4 {
			if !strings.Contains(existing, adminIP) {
				ipsToAdd = append(ipsToAdd, adminIP)
				fmt.Printf(" -> Auto-whitelisting Admin SSH IP: %s\n", adminIP)
			}
		}
	} else {
		fmt.Println("[WARN] Could not safely determine Admin IP from environment.")
	}

	// 2. Infra IPs (DNS, Gateway, Metadata)
	if config.GlobalConfig.WhitelistInfra {
		// Metadata
		ipsToAdd = append(ipsToAdd, "169.254.169.254")

		// DNS
		out, _ := exec.Command("sh", "-c", "grep '^nameserver' /etc/resolv.conf | awk '{print $2}'").Output()
		for _, ip := range strings.Fields(string(out)) {
			if valid, isIPv4 := IsValidIP(ip); valid && isIPv4 {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}

		// Default Gateway
		out, _ = exec.Command("sh", "-c", "ip -4 route show default 2>/dev/null | grep -Eo 'via [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}'").Output()
		for _, ip := range strings.Fields(string(out)) {
			if valid, isIPv4 := IsValidIP(ip); valid && isIPv4 {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}

		// Local IPs
		out, _ = exec.Command("sh", "-c", "ip -4 addr show | grep -oEo 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}' | grep -v '^127\\.'").Output()
		for _, ip := range strings.Fields(string(out)) {
			if valid, isIPv4 := IsValidIP(ip); valid && isIPv4 {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}
	}

	// 3. User-Defined Config IPs
	whitelistFileV6 := "/etc/syswarden/lists/syswarden_whitelist.ipv6"
	contentV6, _ := os.ReadFile(whitelistFileV6)
	existingV6 := string(contentV6)

	var ipsToAddV6 []string

	if config.GlobalConfig.WhitelistIPs != "" {
		customIPs := strings.Fields(config.GlobalConfig.WhitelistIPs)
		for _, ip := range customIPs {
			if valid, isIPv4 := IsValidIP(ip); valid {
				if isIPv4 {
					ipsToAdd = append(ipsToAdd, ip)
				} else {
					ipsToAddV6 = append(ipsToAddV6, ip)
				}
			}
		}
	}

	// Append to IPv4 file safely
	f, err := os.OpenFile(whitelistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
			if ip != adminIP {
				fmt.Printf(" -> Auto-whitelisting Infra IPv4: %s\n", ip)
			}
		}
	}

	// Append to IPv6 file safely
	f6, err6 := os.OpenFile(whitelistFileV6, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
