package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
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

	if adminIP != "" && isValidIPv4(adminIP) && adminIP != "127.0.0.1" {
		if !strings.Contains(existing, adminIP) {
			ipsToAdd = append(ipsToAdd, adminIP)
			fmt.Printf(" -> Auto-whitelisting Admin SSH IP: %s\n", adminIP)
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
			if isValidIPv4(ip) {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}

		// Default Gateway
		out, _ = exec.Command("sh", "-c", "ip -4 route show default 2>/dev/null | grep -Eo 'via [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}'").Output()
		for _, ip := range strings.Fields(string(out)) {
			if isValidIPv4(ip) {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}

		// Local IPs
		out, _ = exec.Command("sh", "-c", "ip -4 addr show | grep -oEo 'inet [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | awk '{print $2}' | grep -v '^127\\.'").Output()
		for _, ip := range strings.Fields(string(out)) {
			if isValidIPv4(ip) {
				ipsToAdd = append(ipsToAdd, ip)
			}
		}
	}

	// Append to file safely
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
				fmt.Printf(" -> Auto-whitelisting Infra IP: %s\n", ip)
			}
		}
	}

	if addedCount > 0 {
		fmt.Printf("[+] Safely added %d IPs to the absolute whitelist.\n", addedCount)
	}

	return nil
}

func isValidIPv4(ip string) bool {
	matched, _ := regexp.MatchString(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`, ip)
	return matched
}
