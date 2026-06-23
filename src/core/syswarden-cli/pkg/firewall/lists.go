package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/pkg/system"
)

const (
	WhitelistV4 = "/etc/syswarden/lists/syswarden_whitelist.ipv4"
	WhitelistV6 = "/etc/syswarden/lists/syswarden_whitelist.ipv6"
	BlocklistV4 = "/etc/syswarden/lists/syswarden_blacklist.ipv4"
	SSHBypass   = "/etc/syswarden/ssh_whitelist.txt"
)

// ensureDir ensures the lists directory exists
func ensureDir() {
 _ = os.MkdirAll("/etc/syswarden/lists", 0750)
}

// IsValidIP checks if a string is a valid IPv4 or IPv6 or a valid CIDR subnet
func IsValidIP(ip string) (bool, bool) {
	// 1. Check if it's a standard single IP
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		return true, parsedIP.To4() != nil
	}
	
	// 2. Check if it's a CIDR block (ex: 10.0.0.0/24)
	parsedIP, _, err := net.ParseCIDR(ip)
	if err == nil && parsedIP != nil {
		return true, parsedIP.To4() != nil
	}

	return false, false
}

// addToFile safely appends a line to a file if it doesn't already exist
func addToFile(filepath, line string) error {
	ensureDir()
	content, _ := os.ReadFile(filepath)
	lines := strings.Split(string(content), "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == line {
			return nil // Already exists
		}
	}
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(line + "\n")
	return err
}

// removeFromFile removes a line from a file
func removeFromFile(filepath, line string) error {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil // File doesn't exist, nothing to remove
	}
	lines := strings.Split(string(content), "\n")
	var newLines []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" && strings.TrimSpace(l) != line {
			newLines = append(newLines, l)
		}
	}
	return os.WriteFile(filepath, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
}

// AddToWhitelist appends an IP securely to the whitelist and reloads
func AddToWhitelist(ip string, port string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	entry := ip
	if port != "" {
		entry = fmt.Sprintf("%s:%s", ip, port)
	}

	// Remove from blocklist just in case
	_ = removeFromFile(BlocklistV4, ip)

	file := WhitelistV6
	if isIPv4 {
		file = WhitelistV4
	}

	if err := addToFile(file, entry); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely whitelisted.\n", entry)
	return ApplyNftables()
}

// RemoveFromWhitelist removes an IP from the whitelist
func RemoveFromWhitelist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	file := WhitelistV6
	if isIPv4 {
		file = WhitelistV4
	}
	// Note: We might need to iterate and remove even if it has a port. 
	// For simplicity, we'll try to remove exact IP, but we should handle IP:PORT stripping.
	content, err := os.ReadFile(file)
	if err == nil {
		lines := strings.Split(string(content), "\n")
		var newLines []string
		found := false
		for _, l := range lines {
			cleanLine := strings.TrimSpace(l)
			ipPart := strings.Split(cleanLine, ":")[0]
			if ipPart == ip {
				found = true
				continue
			}
			if cleanLine != "" {
				newLines = append(newLines, cleanLine)
			}
		}
		if found {
			_ = os.WriteFile(file, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
			fmt.Printf("[SUCCESS] IP %s removed from whitelist.\n", ip)
			return ApplyNftables()
		}
	}
	fmt.Printf("[INFO] IP %s not found in whitelist.\n", ip)
	return nil
}

// AddToBlocklist appends an IP securely to the blocklist and reloads
func AddToBlocklist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid || !isIPv4 {
		return fmt.Errorf("invalid IPv4 address: %s (Blocklist only supports IPv4)", ip)
	}

	if err := addToFile(BlocklistV4, ip); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s safely blocklisted.\n", ip)
	return ApplyNftables()
}

// RemoveFromBlocklist removes an IP from the blocklist
func RemoveFromBlocklist(ip string) error {
	valid, isIPv4 := IsValidIP(ip)
	if !valid || !isIPv4 {
		return fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	if err := removeFromFile(BlocklistV4, ip); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] IP %s removed from blocklist.\n", ip)
	return ApplyNftables()
}

// AllowSSH adds an IP to the SSH bypass list
func AllowSSH(ip string, port string) error {
	valid, _ := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	entry := ip
	if port != "" {
		entry = fmt.Sprintf("%s:%s", ip, port)
	}
	if err := addToFile(SSHBypass, entry); err != nil {
		return err
	}
	fmt.Printf("[SUCCESS] SSH Bypass granted for %s.\n", entry)
	return ApplyNftables()
}

// RevokeSSH removes an IP from the SSH bypass list
func RevokeSSH(ip string) error {
	valid, _ := IsValidIP(ip)
	if !valid {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	content, err := os.ReadFile(SSHBypass)
	if err == nil {
		lines := strings.Split(string(content), "\n")
		var newLines []string
		found := false
		for _, l := range lines {
			cleanLine := strings.TrimSpace(l)
			ipPart := strings.Split(cleanLine, ":")[0]
			if ipPart == ip {
				found = true
				continue
			}
			if cleanLine != "" {
				newLines = append(newLines, cleanLine)
			}
		}
		if found {
			_ = os.WriteFile(SSHBypass, []byte(strings.Join(newLines, "\n")+"\n"), 0644)
			fmt.Printf("[SUCCESS] SSH Bypass revoked for %s.\n", ip)
			return ApplyNftables()
		}
	}
	fmt.Printf("[INFO] IP %s not found in SSH bypass list.\n", ip)
	return nil
}

func WhitelistInfra() error {
	fmt.Println("[INFO] SysWarden Auto-Whitelist Infrastructure")
	ips := []string{}

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
			out, err := exec.Command("sh", "-c", "ss -tnp 2>/dev/null | grep -E 'sshd|ssh' | grep 'ESTAB' | awk '{print $5}' | cut -d: -f1 | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | head -n 1").Output()
			if err == nil {
				adminIP = strings.TrimSpace(string(out))
			}
		}
	}
	if adminIP != "" && adminIP != "127.0.0.1" {
		ips = append(ips, adminIP)
		fmt.Printf("[+] Auto-detected Admin SSH IP: %s\n", adminIP)
	}

	ips = append(ips, "169.254.169.254")

	// Read DNS
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		lines := strings.Split(string(b), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "nameserver ") {
				parts := strings.Fields(l)
				if len(parts) >= 2 {
					ips = append(ips, parts[1])
				}
			}
		}
	}

	// Read Gateway
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, v := range fields {
			if v == "via" && i+1 < len(fields) {
				ips = append(ips, fields[i+1])
			}
		}
	}

	added := false
	for _, ip := range ips {
		valid, isIPv4 := IsValidIP(ip)
		if valid && isIPv4 {
			content, _ := os.ReadFile(WhitelistV4)
			if !strings.Contains(string(content), ip+"\n") {
				_ = addToFile(WhitelistV4, ip)
				fmt.Printf("[+] Auto-whitelisted: %s\n", ip)
				added = true
			}
		}
	}

	if added {
		return ApplyNftables()
	}
	fmt.Println("[SUCCESS] All critical IPs are already whitelisted.")
	return nil
}

// CheckIP performs a global diagnostic on an IP
func CheckIP(ip string) {
	valid, _ := IsValidIP(ip)
	if !valid {
		fmt.Printf("[ERROR] Invalid IP address: %s\n", ip)
		return
	}

	fmt.Printf("\n=== SysWarden Global Search: %s ===\n", ip)

	checkFile := func(filepath, name string) {
		fmt.Printf("[Storage] %-20s : ", name)
		content, err := os.ReadFile(filepath)
		if err == nil && strings.Contains(string(content), ip) {
			fmt.Println("PRESENT")
		} else {
			fmt.Println("Not Found")
		}
	}

	checkFile(WhitelistV4, "Global Whitelist (v4)")
	checkFile(WhitelistV6, "Global Whitelist (v6)")
	checkFile(SSHBypass, "SSH Bypass")
	checkFile(BlocklistV4, "Global Blocklist")

	fmt.Printf("[Kernel]  Active Nftables      : ")
	out, err := exec.Command("nft", "list", "ruleset").Output()
	if err == nil && strings.Contains(string(out), ip) {
		fmt.Println("FOUND in active memory")
	} else {
		fmt.Println("Not found in active memory")
	}
	fmt.Println()
}

// ListIPs prints out all custom IP lists
func ListIPs() {
	fmt.Printf("\n=== SysWarden Custom IP Registry (%s) ===\n", system.Version)
	
	printFile := func(filepath, title string) {
		fmt.Printf("\n[ %s ]\n", title)
		content, err := os.ReadFile(filepath)
		if err != nil || len(strings.TrimSpace(string(content))) == 0 {
			fmt.Println("  None")
			return
		}
		lines := strings.Split(string(content), "\n")
		for _, l := range lines {
			if strings.TrimSpace(l) != "" {
				fmt.Printf("  -> %s\n", l)
			}
		}
	}

	printFile(WhitelistV4, "Global Whitelisted IPv4")
	printFile(WhitelistV6, "Global Whitelisted IPv6")
	printFile(SSHBypass, "SSH-Only Bypass")
	printFile(BlocklistV4, "Manually Blocked IPv4")
	fmt.Println()
}
