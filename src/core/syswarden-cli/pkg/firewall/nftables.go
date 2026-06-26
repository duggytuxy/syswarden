package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"time"
)

// ApplyNftables generates and atomically applies nftables rulesets securely (Zero-Shell execution)
func ApplyNftables() error {
	fmt.Println("[INFO] Applying Firewall Rules (nftables atomic transaction)...")

	// Create configuration dynamically (Secure string building)
	var nftRules strings.Builder

	// 1. Interface Detection (Like old bash: ip route get 8.8.8.8)
	activeIf := GetActiveInterface()

	// 2. Destroy tables atomically if they exist
	_, _ = nftRules.WriteString("destroy table inet syswarden\n")
	_, _ = nftRules.WriteString("destroy table inet syswarden_table\n") // Cleanup legacy table
	_, _ = nftRules.WriteString("destroy table netdev syswarden_hw_drop\n")
	_, _ = nftRules.WriteString("destroy table arp syswarden_arp\n\n")

	// 3. Hardware Drop Table (L2)
	_, _ = nftRules.WriteString("table netdev syswarden_hw_drop {\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist { type ipv4_addr; flags interval; auto-merge; }\n")



	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\tset syswarden_geoip { type ipv4_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
	}

	fmt.Fprintf(&nftRules, "\tchain ingress_frontline {\n\t\ttype filter hook ingress device \"%s\" priority -500; policy accept;\n", activeIf)


	// Allow Whitelist O(1) matching via set (Requested by User)
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")

	// Stateless Layer 4 Structural Anomaly Mitigation
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags ! fin,syn,rst,psh,ack,urg counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (fin|syn) == fin|syn counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (syn|rst) == syn|rst counter drop\n")

	// Layer 7 WAF Dynamic Bans (Prioritized over static L3 lists)
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips limit rate 2/second burst 5 packets log prefix \"[SysWarden-WAF-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips drop\n")

	// Layer 3 Static Global Intelligence Blocks
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist limit rate 2/second burst 5 packets log prefix \"[SysWarden-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist drop\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip limit rate 2/second burst 5 packets log prefix \"[SysWarden-GEO] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip drop\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn limit rate 2/second burst 5 packets log prefix \"[SysWarden-ASN] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn drop\n")
	}

	// ZERO-TRUST MODE: Drop everything that is not in the unified whitelist
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_whitelist limit rate 2/second burst 5 packets log prefix \"[SysWarden-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_whitelist drop\n")
	}
	_, _ = nftRules.WriteString("\t}\n}\n\n")

	// 3.5. INET Table (L3/L4) for Docker & Internal Routing Protection
	_, _ = nftRules.WriteString("table inet syswarden {\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist { type ipv4_addr; flags interval; auto-merge; }\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\tset syswarden_geoip { type ipv4_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
	}

	// Stateful L4 Protections (Host Input)
	_, _ = nftRules.WriteString("\tchain stateful_protect {\n\t\ttype filter hook input priority -10; policy drop;\n")
	_, _ = nftRules.WriteString("\t\tiifname \"lo\" accept\n")
	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	_, _ = nftRules.WriteString("\t\tct state invalid counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|ack) != syn ct state new counter drop\n")

	// Dynamically allow explicitly opened ports
	tcpPorts, udpPorts := GetOpenPorts()
	if len(tcpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } accept\n", strings.Join(tcpPorts, ", "))
	}
	if len(udpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new udp dport { %s } accept\n", strings.Join(udpPorts, ", "))
	}

	sshPort := config.GlobalConfig.SSHPort
	if sshPort == "" {
		// Dynamically query sshd for its effective configuration
		if out, err := exec.Command("sh", "-c", "sshd -T 2>/dev/null | grep -i '^port '").Output(); err == nil && len(out) > 0 {
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				sshPort = fields[1]
			}
		}
		// Absolute fail-safe
		if sshPort == "" {
			sshPort = "22"
		}
	}

	// SSH Cloaking (WireGuard VPN Only) vs Standard SSH
	if config.GlobalConfig.EnableWG {
		_, _ = nftRules.WriteString("\t\t# SSH Cloaking (Strict WG VPN Only)\n")
		// Always allow explicitly whitelisted IPs
		_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr @syswarden_whitelist tcp dport %s accept\n", sshPort)
		_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr @syswarden_whitelist6 tcp dport %s accept\n", sshPort)
		// Allow from the WireGuard Subnet
		_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr %s tcp dport %s accept\n", config.GlobalConfig.WGSubnet, sshPort)
		// Drop from anywhere else
		_, _ = fmt.Fprintf(&nftRules, "\t\ttcp dport %s counter drop\n", sshPort)
	} else {
		_, _ = nftRules.WriteString("\t\t# Standard SSH Access\n")
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport %s accept\n", sshPort)
	}

	// Catch-All Default Deny Logging
	_, _ = nftRules.WriteString("\t\tct state new log prefix \"[SysWarden-BLOCK] [Catch-All] \"\n")
	_, _ = nftRules.WriteString("\t\tct state new counter drop\n")
	_, _ = nftRules.WriteString("\t}\n\n")

	// Protect Docker (Forward chain)
	_, _ = nftRules.WriteString("\tchain docker_protect {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @syswarden_blacklist counter drop\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip counter drop\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn counter drop\n")
	}

	// ZERO-TRUST MODE: Drop everything that is not in the unified whitelist (Forward chain for Docker)
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_whitelist counter drop\n")
	}
	_, _ = nftRules.WriteString("\t}\n}\n\n")

	// 4. ARP Protection Table (L2)
	if config.GlobalConfig.ArpProtect {
		_, _ = nftRules.WriteString("table arp syswarden_arp {\n")
		_, _ = nftRules.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
		_, _ = nftRules.WriteString("\t\tarp operation request limit rate over 10/second counter log prefix \"[SysWarden-ARP-FLOOD] \" drop\n")
		_, _ = nftRules.WriteString("\t}\n}\n\n")
	}

	// 5. Write atomic base file securely (Empty Sets)
	nftFile := "/etc/syswarden/syswarden.nft"
	if err := os.MkdirAll("/etc/syswarden", 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	if err := os.WriteFile(nftFile, []byte(nftRules.String()), 0600); err != nil {
		return fmt.Errorf("failed to write atomic nft file: %w", err)
	}

	// 6. Execute Base Structure atomically (Fast & safe)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", nftFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply base nftables: %w\nOutput: %s", err, string(out))
	}

	// 7. Stream IP Sets dynamically (Anti-OOM / Netlink Buffer Space Fix)
	fmt.Println(" -> Streaming blocklists to kernel safely...")

	// Temporarily increase Netlink socket buffer to handle massive atomic loads (8MB)
	_ = exec.Command("sysctl", "-w", "net.core.wmem_max=8388608").Run()
	_ = exec.Command("sysctl", "-w", "net.core.rmem_max=8388608").Run()

	whitelistFiles := []string{"/etc/syswarden/lists/syswarden_whitelist.ipv4"}
	if config.GlobalConfig.GeoAllowed != "" {
		codes := strings.Split(config.GlobalConfig.GeoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				whitelistFiles = append(whitelistFiles, fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code)))
			}
		}
	}
	if config.GlobalConfig.ASNAllowed != "" {
		asns := strings.Split(config.GlobalConfig.ASNAllowed, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn != "" && asn != "none" && asn != "auto" {
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}
				whitelistFiles = append(whitelistFiles, fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToUpper(asn)))
			}
		}
	}
	populateSet(ctx, whitelistFiles, "syswarden_whitelist")
	populateSet(ctx, []string{"/etc/syswarden/lists/syswarden_whitelist.ipv6"}, "syswarden_whitelist6")
	populateSet(ctx, []string{"/etc/syswarden/lists/syswarden_blacklist.ipv4", "/etc/syswarden/lists/syswarden_threatintel.ipv4"}, "syswarden_blacklist")

	var geoFiles []string
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		codes := strings.Split(config.GlobalConfig.GeoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				geoFiles = append(geoFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code)))
			}
		}
	}
	if len(geoFiles) > 0 {
		populateSet(ctx, geoFiles, "syswarden_geoip")
	}

	var asnFiles []string
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		asns := strings.Split(config.GlobalConfig.ASNList, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn != "" && asn != "none" && asn != "auto" {
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}
				asnFiles = append(asnFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToUpper(asn)))
			}
		}
	}
	if len(asnFiles) > 0 {
		populateSet(ctx, asnFiles, "syswarden_asn")
	}

	fmt.Println("[INFO] Nftables applied successfully.")
	return nil
}

func GetActiveInterface() string {
	// Execute standard ip route get 8.8.8.8 just like the old version
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").Output()
	if err == nil {
		fields := strings.Fields(string(out))
		for i, v := range fields {
			if v == "dev" && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	return "eth0"
}

// GetOpenPorts securely detects all listening TCP and UDP ports to avoid locking out the user
func GetOpenPorts() ([]string, []string) {
	var tcpPorts []string
	var udpPorts []string

	out, err := exec.Command("ss", "-tuln").Output()
	if err != nil {
		// Fallback safe ports if ss fails
		return []string{"22", "80", "443"}, []string{"443"}
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "UNCONN") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				proto := parts[0]
				localAddr := parts[4]

				lastColon := strings.LastIndex(localAddr, ":")
				if lastColon != -1 {
					port := localAddr[lastColon+1:]
					switch proto {
					case "tcp", "tcp6":
						if !contains(tcpPorts, port) {
							tcpPorts = append(tcpPorts, port)
						}
					case "udp", "udp6":
						if !contains(udpPorts, port) {
							udpPorts = append(udpPorts, port)
						}
					}
				}
			}
		}
	}
	return tcpPorts, udpPorts
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func populateSet(ctx context.Context, filepaths []string, setName string) {
	var chunk []string
	for _, filepath := range filepaths {
		content, err := os.ReadFile(filepath)
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				chunk = append(chunk, line)
			}
		}
	}
	if len(chunk) > 0 {
		applyChunk(ctx, setName, chunk)
	}
}

func applyChunk(ctx context.Context, setName string, chunk []string) {
	var nftRules strings.Builder
	_, _ = fmt.Fprintf(&nftRules, "add element netdev syswarden_hw_drop %s { \n%s\n }\n", setName, strings.Join(chunk, ",\n"))
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(nftRules.String()))
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to load NETDEV chunk %s : %v\nOutput: %s\n", setName, err, string(out))
	}

	nftRules.Reset()

	ipStr := strings.Join(chunk, ", ")
	_, _ = fmt.Fprintf(&nftRules, "add element inet syswarden %s { %s }\n", setName, ipStr)

	cmd2 := exec.Command("nft", "-f", "-")
	cmd2.Stdin = bytes.NewReader([]byte(nftRules.String()))
	if out, err := cmd2.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to load INET chunk %s : %v\nOutput: %s\n", setName, err, string(out))
	}
}
