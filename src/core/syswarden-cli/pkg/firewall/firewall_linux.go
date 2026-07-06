//go:build linux

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

// ApplyPolicies triggers the main Linux firewall injection using native Netlink / CLI Nftables
func ApplyPolicies() error {
	fmt.Println("[INFO] Applying Firewall Rules (nftables atomic transaction)...")

	// Create configuration dynamically (Secure string building)
	var nftRules strings.Builder

	// 1. Interface Detection (Like old bash: ip route get 8.8.8.8)
	activeIf := GetActiveInterface()

	// 2. Safely wipe existing tables (Universal backward compatibility)
	// We run these natively and ignore errors if they don't exist, avoiding the 'destroy' syntax error on old nftables.
	_ = exec.Command("nft", "delete", "table", "inet", "syswarden").Run()
	_ = exec.Command("nft", "delete", "table", "inet", "syswarden_table").Run()
	_ = exec.Command("nft", "delete", "table", "netdev", "syswarden_hw_drop").Run()
	_ = exec.Command("nft", "delete", "table", "arp", "syswarden_arp").Run()

	// 3. Hardware Drop Table (L2)
	_, _ = nftRules.WriteString("table netdev syswarden_hw_drop {\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips6 { type ipv6_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist6 { type ipv6_addr; flags interval; auto-merge; }\n")

	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\tset syswarden_geoip { type ipv4_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
		_, _ = nftRules.WriteString("\tset syswarden_asn6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}

	fmt.Fprintf(&nftRules, "\tchain ingress_frontline {\n\t\ttype filter hook ingress device \"%s\" priority -500; policy accept;\n", activeIf)

	// 1. Infra Whitelist (Absolute Priority - Bypasses everything)
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")

	// 2. Layer 7 WAF Dynamic Bans
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-WAF-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @banned_ips6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-WAF-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @banned_ips6 drop\n")

	// Stateless Layer 4 Structural Anomaly Mitigation
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags ! fin,syn,rst,psh,ack,urg counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (fin|syn) == fin|syn counter drop\n")
	_, _ = nftRules.WriteString("\t\tip protocol tcp tcp flags & (syn|rst) == syn|rst counter drop\n")

	// Layer 3 Static Global Intelligence Blocks
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_blacklist6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-BLOCK] \"\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_blacklist6 drop\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-GEO] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip drop\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ASN] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_asn6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ASN] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_asn6 drop\n")
	}

	// ZERO-TRUST MODE: Drop everything that is not in the Zero-Trust allowed GEO/ASN list
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 drop\n")
	}
	_, _ = nftRules.WriteString("\t}\n}\n\n")

	// 3.5. INET Table (L3/L4) for Docker & Internal Routing Protection
	_, _ = nftRules.WriteString("table inet syswarden {\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips6 { type ipv6_addr; flags timeout; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_blacklist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\tset syswarden_geoip { type ipv4_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
		_, _ = nftRules.WriteString("\tset syswarden_asn6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}

	// Stateful L4 Protections (Host Input)
	_, _ = nftRules.WriteString("\tchain stateful_protect {\n\t\ttype filter hook input priority -10; policy drop;\n")
	_, _ = nftRules.WriteString("\t\tiifname \"lo\" accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")
	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	_, _ = nftRules.WriteString("\t\tct state invalid counter drop\n")

	// L3/L4 Threat Intel (Fragments, XMAS, NULL Scans)
	_, _ = nftRules.WriteString("\t\tip frag-off & 0x3fff != 0 counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg counter drop\n")
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

	// Honeyports (Insider Threat Detection)
	if config.GlobalConfig.LANMode && config.GlobalConfig.HoneyPorts != "" {
		ports := strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } limit rate 5/second burst 10 packets log prefix \"[SYSWARDEN-HONEYPORT] \"\n", ports)
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } counter drop\n", ports)
	}

	// CATCH-ALL Default Deny Logging
	_, _ = nftRules.WriteString("\t\tct state new limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-BLOCK] [CATCH-ALL] \"\n")
	_, _ = nftRules.WriteString("\t\tct state new counter drop\n")
	_, _ = nftRules.WriteString("\t}\n\n")

	// DNS Exfiltration Protection (L3/L4)
	_, _ = nftRules.WriteString("\tchain data_leak_protect {\n\t\ttype filter hook output priority 0; policy accept;\n")
	_, _ = nftRules.WriteString("\t\tudp dport 53 udp length > 512 counter log prefix \"[SYSWARDEN-DNS-EXFIL] \" drop\n")
	_, _ = nftRules.WriteString("\t}\n\n")

	// Protect Docker (Forward chain)
	_, _ = nftRules.WriteString("\tchain docker_protect {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @banned_ips6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 daddr @banned_ips6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_blacklist6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 daddr @syswarden_blacklist6 counter drop\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip counter drop\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn counter drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_asn6 counter drop\n")
	}

	// ZERO-TRUST MODE: Drop everything that is not in the allowed GEO/ASN list (Forward chain for Docker)
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed counter drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 counter drop\n")
	}
	_, _ = nftRules.WriteString("\t}\n}\n\n")

	// 4. ARP Protection Table (L2)
	if config.GlobalConfig.ArpProtect {
		_, _ = nftRules.WriteString("table arp syswarden_arp {\n")
		_, _ = nftRules.WriteString("\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
		_, _ = nftRules.WriteString("\t\tarp operation request limit rate over 10/second counter log prefix \"[SYSWARDEN-ARP-FLOOD] \" drop\n")
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
	var ztFiles []string
	var ztFiles6 []string

	if config.GlobalConfig.GeoAllowed != "" {
		codes := strings.Split(config.GlobalConfig.GeoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				ztFiles = append(ztFiles, fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code)))
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
				ztFiles = append(ztFiles, fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToUpper(asn)))
				ztFiles6 = append(ztFiles6, fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv6", strings.ToUpper(asn)))
			}
		}
	}

	populateSet(ctx, whitelistFiles, "syswarden_whitelist")
	populateSet(ctx, []string{"/etc/syswarden/lists/syswarden_whitelist.ipv6"}, "syswarden_whitelist6")

	if len(ztFiles) > 0 {
		populateSet(ctx, ztFiles, "syswarden_zt_allowed")
	}
	if len(ztFiles6) > 0 {
		populateSet(ctx, ztFiles6, "syswarden_zt_allowed6")
	}

	populateSet(ctx, []string{"/etc/syswarden/lists/syswarden_blacklist.ipv4", "/etc/syswarden/lists/syswarden_threatintel.ipv4"}, "syswarden_blacklist")
	populateSet(ctx, []string{"/etc/syswarden/lists/syswarden_blacklist.ipv6", "/etc/syswarden/lists/syswarden_threatintel.ipv6"}, "syswarden_blacklist6")

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
	var asnFiles6 []string
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		asns := strings.Split(config.GlobalConfig.ASNList, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn != "" && asn != "none" && asn != "auto" {
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}
				asnFiles = append(asnFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToUpper(asn)))
				asnFiles6 = append(asnFiles6, fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToUpper(asn)))
			}
		}
	}
	if len(asnFiles) > 0 {
		populateSet(ctx, asnFiles, "syswarden_asn")
	}
	if len(asnFiles6) > 0 {
		populateSet(ctx, asnFiles6, "syswarden_asn6")
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
