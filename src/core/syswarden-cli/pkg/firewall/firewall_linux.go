//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
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

	// 1. Interfaces Detection (Multi-interface support or fallback)
	var interfaces []string
	if config.GlobalConfig.Interfaces != "" {
		for _, iface := range strings.Split(config.GlobalConfig.Interfaces, ",") {
			trimmed := strings.TrimSpace(iface)
			if trimmed != "" {
				interfaces = append(interfaces, trimmed)
			}
		}
	} else {
		interfaces = append(interfaces, GetActiveInterface()) // Fallback to primary if empty
	}

	// 2. Safely wipe existing tables (Universal backward compatibility)
	// We run these natively and ignore errors if they don't exist, avoiding the 'destroy' syntax error on old nftables.
	_ = exec.Command("nft", "delete", "table", "inet", "syswarden").Run()           // #nosec
	_ = exec.Command("nft", "delete", "table", "inet", "syswarden_table").Run()     // #nosec
	_ = exec.Command("nft", "delete", "table", "netdev", "syswarden_hw_drop").Run() // #nosec
	_ = exec.Command("nft", "delete", "table", "arp", "syswarden_arp").Run()        // #nosec

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
		_, _ = nftRules.WriteString("\tset syswarden_geoip6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
		_, _ = nftRules.WriteString("\tset syswarden_asn6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}

	// Modern NFTables ingress array syntax for multiple devices
	var devicesStr []string
	for _, iface := range interfaces {
		devicesStr = append(devicesStr, fmt.Sprintf("%q", iface)) // format as "eth0"
	}

	if len(interfaces) > 1 {
		fmt.Fprintf(&nftRules, "\tchain ingress_frontline {\n\t\ttype filter hook ingress devices = { %s } priority -500; policy accept;\n", strings.Join(devicesStr, ", "))
	} else {
		fmt.Fprintf(&nftRules, "\tchain ingress_frontline {\n\t\ttype filter hook ingress device \"%s\" priority -500; policy accept;\n", interfaces[0])
	}

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
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_geoip6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-GEO] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_geoip6 drop\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ASN] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_asn drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_asn6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ASN] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_asn6 drop\n")
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
		_, _ = nftRules.WriteString("\tset syswarden_geoip6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = nftRules.WriteString("\tset syswarden_asn { type ipv4_addr; flags interval; auto-merge; }\n")
		_, _ = nftRules.WriteString("\tset syswarden_asn6 { type ipv6_addr; flags interval; auto-merge; }\n")
	}

	// Trust LAN Subnets (RFC1918 by default + Custom config)
	validLANSubnets := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	if config.GlobalConfig.LANSubnets != "" {
		cleaned := strings.ReplaceAll(config.GlobalConfig.LANSubnets, ",", " ")
		subnets := strings.Fields(cleaned)
		for _, s := range subnets {
			if s != "" {
				validLANSubnets = append(validLANSubnets, s)
			}
		}
	}

	// Stateful L4 Protections (Host Input)
	_, _ = nftRules.WriteString("\tchain stateful_protect {\n\t\ttype filter hook input priority -10; policy drop;\n")
	_, _ = nftRules.WriteString("\t\tiifname \"lo\" accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")

	// Enforce blacklists BEFORE established state to instantly sever active attacker sessions
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @banned_ips6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_blacklist6 counter drop\n")

	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	_, _ = nftRules.WriteString("\t\tct state invalid counter drop\n")

	// L3/L4 Threat Intel (Fragments, XMAS, NULL Scans)
	_, _ = nftRules.WriteString("\t\tip frag-off & 0x3fff != 0 counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg counter drop\n")
	_, _ = nftRules.WriteString("\t\ttcp flags & (fin|syn|rst|ack) != syn ct state new counter drop\n")

	// ZERO-TRUST MODE: Drop everything that is not in the Zero-Trust allowed GEO/ASN list
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		// LAN Bypass: Explicitly allow internal enterprise subnets to bypass Zero-Trust
		if len(validLANSubnets) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets, ", "))
		}

		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 drop\n")
	}

	// Dynamically allow explicitly opened ports
	tcpPorts, udpPorts := GetOpenPorts()

	// Ensure Web-TUI port is always explicitly opened
	webTuiPort := "62027"
	if !contains(tcpPorts, webTuiPort) {
		tcpPorts = append(tcpPorts, webTuiPort)
	}

	// Safely force open Web-TUI in OS wrapper firewalls if they exist (avoid conflicts)
	if _, err := exec.LookPath("ufw"); err == nil {
		_ = exec.Command("ufw", "allow", fmt.Sprintf("%s/tcp", webTuiPort)).Run() // #nosec
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		_ = exec.Command("firewall-cmd", "--add-port="+webTuiPort+"/tcp", "--permanent").Run() // #nosec
		_ = exec.Command("firewall-cmd", "--reload").Run()                                     // #nosec
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		_ = exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", webTuiPort, "-j", "ACCEPT").Run() // #nosec
	}

	// Ensure HA Peer Port is always explicitly opened if HA is enabled
	if config.GlobalConfig.HAEnabled && config.GlobalConfig.HAPeerPort != "" {
		if !contains(tcpPorts, config.GlobalConfig.HAPeerPort) {
			tcpPorts = append(tcpPorts, config.GlobalConfig.HAPeerPort)
		}

		// Safely force open in OS wrapper firewalls if they exist (avoid conflicts)
		if _, err := exec.LookPath("ufw"); err == nil {
			_ = exec.Command("ufw", "allow", fmt.Sprintf("%s/tcp", config.GlobalConfig.HAPeerPort)).Run() // #nosec
		}
		if _, err := exec.LookPath("firewall-cmd"); err == nil {
			_ = exec.Command("firewall-cmd", "--add-port="+config.GlobalConfig.HAPeerPort+"/tcp", "--permanent").Run() // #nosec
			_ = exec.Command("firewall-cmd", "--reload").Run()                                                         // #nosec
		}
		if _, err := exec.LookPath("iptables"); err == nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", config.GlobalConfig.HAPeerPort, "-j", "ACCEPT").Run() // #nosec
		}
	}

	// Apply all trusted subnets to UFW, Firewalld and iptables
	for _, s := range validLANSubnets {
		if _, err := exec.LookPath("ufw"); err == nil {
			_ = exec.Command("ufw", "allow", "from", s).Run() // #nosec
		}
		if _, err := exec.LookPath("firewall-cmd"); err == nil {
			_ = exec.Command("firewall-cmd", "--add-source="+s, "--zone=trusted", "--permanent").Run() // #nosec
			_ = exec.Command("firewall-cmd", "--reload").Run()                                         // #nosec
		}
		if _, err := exec.LookPath("iptables"); err == nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-s", s, "-j", "ACCEPT").Run() // #nosec
		}
	}

	if len(tcpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } accept\n", strings.Join(tcpPorts, ", "))
	}
	if len(udpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new udp dport { %s } accept\n", strings.Join(udpPorts, ", "))
	}

	sshPort := config.GlobalConfig.SSHPort
	if sshPort == "" {
		// Dynamically query sshd for its effective configuration
		if out, err := exec.Command("sh", "-c", "sshd -T 2>/dev/null | grep -i '^port '").Output(); err == nil && len(out) > 0 { // #nosec
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

	// Explicitly trust internal enterprise subnets (Bypass Catch-All)
	if len(validLANSubnets) > 0 {
		_, _ = nftRules.WriteString("\t\t# Explicitly trust internal enterprise subnets (Bypass Catch-All)\n")
		_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets, ", "))
	}

	// CATCH-ALL Default Deny Logging
	_, _ = nftRules.WriteString("\t\tct state new limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-BLOCK] [CATCH-ALL] \"\n")
	_, _ = nftRules.WriteString("\t\tct state new counter drop\n")
	_, _ = nftRules.WriteString("\t}\n\n")

	// DNS Exfiltration Protection (L3/L4)
	_, _ = nftRules.WriteString("\tchain data_leak_protect {\n\t\ttype filter hook output priority 0; policy accept;\n")
	_, _ = nftRules.WriteString("\t\ttcp dport 8443 accept\n") // Ensure outbound mTLS to Nexus is explicitly allowed
	_, _ = nftRules.WriteString("\t\tudp dport 53 udp length > 512 counter log prefix \"[SYSWARDEN-DNS-EXFIL] \" drop\n")
	_, _ = nftRules.WriteString("\t}\n\n")

	// Protect Docker (Forward chain)
	_, _ = nftRules.WriteString("\tchain docker_protect {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @banned_ips counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @banned_ips6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 daddr @banned_ips6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip daddr @syswarden_blacklist counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_blacklist6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 daddr @syswarden_blacklist6 counter drop\n")
	_, _ = nftRules.WriteString("\t\tct state established,related accept\n")
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = nftRules.WriteString("\t\tip saddr @syswarden_geoip counter drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_geoip6 counter drop\n")
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

		// Anti-ARP Spoofing: Drop if attacker claims to be US
		localIPs := getLocalIPs()
		if len(localIPs) > 0 {
			ipList := strings.Join(localIPs, ", ")
			_, _ = fmt.Fprintf(&nftRules, "\t\tarp saddr ip { %s } counter log prefix \"[SYSWARDEN-ARP-SPOOF] \" drop\n", ipList)
		}

		// ARP Flood limits adapted for Enterprise LAN (500/s burst 1000)
		_, _ = nftRules.WriteString("\t\tarp operation request limit rate over 500/second burst 1000 packets counter log prefix \"[SYSWARDEN-ARP-FLOOD] \" drop\n")
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

	cmd := exec.CommandContext(ctx, "nft", "-f", nftFile) // #nosec
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to apply base nftables: %w\nOutput: %s", err, string(out))
	}

	// 7. Stream IP Sets dynamically (Anti-OOM / Netlink Buffer Space Fix)
	fmt.Println(" -> Streaming blocklists to kernel safely...")

	// Temporarily increase Netlink socket buffer to handle massive atomic loads (8MB)
	_ = exec.Command("sysctl", "-w", "net.core.wmem_max=8388608").Run() // #nosec
	_ = exec.Command("sysctl", "-w", "net.core.rmem_max=8388608").Run() // #nosec

	whitelistFiles := []string{
		"/etc/syswarden/lists/syswarden_whitelist.ipv4",
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv4",
	}

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

	whitelistFiles = append(whitelistFiles,
		"/etc/syswarden/lists/syswarden_whitelist.ipv6",
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv6",
	)
	populateSet(ctx, whitelistFiles, "syswarden_whitelist")
	populateSet(ctx, whitelistFiles, "syswarden_whitelist6")

	if len(ztFiles) > 0 {
		ztAllFiles := append(ztFiles, ztFiles6...)
		populateSet(ctx, ztAllFiles, "syswarden_zt_allowed")
		populateSet(ctx, ztAllFiles, "syswarden_zt_allowed6")
	}

	blacklistFiles := []string{
		"/etc/syswarden/lists/syswarden_blacklist.ipv4",
		"/etc/syswarden/lists/syswarden_threatintel.ipv4",
		"/etc/syswarden/lists/syswarden_blacklist.ipv6",
		"/etc/syswarden/lists/syswarden_threatintel.ipv6",
	}
	populateSet(ctx, blacklistFiles, "syswarden_blacklist")
	populateSet(ctx, blacklistFiles, "syswarden_blacklist6")

	var geoFiles []string
	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		codes := strings.Split(config.GlobalConfig.GeoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				geoFiles = append(geoFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code)))
				geoFiles = append(geoFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToLower(code)))
			}
		}
	}
	if len(geoFiles) > 0 {
		populateSet(ctx, geoFiles, "syswarden_geoip")
		populateSet(ctx, geoFiles, "syswarden_geoip6")
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
				asnFiles = append(asnFiles, fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToUpper(asn)))
			}
		}
	}
	if len(asnFiles) > 0 {
		populateSet(ctx, asnFiles, "syswarden_asn")
		populateSet(ctx, asnFiles, "syswarden_asn6")
	}

	fmt.Println("[INFO] Nftables applied successfully.")
	return nil
}

// getLocalIPs fetches all local IPv4 addresses (excluding loopback) for ARP spoofing protection
func getLocalIPs() []string {
	var ips []string
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}
	return ips
}

func GetActiveInterface() string {
	// Execute standard ip route get 8.8.8.8 just like the old version
	out, err := exec.Command("ip", "route", "get", "8.8.8.8").Output() // #nosec
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

	out, err := exec.Command("ss", "-tuln").Output() // #nosec
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
	isIPv6Set := strings.HasSuffix(setName, "6")

	for _, filepath := range filepaths {
		content, err := os.ReadFile(filepath) // #nosec
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Ignore empty lines and comments
			if line != "" && !strings.HasPrefix(line, "#") {
				valid, isIPv4 := IsValidIP(line)
				if valid {
					// Strictly enforce address family mapping
					if isIPv6Set && !isIPv4 {
						chunk = append(chunk, line)
					} else if !isIPv6Set && isIPv4 {
						chunk = append(chunk, line)
					}
				}
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
	cmd := exec.Command("nft", "-f", "-") // #nosec
	cmd.Stdin = bytes.NewReader([]byte(nftRules.String()))
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to load NETDEV chunk %s : %v\nOutput: %s\n", setName, err, string(out))
	}

	nftRules.Reset()

	ipStr := strings.Join(chunk, ", ")
	_, _ = fmt.Fprintf(&nftRules, "add element inet syswarden %s { %s }\n", setName, ipStr)

	cmd2 := exec.Command("nft", "-f", "-") // #nosec
	cmd2.Stdin = bytes.NewReader([]byte(nftRules.String()))
	if out, err := cmd2.CombinedOutput(); err != nil {
		fmt.Printf("[ERROR] Failed to load INET chunk %s : %v\nOutput: %s\n", setName, err, string(out))
	}
}
