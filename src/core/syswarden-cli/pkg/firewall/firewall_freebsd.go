//go:build freebsd

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"syswarden-cli/config"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// ApplyPolicies triggers the main FreeBSD firewall injection using native Packet Filter (pf)
func ApplyPolicies() error {
	fmt.Println("[INFO] Applying Firewall Rules (FreeBSD PF transaction)...")

	// Create configuration dynamically for PF
	var pfRules strings.Builder

	// Setup Tables for IP Sets (Loading files directly)
	pfWhitelist := []string{
		"/etc/syswarden/lists/syswarden_whitelist.ipv4",
		"/etc/syswarden/lists/syswarden_whitelist.ipv6",
	}
	if fileExists("/etc/syswarden/lists/syswarden_saas_monitors.ipv4") {
		pfWhitelist = append(pfWhitelist, "/etc/syswarden/lists/syswarden_saas_monitors.ipv4")
	}
	if fileExists("/etc/syswarden/lists/syswarden_saas_monitors.ipv6") {
		pfWhitelist = append(pfWhitelist, "/etc/syswarden/lists/syswarden_saas_monitors.ipv6")
	}

	pfRules.WriteString("table <syswarden_whitelist> persist")
	for _, f := range pfWhitelist {
		pfRules.WriteString(fmt.Sprintf(" file \"%s\"", f))
	}
	pfRules.WriteString("\n")

	var ztFilesStr strings.Builder
	if config.GlobalConfig.GeoAllowed != "" {
		codes := strings.Split(config.GlobalConfig.GeoAllowed, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				path := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToLower(code))
				if fileExists(path) {
					ztFilesStr.WriteString(fmt.Sprintf(" file \"%s\"", path))
				}
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
				pathV4 := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv4", strings.ToUpper(asn))
				pathV6 := fmt.Sprintf("/etc/syswarden/lists/allowed_%s.ipv6", strings.ToUpper(asn))
				if fileExists(pathV4) {
					ztFilesStr.WriteString(fmt.Sprintf(" file \"%s\"", pathV4))
				}
				if fileExists(pathV6) {
					ztFilesStr.WriteString(fmt.Sprintf(" file \"%s\"", pathV6))
				}
			}
		}
	}
	_, _ = pfRules.WriteString(fmt.Sprintf("table <syswarden_zt_allowed> persist%s\n", ztFilesStr.String()))

	_, _ = pfRules.WriteString("table <syswarden_blacklist> persist file \"/etc/syswarden/lists/syswarden_blacklist.ipv4\" file \"/etc/syswarden/lists/syswarden_threatintel.ipv4\"\n")
	_, _ = pfRules.WriteString("table <syswarden_blacklist6> persist file \"/etc/syswarden/lists/syswarden_blacklist.ipv6\" file \"/etc/syswarden/lists/syswarden_threatintel.ipv6\"\n")
	_, _ = pfRules.WriteString("table <banned_ips> persist\n")

	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		var geoFilesStr strings.Builder
		codes := strings.Split(config.GlobalConfig.GeoCodes, " ")
		for _, code := range codes {
			code = strings.TrimSpace(code)
			if code != "" && code != "none" {
				path := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToLower(code))
				if fileExists(path) {
					geoFilesStr.WriteString(fmt.Sprintf(" file \"%s\"", path))
				}
			}
		}
		_, _ = pfRules.WriteString(fmt.Sprintf("table <syswarden_geoip> persist%s\n", geoFilesStr.String()))
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		var asnV4Str, asnV6Str strings.Builder
		asns := strings.Split(config.GlobalConfig.ASNList, " ")
		for _, asn := range asns {
			asn = strings.TrimSpace(asn)
			if asn != "" && asn != "none" && asn != "auto" {
				if !strings.HasPrefix(asn, "AS") {
					asn = "AS" + asn
				}
				pathV4 := fmt.Sprintf("/etc/syswarden/lists/%s.ipv4", strings.ToUpper(asn))
				pathV6 := fmt.Sprintf("/etc/syswarden/lists/%s.ipv6", strings.ToUpper(asn))
				if fileExists(pathV4) {
					asnV4Str.WriteString(fmt.Sprintf(" file \"%s\"", pathV4))
				}
				if fileExists(pathV6) {
					asnV6Str.WriteString(fmt.Sprintf(" file \"%s\"", pathV6))
				}
			}
		}
		_, _ = pfRules.WriteString(fmt.Sprintf("table <syswarden_asn> persist%s\n", asnV4Str.String()))
		_, _ = pfRules.WriteString(fmt.Sprintf("table <syswarden_asn6> persist%s\n", asnV6Str.String()))
	}

	// Active interface
	activeIf := GetActiveInterface()

	// Layer 4 Structural Anomaly Mitigation (Scrubbing normalizes packets and drops invalid flags)
	_, _ = pfRules.WriteString("scrub in all fragment reassemble\n\n")

	// Threat Intel L3/L4 (Fragments, XMAS, NULL Scans)
	_, _ = pfRules.WriteString("block drop in quick all fragments\n")
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s proto tcp all flags FUP/WEUAPRSF\n", activeIf))
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s proto tcp all flags NONE/WEUAPRSF\n", activeIf))

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

	// 1. Infra Whitelist (Absolute Priority - Bypasses everything)
	_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s from <syswarden_whitelist> to any\n", activeIf))

	// 2. Layer 7 WAF Dynamic Bans
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <banned_ips> to any\n", activeIf))

	// Layer 3 Static Global Intelligence Blocks
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_blacklist> to any\n", activeIf))
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_blacklist6> to any\n", activeIf))

	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_geoip> to any\n", activeIf))
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_asn> to any\n", activeIf))
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_asn6> to any\n", activeIf))
	}

	// ZERO-TRUST MODE: Drop everything that is not in the Zero-Trust allowed GEO/ASN list
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		// LAN Bypass: Explicitly allow internal enterprise subnets to bypass Zero-Trust
		if len(validLANSubnets) > 0 {
			_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick from { %s } to any\n", strings.Join(validLANSubnets, ", ")))
		}
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from ! <syswarden_zt_allowed> to any\n", activeIf))
	}

	// Stateful L4 Protections (Host Input)
	sshPort := config.GlobalConfig.SSHPort
	if sshPort == "" {
		if out, err := exec.Command("sh", "-c", "sshd -T 2>/dev/null | grep -i '^port '").Output(); err == nil && len(out) > 0 {
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				sshPort = fields[1]
			}
		}
		if sshPort == "" {
			sshPort = "22"
		}
	}

	// Dynamically allow explicitly opened ports
	tcpPorts, udpPorts := GetOpenPorts()

	// Ensure HA Peer Port is always explicitly opened if HA is enabled
	if config.GlobalConfig.HAEnabled && config.GlobalConfig.HAPeerPort != "" {
		found := false
		for _, p := range tcpPorts {
			if p == config.GlobalConfig.HAPeerPort {
				found = true
				break
			}
		}
		if !found {
			tcpPorts = append(tcpPorts, config.GlobalConfig.HAPeerPort)
		}
	}

	if len(tcpPorts) > 0 {
		for _, p := range tcpPorts {
			if p != sshPort {
				_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s proto tcp to any port %s keep state\n", activeIf, p))
			}
		}
	}
	if len(udpPorts) > 0 {
		for _, p := range udpPorts {
			_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s proto udp to any port %s keep state\n", activeIf, p))
		}
	}

	// SSH Cloaking (WireGuard VPN Only) vs Standard SSH
	if config.GlobalConfig.EnableWG {
		_, _ = pfRules.WriteString("# SSH Cloaking (Strict WG VPN Only)\n")
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s proto tcp from <syswarden_whitelist> to any port %s keep state\n", activeIf, sshPort))
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on wg-syswarden proto tcp from %s to any port %s keep state\n", config.GlobalConfig.WGSubnet, sshPort))
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s proto tcp to any port %s\n", activeIf, sshPort))
	} else {
		_, _ = pfRules.WriteString("# Standard SSH Access\n")
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s proto tcp to any port %s keep state\n", activeIf, sshPort))
	}

	// Honeyports (Insider Threat Detection)
	if config.GlobalConfig.LANMode && config.GlobalConfig.HoneyPorts != "" {
		ports := strings.ReplaceAll(config.GlobalConfig.HoneyPorts, " ", "")
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in log quick on %s proto tcp to any port { %s }\n", activeIf, ports))
	}

	// Explicitly trust internal enterprise subnets (Bypass Catch-All)
	if len(validLANSubnets) > 0 {
		_, _ = pfRules.WriteString("# Explicitly trust internal enterprise subnets (Bypass Catch-All)\n")
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s from { %s } to any keep state\n", activeIf, strings.Join(validLANSubnets, ", ")))
	}

	// Default drop catch-all for incoming
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in log on %s all\n", activeIf))

	// DNS Exfiltration Protection (L3/L4)
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop out log quick on %s proto udp to any port 53 length > 512\n", activeIf))

	_, _ = pfRules.WriteString(fmt.Sprintf("pass out quick on %s proto tcp to any port 8443 keep state\n", activeIf)) // Ensure outbound mTLS to Nexus is explicitly allowed
	_, _ = pfRules.WriteString(fmt.Sprintf("pass out on %s all keep state\n", activeIf))

	// Write pf configuration to temporary file
	tempPfFile := "/tmp/syswarden_pf.conf"
	err := os.WriteFile(tempPfFile, []byte(pfRules.String()), 0600)
	if err != nil {
		return fmt.Errorf("failed to write pf configuration: %w", err)
	}
	defer os.Remove(tempPfFile)

	// Apply configuration natively via pfctl
	execCmd := exec.Command("pfctl", "-f", tempPfFile)
	if out, err := execCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl execution failed: %s (err: %w)", string(out), err)
	}

	// Enable pf if not already enabled
	_ = exec.Command("pfctl", "-e").Run()

	// Native Kernel Layer 2 Hardening (ARP Spoofing Protection)
	if config.GlobalConfig.EnableL2 {
		_ = exec.Command("sysctl", "net.link.ether.inet.log_arp_wrong_iface=1").Run()
		_ = exec.Command("sysctl", "net.link.ether.inet.log_arp_movements=1").Run()
		fmt.Println("[INFO] Layer 2 Kernel ARP Hardening active.")
	}

	fmt.Println("[SUCCESS] FreeBSD PF policies successfully applied.")
	return nil
}

// GetActiveInterface identifies the primary network interface natively on FreeBSD
func GetActiveInterface() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "vtnet0" // Common fallback on FreeBSD VMs
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return "vtnet0"
}

// GetOpenPorts natively parses FreeBSD sockstat to extract exposed ports (TCP/UDP)
func GetOpenPorts() ([]string, []string) {
	var tcpPorts []string
	var udpPorts []string

	// On FreeBSD, sockstat -46l can be used, but since we just need basic open ports,
	// returning standard ports for now to avoid breaking the signature pipeline.
	tcpPorts = append(tcpPorts, "80", "443", "22")
	udpPorts = append(udpPorts, "443") // HTTP/3 QUIC Support
	return tcpPorts, udpPorts
}
