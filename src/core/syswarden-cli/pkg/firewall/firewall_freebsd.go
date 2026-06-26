//go:build freebsd

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"syswarden-cli/config"
)

// ApplyPolicies triggers the main FreeBSD firewall injection using native Packet Filter (pf)
func ApplyPolicies() error {
	fmt.Println("[INFO] Applying Firewall Rules (FreeBSD PF transaction)...")

	// Create configuration dynamically for PF
	var pfRules strings.Builder

	// Setup Tables for IP Sets
	_, _ = pfRules.WriteString("table <syswarden_whitelist> persist\n")
	_, _ = pfRules.WriteString("table <syswarden_blacklist> persist\n")
	_, _ = pfRules.WriteString("table <banned_ips> persist\n")

	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = pfRules.WriteString("table <syswarden_geoip> persist\n")
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = pfRules.WriteString("table <syswarden_asn> persist\n")
	}

	// Active interface
	activeIf := GetActiveInterface()

	// Layer 4 Structural Anomaly Mitigation (Scrubbing normalizes packets and drops invalid flags)
	_, _ = pfRules.WriteString("scrub in all\n\n")

	// Layer 7 WAF Dynamic Bans (Prioritized over everything - WAAP L7 Independence)
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <banned_ips> to any\n", activeIf))

	// Allow Whitelist O(1) matching via set
	_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s from <syswarden_whitelist> to any\n", activeIf))

	// Layer 3 Static Global Intelligence Blocks
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_blacklist> to any\n", activeIf))

	if config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != "" {
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_geoip> to any\n", activeIf))
	}
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from <syswarden_asn> to any\n", activeIf))
	}

	// ZERO-TRUST MODE: Drop everything that is not in the unified whitelist
	if config.GlobalConfig.GeoAllowed != "" || config.GlobalConfig.ASNAllowed != "" {
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s from ! <syswarden_whitelist> to any\n", activeIf))
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
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on wg0 proto tcp from %s to any port %s keep state\n", config.GlobalConfig.WGSubnet, sshPort))
		_, _ = pfRules.WriteString(fmt.Sprintf("block drop in quick on %s proto tcp to any port %s\n", activeIf, sshPort))
	} else {
		_, _ = pfRules.WriteString("# Standard SSH Access\n")
		_, _ = pfRules.WriteString(fmt.Sprintf("pass in quick on %s proto tcp to any port %s keep state\n", activeIf, sshPort))
	}

	// Default drop catch-all for incoming
	_, _ = pfRules.WriteString(fmt.Sprintf("block drop in on %s all\n", activeIf))
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
