//go:build linux

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"time"
)

const linuxWrapperStateVersion = "syswarden-firewall-wrappers-v1"

const (
	saasPairManifestFile          = "syswarden_saas_monitors.pair"
	saasPairManifestV1            = "syswarden-saas-pair-v1"
	maximumSaaSListBytes          = 1 << 20
	maximumLegacySaaSListEntries  = 10000
	saasLegacyAdoptionEnvironment = "SYSWARDEN_PKG_INSTALL"
)

var linuxWrapperStateFile = filepath.Join(nftStateDirectory, "firewall-wrappers.state")

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
				canonical, err := canonicalInterfaceName(trimmed)
				if err != nil {
					return err
				}
				if !contains(interfaces, canonical) {
					interfaces = append(interfaces, canonical)
				}
			}
		}
	} else {
		activeInterface, err := canonicalInterfaceName(GetActiveInterface())
		if err != nil {
			return err
		}
		interfaces = append(interfaces, activeInterface) // Fallback to primary if empty
	}
	if len(interfaces) == 0 {
		return fmt.Errorf("no valid firewall interface is configured")
	}

	// 2. Hardware Drop Table (L2)
	_, _ = nftRules.WriteString("table netdev syswarden_hw_drop {\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist_ports { type ipv4_addr . inet_service; flags interval; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist_ports6 { type ipv6_addr . inet_service; flags interval; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags interval,timeout; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips6 { type ipv6_addr; flags interval,timeout; }\n")
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
	_, _ = nftRules.WriteString("\t\tip saddr . tcp dport @syswarden_whitelist_ports accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr . tcp dport @syswarden_whitelist_ports6 accept\n")

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
	_, _ = nftRules.WriteString("\tset syswarden_whitelist_ports { type ipv4_addr . inet_service; flags interval; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_whitelist_ports6 { type ipv6_addr . inet_service; flags interval; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_ssh_bypass { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_ssh_bypass6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed { type ipv4_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset syswarden_zt_allowed6 { type ipv6_addr; flags interval; auto-merge; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips { type ipv4_addr; flags interval,timeout; }\n")
	_, _ = nftRules.WriteString("\tset banned_ips6 { type ipv6_addr; flags interval,timeout; }\n")
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
	validLANSubnets, err := canonicalPolicyNetworks(
		[]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
		config.GlobalConfig.LANSubnets,
	)
	if err != nil {
		return err
	}
	validLANSubnets4, validLANSubnets6, err := splitPolicyNetworksByFamily(validLANSubnets)
	if err != nil {
		return fmt.Errorf("split LAN subnets by address family: %w", err)
	}

	// Stateful L4 Protections (Host Input)
	_, _ = nftRules.WriteString("\tchain stateful_protect {\n\t\ttype filter hook input priority -10; policy drop;\n")
	_, _ = nftRules.WriteString("\t\tiifname \"lo\" accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr @syswarden_whitelist accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr @syswarden_whitelist6 accept\n")
	_, _ = nftRules.WriteString("\t\tip saddr . tcp dport @syswarden_whitelist_ports accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr . tcp dport @syswarden_whitelist_ports6 accept\n")

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
		if len(validLANSubnets4) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets4, ", "))
		}
		if len(validLANSubnets6) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr { %s } accept\n", strings.Join(validLANSubnets6, ", "))
		}

		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed drop\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
		_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 drop\n")
	}
	sshPort, err := effectiveSSHPort(config.GlobalConfig.SSHPort)
	if err != nil {
		return err
	}
	haPort := ""
	if config.GlobalConfig.HAEnabled && config.GlobalConfig.HAPeerPort != "" {
		haPort, err = canonicalPort(config.GlobalConfig.HAPeerPort)
		if err != nil {
			return fmt.Errorf("invalid HA peer port: %w", err)
		}
		if config.GlobalConfig.EnableWG && haPort == sshPort {
			return fmt.Errorf("HA peer port must differ from the effective SSH port while WireGuard cloaking is enabled")
		}
	}

	// Dynamically allow explicitly opened ports
	detectedTCPPorts, detectedUDPPorts := GetOpenPorts()
	tcpPorts, err := canonicalPorts("detected TCP ports", detectedTCPPorts)
	if err != nil {
		return err
	}
	udpPorts, err := canonicalPorts("detected UDP ports", detectedUDPPorts)
	if err != nil {
		return err
	}

	// Port 62027 belonged to the retired Web-TUI. Never adopt a listener on
	// that port into SysWarden policy; an unrelated local service owns its own
	// exposure decision.
	filteredTCPPorts := tcpPorts[:0]
	for _, port := range tcpPorts {
		if port != "62027" && port != sshPort {
			filteredTCPPorts = append(filteredTCPPorts, port)
		}
	}
	tcpPorts = filteredTCPPorts

	// Ensure HA Peer Port is always explicitly opened if HA is enabled
	var wrapperPorts []string
	if haPort != "" {
		if !contains(tcpPorts, haPort) {
			tcpPorts = append(tcpPorts, haPort)
		}
		if !contains(wrapperPorts, haPort) {
			wrapperPorts = append(wrapperPorts, haPort)
		}
	}

	if len(tcpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } accept\n", strings.Join(tcpPorts, ", "))
	}
	if len(udpPorts) > 0 {
		fmt.Fprintf(&nftRules, "\t\tct state new udp dport { %s } accept\n", strings.Join(udpPorts, ", "))
	}

	_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr @syswarden_ssh_bypass tcp dport %s accept\n", sshPort)
	_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr @syswarden_ssh_bypass6 tcp dport %s accept\n", sshPort)

	// SSH Cloaking (WireGuard VPN Only) vs Standard SSH
	if config.GlobalConfig.EnableWG {
		wireGuardSubnet, subnetErr := canonicalIPv4Network(config.GlobalConfig.WGSubnet, "WireGuard subnet")
		if subnetErr != nil {
			return subnetErr
		}
		_, _ = nftRules.WriteString("\t\t# SSH Cloaking (Strict WG VPN Only)\n")
		// Always allow explicitly whitelisted IPs
		_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr @syswarden_whitelist tcp dport %s accept\n", sshPort)
		_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr @syswarden_whitelist6 tcp dport %s accept\n", sshPort)
		// Allow from the WireGuard Subnet
		_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr %s tcp dport %s accept\n", wireGuardSubnet, sshPort)
		// Drop from anywhere else
		_, _ = fmt.Fprintf(&nftRules, "\t\ttcp dport %s counter drop\n", sshPort)
	} else {
		_, _ = nftRules.WriteString("\t\t# Standard SSH Access\n")
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport %s accept\n", sshPort)
	}

	// Honeyports (Insider Threat Detection)
	if config.GlobalConfig.LANMode && config.GlobalConfig.HoneyPorts != "" {
		ports, err := canonicalHoneyPorts(config.GlobalConfig.HoneyPorts)
		if err != nil {
			return fmt.Errorf("invalid honeyport configuration: %w", err)
		}
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } limit rate 5/second burst 10 packets log prefix \"[SYSWARDEN-HONEYPORT] \"\n", ports)
		_, _ = fmt.Fprintf(&nftRules, "\t\tct state new tcp dport { %s } counter drop\n", ports)
	}

	// Explicitly trust internal enterprise subnets (Bypass Catch-All)
	if len(validLANSubnets4) > 0 || len(validLANSubnets6) > 0 {
		_, _ = nftRules.WriteString("\t\t# Explicitly trust internal enterprise subnets (Bypass Catch-All)\n")
		if len(validLANSubnets4) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets4, ", "))
		}
		if len(validLANSubnets6) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr { %s } accept\n", strings.Join(validLANSubnets6, ", "))
		}
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
	_, _ = nftRules.WriteString("\t\tip saddr . tcp dport @syswarden_whitelist_ports accept\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr . tcp dport @syswarden_whitelist_ports6 accept\n")
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

	// Prepare every set before the single kernel transaction. No firewall or
	// wrapper state has been mutated when this phase returns an error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	populations, err := prepareNftSetPopulations(ctx, sshPort)
	if err != nil {
		return fmt.Errorf("failed to prepare nftables sets: %w", err)
	}
	verification := buildNftVerificationPlan(populations, config.GlobalConfig.ArpProtect)
	transactionID, err := applyNftablesPolicyWithWrappers(
		ctx,
		execNFTCommandRunner{},
		nftStateDirectory,
		nftRules.String(),
		populations,
		verification,
		func() error { return applyLinuxFirewallWrappersLocked(validLANSubnets, wrapperPorts) },
	)
	if err != nil {
		return err
	}
	_ = exec.Command("sysctl", "-w", "net.core.wmem_max=8388608").Run() // #nosec
	_ = exec.Command("sysctl", "-w", "net.core.rmem_max=8388608").Run() // #nosec

	fmt.Printf("[INFO] Nftables transaction %s applied and verified successfully.\n", transactionID)
	return nil
}

func effectiveSSHPort(configured string) (string, error) {
	port := configured
	if port == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if output, err := exec.CommandContext(ctx, "sshd", "-T").Output(); err == nil { // #nosec G204 -- sshd is a fixed executable name and receives a fixed argument
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) == 2 && strings.EqualFold(fields[0], "port") {
					port = fields[1]
					break
				}
			}
		}
	}
	if port == "" {
		port = "22"
	}
	canonical, err := canonicalPort(port)
	if err != nil {
		return "", fmt.Errorf("invalid SSH port: %w", err)
	}
	return canonical, nil
}

func applyNftablesPolicyWithWrappers(ctx context.Context, runner nftCommandRunner, stateDirectory, baseRules string, populations []nftSetPopulation, verification nftVerificationPlan, reconcileWrappers func() error) (string, error) {
	transactionID, err := newFirewallTransactionID()
	if err != nil {
		return "", err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: acquire reload lock: %w", transactionID, err)
	}
	defer releaseNFTReloadGuard(lock)
	transactionID, err = applyNftablesTransactionLocked(ctx, runner, stateDirectory, baseRules, populations, verification, transactionID)
	if err != nil {
		return transactionID, err
	}

	// Wrapper firewalls are compatibility layers. nftables is authoritative and
	// has already been applied, independently verified, and persisted here. A
	// wrapper failure is therefore explicit but never triggers a misleading
	// rollback of the authoritative policy.
	if reconcileWrappers != nil {
		if err := reconcileWrappers(); err != nil {
			return transactionID, committedWrapperReconciliationError(transactionID, err)
		}
	}
	return transactionID, nil
}

func committedWrapperReconciliationError(transactionID string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("nftables transaction %s is committed and remains authoritative; compatibility wrapper reconciliation is incomplete: %w", transactionID, err)
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
					ipPart := localAddr[:lastColon]
					port := localAddr[lastColon+1:]

					// Ignore localhost bound services (Do not expose internal DBs like Redis/Postgres)
					if ipPart == "127.0.0.1" || ipPart == "[::1]" || ipPart == "::1" || ipPart == "127.0.0.53" {
						continue
					}

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

func prepareNftSetPopulations(ctx context.Context, effectiveSSHPort string) ([]nftSetPopulation, error) {
	const listDirectory = "/etc/syswarden/lists"
	if _, err := maybeAdoptLegacySaaSListPair(listDirectory, config.GlobalConfig.AllowSaaSMonitors); err != nil {
		return nil, fmt.Errorf("adopt the legacy SaaS monitor lists: %w", err)
	}
	listSnapshotLock, err := lockNftListSnapshot(listDirectory)
	if err != nil {
		return nil, err
	}
	if listSnapshotLock != nil {
		defer unlockNftListSnapshot(listSnapshotLock)
	}
	optional := func(name string) nftListSource {
		return nftListSource{path: filepath.Join(listDirectory, name)}
	}

	includeSaaSPair := false
	var saasPairErr error
	if config.GlobalConfig.AllowSaaSMonitors {
		includeSaaSPair, saasPairErr = validateSaaSListPair(listDirectory)
	}
	whitelist4, whitelist6 := whitelistNftSources(listDirectory, includeSaaSPair)
	blacklist4 := []nftListSource{optional("syswarden_blacklist.ipv4"), optional("syswarden_threatintel.ipv4")}
	blacklist6 := []nftListSource{optional("syswarden_blacklist.ipv6"), optional("syswarden_threatintel.ipv6")}

	zt4, zt6, ztErr := configuredNftSources(listDirectory, config.GlobalConfig.GeoAllowed, config.GlobalConfig.ASNAllowed, true)
	geo4, geo6, geoErr := configuredNftSources(listDirectory, config.GlobalConfig.GeoCodes, "", false)
	asn4, asn6, asnErr := configuredNftSources(listDirectory, "", config.GlobalConfig.ASNList, false)
	whitelistAddress4, whitelistPorts4, whitelist4Err := populateWhitelistSets(ctx, whitelist4, "syswarden_whitelist", "syswarden_whitelist_ports")
	whitelistAddress6, whitelistPorts6, whitelist6Err := populateWhitelistSets(ctx, whitelist6, "syswarden_whitelist6", "syswarden_whitelist_ports6")
	sshBypass4, sshBypass6, sshBypassErr := populateSSHBypassSets(ctx, nftListSource{path: SSHBypass}, effectiveSSHPort)

	requests := []struct {
		name    string
		sources []nftListSource
		enabled bool
	}{
		{name: "syswarden_zt_allowed", sources: zt4, enabled: true},
		{name: "syswarden_zt_allowed6", sources: zt6, enabled: true},
		{name: "syswarden_blacklist", sources: blacklist4, enabled: true},
		{name: "syswarden_blacklist6", sources: blacklist6, enabled: true},
		{name: "syswarden_geoip", sources: geo4, enabled: config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != ""},
		{name: "syswarden_geoip6", sources: geo6, enabled: config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != ""},
		{name: "syswarden_asn", sources: asn4, enabled: config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != ""},
		{name: "syswarden_asn6", sources: asn6, enabled: config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != ""},
	}

	populations := []nftSetPopulation{
		whitelistAddress4,
		whitelistAddress6,
		whitelistPorts4,
		whitelistPorts6,
		sshBypass4,
		sshBypass6,
	}
	errs := []error{ztErr, geoErr, asnErr, saasPairErr, whitelist4Err, whitelist6Err, sshBypassErr}
	for _, request := range requests {
		if !request.enabled {
			continue
		}
		population, err := populateSet(ctx, request.sources, request.name)
		populations = append(populations, population)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return populations, errors.Join(errs...)
}

func whitelistNftSources(directory string, allowSaaSMonitors bool) ([]nftListSource, []nftListSource) {
	ipv4 := []nftListSource{{path: filepath.Join(directory, "syswarden_whitelist.ipv4")}}
	ipv6 := []nftListSource{{path: filepath.Join(directory, "syswarden_whitelist.ipv6")}}
	if allowSaaSMonitors {
		ipv4 = append(ipv4, nftListSource{path: filepath.Join(directory, "syswarden_saas_monitors.ipv4")})
		ipv6 = append(ipv6, nftListSource{path: filepath.Join(directory, "syswarden_saas_monitors.ipv6")})
	}
	return ipv4, ipv6
}

func maybeAdoptLegacySaaSListPair(directory string, enabled bool) (bool, error) {
	if !enabled || os.Getenv(saasLegacyAdoptionEnvironment) != "1" {
		return false, nil
	}
	return adoptLegacySaaSListPair(directory)
}

func verifyLegacySaaSDirectory(directory *os.Root) error {
	info, err := directory.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect legacy SaaS list directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("legacy SaaS list directory is not a private real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("legacy SaaS list directory is not owned by the effective user")
	}
	return nil
}

func readLegacySaaSListComponent(directory *os.Root, target approvedListFile, wantIPv4 bool) ([]byte, bool, int, error) {
	pathInfo, err := directory.Lstat(target.name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, 0, nil
	}
	if err != nil {
		return nil, false, 0, fmt.Errorf("inspect legacy SaaS list %s: %w", target.name, err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm() != 0600 {
		return nil, false, 0, fmt.Errorf("legacy SaaS list %s must be a private regular file", target.name)
	}
	file, _, err := openListFileInRoot(directory, target, os.O_RDONLY, false)
	if err != nil {
		return nil, false, 0, fmt.Errorf("open legacy SaaS list %s: %w", target.name, err)
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil {
		return nil, false, 0, fmt.Errorf("inspect opened legacy SaaS list %s: %w", target.name, err)
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, false, 0, fmt.Errorf("legacy SaaS list %s is not owned by the effective user", target.name)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumSaaSListBytes+1))
	if err != nil {
		return nil, false, 0, fmt.Errorf("read legacy SaaS list %s: %w", target.name, err)
	}
	if len(content) > maximumSaaSListBytes {
		return nil, false, 0, fmt.Errorf("legacy SaaS list %s exceeds %d bytes", target.name, maximumSaaSListBytes)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, false, 0, fmt.Errorf("legacy SaaS list %s changed while it was read", target.name)
	}
	entries, err := validateCanonicalLegacySaaSList(target.name, content, wantIPv4)
	if err != nil {
		return nil, false, 0, err
	}
	return content, true, entries, nil
}

func validateCanonicalLegacySaaSList(name string, content []byte, wantIPv4 bool) (int, error) {
	lines := strings.Split(string(content), "\n")
	entries := 0
	for index, line := range lines {
		if line == "" && index == len(lines)-1 {
			continue
		}
		if line == "" || strings.TrimSpace(line) != line || strings.HasPrefix(line, "#") {
			return 0, fmt.Errorf("legacy SaaS list %s:%d is not in canonical one-entry-per-line form", name, index+1)
		}
		canonical, isIPv4, err := canonicalIPOrPrefix(line)
		if err != nil {
			return 0, fmt.Errorf("legacy SaaS list %s:%d: %w", name, index+1, err)
		}
		if canonical != line {
			return 0, fmt.Errorf("legacy SaaS list %s:%d is not canonical", name, index+1)
		}
		if isIPv4 != wantIPv4 {
			return 0, fmt.Errorf("legacy SaaS list %s:%d has the wrong address family", name, index+1)
		}
		entries++
		if entries > maximumLegacySaaSListEntries {
			return 0, fmt.Errorf("legacy SaaS list %s exceeds %d entries", name, maximumLegacySaaSListEntries)
		}
	}
	return entries, nil
}

func renderSaaSPairManifest(ipv4Content, ipv6Content []byte) []byte {
	ipv4Digest := sha256.Sum256(ipv4Content)
	ipv6Digest := sha256.Sum256(ipv6Content)
	return []byte(fmt.Sprintf(
		"%s\nipv4_sha256=%x\nipv6_sha256=%x\n",
		saasPairManifestV1,
		ipv4Digest,
		ipv6Digest,
	))
}

func adoptLegacySaaSListPair(directoryPath string) (bool, error) {
	ipv4Target := approvedListFile{directory: directoryPath, name: "syswarden_saas_monitors.ipv4"}
	ipv6Target := approvedListFile{directory: directoryPath, name: "syswarden_saas_monitors.ipv6"}
	manifestTarget := approvedListFile{directory: directoryPath, name: saasPairManifestFile}
	for _, target := range []approvedListFile{ipv4Target, ipv6Target, manifestTarget} {
		if err := validateListFileTarget(target); err != nil {
			return false, err
		}
	}

	directory, err := openListDirectory(ipv4Target, false)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = directory.Close() }()
	if err := verifyLegacySaaSDirectory(directory); err != nil {
		return false, err
	}
	lockFile, err := lockListDirectory(directory)
	if err != nil {
		return false, err
	}
	defer unlockListDirectory(lockFile)

	manifestInfo, manifestErr := directory.Lstat(manifestTarget.name)
	if manifestErr == nil {
		if !manifestInfo.Mode().IsRegular() {
			return false, fmt.Errorf("SaaS pair manifest is not a regular file")
		}
		return false, nil
	}
	if !errors.Is(manifestErr, fs.ErrNotExist) {
		return false, fmt.Errorf("inspect SaaS pair manifest before adoption: %w", manifestErr)
	}

	ipv4Content, ipv4Exists, ipv4Entries, err := readLegacySaaSListComponent(directory, ipv4Target, true)
	if err != nil {
		return false, err
	}
	if !ipv4Exists {
		return false, fmt.Errorf("legacy SaaS adoption requires the historical IPv4 list")
	}
	ipv6Content, ipv6Exists, ipv6Entries, err := readLegacySaaSListComponent(directory, ipv6Target, false)
	if err != nil {
		return false, err
	}
	if ipv4Entries+ipv6Entries == 0 {
		return false, fmt.Errorf("legacy SaaS lists contain no monitor address")
	}
	if !ipv6Exists {
		if err := writeListFileInDirectoryBeforeRename(directory, ipv6Target, nil, nil); err != nil {
			return false, fmt.Errorf("create the empty IPv6 half of the legacy SaaS pair: %w", err)
		}
		ipv6Content = nil
	}
	manifest := renderSaaSPairManifest(ipv4Content, ipv6Content)
	if err := writeListFileInDirectoryBeforeRename(directory, manifestTarget, manifest, nil); err != nil {
		return false, fmt.Errorf("publish the adopted SaaS pair manifest: %w", err)
	}
	return true, nil
}

func validateSaaSListPair(directory string) (bool, error) {
	paths := []string{
		filepath.Join(directory, "syswarden_saas_monitors.ipv4"),
		filepath.Join(directory, "syswarden_saas_monitors.ipv6"),
		filepath.Join(directory, saasPairManifestFile),
	}
	contents := make([][]byte, len(paths))
	present := 0
	for index, path := range paths {
		content, err := readRootedNFTFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("read SaaS pair component %s: %w", path, err)
		}
		if len(content) > maximumSaaSListBytes {
			return false, fmt.Errorf("SaaS pair component %s exceeds %d bytes", path, maximumSaaSListBytes)
		}
		contents[index] = content
		present++
	}
	if present == 0 {
		return false, nil
	}
	if present != len(paths) {
		return false, fmt.Errorf("SaaS monitor pair is incomplete; preserve the active firewall policy")
	}
	expected := renderSaaSPairManifest(contents[0], contents[1])
	if !bytes.Equal(contents[2], expected) {
		return false, fmt.Errorf("SaaS monitor pair manifest does not match both list files; preserve the active firewall policy")
	}
	return true, nil
}

func lockNftListSnapshot(directory string) (*os.File, error) {
	info, err := os.Lstat(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect nftables list directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("nftables list directory must be a real directory")
	}
	file, err := os.Open(directory) // #nosec G304 -- directory is a fixed internal path
	if err != nil {
		return nil, fmt.Errorf("open nftables list directory snapshot lock: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("nftables list directory changed while opening")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock nftables list snapshot: %w", err)
	}
	return file, nil
}

func unlockNftListSnapshot(file *os.File) {
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func configuredNftSources(directory, countries, asns string, allowed bool) ([]nftListSource, []nftListSource, error) {
	var ipv4 []nftListSource
	var ipv6 []nftListSource
	var errs []error
	prefix := ""
	if allowed {
		prefix = "allowed_"
	}
	for _, country := range strings.Fields(strings.ReplaceAll(countries, ",", " ")) {
		if strings.EqualFold(country, "none") {
			continue
		}
		if len(country) != 2 || !isASCIILetters(country) {
			errs = append(errs, fmt.Errorf("invalid country list identifier %q", country))
			continue
		}
		base := prefix + strings.ToLower(country)
		ipv4 = append(ipv4, nftListSource{path: filepath.Join(directory, base+".ipv4"), required: true})
		ipv6 = append(ipv6, nftListSource{path: filepath.Join(directory, base+".ipv6"), required: true})
	}
	for _, configuredASN := range strings.Fields(strings.ReplaceAll(asns, ",", " ")) {
		if strings.EqualFold(configuredASN, "none") || strings.EqualFold(configuredASN, "auto") {
			continue
		}
		digits := configuredASN
		if len(digits) >= 2 && strings.EqualFold(digits[:2], "AS") {
			digits = digits[2:]
		}
		if digits == "" || !isASCIIDigits(digits) {
			errs = append(errs, fmt.Errorf("invalid ASN list identifier %q", configuredASN))
			continue
		}
		base := prefix + "AS" + digits
		ipv4 = append(ipv4, nftListSource{path: filepath.Join(directory, base+".ipv4"), required: true})
		ipv6 = append(ipv6, nftListSource{path: filepath.Join(directory, base+".ipv6"), required: true})
	}
	return ipv4, ipv6, errors.Join(errs...)
}

func isASCIILetters(value string) bool {
	for _, r := range value {
		if r < 'A' || r > 'Z' && r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func isASCIIDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func buildNftVerificationPlan(populations []nftSetPopulation, arpProtect bool) nftVerificationPlan {
	plan := nftVerificationPlan{
		tables: map[nftObjectKey]struct{}{
			{family: "inet", name: "syswarden"}:           {},
			{family: "netdev", name: "syswarden_hw_drop"}: {},
		},
		chains: map[nftObjectKey]string{
			{family: "inet", table: "syswarden", name: "stateful_protect"}:            "input",
			{family: "inet", table: "syswarden", name: "data_leak_protect"}:           "output",
			{family: "inet", table: "syswarden", name: "docker_protect"}:              "forward",
			{family: "netdev", table: "syswarden_hw_drop", name: "ingress_frontline"}: "ingress",
		},
		sets: make(map[nftObjectKey]int),
	}
	if arpProtect {
		plan.tables[nftObjectKey{family: "arp", name: "syswarden_arp"}] = struct{}{}
		plan.chains[nftObjectKey{family: "arp", table: "syswarden_arp", name: "input"}] = "input"
	}
	for _, setName := range []string{
		"syswarden_whitelist", "syswarden_whitelist6", "syswarden_zt_allowed", "syswarden_zt_allowed6",
		"syswarden_blacklist", "syswarden_blacklist6",
	} {
		plan.sets[nftObjectKey{family: "inet", table: "syswarden", name: setName}] = 0
		plan.sets[nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: setName}] = 0
	}
	for _, setName := range []string{"banned_ips", "banned_ips6"} {
		plan.sets[nftObjectKey{family: "inet", table: "syswarden", name: setName}] = -1
		plan.sets[nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: setName}] = -1
	}
	for _, population := range populations {
		count := len(population.entries)
		plan.sets[nftObjectKey{family: "inet", table: "syswarden", name: population.name}] = count
		if !population.inetOnly {
			plan.sets[nftObjectKey{family: "netdev", table: "syswarden_hw_drop", name: population.name}] = count
		}
	}
	return plan
}

func runLinuxFirewallCommand(path string, arguments ...string) ([]byte, error) {
	command := exec.Command(path, arguments...) // #nosec G204 -- path comes from LookPath and all arguments are canonical firewall values
	command.Env = append(command.Environ(), "LC_ALL=C", "LANG=C")
	return command.CombinedOutput()
}

type linuxWrapperRule struct {
	backend string
	kind    string
	value   string
}

func (rule linuxWrapperRule) key() string {
	return rule.backend + "\t" + rule.kind + "\t" + rule.value
}

func canonicalLinuxWrapperRule(backend, kind, value string) (linuxWrapperRule, error) {
	switch backend {
	case "ufw", "firewalld", "iptables", "ip6tables":
	default:
		return linuxWrapperRule{}, fmt.Errorf("unsupported wrapper backend %q", backend)
	}
	rule := linuxWrapperRule{backend: backend, kind: kind}
	switch kind {
	case "port":
		canonical, err := canonicalPort(value)
		if err != nil || canonical != value {
			return linuxWrapperRule{}, fmt.Errorf("invalid wrapper port %q", value)
		}
		rule.value = canonical
	case "source":
		canonical, isIPv4, err := canonicalIPOrPrefix(value)
		if err != nil || canonical != value {
			return linuxWrapperRule{}, fmt.Errorf("invalid wrapper source %q", value)
		}
		if backend == "iptables" && !isIPv4 {
			return linuxWrapperRule{}, fmt.Errorf("IPv6 source %q is assigned to iptables", value)
		}
		if backend == "ip6tables" && isIPv4 {
			return linuxWrapperRule{}, fmt.Errorf("IPv4 source %q is assigned to ip6tables", value)
		}
		rule.value = canonical
	default:
		return linuxWrapperRule{}, fmt.Errorf("unsupported wrapper rule kind %q", kind)
	}
	return rule, nil
}

func readLinuxWrapperState(path string) (map[string]linuxWrapperRule, bool, error) {
	file, err := openRootedNFTFile(path, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return make(map[string]linuxWrapperRule), false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open wrapper ownership state: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("inspect wrapper ownership state: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, false, fmt.Errorf("wrapper ownership state is not a private regular file owned by the effective user")
	}
	const maximumWrapperStateSize = 1 << 20
	if info.Size() < 0 || info.Size() > maximumWrapperStateSize {
		return nil, false, fmt.Errorf("wrapper ownership state exceeds %d bytes", maximumWrapperStateSize)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumWrapperStateSize+1))
	if err != nil {
		return nil, false, fmt.Errorf("read wrapper ownership state: %w", err)
	}
	if len(content) > maximumWrapperStateSize {
		return nil, false, fmt.Errorf("wrapper ownership state exceeds %d bytes", maximumWrapperStateSize)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) == 0 || lines[0] != linuxWrapperStateVersion {
		return nil, false, fmt.Errorf("wrapper ownership state has an unsupported header")
	}
	rules := make(map[string]linuxWrapperRule, len(lines)-1)
	for lineNumber, line := range lines[1:] {
		if line == "" {
			return nil, false, fmt.Errorf("wrapper ownership state line %d is empty", lineNumber+2)
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return nil, false, fmt.Errorf("wrapper ownership state line %d is malformed", lineNumber+2)
		}
		rule, err := canonicalLinuxWrapperRule(fields[0], fields[1], fields[2])
		if err != nil {
			return nil, false, fmt.Errorf("wrapper ownership state line %d: %w", lineNumber+2, err)
		}
		if _, duplicate := rules[rule.key()]; duplicate {
			return nil, false, fmt.Errorf("wrapper ownership state line %d duplicates %s", lineNumber+2, rule.key())
		}
		rules[rule.key()] = rule
	}
	return rules, true, nil
}

func writeLinuxWrapperState(path string, rules map[string]linuxWrapperRule) error {
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var content strings.Builder
	_, _ = content.WriteString(linuxWrapperStateVersion + "\n")
	for _, key := range keys {
		rule := rules[key]
		_, _ = fmt.Fprintf(&content, "%s\t%s\t%s\n", rule.backend, rule.kind, rule.value)
	}
	directory := filepath.Dir(path)
	candidate, err := os.CreateTemp(directory, ".firewall-wrappers-state-")
	if err != nil {
		return fmt.Errorf("create wrapper ownership candidate: %w", err)
	}
	candidatePath := candidate.Name()
	defer func() { _ = os.Remove(candidatePath) }()
	if err := candidate.Chmod(0600); err != nil {
		_ = candidate.Close()
		return fmt.Errorf("protect wrapper ownership candidate: %w", err)
	}
	if _, err := io.WriteString(candidate, content.String()); err != nil {
		_ = candidate.Close()
		return fmt.Errorf("write wrapper ownership candidate: %w", err)
	}
	if err := candidate.Sync(); err != nil {
		_ = candidate.Close()
		return fmt.Errorf("sync wrapper ownership candidate: %w", err)
	}
	if err := candidate.Close(); err != nil {
		return fmt.Errorf("close wrapper ownership candidate: %w", err)
	}
	if err := publishNftablesFile(directory, candidatePath, path); err != nil {
		return fmt.Errorf("publish wrapper ownership state: %w", err)
	}
	return nil
}

func copyLinuxWrapperRules(source map[string]linuxWrapperRule) map[string]linuxWrapperRule {
	destination := make(map[string]linuxWrapperRule, len(source))
	for key, rule := range source {
		destination[key] = rule
	}
	return destination
}

func wrapperCommandPresent(path string, arguments ...string) (bool, error) {
	output, err := runLinuxFirewallCommand(path, arguments...)
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("query %s %s: %w: %s", path, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
}

func ensureWrapperCommand(path string, queryArguments, addArguments []string) (bool, error) {
	present, err := wrapperCommandPresent(path, queryArguments...)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	if output, err := runLinuxFirewallCommand(path, addArguments...); err != nil {
		return false, fmt.Errorf("add wrapper rule through %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	present, err = wrapperCommandPresent(path, queryArguments...)
	if err != nil {
		return false, err
	}
	if !present {
		return false, fmt.Errorf("wrapper rule added through %s but post-verification still reports it absent", path)
	}
	return true, nil
}

func ufwWrapperPresent(path, value string, requireOwnershipMarker bool) (bool, error) {
	output, err := runLinuxFirewallCommand(path, "status")
	if err != nil {
		return false, fmt.Errorf("query ufw wrapper state: %w: %s", err, strings.TrimSpace(string(output)))
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "Status: active" {
		return false, fmt.Errorf("ufw is installed but not active")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		hasValue := false
		hasAllow := false
		for _, field := range fields {
			hasValue = hasValue || field == value
			hasAllow = hasAllow || field == "ALLOW"
		}
		if hasValue && hasAllow {
			if !requireOwnershipMarker || strings.Contains(line, "# SYSWARDEN_CORE") {
				return true, nil
			}
		}
	}
	return false, nil
}

func linuxWrapperRuleArguments(rule linuxWrapperRule, operation string, permanent bool) ([]string, error) {
	switch rule.backend {
	case "iptables", "ip6tables":
		var body []string
		switch rule.kind {
		case "port":
			body = []string{"INPUT", "-p", "tcp", "--dport", rule.value, "-m", "comment", "--comment", "SYSWARDEN_CORE", "-j", "ACCEPT"}
		case "source":
			body = []string{"INPUT", "-s", rule.value, "-m", "comment", "--comment", "SYSWARDEN_CORE", "-j", "ACCEPT"}
		}
		switch operation {
		case "query":
			return append([]string{"-C"}, body...), nil
		case "add":
			return append([]string{"-I", "INPUT", "1"}, body[1:]...), nil
		case "remove":
			return append([]string{"-D"}, body...), nil
		}
	case "firewalld":
		prefix := []string{}
		if permanent {
			prefix = append(prefix, "--permanent")
		}
		var selector string
		if rule.kind == "port" {
			selector = "port=" + rule.value + "/tcp"
		} else {
			prefix = append(prefix, "--zone=trusted")
			selector = "source=" + rule.value
		}
		switch operation {
		case "query":
			return append(prefix, "--query-"+selector), nil
		case "add":
			return append(prefix, "--add-"+selector), nil
		case "remove":
			return append(prefix, "--remove-"+selector), nil
		}
	case "ufw":
		value := rule.value
		arguments := []string{}
		if operation == "remove" {
			arguments = append(arguments, "--force", "delete")
		}
		arguments = append(arguments, "allow")
		if rule.kind == "port" {
			arguments = append(arguments, value+"/tcp")
		} else {
			arguments = append(arguments, "from", value)
		}
		arguments = append(arguments, "comment", "SYSWARDEN_CORE")
		return arguments, nil
	}
	return nil, fmt.Errorf("unsupported %s operation for wrapper rule %s", operation, rule.key())
}

func linuxWrapperRulePresent(rule linuxWrapperRule, path string, owned, permanent bool) (bool, error) {
	if rule.backend == "ufw" {
		value := rule.value
		if rule.kind == "port" {
			value += "/tcp"
		}
		return ufwWrapperPresent(path, value, owned)
	}
	arguments, err := linuxWrapperRuleArguments(rule, "query", permanent)
	if err != nil {
		return false, err
	}
	present, err := wrapperCommandPresent(path, arguments...)
	if err != nil || present || owned || rule.backend != "iptables" && rule.backend != "ip6tables" {
		return present, err
	}
	// A simple operator-owned ACCEPT may predate SysWarden and has no ownership
	// comment. Treat it as sufficient compatibility coverage, but never record
	// or later remove it through the SysWarden ownership manifest.
	var body []string
	if rule.kind == "port" {
		body = []string{"-C", "INPUT", "-p", "tcp", "--dport", rule.value, "-j", "ACCEPT"}
	} else {
		body = []string{"-C", "INPUT", "-s", rule.value, "-j", "ACCEPT"}
	}
	return wrapperCommandPresent(path, body...)
}

func ensureLinuxWrapperRule(rule linuxWrapperRule, path string) (bool, error) {
	if rule.backend == "ufw" {
		present, err := linuxWrapperRulePresent(rule, path, true, false)
		if err != nil || present {
			return false, err
		}
		arguments, err := linuxWrapperRuleArguments(rule, "add", false)
		if err != nil {
			return false, err
		}
		if output, err := runLinuxFirewallCommand(path, arguments...); err != nil {
			return false, fmt.Errorf("add ufw wrapper rule: %w: %s", err, strings.TrimSpace(string(output)))
		}
		present, err = linuxWrapperRulePresent(rule, path, true, false)
		if err != nil || !present {
			return false, errors.Join(err, fmt.Errorf("ufw wrapper post-verification still reports %s absent", rule.value))
		}
		return true, nil
	}
	query, err := linuxWrapperRuleArguments(rule, "query", true)
	if err != nil {
		return false, err
	}
	add, err := linuxWrapperRuleArguments(rule, "add", true)
	if err != nil {
		return false, err
	}
	return ensureWrapperCommand(path, query, add)
}

func removeLinuxWrapperRule(rule linuxWrapperRule, path string) (bool, error) {
	removed := false
	for attempt := 0; attempt < 256; attempt++ {
		present, err := linuxWrapperRulePresent(rule, path, true, true)
		if err != nil {
			return removed, err
		}
		if !present {
			return removed, nil
		}
		arguments, err := linuxWrapperRuleArguments(rule, "remove", true)
		if err != nil {
			return removed, err
		}
		if output, err := runLinuxFirewallCommand(path, arguments...); err != nil {
			return removed, fmt.Errorf("remove wrapper rule %s through %s: %w: %s", rule.key(), path, err, strings.TrimSpace(string(output)))
		}
		removed = true
		if rule.backend == "firewalld" {
			present, err = linuxWrapperRulePresent(rule, path, true, true)
			if err != nil || present {
				return removed, errors.Join(err, fmt.Errorf("firewalld permanent rule %s remains after removal", rule.key()))
			}
			return removed, nil
		}
	}
	return removed, fmt.Errorf("refuse more than 256 duplicate removals for wrapper rule %s", rule.key())
}

func discoverLinuxWrapperPaths() map[string]string {
	paths := make(map[string]string)
	for backend, executable := range map[string]string{
		"ufw":       "ufw",
		"firewalld": "firewall-cmd",
		"iptables":  "iptables",
		"ip6tables": "ip6tables",
	} {
		if path, err := exec.LookPath(executable); err == nil {
			paths[backend] = path
		}
	}
	return paths
}

func desiredLinuxWrapperRules(trustedSubnets, ports []string, paths map[string]string) (map[string]linuxWrapperRule, error) {
	rules := make(map[string]linuxWrapperRule)
	appendRule := func(backend, kind, value string) error {
		rule, err := canonicalLinuxWrapperRule(backend, kind, value)
		if err != nil {
			return err
		}
		rules[rule.key()] = rule
		return nil
	}
	for _, port := range ports {
		canonical, err := canonicalPort(port)
		if err != nil {
			return nil, err
		}
		for _, backend := range []string{"ufw", "firewalld", "iptables"} {
			if _, available := paths[backend]; available {
				if err := appendRule(backend, "port", canonical); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, subnet := range trustedSubnets {
		canonical, isIPv4, err := canonicalIPOrPrefix(subnet)
		if err != nil {
			return nil, err
		}
		for _, backend := range []string{"ufw", "firewalld"} {
			if _, available := paths[backend]; available {
				if err := appendRule(backend, "source", canonical); err != nil {
					return nil, err
				}
			}
		}
		backend := "ip6tables"
		if isIPv4 {
			backend = "iptables"
		}
		if _, available := paths[backend]; available {
			if err := appendRule(backend, "source", canonical); err != nil {
				return nil, err
			}
		}
	}
	return rules, nil
}

func applyLinuxFirewallWrappers(trustedSubnets, ports []string) error {
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return fmt.Errorf("acquire wrapper reconciliation lock: %w", err)
	}
	defer releaseNFTReloadGuard(lock)
	return applyLinuxFirewallWrappersLocked(trustedSubnets, ports)
}

func applyLinuxFirewallWrappersLocked(trustedSubnets, ports []string) error {
	paths := discoverLinuxWrapperPaths()
	desired, err := desiredLinuxWrapperRules(trustedSubnets, ports, paths)
	if err != nil {
		return fmt.Errorf("prepare wrapper rules: %w", err)
	}
	previous, stateExists, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return err
	}
	if len(desired) == 0 && len(previous) == 0 {
		return nil
	}

	var preflightErrs []error
	for _, rule := range previous {
		if _, available := paths[rule.backend]; !available {
			preflightErrs = append(preflightErrs, fmt.Errorf("cannot reconcile owned %s rule because its executable is unavailable", rule.backend))
		}
	}
	finalOwned := make(map[string]linuxWrapperRule)
	pendingOwned := copyLinuxWrapperRules(previous)
	preexisting := make(map[string]linuxWrapperRule)
	for key, rule := range desired {
		if _, owned := previous[key]; owned {
			finalOwned[key] = rule
			continue
		}
		path := paths[rule.backend]
		present, queryErr := linuxWrapperRulePresent(rule, path, false, true)
		if queryErr != nil {
			preflightErrs = append(preflightErrs, fmt.Errorf("preflight wrapper rule %s: %w", key, queryErr))
			continue
		}
		if present {
			preexisting[key] = rule
			continue
		}
		pendingOwned[key] = rule
		finalOwned[key] = rule
	}
	if err := errors.Join(preflightErrs...); err != nil {
		return err
	}
	if !stateExists || len(pendingOwned) > 0 {
		if err := writeLinuxWrapperState(linuxWrapperStateFile, pendingOwned); err != nil {
			return err
		}
	}

	var errs []error
	staleFirewalld := false
	for key, rule := range previous {
		if _, stillDesired := desired[key]; stillDesired {
			continue
		}
		if rule.backend == "firewalld" {
			staleFirewalld = true
		}
		if _, removeErr := removeLinuxWrapperRule(rule, paths[rule.backend]); removeErr != nil {
			errs = append(errs, removeErr)
		}
	}
	for key, rule := range desired {
		if _, existedWithoutOwnership := preexisting[key]; existedWithoutOwnership {
			present, queryErr := linuxWrapperRulePresent(rule, paths[rule.backend], false, true)
			if queryErr != nil || !present {
				errs = append(errs, errors.Join(queryErr, fmt.Errorf("pre-existing wrapper rule %s disappeared during reconciliation", key)))
			}
			continue
		}
		if _, ensureErr := ensureLinuxWrapperRule(rule, paths[rule.backend]); ensureErr != nil {
			errs = append(errs, ensureErr)
		}
	}

	_, hasFirewalld := paths["firewalld"]
	if hasFirewalld && (staleFirewalld || len(desired) > 0 || len(previous) > 0) {
		if output, reloadErr := runLinuxFirewallCommand(paths["firewalld"], "--reload"); reloadErr != nil {
			errs = append(errs, fmt.Errorf("reload firewalld wrapper state: %w: %s", reloadErr, strings.TrimSpace(string(output))))
		} else {
			for key, rule := range desired {
				if rule.backend != "firewalld" {
					continue
				}
				present, queryErr := linuxWrapperRulePresent(rule, paths["firewalld"], false, false)
				if queryErr != nil || !present {
					errs = append(errs, errors.Join(queryErr, fmt.Errorf("firewalld runtime rule %s is not active after reload", key)))
				}
			}
			for key, rule := range previous {
				if rule.backend != "firewalld" {
					continue
				}
				if _, stillDesired := desired[key]; stillDesired {
					continue
				}
				present, queryErr := linuxWrapperRulePresent(rule, paths["firewalld"], false, false)
				if queryErr != nil || present {
					errs = append(errs, errors.Join(queryErr, fmt.Errorf("stale firewalld runtime rule %s remains after reload", key)))
				}
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := writeLinuxWrapperState(linuxWrapperStateFile, finalOwned); err != nil {
		return err
	}
	return nil
}
