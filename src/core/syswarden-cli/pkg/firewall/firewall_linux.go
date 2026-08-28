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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
	"time"
)

const (
	linuxWrapperStateVersion       = "syswarden-firewall-wrappers-v3"
	zonedLinuxWrapperStateVersion  = "syswarden-firewall-wrappers-v2"
	legacyLinuxWrapperStateVersion = "syswarden-firewall-wrappers-v1"
	firewalldSourceZone            = "trusted"
	maximumFirewallCommandOutput   = 64 << 10
	firewallCommandTimeout         = 15 * time.Second
)

const (
	saasPairManifestFile          = "syswarden_saas_monitors.pair"
	saasPairManifestV1            = "syswarden-saas-pair-v1"
	maximumSaaSListBytes          = 1 << 20
	maximumLegacySaaSListEntries  = 10000
	saasLegacyAdoptionEnvironment = "SYSWARDEN_PKG_INSTALL"
)

var linuxWrapperStateFile = filepath.Join(nftStateDirectory, "firewall-wrappers.state")

var linuxWrapperExecutableValidator = validateResolvedLinuxWrapperExecutable

var linuxWrapperCommandEnvironment = fixedLinuxWrapperCommandEnvironment

var firewallBackendPreflight = system.PreflightHostFirewallBackend

var firewallCleanupEffectiveUserID = os.Geteuid

var uninstallNFTRunnerFactory = newExecNFTCommandRunner

var firewallRecoveryNFTRunnerFactory = newExecNFTCommandRunner

var firewallRemovalServiceReattest = system.ReattestFirewallStatePreparedForRemoval

var applyLinuxFirewallWrappersForUninstall = applyLinuxFirewallWrappersLocked

func fixedLinuxWrapperCommandEnvironment() []string {
	return []string{
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	}
}

func configuredLinuxFirewallBackend() (string, error) {
	backend := "keep"
	if config.GlobalConfig != nil && config.GlobalConfig.FirewallBackend != "" {
		backend = config.GlobalConfig.FirewallBackend
	}
	switch backend {
	case "keep", "nftables":
		return backend, nil
	case "iptables":
		return "", fmt.Errorf("iptables is accepted for configuration compatibility but refused for firewall mutations")
	default:
		return "", fmt.Errorf("unsupported firewall backend %q", backend)
	}
}

func preflightConfiguredFirewallBackendMutation() (string, error) {
	backend, err := configuredLinuxFirewallBackend()
	if err != nil {
		return "", err
	}
	if err := firewallBackendPreflight(backend); err != nil {
		return "", fmt.Errorf("attest configured firewall backend %s: %w", backend, err)
	}
	return backend, nil
}

// PreflightConfiguredBackendMutation attests the configured firewall backend
// before a command changes persistent policy inputs or kernel state.
func PreflightConfiguredBackendMutation() error {
	_, err := preflightConfiguredFirewallBackendMutation()
	return err
}

// RecoverPendingAuthoritativeTransaction resolves an interrupted nftables
// commit before callers inspect or mutate any new configuration input. The
// final transaction path repeats this check under its own lock, closing the
// race with another process that may start after this early barrier.
func RecoverPendingAuthoritativeTransaction() error {
	return recoverPendingAuthoritativeTransactionAt(nftStateDirectory, firewallRecoveryNFTRunnerFactory)
}

func recoverPendingAuthoritativeTransactionAt(
	stateDirectory string,
	runnerFactory func() (nftCommandRunner, error),
) error {
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return fmt.Errorf("acquire early firewall recovery lock: %w", err)
	}
	defer releaseNFTReloadGuard(lock)

	if _, err := os.Lstat(stateDirectory); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect early firewall recovery directory: %w", err)
	}
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return fmt.Errorf("attest early firewall recovery directory: %w", err)
	}
	if _, err := os.Lstat(nftTransactionJournalPath(stateDirectory)); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect early firewall recovery journal: %w", err)
	}
	if runnerFactory == nil {
		return fmt.Errorf("prepare early firewall recovery runner: factory is nil")
	}
	runner, err := runnerFactory()
	if err != nil {
		return fmt.Errorf("prepare early firewall recovery runner: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := recoverPendingNftablesTransaction(ctx, runner, stateDirectory); err != nil {
		return fmt.Errorf("recover interrupted authoritative firewall transaction before new preparation: %w", err)
	}
	return nil
}

// CleanupOwnedCompatibilityRulesForUninstall removes only compatibility
// permissions proven by the ownership manifest. Any unavailable or ambiguous
// frontend leaves the manifest intact and aborts the caller's uninstall.
func CleanupOwnedCompatibilityRulesForUninstall() error {
	if firewallCleanupEffectiveUserID() != 0 {
		return fmt.Errorf("compatibility wrapper cleanup requires root")
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return fmt.Errorf("acquire uninstall firewall cleanup lock: %w", err)
	}
	defer releaseNFTReloadGuard(lock)
	if err := firewallRemovalServiceReattest(); err != nil {
		return fmt.Errorf("reattest stopped firewall mutators before cleanup: %w", err)
	}
	if err := applyLinuxFirewallWrappersForUninstall(nil, nil); err != nil {
		return fmt.Errorf("clean owned compatibility wrapper permissions: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return fmt.Errorf("prepare nftables uninstall runner: %w", err)
	}
	if err := cleanupReservedNFTablesForUninstall(ctx, runner); err != nil {
		return fmt.Errorf("clean reserved SysWarden nftables tables: %w", err)
	}
	if err := firewallRemovalServiceReattest(); err != nil {
		return fmt.Errorf("reattest stopped firewall mutators after cleanup: %w", err)
	}
	return nil
}

func validateLinuxWrapperBackendConstraint(backend string, activePaths map[string]string) error {
	switch backend {
	case "keep":
		return nil
	case "nftables":
		if len(activePaths) == 0 {
			return nil
		}
		names := make([]string, 0, len(activePaths))
		for name := range activePaths {
			names = append(names, name)
		}
		sort.Strings(names)
		return fmt.Errorf("explicit nftables backend forbids active compatibility frontends: %s", strings.Join(names, ", "))
	default:
		return fmt.Errorf("unsupported prepared firewall backend %q", backend)
	}
}

// ApplyPolicies triggers the main Linux firewall injection using native Netlink / CLI Nftables
func ApplyPolicies() error {
	if err := RecoverPendingAuthoritativeTransaction(); err != nil {
		return err
	}
	firewallBackend, err := preflightConfiguredFirewallBackendMutation()
	if err != nil {
		return err
	}
	if err := config.ValidateOperatorPolicy(config.GlobalConfig.OperatorPolicy); err != nil {
		return fmt.Errorf("validate operator policy before firewall mutation: %w", err)
	}
	if err := config.ReattestOperatorPolicySource(config.GlobalConfig); err != nil {
		return fmt.Errorf("reattest operator policy source before firewall mutation: %w", err)
	}
	operatorPolicy, err := compileOperatorPolicy(config.GlobalConfig.OperatorPolicy.Rules)
	if err != nil {
		return fmt.Errorf("compile operator policy: %w", err)
	}
	strictAllow := normalizeStrictAllowConfiguration(
		config.GlobalConfig.GeoAllowed,
		config.GlobalConfig.ASNAllowed,
	)
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

	// The operator-owned chain is always present so reloads and upgrades retain
	// one stable topology. It can only return to the product-owned input chain.
	_, _ = nftRules.WriteString(operatorPolicy.chain)

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
	appendStrictAllowInputRules(&nftRules, strictAllow.configured, validLANSubnets4, validLANSubnets6)
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

	// Explicitly trust internal private subnets (Bypass Catch-All)
	if len(validLANSubnets4) > 0 || len(validLANSubnets6) > 0 {
		_, _ = nftRules.WriteString("\t\t# Explicitly trust internal private subnets (Bypass Catch-All)\n")
		if len(validLANSubnets4) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets4, ", "))
		}
		if len(validLANSubnets6) > 0 {
			_, _ = fmt.Fprintf(&nftRules, "\t\tip6 saddr { %s } accept\n", strings.Join(validLANSubnets6, ", "))
		}
	}

	// Operator policy is deliberately the final permission surface. Mandatory
	// product refusals and every existing permission path run first; a non-match
	// returns here and still reaches the product-owned catch-all deny below.
	_, _ = nftRules.WriteString(operatorPolicyDispatchRule())

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
	appendStrictAllowForwardRules(&nftRules, strictAllow.configured)
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

		// ARP Flood limits adapted for the local-network profile (500/s burst 1000)
		_, _ = nftRules.WriteString("\t\tarp operation request limit rate over 500/second burst 1000 packets counter log prefix \"[SYSWARDEN-ARP-FLOOD] \" drop\n")
		_, _ = nftRules.WriteString("\t}\n}\n\n")
	}

	// Prepare every set before the single kernel transaction. No firewall or
	// wrapper state has been mutated when this phase returns an error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	populations, err := prepareNftSetPopulations(ctx, sshPort, strictAllow)
	if err != nil {
		return fmt.Errorf("failed to prepare nftables sets: %w", err)
	}
	verification := buildNftVerificationPlan(populations, config.GlobalConfig.ArpProtect, operatorPolicy.verificationPlan())
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		return fmt.Errorf("prepare authoritative nftables runner: %w", err)
	}
	var wrapperPlan *linuxWrapperReconciliationPlan
	transactionID, err := applyNftablesPolicyWithWrappers(
		ctx,
		runner,
		nftStateDirectory,
		nftRules.String(),
		populations,
		verification,
		func() error {
			var prepareErr error
			wrapperPlan, prepareErr = prepareLinuxFirewallWrapperReconciliationForBackend(firewallBackend, validLANSubnets, wrapperPorts)
			if prepareErr != nil {
				return prepareErr
			}
			return validateOperatorPolicyWrapperCompatibility(operatorPolicy, wrapperPlan.paths)
		},
		func() error {
			if err := config.ValidateOperatorPolicy(config.GlobalConfig.OperatorPolicy); err != nil {
				return fmt.Errorf("revalidate operator policy at commit boundary: %w", err)
			}
			if err := config.ReattestOperatorPolicySource(config.GlobalConfig); err != nil {
				return fmt.Errorf("reattest operator policy source at commit boundary: %w", err)
			}
			if err := firewallBackendPreflight(firewallBackend); err != nil {
				return fmt.Errorf("reattest configured firewall backend before commit: %w", err)
			}
			return reattestLinuxWrapperPlan(wrapperPlan)
		},
		func() error { return reconcileLinuxFirewallWrapperPlan(wrapperPlan) },
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

func applyNftablesPolicyWithWrappers(
	ctx context.Context,
	runner nftCommandRunner,
	stateDirectory, baseRules string,
	populations []nftSetPopulation,
	verification nftVerificationPlan,
	preflightWrappers, precommitWrappers, reconcileWrappers func() error,
) (string, error) {
	transactionID, err := newFirewallTransactionID()
	if err != nil {
		return "", err
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: acquire reload lock: %w", transactionID, err)
	}
	defer releaseNFTReloadGuard(lock)
	if err := os.MkdirAll(stateDirectory, 0750); err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s cannot prepare recovery state: %w", transactionID, err)
	}
	if err := attestNFTStateDirectory(stateDirectory); err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s cannot attest recovery state: %w", transactionID, err)
	}
	if err := recoverPendingNftablesTransaction(ctx, runner, stateDirectory); err != nil {
		return transactionID, fmt.Errorf("firewall transaction %s cannot recover an interrupted authoritative transaction: %w", transactionID, err)
	}
	if preflightWrappers != nil {
		if err := preflightWrappers(); err != nil {
			return transactionID, fmt.Errorf("firewall transaction %s preserved the previous ruleset: compatibility wrapper preflight: %w", transactionID, err)
		}
	}
	transactionID, err = applyNftablesTransactionLocked(ctx, runner, stateDirectory, baseRules, populations, verification, transactionID, precommitWrappers)
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

func prepareNftSetPopulations(
	ctx context.Context,
	effectiveSSHPort string,
	strictAllow strictAllowConfiguration,
) ([]nftSetPopulation, error) {
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

	ztASN4, ztASN6, ztASNSourceErr := configuredASNNftSources(listDirectory, strictAllow.asns, true)
	asn4, asn6, asnErr := configuredASNNftSources(listDirectory, config.GlobalConfig.ASNList, false)
	whitelistAddress4, whitelistPorts4, whitelist4Err := populateWhitelistSets(ctx, whitelist4, "syswarden_whitelist", "syswarden_whitelist_ports")
	whitelistAddress6, whitelistPorts6, whitelist6Err := populateWhitelistSets(ctx, whitelist6, "syswarden_whitelist6", "syswarden_whitelist_ports6")
	sshBypass4, sshBypass6, sshBypassErr := populateSSHBypassSets(ctx, nftListSource{path: SSHBypass}, effectiveSSHPort)
	ztASN4Population, ztASN4Err := populateSet(ctx, ztASN4, "syswarden_zt_allowed")
	ztASN6Population, ztASN6Err := populateSet(ctx, ztASN6, "syswarden_zt_allowed6")
	ztGeo4Population := nftSetPopulation{name: "syswarden_zt_allowed"}
	ztGeo6Population := nftSetPopulation{name: "syswarden_zt_allowed6"}
	var ztGeoErr error
	if strictAllow.countries != "" {
		ztGeo4Population, ztGeo6Population, ztGeoErr = configuredAuthenticatedGeoIPPopulations(
			strictAllow.countries,
			"syswarden_zt_allowed",
			"syswarden_zt_allowed6",
		)
	}
	zt4Population, zt4MergeErr := mergeNFTAddressPopulations("syswarden_zt_allowed", ztASN4Population, ztGeo4Population)
	zt6Population, zt6MergeErr := mergeNFTAddressPopulations("syswarden_zt_allowed6", ztASN6Population, ztGeo6Population)
	strictAllowPopulationErr := validateStrictAllowPopulations(
		strictAllow.configured,
		zt4Population,
		zt6Population,
	)
	blacklist4Population, blacklist4Err := populateSet(ctx, blacklist4, "syswarden_blacklist")
	blacklist6Population, blacklist6Err := populateSet(ctx, blacklist6, "syswarden_blacklist6")
	geoEnabled := config.GlobalConfig.EnableGeo && config.GlobalConfig.GeoCodes != ""
	geo4Population := nftSetPopulation{name: "syswarden_geoip"}
	geo6Population := nftSetPopulation{name: "syswarden_geoip6"}
	var geoErr error
	if geoEnabled {
		geo4Population, geo6Population, geoErr = configuredAuthenticatedGeoIPPopulations(
			config.GlobalConfig.GeoCodes,
			"syswarden_geoip",
			"syswarden_geoip6",
		)
	}

	populations := []nftSetPopulation{
		whitelistAddress4,
		whitelistAddress6,
		whitelistPorts4,
		whitelistPorts6,
		sshBypass4,
		sshBypass6,
		zt4Population,
		zt6Population,
		blacklist4Population,
		blacklist6Population,
	}
	if geoEnabled {
		populations = append(populations, geo4Population, geo6Population)
	}
	var asn4Err, asn6Err error
	if config.GlobalConfig.EnableASN && config.GlobalConfig.ASNList != "" {
		asn4Population, err := populateSet(ctx, asn4, "syswarden_asn")
		populations = append(populations, asn4Population)
		asn4Err = err
		asn6Population, err := populateSet(ctx, asn6, "syswarden_asn6")
		populations = append(populations, asn6Population)
		asn6Err = err
	}
	errs := []error{
		ztASNSourceErr, ztASN4Err, ztASN6Err, ztGeoErr, zt4MergeErr, zt6MergeErr, strictAllowPopulationErr,
		blacklist4Err, blacklist6Err, geoErr, asnErr, asn4Err, asn6Err,
		saasPairErr, whitelist4Err, whitelist6Err, sshBypassErr,
	}
	return populations, errors.Join(errs...)
}

func validateStrictAllowPopulations(configured bool, ipv4, ipv6 nftSetPopulation) error {
	if !configured || len(ipv4.entries) > 0 || len(ipv6.entries) > 0 {
		return nil
	}
	return fmt.Errorf("strict allow policy is configured but the merged GeoIP and ASN allow populations are empty for both IPv4 and IPv6")
}

type strictAllowConfiguration struct {
	countries  string
	asns       string
	configured bool
}

func normalizeStrictAllowConfiguration(countries, asns string) strictAllowConfiguration {
	normalizedCountries := authenticatedGeoIPCountryInput(countries)
	normalizedASNs := authenticatedASNInput(asns)
	return strictAllowConfiguration{
		countries:  normalizedCountries,
		asns:       normalizedASNs,
		configured: normalizedCountries != "" || normalizedASNs != "",
	}
}

func hasConfiguredStrictAllowSelection(countries, asns string) bool {
	return normalizeStrictAllowConfiguration(countries, asns).configured
}

func authenticatedASNInput(raw string) string {
	selected := make([]string, 0)
	for _, candidate := range strings.Fields(strings.ReplaceAll(raw, ",", " ")) {
		if !strings.EqualFold(candidate, "none") && !strings.EqualFold(candidate, "auto") {
			selected = append(selected, candidate)
		}
	}
	return strings.Join(selected, " ")
}

func appendStrictAllowInputRules(
	nftRules *strings.Builder,
	configured bool,
	validLANSubnets4 []string,
	validLANSubnets6 []string,
) {
	if !configured {
		return
	}
	// LAN Bypass: Explicitly allow internal private subnets to bypass Zero-Trust.
	if len(validLANSubnets4) > 0 {
		_, _ = fmt.Fprintf(nftRules, "\t\tip saddr { %s } accept\n", strings.Join(validLANSubnets4, ", "))
	}
	if len(validLANSubnets6) > 0 {
		_, _ = fmt.Fprintf(nftRules, "\t\tip6 saddr { %s } accept\n", strings.Join(validLANSubnets6, ", "))
	}
	_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
	_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 limit rate 2/second burst 5 packets log prefix \"[SYSWARDEN-ZERO-TRUST] \"\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 drop\n")
}

func appendStrictAllowForwardRules(nftRules *strings.Builder, configured bool) {
	if !configured {
		return
	}
	_, _ = nftRules.WriteString("\t\tip saddr != @syswarden_zt_allowed counter drop\n")
	_, _ = nftRules.WriteString("\t\tip6 saddr != @syswarden_zt_allowed6 counter drop\n")
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
	return maybeAdoptLegacySaaSListPairWithPolicy(
		directory,
		enabled,
		currentLegacySaaSNetworkPolicy,
	)
}

func maybeAdoptLegacySaaSListPairWithPolicy(
	directory string,
	enabled bool,
	policyProvider func() (legacySaaSNetworkPolicy, error),
) (bool, error) {
	if !enabled || os.Getenv(saasLegacyAdoptionEnvironment) != "1" {
		return false, nil
	}
	policy, err := policyProvider()
	if err != nil {
		return false, err
	}
	return adoptLegacySaaSListPairWithPolicy(directory, policy)
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

type legacySaaSNetworkPolicy struct {
	localAddresses    []netip.Addr
	protectedPrefixes []netip.Prefix
}

func currentLegacySaaSNetworkPolicy() (legacySaaSNetworkPolicy, error) {
	policy := legacySaaSNetworkPolicy{}
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return policy, fmt.Errorf("enumerate local interfaces for legacy SaaS adoption: %w", err)
	}
	for _, raw := range interfaceAddresses {
		var addressBytes net.IP
		switch value := raw.(type) {
		case *net.IPNet:
			addressBytes = value.IP
		case *net.IPAddr:
			addressBytes = value.IP
		default:
			return policy, fmt.Errorf("unsupported local interface address type %T", raw)
		}
		address, ok := netip.AddrFromSlice(addressBytes)
		if !ok {
			return policy, fmt.Errorf("invalid local interface address %q", raw.String())
		}
		policy.localAddresses = append(policy.localAddresses, address.Unmap())
	}
	if config.GlobalConfig == nil {
		return policy, fmt.Errorf("validated configuration is unavailable for legacy SaaS adoption")
	}
	for _, raw := range strings.Fields(strings.ReplaceAll(config.GlobalConfig.HAPeerIP, ",", " ")) {
		canonical, err := config.CanonicalHAPeer(raw)
		if err != nil {
			return policy, fmt.Errorf("validate protected HA peer for legacy SaaS adoption: %w", err)
		}
		if address, parseErr := netip.ParseAddr(canonical); parseErr == nil {
			policy.protectedPrefixes = append(
				policy.protectedPrefixes,
				netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()),
			)
			continue
		}
		prefix, parseErr := netip.ParsePrefix(canonical)
		if parseErr != nil {
			return policy, fmt.Errorf("parse protected HA peer for legacy SaaS adoption: %w", parseErr)
		}
		policy.protectedPrefixes = append(policy.protectedPrefixes, prefix.Masked())
	}
	return policy, nil
}

func readLegacySaaSListComponent(directory *os.Root, target approvedListFile, wantIPv4 bool, policy legacySaaSNetworkPolicy) ([]byte, bool, int, error) {
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
	entries, err := validateCanonicalLegacySaaSList(target.name, content, wantIPv4, policy)
	if err != nil {
		return nil, false, 0, err
	}
	return content, true, entries, nil
}

func validateCanonicalLegacySaaSList(name string, content []byte, wantIPv4 bool, policy legacySaaSNetworkPolicy) (int, error) {
	lines := strings.Split(string(content), "\n")
	entries := 0
	for index, line := range lines {
		if line == "" && index == len(lines)-1 {
			continue
		}
		if line == "" || strings.TrimSpace(line) != line || strings.HasPrefix(line, "#") {
			return 0, fmt.Errorf("legacy SaaS list %s:%d is not in canonical one-entry-per-line form", name, index+1)
		}
		canonical, isIPv4, prefix, err := canonicalSaaSMonitorNetwork(line)
		if err != nil {
			return 0, fmt.Errorf("legacy SaaS list %s:%d: %w", name, index+1, err)
		}
		if canonical != line {
			return 0, fmt.Errorf("legacy SaaS list %s:%d is not canonical", name, index+1)
		}
		if isIPv4 != wantIPv4 {
			return 0, fmt.Errorf("legacy SaaS list %s:%d has the wrong address family", name, index+1)
		}
		for _, local := range policy.localAddresses {
			if prefix.Contains(local.Unmap()) {
				return 0, fmt.Errorf("legacy SaaS list %s:%d contains a local interface address", name, index+1)
			}
		}
		for _, protected := range policy.protectedPrefixes {
			if networkPrefixesOverlap(prefix, protected) {
				return 0, fmt.Errorf("legacy SaaS list %s:%d overlaps a protected HA peer", name, index+1)
			}
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

func adoptLegacySaaSListPairWithPolicy(directoryPath string, policy legacySaaSNetworkPolicy) (bool, error) {
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

	ipv4Content, ipv4Exists, ipv4Entries, err := readLegacySaaSListComponent(directory, ipv4Target, true, policy)
	if err != nil {
		return false, err
	}
	if !ipv4Exists {
		return false, fmt.Errorf("legacy SaaS adoption requires the historical IPv4 list")
	}
	ipv6Content, ipv6Exists, ipv6Entries, err := readLegacySaaSListComponent(directory, ipv6Target, false, policy)
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

func configuredASNNftSources(directory, asns string, allowed bool) ([]nftListSource, []nftListSource, error) {
	var ipv4 []nftListSource
	var ipv6 []nftListSource
	var errs []error
	prefix := ""
	if allowed {
		prefix = "allowed_"
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

func isASCIIDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func buildNftVerificationPlan(populations []nftSetPopulation, arpProtect bool, operatorPolicy operatorPolicyVerification) nftVerificationPlan {
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
		sets:           make(map[nftObjectKey]int),
		operatorPolicy: operatorPolicy,
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

type boundedFirewallCommandOutput struct {
	content  bytes.Buffer
	exceeded bool
}

func (output *boundedFirewallCommandOutput) Write(content []byte) (int, error) {
	remaining := maximumFirewallCommandOutput - output.content.Len()
	if remaining > 0 {
		written := len(content)
		if written > remaining {
			written = remaining
		}
		_, _ = output.content.Write(content[:written])
	}
	if len(content) > remaining {
		output.exceeded = true
	}
	return len(content), nil
}

func runLinuxFirewallCommand(path string, arguments ...string) ([]byte, error) {
	return runLinuxFirewallCommandWithTimeout(path, firewallCommandTimeout, arguments...)
}

func runLinuxFirewallCommandWithTimeout(path string, timeout time.Duration, arguments ...string) ([]byte, error) {
	if err := linuxWrapperExecutableValidator(path); err != nil {
		return nil, err
	}
	if timeout <= 0 || timeout > firewallCommandTimeout {
		return nil, fmt.Errorf("invalid firewall wrapper command timeout %s", timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...) // #nosec G204 -- path is a validated resolved executable and all arguments are canonical firewall values
	command.Env = linuxWrapperCommandEnvironment()
	command.WaitDelay = time.Second
	output := &boundedFirewallCommandOutput{}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	content := append([]byte(nil), output.content.Bytes()...)
	if output.exceeded {
		return content, fmt.Errorf("firewall wrapper command output exceeds %d bytes", maximumFirewallCommandOutput)
	}
	if ctx.Err() != nil {
		return content, fmt.Errorf("firewall wrapper command exceeded %s: %w", timeout, ctx.Err())
	}
	return content, err
}

func validateResolvedLinuxWrapperExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("wrapper executable path %q is not a clean absolute path", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect wrapper executable %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 || !ok {
		return fmt.Errorf("wrapper executable %s is not a trusted non-writable regular executable", path)
	}
	if stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("wrapper executable %s is not owned by root or the effective user", path)
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil {
			return fmt.Errorf("inspect wrapper executable directory %s: %w", directory, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		writable := info.Mode().Perm()&0022 != 0
		if !info.IsDir() || !ok || writable {
			return fmt.Errorf("wrapper executable directory %s is not trusted", directory)
		}
		if stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) {
			return fmt.Errorf("wrapper executable directory %s is not owned by root or the effective user", directory)
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func resolveLinuxWrapperExecutable(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("wrapper executable path %q is not absolute", path)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve wrapper executable %s: %w", path, err)
	}
	resolved = filepath.Clean(resolved)
	if err := linuxWrapperExecutableValidator(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

type linuxWrapperRule struct {
	backend string
	kind    string
	value   string
	zone    string
	pending bool
}

func (rule linuxWrapperRule) key() string {
	zone := rule.zone
	if zone == "" {
		zone = "-"
	}
	return rule.backend + "\t" + rule.kind + "\t" + rule.value + "\t" + zone
}

func canonicalLinuxWrapperRule(backend, kind, value, zone string) (linuxWrapperRule, error) {
	switch backend {
	case "ufw", "firewalld", "iptables", "ip6tables":
	default:
		return linuxWrapperRule{}, fmt.Errorf("unsupported wrapper backend %q", backend)
	}
	rule := linuxWrapperRule{backend: backend, kind: kind}
	if backend == "firewalld" {
		if err := validateFirewalldZone(zone); err != nil {
			return linuxWrapperRule{}, err
		}
		rule.zone = zone
	} else if zone != "-" && zone != "" {
		return linuxWrapperRule{}, fmt.Errorf("non-firewalld wrapper %s has unexpected zone %q", backend, zone)
	}
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

func validateFirewalldZone(zone string) error {
	if len(zone) == 0 || len(zone) > 64 {
		return fmt.Errorf("invalid firewalld zone %q", zone)
	}
	for index, character := range zone {
		isLetter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isLetter && !isDigit && character != '_' && character != '-' {
			return fmt.Errorf("invalid firewalld zone %q", zone)
		}
		if index == 0 && !isLetter && !isDigit {
			return fmt.Errorf("invalid firewalld zone %q", zone)
		}
	}
	return nil
}

func readLinuxWrapperState(path string) (map[string]linuxWrapperRule, bool, bool, error) {
	file, err := openRootedNFTFile(path, os.O_RDONLY, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return make(map[string]linuxWrapperRule), false, false, nil
	}
	if err != nil {
		return nil, false, false, fmt.Errorf("open wrapper ownership state: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, false, false, fmt.Errorf("inspect wrapper ownership state: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, false, false, fmt.Errorf("wrapper ownership state is not a private regular file owned by the effective user")
	}
	const maximumWrapperStateSize = 1 << 20
	if info.Size() < 0 || info.Size() > maximumWrapperStateSize {
		return nil, false, false, fmt.Errorf("wrapper ownership state exceeds %d bytes", maximumWrapperStateSize)
	}
	content, err := io.ReadAll(io.LimitReader(file, maximumWrapperStateSize+1))
	if err != nil {
		return nil, false, false, fmt.Errorf("read wrapper ownership state: %w", err)
	}
	if len(content) > maximumWrapperStateSize {
		return nil, false, false, fmt.Errorf("wrapper ownership state exceeds %d bytes", maximumWrapperStateSize)
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	if len(lines) == 0 ||
		lines[0] != linuxWrapperStateVersion &&
			lines[0] != zonedLinuxWrapperStateVersion &&
			lines[0] != legacyLinuxWrapperStateVersion {
		return nil, false, false, fmt.Errorf("wrapper ownership state has an unsupported header")
	}
	legacy := lines[0] == legacyLinuxWrapperStateVersion
	zoned := lines[0] == zonedLinuxWrapperStateVersion
	rules := make(map[string]linuxWrapperRule, len(lines)-1)
	for lineNumber, line := range lines[1:] {
		if line == "" {
			return nil, false, false, fmt.Errorf("wrapper ownership state line %d is empty", lineNumber+2)
		}
		fields := strings.Split(line, "\t")
		wantFields := 5
		if legacy {
			wantFields = 3
		} else if zoned {
			wantFields = 4
		}
		if len(fields) != wantFields {
			return nil, false, false, fmt.Errorf("wrapper ownership state line %d is malformed", lineNumber+2)
		}
		zone := "-"
		if legacy {
			if fields[0] == "firewalld" {
				return nil, false, false, fmt.Errorf(
					"legacy firewalld %s ownership at line %d has no explicit zone; verified cleanup or migration is required",
					fields[1],
					lineNumber+2,
				)
			}
		} else {
			zone = fields[3]
		}
		rule, err := canonicalLinuxWrapperRule(fields[0], fields[1], fields[2], zone)
		if err != nil {
			return nil, false, false, fmt.Errorf("wrapper ownership state line %d: %w", lineNumber+2, err)
		}
		if _, duplicate := rules[rule.key()]; duplicate {
			return nil, false, false, fmt.Errorf("wrapper ownership state line %d duplicates %s", lineNumber+2, rule.key())
		}
		if !legacy && !zoned {
			switch fields[4] {
			case "owned":
			case "pending":
				rule.pending = true
			default:
				return nil, false, false, fmt.Errorf("wrapper ownership state line %d has invalid ownership status %q", lineNumber+2, fields[4])
			}
		}
		rules[rule.key()] = rule
	}
	return rules, true, legacy || zoned, nil
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
		zone := rule.zone
		if zone == "" {
			zone = "-"
		}
		status := "owned"
		if rule.pending {
			status = "pending"
		}
		_, _ = fmt.Fprintf(&content, "%s\t%s\t%s\t%s\t%s\n", rule.backend, rule.kind, rule.value, zone, status)
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

func ufwStatusColumnMatches(fields []string, value string) bool {
	return len(fields) == 1 && fields[0] == value ||
		len(fields) == 2 && fields[0] == value && fields[1] == "(v6)"
}

func ufwStatusLineMatchesRule(line string, rule linuxWrapperRule) bool {
	fields := strings.Fields(line)
	actionIndex := -1
	for index, field := range fields {
		if field == "ALLOW" {
			actionIndex = index
			break
		}
	}
	if actionIndex <= 0 {
		return false
	}
	fromIndex := actionIndex + 1
	if fromIndex < len(fields) {
		switch fields[fromIndex] {
		case "OUT", "FWD":
			return false
		case "IN":
			fromIndex++
		}
	}
	commentIndex := len(fields)
	for index := fromIndex; index < len(fields); index++ {
		if fields[index] == "#" {
			commentIndex = index
			break
		}
	}
	toFields := fields[:actionIndex]
	fromFields := fields[fromIndex:commentIndex]
	value := rule.value
	if rule.kind == "port" {
		value += "/tcp"
		return ufwStatusColumnMatches(toFields, value) && ufwStatusColumnMatches(fromFields, "Anywhere")
	}
	return ufwStatusColumnMatches(toFields, "Anywhere") && ufwStatusColumnMatches(fromFields, value)
}

func ufwStatusLineHasExactOwnershipMarker(line string) bool {
	fields := strings.Fields(line)
	for index, field := range fields {
		if field == "#" {
			return index == len(fields)-2 && fields[index+1] == "SYSWARDEN_CORE"
		}
	}
	return false
}

func ufwWrapperPresent(path string, rule linuxWrapperRule, requireOwnershipMarker bool) (bool, error) {
	output, err := runLinuxFirewallCommand(path, "status")
	if err != nil {
		return false, fmt.Errorf("query ufw wrapper state: %w: %s", err, strings.TrimSpace(string(output)))
	}
	lines := strings.Split(string(output), "\n")
	active, err := parseUFWWrapperStatus(lines)
	if err != nil {
		return false, err
	}
	if !active {
		return false, fmt.Errorf("ufw became inactive during wrapper reconciliation")
	}
	for _, line := range lines[1:] {
		if ufwStatusLineMatchesRule(line, rule) && (!requireOwnershipMarker || ufwStatusLineHasExactOwnershipMarker(line)) {
			return true, nil
		}
	}
	return false, nil
}

func parseUFWWrapperStatus(lines []string) (bool, error) {
	if len(lines) == 0 {
		return false, fmt.Errorf("ufw status response is empty")
	}
	switch strings.TrimSpace(lines[0]) {
	case "Status: active":
		return true, nil
	case "Status: inactive":
		return false, nil
	default:
		return false, fmt.Errorf("ufw status response has an unexpected state %q", strings.TrimSpace(lines[0]))
	}
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
		if err := validateFirewalldZone(rule.zone); err != nil {
			return nil, err
		}
		prefix = append(prefix, "--zone="+rule.zone)
		var selector string
		if rule.kind == "port" {
			selector = "port=" + rule.value + "/tcp"
		} else {
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
		return ufwWrapperPresent(path, rule, owned)
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

func ensureLinuxWrapperRule(rule linuxWrapperRule, path string, permanent bool) (bool, error) {
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
	query, err := linuxWrapperRuleArguments(rule, "query", permanent)
	if err != nil {
		return false, err
	}
	add, err := linuxWrapperRuleArguments(rule, "add", permanent)
	if err != nil {
		return false, err
	}
	return ensureWrapperCommand(path, query, add)
}

func removeLinuxWrapperRule(rule linuxWrapperRule, path string, permanent bool) (bool, error) {
	removed := false
	for attempt := 0; attempt < 256; attempt++ {
		present, err := linuxWrapperRulePresent(rule, path, true, permanent)
		if err != nil {
			return removed, err
		}
		if !present {
			return removed, nil
		}
		arguments, err := linuxWrapperRuleArguments(rule, "remove", permanent)
		if err != nil {
			return removed, err
		}
		if output, err := runLinuxFirewallCommand(path, arguments...); err != nil {
			return removed, fmt.Errorf("remove wrapper rule %s through %s: %w: %s", rule.key(), path, err, strings.TrimSpace(string(output)))
		}
		removed = true
		if rule.backend == "firewalld" {
			present, err = linuxWrapperRulePresent(rule, path, true, permanent)
			if err != nil || present {
				scope := "runtime"
				if permanent {
					scope = "permanent"
				}
				return removed, errors.Join(err, fmt.Errorf("firewalld %s rule %s remains after removal", scope, rule.key()))
			}
			return removed, nil
		}
	}
	return removed, fmt.Errorf("refuse more than 256 duplicate removals for wrapper rule %s", rule.key())
}

func linuxWrapperRuleScopes(rule linuxWrapperRule) []bool {
	if rule.backend == "firewalld" {
		return []bool{true, false}
	}
	return []bool{false}
}

func managedLinuxWrapperActive(backend, path string) (bool, error) {
	var arguments []string
	switch backend {
	case "ufw":
		arguments = []string{"status"}
	case "firewalld":
		arguments = []string{"--state"}
	default:
		return false, fmt.Errorf("unsupported managed wrapper backend %q", backend)
	}
	output, err := runLinuxFirewallCommand(path, arguments...)
	state := strings.TrimSpace(string(output))
	if backend == "ufw" {
		if err != nil {
			return false, fmt.Errorf("query ufw service state: %w: %s", err, state)
		}
		return parseUFWWrapperStatus(strings.Split(string(output), "\n"))
	}
	if err == nil {
		switch state {
		case "running":
			return true, nil
		case "not running":
			return false, nil
		default:
			return false, fmt.Errorf("firewalld state response has an unexpected value %q", state)
		}
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 252 {
		switch strings.ToLower(state) {
		case "not running", "firewalld is not running":
			return false, nil
		}
	}
	return false, fmt.Errorf("query firewalld service state: %w: %s", err, state)
}

func validateFirewalldWrapperZones(path string, ruleSets ...map[string]linuxWrapperRule) error {
	required := make(map[string]struct{})
	for _, rules := range ruleSets {
		for _, rule := range rules {
			if rule.backend == "firewalld" {
				required[rule.zone] = struct{}{}
			}
		}
	}
	if len(required) == 0 {
		return nil
	}
	output, err := runLinuxFirewallCommand(path, "--get-zones")
	if err != nil {
		return fmt.Errorf("list explicit firewalld zones: %w: %s", err, strings.TrimSpace(string(output)))
	}
	available := make(map[string]struct{})
	for _, zone := range strings.Fields(string(output)) {
		available[zone] = struct{}{}
	}
	for zone := range required {
		if _, ok := available[zone]; !ok {
			return fmt.Errorf("required explicit firewalld zone %q is unavailable", zone)
		}
	}
	return nil
}

func resolveUniqueActiveFirewalldZone(path string) (string, error) {
	output, err := runLinuxFirewallCommand(path, "--get-active-zones")
	if err != nil {
		return "", fmt.Errorf("list active firewalld zones: %w: %s", err, strings.TrimSpace(string(output)))
	}
	interfaceZones := make(map[string]struct{})
	currentZone := ""
	for lineNumber, line := range strings.Split(string(output), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentZone == "" {
				return "", fmt.Errorf("active firewalld zone detail at line %d has no zone header", lineNumber+1)
			}
			fields := strings.Fields(trimmed)
			if len(fields) > 1 && fields[0] == "interfaces:" {
				interfaceZones[currentZone] = struct{}{}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 {
			return "", fmt.Errorf("active firewalld zone line %d is malformed", lineNumber+1)
		}
		if err := validateFirewalldZone(fields[0]); err != nil {
			return "", fmt.Errorf("active firewalld zone line %d: %w", lineNumber+1, err)
		}
		currentZone = fields[0]
	}
	if len(interfaceZones) == 0 {
		return "", fmt.Errorf("firewalld has no active interface-bound zone for the required compatibility port")
	}
	if len(interfaceZones) > 1 {
		names := make([]string, 0, len(interfaceZones))
		for zone := range interfaceZones {
			names = append(names, zone)
		}
		sort.Strings(names)
		return "", fmt.Errorf("firewalld has multiple active interface-bound zones for the required compatibility port: %s", strings.Join(names, ", "))
	}
	for zone := range interfaceZones {
		return zone, nil
	}
	return "", fmt.Errorf("firewalld active zone resolution failed")
}

func discoverLinuxWrapperPaths() (map[string]string, map[string]string, map[string]string, error) {
	active := make(map[string]string)
	inactive := make(map[string]string)
	cleanupOnly := make(map[string]string)
	candidates := []struct {
		backend    string
		executable string
		managed    bool
	}{
		{backend: "ufw", executable: "ufw", managed: true},
		{backend: "firewalld", executable: "firewall-cmd", managed: true},
		{backend: "iptables", executable: "iptables"},
		{backend: "ip6tables", executable: "ip6tables"},
	}
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate.executable)
		if errors.Is(err, exec.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("discover %s compatibility wrapper: %w", candidate.backend, err)
		}
		path, err = resolveLinuxWrapperExecutable(path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("resolve %s compatibility wrapper: %w", candidate.backend, err)
		}
		if !candidate.managed {
			cleanupOnly[candidate.backend] = path
			continue
		}
		isActive, err := managedLinuxWrapperActive(candidate.backend, path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("inspect installed %s compatibility wrapper: %w", candidate.backend, err)
		}
		if isActive {
			active[candidate.backend] = path
		} else {
			inactive[candidate.backend] = path
		}
	}
	_, ufwActive := active["ufw"]
	_, firewalldActive := active["firewalld"]
	if ufwActive && firewalldActive {
		return nil, nil, nil, fmt.Errorf("ufw and firewalld are both active; exactly one compatibility frontend is allowed")
	}
	return active, inactive, cleanupOnly, nil
}

func desiredLinuxWrapperRules(trustedSubnets, ports []string, paths map[string]string, firewalldPortZone string) (map[string]linuxWrapperRule, error) {
	rules := make(map[string]linuxWrapperRule)
	appendRule := func(backend, kind, value string) error {
		zone := "-"
		if backend == "firewalld" {
			zone = firewalldPortZone
			if kind == "source" {
				zone = firewalldSourceZone
			}
		}
		rule, err := canonicalLinuxWrapperRule(backend, kind, value, zone)
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
		for _, backend := range []string{"ufw", "firewalld"} {
			if _, available := paths[backend]; available {
				if err := appendRule(backend, "port", canonical); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, subnet := range trustedSubnets {
		canonical, _, err := canonicalIPOrPrefix(subnet)
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
	}
	return rules, nil
}

func canonicalLinuxWrapperIntent(trustedSubnets, ports []string) (map[string]struct{}, map[string]struct{}, error) {
	intendedPorts := make(map[string]struct{}, len(ports))
	for _, port := range ports {
		canonical, err := canonicalPort(port)
		if err != nil {
			return nil, nil, err
		}
		intendedPorts[canonical] = struct{}{}
	}
	intendedSources := make(map[string]struct{}, len(trustedSubnets))
	for _, subnet := range trustedSubnets {
		canonical, _, err := canonicalIPOrPrefix(subnet)
		if err != nil {
			return nil, nil, err
		}
		intendedSources[canonical] = struct{}{}
	}
	return intendedPorts, intendedSources, nil
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
	plan, err := prepareLinuxFirewallWrapperReconciliation(trustedSubnets, ports)
	if err != nil {
		return err
	}
	return reconcileLinuxFirewallWrapperPlan(plan)
}

type linuxWrapperReconciliationPlan struct {
	backend                string
	paths                  map[string]string
	inactivePaths          map[string]string
	cleanupPaths           map[string]string
	desired                map[string]linuxWrapperRule
	previous               map[string]linuxWrapperRule
	stateExists            bool
	stateMigrationRequired bool
	firewalldPortZone      string
}

func sameLinuxWrapperPaths(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for backend, path := range left {
		if right[backend] != path {
			return false
		}
	}
	return true
}

func reattestLinuxWrapperPlan(plan *linuxWrapperReconciliationPlan) error {
	if plan == nil {
		return fmt.Errorf("prepared wrapper reconciliation plan is unavailable")
	}
	currentPaths, _, _, err := discoverLinuxWrapperPaths()
	if err != nil {
		return err
	}
	if err := validateLinuxWrapperBackendConstraint(plan.backend, currentPaths); err != nil {
		return err
	}
	if !sameLinuxWrapperPaths(plan.paths, currentPaths) {
		return fmt.Errorf("active compatibility frontend set or executable identity changed after preflight")
	}
	if firewalldPath, active := currentPaths["firewalld"]; active {
		if err := validateFirewalldWrapperZones(firewalldPath, plan.desired, plan.previous); err != nil {
			return err
		}
		if plan.firewalldPortZone != "" {
			currentZone, err := resolveUniqueActiveFirewalldZone(firewalldPath)
			if err != nil {
				return err
			}
			if currentZone != plan.firewalldPortZone {
				return fmt.Errorf(
					"active firewalld port zone changed from %q to %q after preflight",
					plan.firewalldPortZone,
					currentZone,
				)
			}
		}
	}
	return nil
}

func prepareLinuxFirewallWrapperReconciliation(trustedSubnets, ports []string) (*linuxWrapperReconciliationPlan, error) {
	return prepareLinuxFirewallWrapperReconciliationForBackend("keep", trustedSubnets, ports)
}

func prepareLinuxFirewallWrapperReconciliationForBackend(backend string, trustedSubnets, ports []string) (*linuxWrapperReconciliationPlan, error) {
	paths, inactivePaths, cleanupPaths, err := discoverLinuxWrapperPaths()
	if err != nil {
		return nil, err
	}
	if err := validateLinuxWrapperBackendConstraint(backend, paths); err != nil {
		return nil, err
	}
	intendedPorts, intendedSources, err := canonicalLinuxWrapperIntent(trustedSubnets, ports)
	if err != nil {
		return nil, fmt.Errorf("prepare wrapper intent: %w", err)
	}
	previous, stateExists, stateMigrationRequired, err := readLinuxWrapperState(linuxWrapperStateFile)
	if err != nil {
		return nil, err
	}
	firewalldPortZone := ""
	if firewalldPath, active := paths["firewalld"]; active && len(intendedPorts) > 0 {
		firewalldPortZone, err = resolveUniqueActiveFirewalldZone(firewalldPath)
		if err != nil {
			return nil, err
		}
	}
	desired, err := desiredLinuxWrapperRules(trustedSubnets, ports, paths, firewalldPortZone)
	if err != nil {
		return nil, fmt.Errorf("prepare wrapper rules: %w", err)
	}
	if firewalldPath, active := paths["firewalld"]; active {
		if err := validateFirewalldWrapperZones(firewalldPath, desired, previous); err != nil {
			return nil, err
		}
	}
	plan := &linuxWrapperReconciliationPlan{
		backend:                backend,
		paths:                  paths,
		inactivePaths:          inactivePaths,
		cleanupPaths:           cleanupPaths,
		desired:                desired,
		previous:               previous,
		stateExists:            stateExists,
		stateMigrationRequired: stateMigrationRequired,
		firewalldPortZone:      firewalldPortZone,
	}

	var preflightErrs []error
	for key, rule := range previous {
		if rule.pending {
			if _, stillDesired := desired[key]; !stillDesired {
				preflightErrs = append(preflightErrs, fmt.Errorf(
					"pending wrapper ownership %s is not part of the active plan; verified cleanup or attribution is required before the nftables commit",
					key,
				))
				continue
			}
			if _, inactive := inactivePaths[rule.backend]; inactive {
				preflightErrs = append(preflightErrs, fmt.Errorf(
					"inactive %s has unresolved pending ownership %s; verified cleanup or attribution is required before the nftables commit",
					rule.backend,
					key,
				))
				continue
			}
		}
		if _, inactive := inactivePaths[rule.backend]; inactive {
			_, stillIntended := intendedPorts[rule.value]
			if rule.kind == "source" {
				_, stillIntended = intendedSources[rule.value]
			}
			if !stillIntended {
				preflightErrs = append(preflightErrs, fmt.Errorf(
					"inactive %s retains stale owned permission %s; verified cleanup is required before the nftables commit",
					rule.backend,
					key,
				))
			}
			continue
		}
		_, activeAvailable := paths[rule.backend]
		_, cleanupAvailable := cleanupPaths[rule.backend]
		if !activeAvailable && !cleanupAvailable {
			preflightErrs = append(preflightErrs, fmt.Errorf("cannot reconcile owned %s rule because its executable is unavailable", rule.backend))
		}
	}
	if err := errors.Join(preflightErrs...); err != nil {
		return nil, err
	}
	return plan, nil
}

func reconcileLinuxFirewallWrapperPlan(plan *linuxWrapperReconciliationPlan) error {
	if plan == nil {
		return fmt.Errorf("prepared wrapper reconciliation plan is unavailable")
	}
	if err := reattestLinuxWrapperPlan(plan); err != nil {
		return fmt.Errorf("reinspect compatibility wrappers before reconciliation: %w", err)
	}
	paths := plan.paths
	inactivePaths := plan.inactivePaths
	cleanupPaths := plan.cleanupPaths
	desired := plan.desired
	previous := plan.previous
	stateExists := plan.stateExists
	stateMigrationRequired := plan.stateMigrationRequired
	if len(desired) == 0 && len(previous) == 0 {
		if stateExists && stateMigrationRequired {
			return writeLinuxWrapperState(linuxWrapperStateFile, previous)
		}
		return nil
	}

	deferredOwned := make(map[string]linuxWrapperRule)
	finalOwned := make(map[string]linuxWrapperRule)
	for key, rule := range previous {
		if _, inactive := inactivePaths[rule.backend]; inactive {
			deferredOwned[key] = rule
			finalOwned[key] = rule
		}
	}
	pendingOwned := copyLinuxWrapperRules(previous)
	preexisting := make(map[string]linuxWrapperRule)
	mustAddEveryScope := make(map[string]struct{})
	var preflightErrs []error
	for key, rule := range desired {
		if previousRule, tracked := previous[key]; tracked && !previousRule.pending {
			finalOwned[key] = rule
			continue
		}
		path := paths[rule.backend]
		allPresent := true
		anyPresent := false
		queryFailed := false
		for _, permanent := range linuxWrapperRuleScopes(rule) {
			present, queryErr := linuxWrapperRulePresent(rule, path, false, permanent)
			if queryErr != nil {
				preflightErrs = append(preflightErrs, fmt.Errorf("preflight wrapper rule %s: %w", key, queryErr))
				queryFailed = true
				break
			}
			allPresent = allPresent && present
			anyPresent = anyPresent || present
		}
		if queryFailed {
			continue
		}
		if previousRule, tracked := previous[key]; tracked && previousRule.pending {
			if anyPresent {
				preflightErrs = append(preflightErrs, fmt.Errorf(
					"pending wrapper ownership %s is present but cannot be attributed safely; verified attribution is required",
					key,
				))
				continue
			}
			finalOwned[key] = rule
			mustAddEveryScope[key] = struct{}{}
			continue
		}
		if anyPresent && !allPresent {
			preflightErrs = append(preflightErrs, fmt.Errorf(
				"pre-existing unowned wrapper rule %s has inconsistent permanent and runtime state",
				key,
			))
			continue
		}
		if allPresent {
			preexisting[key] = rule
			continue
		}
		pendingRule := rule
		pendingRule.pending = true
		pendingOwned[key] = pendingRule
		finalOwned[key] = rule
		mustAddEveryScope[key] = struct{}{}
	}
	if err := errors.Join(preflightErrs...); err != nil {
		return err
	}
	if err := reattestLinuxWrapperPlan(plan); err != nil {
		return fmt.Errorf("reinspect compatibility wrappers immediately before mutation: %w", err)
	}
	if !stateExists || stateMigrationRequired || !sameLinuxWrapperRules(previous, pendingOwned) {
		if err := writeLinuxWrapperState(linuxWrapperStateFile, pendingOwned); err != nil {
			return err
		}
	}

	var errs []error
	for key, rule := range previous {
		if _, deferred := deferredOwned[key]; deferred {
			continue
		}
		if _, stillDesired := desired[key]; stillDesired {
			continue
		}
		path := paths[rule.backend]
		if path == "" {
			path = cleanupPaths[rule.backend]
		}
		for _, permanent := range linuxWrapperRuleScopes(rule) {
			if _, removeErr := removeLinuxWrapperRule(rule, path, permanent); removeErr != nil {
				errs = append(errs, removeErr)
				break
			}
		}
	}
	for key, rule := range desired {
		if _, existedWithoutOwnership := preexisting[key]; existedWithoutOwnership {
			continue
		}
		for _, permanent := range linuxWrapperRuleScopes(rule) {
			added, ensureErr := ensureLinuxWrapperRule(rule, paths[rule.backend], permanent)
			if ensureErr != nil {
				errs = append(errs, ensureErr)
				break
			}
			if _, mustAdd := mustAddEveryScope[key]; mustAdd && !added {
				errs = append(errs, fmt.Errorf(
					"wrapper rule %s appeared after the ownership preflight; pending ownership is retained for verified attribution",
					key,
				))
				break
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}

	for key, rule := range desired {
		for _, permanent := range linuxWrapperRuleScopes(rule) {
			present, queryErr := linuxWrapperRulePresent(rule, paths[rule.backend], false, permanent)
			if queryErr != nil || !present {
				errs = append(errs, errors.Join(queryErr, fmt.Errorf("desired wrapper rule %s is not active in every required scope", key)))
				break
			}
		}
	}
	for key, rule := range previous {
		if _, deferred := deferredOwned[key]; deferred {
			continue
		}
		if _, stillDesired := desired[key]; stillDesired {
			continue
		}
		path := paths[rule.backend]
		if path == "" {
			path = cleanupPaths[rule.backend]
		}
		for _, permanent := range linuxWrapperRuleScopes(rule) {
			present, queryErr := linuxWrapperRulePresent(rule, path, true, permanent)
			if queryErr != nil || present {
				errs = append(errs, errors.Join(queryErr, fmt.Errorf("stale wrapper rule %s remains in a required scope", key)))
				break
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if err := reattestLinuxWrapperPlan(plan); err != nil {
		return fmt.Errorf("reinspect compatibility wrappers after reconciliation: %w", err)
	}
	if !sameLinuxWrapperRules(pendingOwned, finalOwned) {
		if err := writeLinuxWrapperState(linuxWrapperStateFile, finalOwned); err != nil {
			return err
		}
	}
	return nil
}

func sameLinuxWrapperRules(left, right map[string]linuxWrapperRule) bool {
	if len(left) != len(right) {
		return false
	}
	for key, rule := range left {
		if other, ok := right[key]; !ok || other != rule {
			return false
		}
	}
	return true
}
