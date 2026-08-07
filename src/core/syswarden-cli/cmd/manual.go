package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const (
	ansiCyan   = "\033[1;36m"
	ansiGreen  = "\033[1;32m"
	ansiYellow = "\033[1;33m"
	ansiRed    = "\033[1;31m"
	ansiWhite  = "\033[1;37m"
	ansiReset  = "\033[0m"
)

var manualCmd = &cobra.Command{
	Use:   "manual",
	Short: "Comprehensive SysAdmin Manual and Documentation",
	Long:  "Displays the exhaustive SYSWARDEN administration manual, including CLI commands, configuration parameters, and threat intelligence options.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%s                     SYSWARDEN ENTERPRISE MANUAL                               %s\n", ansiCyan, ansiReset)
		fmt.Printf("%s================================================================================%s\n\n", ansiCyan, ansiReset)

		// 1. CLI Commands
		fmt.Printf("%s--- 1. CLI COMMANDS REFERENCE ---%s\n", ansiYellow, ansiReset)

		fmt.Printf("  %sinstall%s         : Compiles, hardens, and deploys the firewall and WAAP engine.\n", ansiGreen, ansiReset)
		fmt.Printf("  %suninstall%s       : Safely removes SYSWARDEN and reverts the OS to its previous state.\n", ansiGreen, ansiReset)
		fmt.Printf("  %saudit%s           : Validates Zero-Trust L3 boundaries and L7 WAAP independence.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sconfig%s          : Opens the interactive configuration editor (Modular TOML in /etc/syswarden/config/modules/).\n", ansiGreen, ansiReset)
		fmt.Printf("  %stui%s             : Launches the real-time Terminal User Interface (TUI) dashboard. (Hotkeys: 'b' ban, 'u' unban, 'w' whitelist)\n", ansiGreen, ansiReset)
		fmt.Printf("  %salerts%s          : Streams live WAAP/L7 JSON telemetry and block events.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sreload%s          : Applies configuration changes to the kernel atomically without dropping connections.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sblock <IP>%s      : Manually bans an IPv4/IPv6 address via L3 Netfilter (Immediately applied).\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunblock <IP>%s    : Removes an IPv4/IPv6 address from the banned set.\n", ansiGreen, ansiReset)
		fmt.Printf("  %swhitelist <IP>%s  : Adds an IPv4/IPv6 to the absolute hardware bypass list (ignores all checks).\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunwhitelist <IP>%s: Removes an IPv4/IPv6 from the hardware whitelist.\n", ansiGreen, ansiReset)
		fmt.Printf("  %scheck <IP>%s      : Checks if an IPv4/IPv6 is currently banned or whitelisted.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate%s          : Automatically updates the SYSWARDEN core binary and daemon.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate-feeds%s    : Forces an immediate refresh of the Data-Shield Threat Intelligence feeds.\n", ansiGreen, ansiReset)
		fmt.Printf("  %senroll%s          : Securely attaches this node to a centralized SysWarden Nexus console.\n\n", ansiGreen, ansiReset)

		// 1.5 Global Flags
		fmt.Printf("%s--- 2. GLOBAL FLAGS ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("  %s--config <path>%s : Overrides the default configuration directory path (Default: /etc/syswarden/config).\n", ansiGreen, ansiReset)
		fmt.Printf("  %s--help%s          : Displays standard CLI help for a specific command.\n\n", ansiGreen, ansiReset)

		// 2. Configuration Options
		fmt.Printf("%s--- 3. MODULAR CONFIGURATION (TOML) ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("SysWarden uses a priority-based TOML modular configuration loaded from /etc/syswarden/config/modules/\n")
		fmt.Printf("Modules are loaded in order (00-core.toml to 99-user.toml). 99-user.toml overrides everything.\n\n")

		fmt.Printf("%s[WAAP Engine: 30-waap.toml]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %senforcement_mode%s: \"enforcing\" (Default) drops malicious IPs via Nftables. \"audit\" logs [SIMULATED-BAN] without dropping.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sbruteforce_logs%s : Set to \"auto\" to let SYSWARDEN natively discover web server logs (Nginx/Apache), or provide an absolute path.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sbruteforce_threshold%s: Number of failed requests before an L3 ban is triggered.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[Network & Zero-Trust: 10-network.toml]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sallowed_countries%s: List of ISO Country Codes (e.g., [\"FR\", \"DE\"]). Implements Default-Deny L3.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sallowed_asns%s     : List of ASNs. Only traffic from these Autonomous Systems is allowed.\n", ansiWhite, ansiReset)
		fmt.Printf("  %swhitelist_infra%s  : Auto-detects and whitelists Admin IP, Gateways, DNS (IPv4/IPv6).\n", ansiWhite, ansiReset)
		fmt.Printf("  %swhitelist_ips%s    : Absolute bypass IPs (e.g., [\"192.168.1.100\", \"::1\"]).\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[Security & Compliance: 20-security.toml]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %shoneyports%s       : List of fake open ports (e.g., [\"6379\", \"27017\", \"3306\"]). Traps internal scanners.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sl2_enabled%s       : Activates Hardware Layer 2 ARP Spoofing prevention.\n", ansiWhite, ansiReset)
		fmt.Printf("  %scompliance%s       : SysWarden inherently verifies tcp_syncookies, rp_filter every 24h. Alerts appear as [COMPLIANCE-DRIFT].\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[Integrations & HA: 40-integrations.toml]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %ssiem_enabled%s     : Forwards native WAAP JSON telemetry via Rsyslog to a central SIEM.\n", ansiWhite, ansiReset)
		fmt.Printf("  %swazuh_enabled%s    : Automates Wazuh HIDS agent deployment and enrollment.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sha.enabled%s       : Enables the High-Availability state sync between active firewall nodes.\n", ansiWhite, ansiReset)
		fmt.Printf("  %swebhooks%s         : Discord/Teams/Slack SOC alerts URLs.\n\n", ansiWhite, ansiReset)

		// 4. Data-Shield Lists
		fmt.Printf("%s--- 4. DATA-SHIELD POSTURES (SYSWARDEN_LIST_CHOICE) ---%s\n", ansiYellow, ansiReset)

		fmt.Printf("  %sstandard%s\n", ansiGreen, ansiReset)
		fmt.Printf("      - %sBlocklist.de%s: Aggregates real-time SSH, Mail, and Web application attackers.\n", ansiWhite, ansiReset)
		fmt.Printf("      - %sCINS Score%s  : High-confidence malicious scanner intelligence.\n\n", ansiWhite, ansiReset)

		fmt.Printf("  %scritical%s\n", ansiRed, ansiReset)
		fmt.Printf("      - Adds %sFireHOL Level 1%s: Drops known cybercrime infrastructures and botnets.\n", ansiWhite, ansiReset)
		fmt.Printf("      - Adds %sSpamhaus DROP%s  : Drops hijacked Autonomous Systems and BGP prefixes.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%sNOTE: Before modifying the configuration in /etc/syswarden/config/, it is highly recommended to run this manual.%s\n", ansiWhite, ansiReset)
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
	},
}

func init() {
	rootCmd.AddCommand(manualCmd)
}
