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
	Long:  "Displays the exhaustive SysWarden administration manual, including CLI commands, configuration parameters, and threat intelligence options.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%s                     SYSWARDEN ENTERPRISE MANUAL                               %s\n", ansiCyan, ansiReset)
		fmt.Printf("%s================================================================================%s\n\n", ansiCyan, ansiReset)

		// 1. CLI Commands
		fmt.Printf("%s--- 1. CLI COMMANDS REFERENCE ---%s\n", ansiYellow, ansiReset)

		fmt.Printf("  %sinstall%s       : Compiles, hardens, and deploys the firewall and WAAP engine.\n", ansiGreen, ansiReset)
		fmt.Printf("  %suninstall%s     : Safely removes SysWarden and reverts the OS to its previous state.\n", ansiGreen, ansiReset)
		fmt.Printf("  %saudit%s         : Validates Zero-Trust L3 boundaries and L7 WAAP independence.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sconfig%s        : Opens the interactive configuration editor (/opt/syswarden/syswarden-auto.conf).\n", ansiGreen, ansiReset)
		fmt.Printf("  %stui%s           : Launches the real-time Terminal User Interface (TUI) dashboard.\n", ansiGreen, ansiReset)
		fmt.Printf("  %salerts%s        : Streams live WAAP/L7 JSON telemetry and block events.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sreload%s        : Applies configuration changes to the kernel atomically without dropping active connections.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sblock%s         : Manually bans an IPv4/IPv6 address via L3 Netfilter.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunblock%s       : Removes an IP address from the banned set.\n", ansiGreen, ansiReset)
		fmt.Printf("  %swhitelist%s     : Adds an IP to the absolute hardware bypass list (ignores all checks).\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunwhitelist%s   : Removes an IP from the hardware whitelist.\n", ansiGreen, ansiReset)
		fmt.Printf("  %scheck%s         : Checks if an IP is currently banned or whitelisted.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate%s        : Automatically updates the SysWarden core binary and daemon.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate-feeds%s  : Forces an immediate refresh of the Data-Shield Threat Intelligence feeds.\n\n", ansiGreen, ansiReset)

		// 2. Configuration Options
		fmt.Printf("%s--- 2. CONFIGURATION FILE (syswarden-auto.conf) ---%s\n", ansiYellow, ansiReset)

		fmt.Printf("%s[Zero-Trust Governance]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sSYSWARDEN_GEO_ALLOWED%s    : Comma-separated ISO Country Codes (e.g., \"FR,DE\"). Implements Default-Deny L3.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sSYSWARDEN_ASN_ALLOWED%s    : Comma-separated ASNs. Only traffic from these Autonomous Systems is allowed.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[WAAP L7 Independence]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sSYSWARDEN_BRUTEFORCE_LOGS%s: Set to \"auto\" to let SysWarden natively discover web server logs (Nginx/Apache), or provide an absolute path.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sSYSWARDEN_BRUTEFORCE_THRESHOLD%s: Number of failed requests before an L3 ban is triggered.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[Threat Intelligence & Data-Shield]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sSYSWARDEN_LIST_CHOICE%s    : Defines the posture of the Threat Intelligence engine (see Section 3).\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[SIEM & Integrations]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sSYSWARDEN_SIEM_ENABLED%s   : Forwards native WAAP JSON telemetry via Rsyslog to a central SIEM.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sSYSWARDEN_WAZUH_ENABLED%s  : Automates Wazuh HIDS agent deployment and enrollment.\n", ansiWhite, ansiReset)
		fmt.Printf("  %sSYSWARDEN_ABUSEIPDB_ENABLED%s: Reports all WAAP attackers securely to AbuseIPDB (Requires API Key).\n", ansiWhite, ansiReset)
		fmt.Printf("  %sSYSWARDEN_HA_ENABLED%s     : Enables the High-Availability state sync between active firewall nodes.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s[Layer 2 Protections]%s\n", ansiCyan, ansiReset)
		fmt.Printf("  %sSYSWARDEN_L2_ENABLED%s     : Activates Hardware Layer 2 ARP Spoofing prevention.\n\n", ansiWhite, ansiReset)

		// 3. Data-Shield Lists
		fmt.Printf("%s--- 3. DATA-SHIELD POSTURES (SYSWARDEN_LIST_CHOICE) ---%s\n", ansiYellow, ansiReset)

		fmt.Printf("  %sstandard%s\n", ansiGreen, ansiReset)
		fmt.Printf("      - %sBlocklist.de%s: Aggregates real-time SSH, Mail, and Web application attackers.\n", ansiWhite, ansiReset)
		fmt.Printf("      - %sCINS Score%s  : High-confidence malicious scanner intelligence.\n\n", ansiWhite, ansiReset)

		fmt.Printf("  %scritical%s\n", ansiRed, ansiReset)
		fmt.Printf("      - Adds %sFireHOL Level 1%s: Drops known cybercrime infrastructures and botnets.\n", ansiWhite, ansiReset)
		fmt.Printf("      - Adds %sSpamhaus DROP%s  : Drops hijacked Autonomous Systems and BGP prefixes.\n\n", ansiWhite, ansiReset)

		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%sNOTE: Before modifying the configuration, it is highly recommended to run this manual.%s\n", ansiWhite, ansiReset)
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
	},
}

func init() {
	rootCmd.AddCommand(manualCmd)
}
