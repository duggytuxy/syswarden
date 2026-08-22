package cmd

import (
	"fmt"
	"syswarden-cli/pkg/platformpaths"

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
	Short: "Display the built-in operator reference",
	Long:  "Displays the current product-command inventory, configuration layout, exposed ports, and lifecycle warnings. Cobra help and completion utilities remain available through --help.",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%s                       SYSWARDEN OPERATOR REFERENCE                            %s\n", ansiCyan, ansiReset)
		fmt.Printf("%s================================================================================%s\n\n", ansiCyan, ansiReset)

		fmt.Printf("%s--- 1. CLI COMMANDS REFERENCE ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("  %salerts%s             : Displays kernel and WAAP events in an alert dashboard.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sallow-ssh%s           : Adds an address to the SSH exception registry; verify the resulting kernel rule.\n", ansiGreen, ansiReset)
		fmt.Printf("  %saudit%s               : Runs a local operational diagnostic; it is not a compliance certification.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sblock%s               : Adds one or more addresses or CIDRs to the persistent blocklist.\n", ansiGreen, ansiReset)
		fmt.Printf("  %scheck%s               : Inspects the recorded firewall state for one address.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sconfig%s              : Opens the editor and provides validate and migrate subcommands.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sconfig-get%s          : Reads one key from the merged modular configuration.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sha-fence%s            : Administers the root-only native-sync migration fence.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sha-sync%s             : Pushes missing local blocklist entries to each configured peer.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sinstall%s             : Applies host dependencies, firewall, hardening, integrations, services and cron jobs.\n", ansiGreen, ansiReset)
		fmt.Printf("  %slist%s                : Displays manual IP registries and active HA bans with provenance and expiry.\n", ansiGreen, ansiReset)
		fmt.Printf("  %smanual%s              : Displays this operator reference.\n", ansiGreen, ansiReset)
		fmt.Printf("  %smigrate-config%s      : Compatibility alias for transactional modular migration.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sreload%s              : Reapplies policy, repairs cron jobs and normally restarts the core.\n", ansiGreen, ansiReset)
		fmt.Printf("  %srevoke-ssh%s          : Removes an address from the SSH exception registry.\n", ansiGreen, ansiReset)
		fmt.Printf("  %stui%s                 : Launches the local terminal dashboard; it opens no network listener.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunblock%s             : Removes one or more addresses or CIDRs from the blocklist.\n", ansiGreen, ansiReset)
		fmt.Printf("  %suninstall%s           : Deletes SysWarden services, rules, configuration, data and logs.\n", ansiGreen, ansiReset)
		fmt.Printf("  %sunwhitelist%s         : Removes one or more addresses or CIDRs from the whitelist.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate%s              : Installs an update only after signed-manifest and package verification.\n", ansiGreen, ansiReset)
		fmt.Printf("  %supdate-feeds%s        : Downloads configured feeds and reapplies firewall policy.\n", ansiGreen, ansiReset)
		fmt.Printf("  %swhitelist%s           : Adds canonical addresses or CIDRs, optionally scoped by --port to one TCP service.\n", ansiGreen, ansiReset)
		fmt.Printf("  %swhitelist-infra%s     : Detects and adds local infrastructure addresses.\n\n", ansiGreen, ansiReset)

		fmt.Printf("%s--- 2. GLOBAL FLAGS ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("  %s--config <path>%s : Overrides the legacy flat file path. The default is %s.\n", ansiGreen, ansiReset, platformpaths.LegacyConfig)
		fmt.Printf("  %s--help%s          : Displays Cobra help for the selected command.\n\n", ansiGreen, ansiReset)

		fmt.Printf("%s--- 3. MODULAR CONFIGURATION (TOML) ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("Master file: /etc/syswarden/config/config.toml\n")
		fmt.Printf("Modules: /etc/syswarden/config/modules/00-core.toml through 99-user.toml\n")
		fmt.Printf("Later filenames have higher precedence. Back up the complete directory before editing.\n")
		fmt.Printf("schema_version = 1 is current; an absent schema_version denotes historical input.\n")
		fmt.Printf("syswarden config validate --path /etc/syswarden/config is read-only and reports unknown and deprecated keys.\n")
		fmt.Printf("syswarden config migrate --dry-run performs zero source or destination writes.\n")
		fmt.Printf("syswarden migrate-config is the compatibility alias with the same migration contract.\n")
		fmt.Printf("The CLI validator and core loader share the choice/URL/hash, Wazuh, interval, SHA-256 prefix and HA-peer validation matrix.\n\n")

		fmt.Printf("%s[core]%s firewall_backend, hardening_enabled, cis_l2_hardening, secure_wipe_conf, ssh_port\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network]%s whitelist_infra, lan_subnets, whitelist_ips, interfaces\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network.geo]%s enabled, blocked_countries, allowed_countries\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network.asn]%s enabled, blocked_asns, allowed_asns\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network.blocklists]%s list_choice, custom_url, custom_url_ipv6, custom_hash, custom_hash_ipv6\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network.saas]%s allow_monitors (official key; default false)\n", ansiCyan, ansiReset)
		fmt.Printf("%s[network.wireguard]%s enabled, port, subnet\n", ansiCyan, ansiReset)
		fmt.Printf("%s[security]%s honeyports; %s[security.l2]%s enable_l2, arp_protect, lan_mode\n", ansiCyan, ansiReset, ansiCyan, ansiReset)
		fmt.Printf("%s[waap]%s enforcement_mode, bruteforce_logs, bruteforce_threshold, bruteforce_window_seconds, modsec_logs\n", ansiCyan, ansiReset)
		fmt.Printf("%s[integrations.ha]%s enabled, peer_ips, peer_port, token\n", ansiCyan, ansiReset)
		fmt.Printf("%s[integrations.bunkerweb]%s enabled (default false; requires authenticated HA)\n", ansiCyan, ansiReset)
		fmt.Printf("%s[integrations.siem]%s enabled, ip, port, protocol, tls_ca\n", ansiCyan, ansiReset)
		fmt.Printf("%s[integrations.webhooks]%s enabled, discord_url, teams_url, slack_url\n", ansiCyan, ansiReset)
		fmt.Printf("%s[user]%s profile_name and operator-defined overrides\n\n", ansiCyan, ansiReset)

		fmt.Printf("%s--- 4. NETWORK EXPOSURE AND HA ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("  Native TUI: no listening port.\n")
		fmt.Printf("  HA API: configurable TCP port, default 62026, persistent self-signed TLS 1.3 identity.\n")
		fmt.Printf("  HA identity: /var/lib/syswarden/ha/server.crt and /var/lib/syswarden/ha/server.key. Never copy server.key to a client.\n")
		fmt.Printf("  HA certificate lifetime: one year; replace the identity before expiry and redistribute only server.crt.\n")
		fmt.Printf("  TUI and ha-sync trust: /etc/syswarden/ha-ca.pem when present, otherwise system roots. Restart clients after trust changes.\n")
		fmt.Printf("  An explicit HA CA bundle is exclusive and must contain only valid CERTIFICATE blocks; malformed input fails closed.\n")
		fmt.Printf("  Transfer server.crt through a trusted out-of-band channel and verify its fingerprint before trusting it.\n")
		fmt.Printf("  All HA routes require the bearer token; an empty token prevents the listener from starting.\n")
		fmt.Printf("  Exact peer IPs are outbound destinations; canonical CIDRs authorize inbound peers only and are never dialed.\n")
		fmt.Printf("  Enriched temporary-ban batches are limited to 500 entries with TTLs from one second to 30 days.\n")
		fmt.Printf("  BunkerWeb can use the authenticated HA API; docker_protect covers forwarded container traffic.\n")
		fmt.Printf("  Disabling BunkerWeb gates only partner extensions; secure node-to-node HA still exchanges durable L7/WAAP bans.\n")
		fmt.Printf("  Each exact peer receives a bounded one-way push every 30 minutes; schedule both nodes for A-to-B and B-to-A exchange.\n\n")
		fmt.Printf("  SaaS monitor precedence: network.saas.allow_monitors, then deprecated integrations.saas.enabled, then false.\n")
		fmt.Printf("  SaaS feeds require bounded TLS 1.3 HTTPS without redirects; required-feed failure retains the previous atomic IPv4/IPv6 pair.\n")
		fmt.Printf("  Persistent lists accept exact canonical IP/CIDR entries and a service port only where supported; malformed input fails closed.\n")
		fmt.Printf("  whitelist --port scopes the entry to one TCP service; omission creates an address-wide entry.\n")
		fmt.Printf("  SSH exceptions are rendered only for the effective SSH port; a changed-port mismatch blocks candidate policy application.\n\n")
		fmt.Printf("  WAAP log patterns use canonical single-space separation; the core revalidates exact regular files without following links on every rotation.\n")
		fmt.Printf("  Rsyslog inputs are generated only for initially validated paths; protect parent directories because rsyslog reopens names itself.\n")
		fmt.Printf("  Rsyslog strings and WireGuard values are validated and encoded for their destination grammars.\n\n")
		fmt.Printf("  With WireGuard and HA enabled, the configured HA peer port must differ from the configured SSH port.\n\n")
		fmt.Printf("  Fence capability native_sync_fence_v1 announces schema support only; the dynamic status object proves live state.\n")
		fmt.Printf("  Fence epoch and digest values are opaque, case-sensitive strings for an integrator; compare them without recalculating canonical data.\n")
		fmt.Printf("  Legacy cleanup sends X-SysWarden-HA-Fence-Condition exactly as attested; HTTP 428, 400 and 412 perform no mutation.\n\n")

		fmt.Printf("%s--- 5. SAFETY LIMITS ---%s\n", ansiYellow, ansiReset)
		fmt.Printf("  %sRELOAD:%s the Linux nftables candidate is committed atomically and verified; compatibility-wrapper failure leaves nftables authoritative and returns an error. The core normally restarts, so keep console access and a ruleset backup.\n", ansiRed, ansiReset)
		fmt.Printf("  %sUPDATE:%s v4.02.9+ requires a trusted Ed25519 release manifest; v4.02.8 needs a separately verified manual first hop to the qualified v4.03.1 Linux package.\n", ansiRed, ansiReset)
		fmt.Printf("  %sUNINSTALL:%s configuration, data, logs, services and firewall tables are deleted; it is not a rollback.\n", ansiRed, ansiReset)
		fmt.Printf("  %sALPINE:%s dedicated CGO-free static APK binaries are built for x86_64 and aarch64; install only an exact release-qualified artifact.\n", ansiRed, ansiReset)
		fmt.Printf("  %sPLATFORMS:%s v4.03.1 supports the qualified Linux DEB, RPM and APK package matrix only.\n\n", ansiRed, ansiReset)

		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
		fmt.Printf("%sRead README.md and the command-specific --help output before a host-mutating action.%s\n", ansiWhite, ansiReset)
		fmt.Printf("%s================================================================================%s\n", ansiCyan, ansiReset)
	},
}

func init() {
	rootCmd.AddCommand(manualCmd)
}
