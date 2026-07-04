# Release v3.50.4

## FIXED
- **OSINT Telemetry Rate-Limiting & Cache Loss**: Resolved a critical issue in `syswarden-core` where OSINT data (Country, ASN, ISP) disappeared in the TUI after executing `syswarden reload`. The in-memory telemetry cache (`osintCache`) is now securely persisted to `/var/lib/syswarden/ui/osint_cache.json` across daemon restarts. Additionally, the HTTP request execution flow to the external OSINT API has been decoupled from the primary Mutex (`osintMu`), completely preventing sequential rate-limiting (HTTP 429) and telemetry lockups (timeout) during mass ingestion of new attacking IPs.
---

# Release v3.50.3

## ADDED
- **Data-Shield Dynamic Latency Benchmark**: Engineered an autonomous, multi-threaded latency benchmarking system (`SelectFastestThreatIntelMirror`) to dynamically select the fastest Threat Intelligence mirror upon execution. The orchestration engine now pre-tests GitHub, GitLab, jsDelivr, Bitbucket, and Codeberg via HTTP `HEAD` probes, chronometers their response times, and sorts the fallback sequence strictly by optimal latency. This completely replaces the blind sequential failover, guaranteeing absolute maximum bandwidth and minimal network overhead during Zero-Trust ingestion operations.
---

# Release v3.50.2

## ADDED
- **High Availability (HA) Multi-Node Support**: The `syswarden-cli ha-sync` orchestration engine natively supports resolving and synchronizing across multiple HA peer nodes simultaneously. `SYSWARDEN_HA_PEER_IP` now accepts a space- or comma-separated list of IP addresses, effortlessly projecting the active Zero-Trust blocklist state to an entire cluster ecosystem in parallel.

## FIXED
- **AbuseIPDB Configuration Reloading**: Patched a configuration drift bug where dynamically altering `SYSWARDEN_ENTERPRISE_MODE` or `SYSWARDEN_ENABLE_ABUSE` post-installation was ignored by `syswarden reload`. The orchestrator now properly executes `SetupAbuseIPDB()` during live reloads and securely zeroes out legacy `secrets.env` configurations if the service is downgraded or deactivated.
- **Threat Intelligence Mirror Resilience**: Fixed an edge-case network exhaustion bug (`context deadline exceeded`) observed on RHEL/AlmaLinux families. The orchestration engine's global context timeout has been aggressively expanded (from 2m to 15m) to guarantee that all fallback mirrors (GitHub, GitLab, jsDelivr, Bitbucket, Codeberg) can fully execute their retry loops sequentially without being prematurely terminated by the main thread.
- **High Availability (HA) TOFU Automation**: Engineered a secure Trust On First Use (TOFU) host-key exchange sequence within the `cluster.go` orchestration engine. SysWarden now autonomously utilizes native `ssh-keyscan` during HA initialization to securely pin the standby node's ED25519 public key into the local `known_hosts` vault. This completely eliminates silent `StrictHostKeyChecking` connection drops and guarantees immediate Zero-Touch synchronization across cluster nodes without any post-installation key bridging.

---

# Release v3.50.1

## FIXED
- **Threat Intelligence Mirror Resilience**: Implemented a highly resilient mirror fallback rotation (GitHub, GitLab, jsDelivr, Bitbucket, Codeberg) within the `downloader.go` orchestration engine. This natively mitigates single-point-of-failure network timeouts (e.g., Codeberg IPv6 rate-limiting) during Data-Shield ingestion by automatically failing over to the next available enterprise CDN, ensuring uninterrupted Zero-Trust L3 protection.

---

# Release v3.50.0

## ADDED
- **Native IPv6 Support (WAF & L3/L4)**: SysWarden now natively supports full IPv6 mitigation. The Linux Nftables backend autonomously provisions the `banned_ips6` Set and corresponding drop rules, while the FreeBSD (`pf`) backend handles IPv6 blocks seamlessly, closing all potential IPv6 WAF bypass vectors.
- **Custom IPv6 Threat Intelligence Feeds**: Added native support for downloading and parsing custom IPv6 blocklists via `SYSWARDEN_CUSTOM_URL6` (when `SYSWARDEN_LIST_CHOICE=3`). The `downloader` orchestration engine now automatically syncs and injects these into `syswarden_blacklist6` ensuring custom enterprise defense coverage.
- **Zero-Trust Native IPv6 Whitelist**: Completely overhauled the `SYSWARDEN_WHITELIST_IPS` parsing engine (`auto_whitelist.go`). SysAdmins can now pass space-separated arrays containing both absolute IPv4 and IPv6 addresses. The engine intelligently parses and routes them to their respective backend firewall tables without breaking the legacy configuration footprint.

## UPGRADED
- **High Availability (HA) IPv6 Sync**: Expanded the `syswarden-cli ha-sync` engine to automatically synchronize the IPv6 manual blocklist (`syswarden_blacklist.ipv6`) alongside the legacy IPv4 blocklist. The HA module utilizes purely native Go SSH automation to atomically stream cross-node IPv6 threat state without bash dependencies.
- **CLI IPv6 Enforcement**: Upgraded the `syswarden block`, `syswarden unblock`, `syswarden check`, and `syswarden list` commands to natively accept, parse, and enforce full IPv6 arrays, injecting them dynamically into the kernel L3 firewall.
- **UDS Socket Hardening (LPE Prevention)**: Strictly hardened the UNIX Domain Socket permissions for `/var/run/syswarden.sock` from `0666` to `0660`. This aggressively isolates the daemon communication bridge, preventing any non-privileged user from interacting with the socket and nullifying Local Privilege Escalation (LPE) risks.
- **Code Hygiene**: Enforced strict `gofmt` formatting and standard library `net` imports across the Core engine to guarantee 100% CI/CD pipeline compliance and robust cross-platform compilation.

## FIXED
- **IPv6 Regex Precision (Aho-Corasick)**: Completely rewrote the `ExtractIP` regular expression engine to surgically capture abbreviated IPv6 formats (e.g., `fe80::1`) while strictly preventing greedy matches against standard log timestamps (e.g., `12:00:00`), ensuring Zero False Positives during IPv6 threat qualification.
- **FreeBSD Threat Intelligence Persistence (PF)**: Resolved a critical regression where the FreeBSD Packet Filter (`pf`) backend silently failed to load massive threat intelligence sets (Global Blocklist, GeoIP, ASN). SysWarden now orchestrates the `persist file` directive to force native filesystem loading for all PF tables, securely mapping up to 400,000 dual-stack CIDRs into kernel memory without overflowing the CLI execution buffer.
- **Dual-Stack ASN WHOIS Routing**: Corrected the `syswarden update-feeds` engine to natively intercept both `route:` and `route6:` objects when querying RADB (`whois.radb.net`). The ASN threat vectors are now flawlessly segmented into `.ipv4` and `.ipv6` lists and injected directly into `syswarden_asn` and `syswarden_asn6` kernel sets, guaranteeing absolute IPv6 infrastructure defense.

---

# Release v3.41.0

## UPDATED
- **Signatures Mapping / CMS Honeypot**: Renamed the generic `cms-honeypot` L7 WAAP rule to a highly specific `cms-wordpress` identifier. Realigned the Aho-Corasick payload array (`/wp-includes`, `/wp-admin`, `/wp-login.php`, `xmlrpc.php`, `wp-config.php`) to strictly target WordPress vectors, drastically improving SIEM visibility and eliminating heuristic overlaps.

## FIXED
- **L7 WAAP Signature Shadowing**: Restructured the hierarchical evaluation order within `signatures.json` to enforce a "Most Specific First" paradigm. Moved aggressive catch-all regexes (`nginx-scanner`, `laravel-login`, `generic-auth`) to the absolute bottom of the evaluation stack. This completely eliminates rule shadowing and guarantees that highly specific CVEs and service alerts (e.g., `nginx-tls`) trigger correctly before being swallowed by generic L7 patterns.
- **SQLi-XSS Payload Refactoring**: Split the monolithic `sqli-xss` Aho-Corasick rule to exclusively target SQL injection patterns (`UNION SELECT`, `CONCAT(`, `WAITFOR DELAY`, `SLEEP(`). Stripped redundant XSS and LFI vectors (`<script`, `alert(`, `../../`) that were already covered by the dedicated Zero-Overhead `owasp-a03-xss` and `l7-lfi` rules, ensuring absolute precision and Zero False Positives during heuristic analysis.
- **Regex Extraction Precision**: Fixed critical regex spacing and string boundary matching anomalies within the `haproxy-abuse`, `slowloris`, and `redis-auth` L7 rules. Ensures that WAF detection executes flawlessly across a 74/74 multi-vector signature battery test.

---

# Release v3.40.8

## FIXED
- **Engine / Regex False Positives**: Fixed a highly specific false-positive in the `ahocorasick` matching engine where the generic `<HOST>` replacement regex for IPv6 (`[a-fA-F0-9:]+`) was overly greedy and could mistakenly match log timestamps (e.g., `12:50:59`) and random port combinations, triggering incorrect L7 WAAP jails (like `haproxy-abuse`) for standard SSH blocks. The `<HOST>` placeholder now uses a strict, boundary-enforced regex to exclusively match valid IPv4 and IPv6 structures, ensuring flawless threat qualification.

---

# Release v3.40.7

## FIXED
- **Telemetry Formatting & Syslog Recursion Loop**: Resolved a critical defect where SysWarden logging its own block events into Syslog caused an infinite recursive feedback loop through the Rsyslog `waf_bridge`, inflating the `payload` field uncontrollably in the UI. Implemented a strict drop-rule for `syswarden-core` messages at the bridge layer and introduced a native `SysWardenRaw` template to strip Syslog framing (`<PRI>`, timestamp, hostname) before routing to the UDS socket. As a result, SIEM, Wazuh, and local TUI logs are now perfectly formatted with exact raw string payloads for both Web and SSH components.

---

# Release v3.40.6

## FIXED
- **HIDS / SSH Brute-Force Visibility**: Fixed a critical log forwarding omission where `syswarden-cli` only configured Rsyslog to forward Web server logs (Nginx/Apache) to the core engine socket (`waf_bridge`). The configuration (`waf_logs_linux.go` and `waf_logs_freebsd.go`) has been updated to nativey include `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, and `/var/log/messages`, instantly restoring SysWarden's capability to detect and ban SSH brute-force attempts.

---

# Release v3.40.5

## ADDED
- **Advanced Threat Intel WAAP Signatures (L7)**: Integrated new zero-day/CVE signatures (JetBrains TeamCity, Citrix Bleed, MOVEit, F5 BIG-IP) with immediate BAN enforcement. Added advanced generic payloads targeting Cloud SSRF (AWS/Azure/GCP Metadata), Java SSTI/RCE (freemarker, getRuntime), and malicious AI crawlers in DETECT mode for precise triage and low false-positive rates.
- **Deep Packet Inspection & Network Threat Intel (L3/L4)**: Drastically hardened native firewalls (Nftables for Linux/Alpine, PF for FreeBSD) by introducing kernel-level mitigation against NULL and XMAS port scans, dropping invalid IP fragments (Nmap evasion), and implementing strict UDP payload limits (dropping UDP/53 > 512 bytes) to proactively neutralize DNS exfiltration attempts.
---

# Release v3.40.4

## ADDED
- **Spamhaus ASN-DROP Support**: Implemented dynamic downloading and parsing of the `asndrop.json` (JSON Lines) list. Integrated deduplication against custom ASN lists, enforcing native ASN extraction and blocking while strictly rate-limiting RADB WHOIS lookups to prevent blacklisting. The implementation safely ignores IPv6 constraints at the WHOIS parsing layer to maintain compatibility with Nftables chunking logic.

---

# Release v3.40.3

## FIXED
- **Alpine Linux Support (In-Place Upgrade)**: Fixed a critical issue where running `syswarden update` on Alpine Linux 3.23+ would fail with a missing package manager error. The `upgrade.go` engine has been updated to nativey detect and use `apk` to securely download and install `.apk` updates via `apk add --allow-untrusted`.

---

# Release v3.40.2

### FIXED

Error package and code hygiene v3.40.1

---

# Release v3.40.1

## FIXED
- **Code Hygiene (golangci-lint)**: Addressed a `staticcheck` error (`QF1003: could use tagged switch on b.Action`) in the TUI (`syswarden-tui/main.go`). The `if-else if` block for parsing telemetry actions has been optimized into a clean `switch` statement to satisfy strict continuous integration compliance and eliminate pipeline failures.

---

# Release v3.40.0

## ADDED
- **Insider Threat Detection (DETECTED Mode)**: Implemented the `DETECTED` action mode for WAAP signatures. Rules tagged with `"action": "detect"` are logged natively as `DETECTED` severity without executing an L7 ban, ensuring zero-regression observability.
- **SIEM Telemetry Parsing**: Enhanced the WAF/Telemetry JSON parser and `syswarden-core/logger` to dynamically append `Severity` mapping: `BANNED=10`, `SHADOW-ALERT=8`, `DETECTED=7`, `ALLOWED=3`. This natively guarantees accurate severity routing across SIEM integrations (Wazuh, Splunk).

## UPDATED
- **TUI & Live Alerts Real-Time Display**: Overhauled `syswarden alerts` and `syswarden tui` (Dashboards) to distinctly colorize and trace `DETECTED` heuristics (Yellow) in real-time, matching SOC visibility standards.
- **Webhook Dispatcher (Discord/Slack)**: Updated the webhook integration core to uniquely style and map `DETECTED` alert vectors with a dedicated Orange/Yellow visual indicator to distinguish from active blocking.

## FIXED
- **WireGuard Persistence (#43)**: Remedied a devastating oversight where installing `syswarden v3.31.1` abruptly terminated the active WireGuard `wg0` tunnel. SysWarden now rigorously preserves pre-existing encrypted tunnels during setup.

---


# Release v3.31.1

## FIXED
- **OSINT Enrichment (Datacenter IP Ban)**: Switched the telemetry OSINT provider from `FreeIPAPI` to `ip-api.com`. `FreeIPAPI` was found to natively block HTTP requests originating from Cloud/Datacenter ASNs (like OVH) with a `403 Forbidden` error, resulting in empty data in the TUI. `ip-api.com` natively handles 45 req/min (64,800/day) and cleanly resolves IP geolocation and ASN data regardless of the hosting provider.

---

# Release v3.31.0

## ADDED
- **ARM64 Support**: Native cross-compilation support for `linux/arm64` (aarch64) in CI/CD. Distribution packages (`.deb`, `.rpm`, `.apk`) and raw binaries are now seamlessly built, bundled, and released automatically to support ARM architectures (e.g., AWS Graviton, Raspberry Pi, Oracle Cloud).

## UPDATED
- **OSINT Threat Intelligence Engine**: Migrated the core IP metadata enrichment provider to `FreeIPAPI` over HTTPS (`de.freeipapi.com`). This enterprise-level transition natively supports extremely high-volume environments (60 requests/minute or ~86,000/day) without requiring API keys, eliminating previous restrictions while maintaining absolute 100% precision on Country, ASN, and ISP data in the TUI Dashboard.

---

# Release v3.30.0

## ADDED
- **Alpine Linux Support**: Full native support for Alpine Linux (3.21+). The Go WAF and CLI orchestrator automatically detect Alpine at runtime and natively configure `apk` dependencies, `rc-update/rc-service` (OpenRC) system services, and route WAF/kernel logging via `/var/log/messages` (`tail -F`) instead of `journalctl`, providing a seamless and highly optimized security deployment on lightweight alpine architectures.

---

# Release v3.20.2

## FIXED
- **OSINT Enrichment**: Fixed an inconsistency in the `syswarden tui` dashboard where the "Top Attackers" table displayed a hardcoded port (`80/443`) regardless of the actual attack vector. The `enrichOSINT` telemetry engine now dynamically extracts the exact targeted port (`DPT`) directly from the firewall drop payload using robust regular expressions, ensuring perfect alignment with the "Trigger Payload" data.

---

# Release v3.20.1

## FIXED
- **Code Hygiene (golangci-lint)**: Addressed multiple CI pipeline errors flagged by `govet` and `staticcheck`. Fixed missing `%s` formatting directives in `manual.go` ANSI color output blocks.
- **Code Hygiene (golangci-lint)**: Refactored redundant `if-else` action chains into optimized `switch` statements across `alerts.go` and `worker.go` to satisfy `QF1003` staticcheck constraints.
- **Code Hygiene (golangci-lint)**: Eliminated explicit slice type declarations (`var finalData []byte = data`) in `discord.go` in favor of idiomatic type inference (`finalData := data`), resolving `ST1023` linting warnings and ensuring a flawless CI/CD green build.

---

# Release v3.20.0

## ADDED
- **Insider Threat Detection (Shadow Mode)**: Implemented a robust 'Shadow Mode' framework designed specifically for zero-trust environments. When malicious L7/WAF behaviors (e.g., PrivEsc, RCE attempts, unauthorized enumeration) originate from whitelisted administrative IPs, SysWarden now silently tags the event as a `SHADOW-ALERT` instead of enforcing a ban. This prevents service disruption for legitimate admins while ensuring immediate SOC visibility into compromised credentials.
- **Honeyports (L3 Lures)**: Introduced `SYSWARDEN_HONEYPORTS`, allowing SysAdmins to seamlessly expose fake open ports natively protected by Nftables and PF. Any internal connection attempts to these decoys immediately trigger silent SOC alerts if originating from a whitelisted IP, or result in an instant ban for unauthorized IPs.
- **Unified Multi-Webhook Dispatcher**: Rewrote the webhook telemetry engine to natively support Slack, alongside Discord and MS Teams. Security Operations Centers now receive rich, color-coded, real-time threat intelligence feeds directly to their platform of choice, including explicit differentiation for `SHADOW-ALERT` events.
- **SysWarden Dashboard (TUI) Enhancements**: Expanded the terminal user interface (`syswarden tui`) and live telemetry stream (`syswarden alerts`) to natively parse and distinctly colorize `SHADOW-ALERT` and `ALLOWED` events, improving visibility for SOC analysts.

## UPDATED
- **Wazuh HIDS Integration**: Upgraded the automated Wazuh agent integration engine. SysWarden now natively injects explicit `<localfile>` blocks into `/var/ossec/etc/ossec.conf` to guarantee `waf.json` telemetry and `core.log` tracing are immediately ingested by Wazuh, maintaining 100% SIEM compliance.
- **FreeBSD Compatibility**: Ensured full compatibility for FreeBSD 14.4+ architectures, translating native Honeyport traps into compliant Packet Filter (`pf`) drop rules, guaranteeing identical enterprise-grade protection across Linux and BSD deployments.

---

# Release v3.10.3

## ADDED
- **L7 WAAP Programmatic Immunity:** Developed a native, high-performance, in-memory cache module (`utils.IsWhitelisted()`) that dynamically parses and caches infrastructure IPs (`syswarden_whitelist.ipv4`, `syswarden_whitelist.ipv6`) and local loopbacks (`127.0.0.1`, `::1`). This explicitly grants absolute L7 WAAP and L3 Catch-All immunity to administrative IPs, drastically reducing CPU overhead and disk I/O bottlenecks without relying on external packages.

## FIXED
- **WordPress Administrator Self-Lockouts:** Resolved a critical bug where the asynchronous L7 WAAP daemon (`waap.go`) blindly banned authenticated administrators and legitimate local server cron jobs (e.g., `wp-cron.php` HTTP POST requests) that tripped rate-limits or payload heuristics. The WAAP engine now natively validates all requests against the programmatic immunity cache before enforcing drops or logging.

## UPDATED
- **Zero-Trust Architectural Separation:** Completely refactored the kernel firewall architectures (`firewall_linux.go` and `firewall_freebsd.go`) to physically decouple the **Infra Whitelist** (`syswarden_whitelist`) from the **Zero-Trust Allowed** countries/ASNs (`syswarden_zt_allowed`). This seals a critical logic flaw where Zero-Trust permitted countries inadvertently bypassed ThreatIntel blocklists. Infra IPs are now processed with ultimate `pass in quick` priority, while Zero-Trust ranges remain strictly subjected to all WAF and Intelligence evaluation phases.

---

# Release v3.10.2

## FIXED
- **Universal Nftables Compatibility (LXC/Proxmox):** Refactored the core atomic firewall transaction in `syswarden-cli`. The modern `destroy table` syntax, which triggers `unexpected table` syntax errors on older or strict LXC environments (e.g., Debian 11/12 on Proxmox VE), has been replaced with pre-transaction silent `nft delete table` commands. This guarantees 100% backward and forward compatibility without sacrificing atomic load safety.

---

# Release v3.10.1

## UPDATED
- **TUI & Alerts Formatting:** Enhanced `syswarden alerts` to intelligently parse raw kernel payload strings for `L3-PORTSCAN` and `L2-ARP-FLOOD` blocks. Instead of displaying the raw `dmesg` buffer, the alerts now cleanly extract and display just the relevant `PORT` or `PROTO` (e.g., `JAIL: L3-PORTSCAN | PORT: 8080`), vastly improving terminal readability.

---

# Release v3.10.0

## FIXED
- **CWE-400 (Uncontrolled Resource Consumption):** Applied a strict kernel-level rate limit (`limit rate 2/second burst 5 packets`) to the `[Catch-All]` firewall logging rule in Linux (nftables/iptables) to completely eliminate CPU exhaustion loops during aggressive volumetric port scans (e.g. Nmap, OpenVAS).
- **L3 Portscan Auto-Ban (Fail2ban Parity):** Engineered a high-performance in-memory telemetry state tracker native to Go. SysWarden now parses dropped packet logs efficiently and executes a definitive L3 native silent drop ban after 3 occurrences, instantly terminating the attacker's portscan without external dependencies.

---

# Release v3.01.0

## ADDED
- **Native FreeBSD CIS Hardening:** Successfully ported the CIS Level 2 Kernel and OS-level hardening directly to FreeBSD 14+. The new architecture implements rigorous protection equivalent to Linux configurations via native sysctl overrides (`security.bsd.*` and `net.inet.tcp.blackhole=2`), without interfering with the PF engine.
- **Zero-Trust FreeBSD Profiles:** Hardened standard FreeBSD profiles (`.cshrc`, `.profile`) with the `schg` immutable file flag, matching Linux `chattr` standards.
- **FreeBSD Core Dump Restrictions:** Implemented strict memory limits (`kern.coredump=0`, `kern.sugid_coredump=0`) via `sysctl.conf` to block memory exploitation.

---

# Release v3.00.1

## FIXED
- **CI/CD Pipeline (FreeBSD Artifacts):** Resolved a failure in `package.yml` and `release-manager.yml` where `sha256sum` and GitHub Artifact uploads expected `.pkg` files, whereas FPM accurately generates `.txz` archives for FreeBSD. All pipeline references have been safely updated to `.txz`.
- **Go Cache Dependency Resolution:** Fixed a caching crash during the `actions/setup-go` workflow step by explicitly mapping `cache-dependency-path` to `go.work.sum`, since SysWarden utilizes a root-level workspace architecture.

---

# Release v3.00.0

## ADDED
- FreeBSD 14+ Native Support via abstraction layer (`//go:build freebsd`).
- Full PF (Packet Filter) support for L3/L4 and L7 WAAP integration.
- Native Kernel Layer 2 ARP Spoofing Protection for FreeBSD via `sysctl` hardening (`log_arp_movements`).
- Native `rc.d` FreeBSD service orchestration integration.
- Abstracted WireGuard VPN integration using PF NAT anchor (`syswarden_wg`) and `sysrc` for FreeBSD.
- Abstracted SIEM (Wazuh/Rsyslog) bridge telemetry integration for FreeBSD paths and daemons (`/usr/local/etc/rsyslog.d`).
- Abstracted Real-Time Telemetry (Core & CLI) from Linux `journalctl` to native FreeBSD `syslog` (`/var/log/messages`).
- Package generation for `.pkg` explicitly utilizing FPM inside the GitHub CI/CD Actions pipeline.

## UPGRADED
- Refactored `pkg/system`, `pkg/network` and `pkg/integration` to securely support FreeBSD without breaking the Linux ecosystem.
- Cross-platform dependency check mechanisms adapted for `pkg` versus `apt`/`dnf`.
- Web Showcase and Wiki fully updated to reflect multi-OS integration (Linux & FreeBSD Jails/bhyve capabilities).

## FIXED
- **OSSF Scorecard (Supply Chain Security):** Addressed the High-Severity `Binary-Artifacts #91` alert by aggressively purging the local compiled test binary (`syswarden_test`) from the repository's git index and enforcing strict `.gitignore` boundaries for all Go test artifacts. This guarantees absolute compliance with SLSA and OSSF source-review guidelines.

---

# Release v2.40.0

## ADDED
- [WAAP L7] Proactive Heuristics: Integrated three new zero-overhead detection jails natively into `waap.go` (`l7-ssrf`, `l7-nosql`, `l7-api`), successfully blocking Cloud metadata exfiltration, MongoDB/CouchDB injections, and generic API/GraphQL schema enumeration without impacting performance.
- [Telemetry] SIEM & AbuseIPDB Mapping: Dynamically integrated the new WAAP L7 jails into the `telemetry/abuse.go` AbuseIPDB reporter, natively mapping them to the Web App Attack (Category 21) logic.
- [Threat Intelligence] Modern CVEs & Scanners: Expanded `signatures.json` with highly critical Aho-Corasick patterns targeting Java/PHP Deserialization (`ysoserial`), Ivanti/Confluence CVE paths, and aggressively dropping advanced fuzzers (`ffuf`, `kiterunner`) and novel AI crawlers (PerplexityBot, ClaudeBot).

## REMOVED
- [Layer 2] MAC Address Filtering: Removed `SYSWARDEN_MAC_BLACKLIST` and associated filtering logic. MAC blocking is easily circumvented via spoofing and offers no real Zero-Trust boundary. Hardware Layer 2 ARP Spoofing prevention (`SYSWARDEN_ARP_PROTECT`) remains active and strictly enforced.

## UPDATED
- [WAAP L7] Legacy Substring Engine: Fortified existing SQLi, XSS, LFI, and RCE zero-overhead arrays with advanced bypass vectors (`pg_sleep`, `php://filter`, `${lower:jndi}`).

---

# Release v2.30.2

## ADDED
- [SecOps] SysWarden Enterprise Manual: Introduced the exhaustive `syswarden manual` command. This interactive module provides comprehensive documentation on all CLI commands, `syswarden-auto.conf` configuration parameters (including Zero-Trust L3 and WAAP L7 variables), and the complete structure of the Data-Shield Threat Intelligence postures (`standard`, `critical`).

---

# Release v2.30.1

## UPDATED
- [SecOps] SysWarden Audit Engine: The `syswarden audit` CLI command has been completely overhauled to natively recognize and validate the new Zero-Trust Strict ALLOW architecture (GeoIP and ASN). It now also actively audits the WAAP L7 Engine status, confirming Auto-Discovery mechanisms and L7 Independence capabilities.

---

# Release v2.30.0

## ADDED
- [Governance] Zero-Trust Strict ALLOW Mode for GeoIP and ASN. Introduces `SYSWARDEN_GEO_ALLOWED` and `SYSWARDEN_ASN_ALLOWED`. If configured, the engine operates in a default-deny state, blocking all inbound traffic except for the explicitly whitelisted countries or ASNs, natively merging with the hardware `syswarden_whitelist` set for O(1) processing.
- [SecOps] WAAP L7 Independence: Even if an IP is allowed via the new Zero-Trust L3 whitelist, the WAAP engine retains absolute priority. If a whitelisted IP initiates a malicious attack (SQLi, XSS, etc.), it is immediately banned, dropped, and reported to the SIEM.
---

# Release v2.20.1

## ADDED
- WAAP Auto-Discovery (Zero-Config Absolu): The WAAP engine now natively probes the file system for standard web server log directories (`/var/log/nginx`, `/var/log/apache2`, `/var/log/httpd`, `/var/log/caddy`, `/var/log/traefik`, `/var/log/lighttpd`). By setting `SYSWARDEN_BRUTEFORCE_LOGS="auto"` (the new default), SysWarden intelligently tails active web server access logs. This guarantees instant, zero-configuration L7 protection for amateur sysadmins without losing manual override capabilities for advanced users.

---

# Release v2.20.0

## ADDED
- Advanced WAAP (L7) Engine: The L7 engine (`waap.go`) now performs Zero-Overhead Substring Matching for critical payload signatures, expanding defense beyond brute-force. It now natively detects and immediately bans attacks targeting SQL Injection (`l7-sqli`), Cross-Site Scripting (`l7-xss`), Local File Inclusion (`l7-lfi`), Remote Code Execution (`l7-rce`), and Malicious Scanners (`l7-scanner`), all without complex RegEx CPU overhead.
- MITRE ATT&CK Mapping: Dynamically integrated specific MITRE ATT&CK techniques in the telemetry engine to natively reflect heuristic WAF bans in the TUI (e.g., T1190 for Exploits, T1595 for Active Scanning, T1110 for Brute Force).
- AbuseIPDB Integration: Added dynamic mappings for the new WAAP jails (`l7-sqli`, `l7-rce`, etc.) to specific AbuseIPDB categories (16, 19, 21) for highly accurate Threat Intelligence reporting.
- Native JSON SIEM Integration: Rsyslog integration now explicitly leverages the `imfile` module to forward the raw WAAP telemetry (`/var/log/syswarden/waf.json`) in pure JSON format to enterprise SIEMs (Elastic, Splunk, Wazuh) without requiring complex grok decoding.

## FIXED
- TTY Fallback (Non-Interactive CLI): Implemented an intelligent fallback mechanism (`term.IsTerminal`) across `syswarden alerts` and `syswarden tui`. The interface now perfectly degrades into a clean, parseable text stream instead of panicking when executed without a pseudo-terminal (e.g., Cron, SSH without `-t`, or CI/CD pipelines).
- Webhook Asymmetry: Resolved an issue where only Kernel-level (L3) drops triggered Discord/Teams notifications. The notification payload generation is now strictly coupled with the `logger.go` core, ensuring all WAAP (L7) mitigation events are immediately broadcasted to the SOC.

---

# Release v2.10.1

## ADDED
- ARP Spoofing Telemetry Integration: Natively integrated OSI Layer 2 ARP flood alerts directly into the Enterprise Dashboard (`syswarden tui`) and live alerts feed (`syswarden alerts`). The `syswarden-core` daemon now asynchronously monitors the kernel ring buffer for `[SysWarden-ARP-FLOOD]` events via `journalctl -k` and injects hardware-level attack traces seamlessly into the WAF telemetry pipeline.

---

# Release v2.10.0

## ADDED
- Layer 2 Protection Engine: Implemented native OSI Layer 2 filtering capabilities leveraging NFTables netdev and arp families.
- MAC Blacklist Capability: Introduced strict MAC address blocking at the ingress hook, ensuring zero interference with L3 routing, Docker networks, or existing firewalls (UFW/Firewalld).
- ARP Flooding Protection: Integrated aggressive ARP request rate-limiting (max 10 req/s) to neutralize ARP Spoofing/Flooding attacks while maintaining full compatibility with High Availability architectures (VRRP/Keepalived).
- Configuration Variables: Added SYSWARDEN_ENABLE_L2, SYSWARDEN_MAC_BLACKLIST, SYSWARDEN_ARP_PROTECT, and SYSWARDEN_LAN_MODE to the global configuration parser.
- Local LAN Mode (Air-Gapped/Zero-Trust): Implemented SYSWARDEN_LAN_MODE. When enabled, SysWarden intelligently bypasses the download and memory injection of massive public OSINT blocklists (Data-Shield, GeoIP, ASN) to heavily optimize RAM/CPU/Bandwidth on strictly internal servers, while maintaining full internal L2/L7 defenses.

## UPGRADED
- Configuration Security: Implemented rigorous IEEE 802 Regex validation for all MAC address inputs to definitively prevent NFTables syntax poisoning and runtime crashes.

## UPDATED
- Nftables Generator: Restructured the atomic deployment engine to cleanly provision, append, and destroy the netdev and arp families upon reload.

## FIXED
- None

---

# Release v2.01.11

## FIXED
- **Missing Cron Jobs Persistent Warning**: Fixed an issue where nodes upgraded from a previously bugged version (v2.01.8) would continuously report missing background tasks during `syswarden audit`. The `syswarden reload` command, executed automatically during package upgrades, now proactively inspects and safely repairs any missing `update-feeds` and `ha-sync` cron orchestration routines.
- **CI/CD Pipeline Failure (`syswarden-cli`)**: Resolved a fatal compilation error (`undefined: strings`) in `pkg/system/uninstall.go` caused by a missing library import during the native Go cron refactoring. The build pipeline and GitHub Actions now successfully compile the executable and generate the `.deb` and `.rpm` deployment artifacts.

---

# Release v2.01.9

## FIXED
- **Cron Orchestration Idempotency Bug**: Resolved a critical logic flaw in `downloader.go` and `cluster.go` where updating SysWarden on minimalist/hardened Debian systems would permanently delete the background Threat Intelligence and HA synchronization cron jobs. The update routine now uses 100% native Go string parsing to guarantee clean, atomic modifications to the `crontab` without relying on fragile bash pipelines (`grep -v`), fully resolving the `No automated SysWarden background jobs found` warning during `syswarden audit`.

---

# Release v2.01.8

## FIXED
- **Code Hygiene (CI/CD Pipeline)**: Cleaned up phantom `"os"` package imports across multiple CLI commands (`whitelist.go`, `unwhitelist.go`, `block.go`, `unblock.go`). This resolves a strict compilation and `golangci-lint` failure encountered by GitHub Actions runners during the automated build process.

---

# Release v2.01.6

## FIXED
- **Config Parser Oversight**: Resolved a core engine issue where the `SYSWARDEN_WHITELIST_IPS` configuration parameter was successfully parsed from `syswarden-auto.conf` but skipped during the firewall compilation phase. Custom whitelists are now flawlessly injected into the Nftables `syswarden_whitelist` set upon startup and reload.

## ADDED
- **Unlimited CLI Arguments**: The SysWarden CLI `whitelist`, `block`, `unwhitelist`, and `unblock` commands now natively support an unlimited number of arguments simultaneously (`syswarden block IP1 IP2 IP3...`). The strict parameter limits (e.g., `cobra.RangeArgs(1, 2)`) have been lifted, enabling instantaneous mass-processing.

---

# Release v2.01.4
- **APT Sandbox Warning (CIS2/ANSSI)**: Resolved an issue where `syswarden update` triggered an APT Notice (`_apt` user permission denied) during `.deb` upgrades on highly hardened Debian/Ubuntu servers enforcing `fs.protected_regular=2`. The update engine now natively changes the ownership of the downloaded package to the `_apt` user before installation, guaranteeing flawless and completely silent APT Sandbox compliance.

---

# Release v2.01.3

## ADDED
- **Native CIDR (Subnet) Support**: The SysWarden CLI `whitelist` and `block` commands now natively accept full CIDR notations (e.g., `10.0.0.0/24`, `192.168.0.0/16`). These subnets are dynamically parsed and injected into Nftables interval sets (`flags interval; auto-merge;`), enabling O(1) matching for massive IP ranges without any performance degradation.

---

# Release v2.01.2

## FIXED
- **Ubuntu/Debian Autocompletion**: Added an automated post-installation hook in the `.deb` package (`postinst.sh`) to natively append and uncomment the `bash_completion` logic within the `root` user's `~/.bashrc`. This guarantees that the SysWarden CLI `<TAB>` autocompletion is fully functional out-of-the-box on minimal Ubuntu/Debian server environments where it is disabled by default.

---

# Release v2.01.1

## FIXED
- Resolved a `staticcheck` pipeline failure (deprecation warning) in the L7 Brute-Force module by replacing `os.SEEK_END` with the standard `io.SeekEnd` for file tailing operations, ensuring full compliance with Go 1.26 static analysis.

---

# Release v2.01.0

## ADDED
- **L7 Brute-Force & Log Analytics Engine:** SysWarden now natively replaces Fail2ban. It autonomously parses application access logs (Traefik, Nginx, Apache) in real-time (`SYSWARDEN_BRUTEFORCE_LOGS`) via an asynchronous Goroutine and detects HTTP 401/403/404 abuse. It implements a sliding-window tracker and native Nftables blocking to counter L7 bruteforce attempts.
- **Native CLI Auto-Completion:** Added full auto-completion support for `bash`, `zsh`, `fish`, and `powershell`. The script is automatically deployed to `/etc/bash_completion.d/syswarden` upon installation to provide immediate `<TAB>` suggestions for all SysWarden CLI commands.

---

# Release v2.00.10

## ADDED
- The `syswarden-core` WAF Engine now dynamically fetches the latest available release directly from the GitHub API (`https://api.github.com/repos/duggytuxy/syswarden/releases/latest`) and streams it to the TUI.

## FIXED
- Resolved a critical desynchronization issue where several subcomponents (like `syswarden-tui`, internal `webhooks`, and the `install.go` routines) were displaying stale, hardcoded version strings (`v2.00.0`). The automated release script (`Release-SysWarden.ps1`) has been patched to aggressively sweep and identically bump all Go files containing version strings.

---

# Release v2.00.9

## ADDED
- Implemented an **Auto-Healing WAF Bridge** recovery mechanism. The `syswarden-cli reload` command now automatically and dynamically regenerates the `rsyslog` integration bridge (`99-syswarden-waf-bridge.conf`) based on the active user configuration.

## FIXED
- Updated the CI/CD `postinst.sh` lifecycle script to execute a native `syswarden reload` instead of a simple service restart during an upgrade. This guarantees that any configuration components (like firewall rules and log bridges) destructively purged by older versions are instantaneously restored without user intervention, achieving 100% Zero-Touch Upgrades.

---

# Release v2.00.8

## FIXED
- Synchronized FPM lifecycle orchestration scripts (`postinst.sh`, `prerm.sh`, `postrm.sh`) within the official GitHub Actions CI/CD pipeline (`package.yml`). This ensures that natively compiled `.rpm` and `.deb` releases correctly inherit the In-Place Upgrade capabilities, preventing `syswarden-core` downtime during automated package manager upgrades.

---

# Release v2.00.7

## FIXED
- Completely restructured the internal packaging lifecycle scripts (`prerm`, `postinst`, `postrm`) within `build_packages.sh` to natively identify and manage *In-Place Upgrade* states across both `dnf/rpm` and `apt-get/dpkg` package managers. This entirely resolves a critical flaw where `syswarden-core` services and `nftables` firewall rules were being inappropriately purged or deadlocked by the package manager during an upgrade.

---

# Release v2.00.6

## FIXED
- Remediated `golangci-lint` regressions (`errcheck`) by enforcing strict and explicit error handling on all `defer` file closure operations across the Go Native engine, maintaining compliance with Zero CWE standards.

---

# Release v2.00.5

## UPDATED
- Completely rewrote the `syswarden update` orchestration engine in native Go (`pkg/system/upgrade.go`), entirely eradicating the legacy Bash script dependency (`install.sh`). The in-place upgrade mechanism now natively detects the OS architecture, securely downloads the `.rpm` or `.deb` packages via the GitHub API into memory, and natively executes `dnf install` or `apt-get install` without relying on insecure subshells.

---

# Release v2.00.3

## FIXED
- Resolved a missing cron daemon dependency during automated unattended installations on minimal RHEL 9 and Debian environments. The `.rpm` and `.deb` deployment pipelines now strictly enforce `cronie` and `cron` dependencies natively.

---

# Release v2.00.2

## ADDED
- Enterprise SIEM Forwarding: Native support for robust TCP and TLS encryption via Rsyslog's `StreamDriver` (preventing CWE-319 vulnerabilities).
- The SIEM forwarder dynamically configures TLS authentication in `anon` mode to ensure maximum compatibility with self-signed Enterprise PKIs without dropping encrypted logs.

---

# Release v2.00.1

## ADDED
- Compliance & Security SBOM artifacts generated and attached to the release payload.

## UPGRADED
- All underlying Go dependencies across `syswarden-cli`, `syswarden-core`, and `syswarden-tui` modules to mitigate OSV and CVE vulnerabilities.

## UPDATED
- Removed binary artifacts from the source repository to enforce OSSF Scorecard best practices.
- Expanded `.gitignore` controls to strictly prevent accidental binary artifact contamination.

## FIXED
- Remediated `golangci-lint` regressions, including `errcheck` and `staticcheck` issues via robust error handling and `switch` block refactoring.
- Rectified `govulncheck` execution paths within `security-audit.yml` to support multi-module workspaces.
- Corrected `gh run download` logic and pathing within `release-manager.yml` to reliably fetch release assets from parallel CI/CD jobs.
- Fixed `push` event triggers in GitHub Action workflows (`package.yml`, `security-audit.yml`, `compliance.yml`) to correctly execute on version tags.

---

# Release v2.00.0

## ADDED
- Implemented native compilation and packaging support (.deb and .rpm) within the build pipeline using FPM.
- Embedded default configuration directly into the Golang binary to enhance package integrity and enforce strict structure validation.
- Interactive `syswarden config` CLI command acting as a secure wrapper using the system `$EDITOR` (nano/vi fallback).
- Real-time `ALLOWED` connection telemetry parser traversing native access logs (`sshd`, `nginx`, `apache2`) to extract legitimate traffic without cron/bash orchestration overhead.
- New real-time TUI dashboard for the `syswarden alerts` CLI command with dynamic auto-scrolling and dark theme.
- Native Golang integration of the complete SysWarden Management CLI (`syswarden block`, `syswarden whitelist`, `syswarden allow-ssh`, etc.), entirely replacing `syswarden-manager.sh` and its legacy bash firewall logic with dynamic Native Nftables file synchronization.
- Native Golang implementation of the full Enterprise DevSecOps Audit (`syswarden audit`), actively scanning the Go orchestration endpoints, Docker Nftables layers, and UDS Rsyslog sockets without relying on external `syswarden-audit.sh` parsing.
- Seamless TUI execution natively integrated into the core engine via the `syswarden tui` CLI command.
- Native Go module (pkg/security/cis.go) enforcing CIS Benchmark Level 2 Kernel and System hardening natively without external bash dependencies.
- Native Go module (pkg/security/os_hardening.go) establishing strict OS-level access controls, zero-trust profile locking, and secure anti-forging log routing.
- Native Go module (pkg/network/wireguard.go) orchestrating Wireguard cryptographic key generation in secure memory and configuring dynamic NAT routing directly.
- Native Go module (pkg/network/cluster.go) deploying a resilient High Availability synchronization engine.
- Native Go module (pkg/integration/abuseipdb.go) translating Python-based telemetry exfiltration to a compiled, secure Go worker.
- Native Go module (pkg/firewall/auto_whitelist.go) detecting active SSH sockets to safely automatically authorize infrastructure and admin IPs.
- Native Go module (pkg/firewall/lists.go) managing strict hierarchy whitelists and blocklists dynamically.
- Native Go uninstallation and update sequence modules (pkg/system/uninstall.go, pkg/system/upgrade.go).
- Entire SysWarden core Web Application Firewall (WAF) completely rewritten in native Golang (`syswarden-core`), utilizing the high-performance Aho-Corasick algorithm for real-time Layer 7 mitigation.
- Advanced Event-Driven Terminal User Interface (TUI) fully compiled in Golang (`syswarden-tui`). Replaces the legacy Bash interface with a raw terminal mode architecture that guarantees absolute Zero-CPU idling.
- Autonomous background telemetry engine (`setup_telemetry_backend.sh`) featuring an intelligent 15-minute offline cache for the GitHub API, strictly preventing external API rate-limit bans.
- Secure and robust fallback installation mechanism for the Golang compiler during local deployments, supporting strictly verified PGP installations via APT/DNF (ISO 27001 compliance) and Winget for Windows cross-compilation environments.
- Native Golang SysWarden WAF Engine replacing all legacy Fail2ban dependencies.
- Native Docker integration with Layer 3 (DOCKER-USER chain) and Layer 7 anomaly detection.
- Kernel Socket Detection feature to prevent Admin IP hijacking during automated installations.
- Enterprise TUI Dashboard written in Go for zero-CPU telemetry visualization.
- Systemd daemon orchestration module for syswarden-core.service auto-deployment.
- Deep signatures mapping for Docker API abuse and Docker authentication brute-force.
- High Availability (HA) native UDS payload streaming for zero-duplicate WAF ban synchronization across cluster nodes.
- Dynamic cluster intelligence vector `[HA-Cluster]` in `signatures.json` for native peer state ingestion.
- Explicit UI telemetry error tracking (`[OFFLINE (Telemetry Error)]` state) to prevent silent interface lockups during JSON parsing failures.
- Integrated Rsyslog UDS bridge checks in the audit script to securely track the omuxsock routing to /var/run/syswarden.sock.
- Dynamic Open Port detection (`ss -tuln`) integrated directly into the `nftables.go` configuration payload to intelligently allow legitimate listener sockets on the host.
- Restored the Zero-Trust `Catch-All` logging mechanism at the end of the `stateful_protect` input chain to capture and block unauthorized closed-port scans natively in `nftables.go`.
- Native parsing of `/etc/os-release` to flawlessly extract accurate OS telemetry (e.g. `Debian GNU/Linux 13 (trixie)`).
- TUI Dashboard `syswarden alerts` entirely recreated in native Go with pristine ANSI color-coded segmentation (`TIMESTAMP | MODULE | ACTION | SOURCE IP | TARGET (PORT/JAIL)`).
- Natively multiplexed WAF JSON and Kernel Journalctl log parsing inside the Go orchestrator for absolute real-time metrics generation.

## UPGRADED
- Rewrote the firewall orchestration engine to dynamically query the effective SSH port configuration via 'sshd -T' directly from the OS, guaranteeing boot-time lockout prevention even with missing configurations.
- TUI and Alert dashboards dynamically separate and categorize "ALLOWED" connections in high-contrast green.
- Telemetry worker module (`worker.go`) rewritten to decouple the dependency on `syswarden-auto.conf` file mappings.
- Nftables Kernel injection engine to an O(1) atomic aggregation transaction for 350k+ GeoIP and ASN Threat Intelligence feeds.
- The entire SysWarden platform architecture is upgraded to a 100% Native Go application. All legacy bash scripts, including the entire src/functions/ directory and build.sh scripts, were completely eradicated.
- Entire analytics core transitioned from Web UI to the high-performance Enterprise TUI Engine.
- Package manager wrapper secured with strict ISO 27001 GPG checks.
- Go backend error handling transitioned comprehensively to idiomatic `%w` context wrapping, aligning with Zero CWE and NIS2 telemetry standards.
- Refactored memory safe I/O operations by replacing deprecated `ioutil` with modern `os.ReadFile` in the core engine.

## UPDATED
- Expanded the WAF ALLOWED/BANNED IP REGISTRY (L4/L7) dashboard history to persistently display the last 50 real-time events for deeper log auditing.
- Enhanced the `syswarden alerts` live console with interactive row-highlighting selection bars for better readability.
- Upgraded the telemetry log ingestion mechanism to use a hybrid stream architecture (journalctl + standard tail) to ensure absolute compatibility and real-time ALLOWED event tracking across Debian 13, Ubuntu 24.04, and AlmaLinux 10.
- Modernized the 'syswarden audit' permissions evaluation to securely accept both 0600 and 0640 permissions on critical log files.
- Refactored the Global Blocklist aggregation logic to automatically track and count dynamically downloaded Data-Shield intelligence feeds in real-time.
- Dashboard Target column renamed comprehensively to `TARGET (PORT/JAIL/SERVICES)`.
- CI/CD packaging configurations (`build_packages.sh`, `package.yml`) simplified to purge the legacy copy instruction for `syswarden-auto.conf`.
- Threat feed download parser to strictly filter pure IPv4 addresses.
- Refactored the core syswarden-cli Orchestrator (cmd/install.go) to seamlessly chain the execution of all new security, firewall, network, and system modules in a strict monolithic deployment cycle.
- Total deprecation and complete removal of Fail2ban from the architectural stack. SysWarden now natively manages its own high-speed memory jails and IP state tracking via the new Golang engine.
- CI/CD GitHub Action build pipelines (`package.yml`) have been entirely restructured to cross-compile and seamlessly bundle both `syswarden-core` and `syswarden-tui` binaries natively inside the `.deb` and `.rpm` distribution packages.
- Real-time active threats registry in the TUI now features dynamic keyboard navigation (scrolling) and handles window resizing dynamically via OS-level SIGWINCH syscalls.
- Global WAF Blocklist now natively handles multi-tenant routing without jail.local dependencies.
- Uninstaller module completely revamped to surgically purge legacy Fail2ban configurations and SysWarden v2 Go daemons simultaneously.
- `define_ha_cluster.sh` engineered to strictly enforce `StrictHostKeyChecking=yes` and AES-256-GCM cipher over port 62026 for maximal MiTM mitigation.
- Mathematical intersection logic (`comm -23`) applied to `syswarden-sync.sh` to prevent redundant network transmissions of banned IP states.
- Adjusted DevSecOps audit Phase 3 to accurately validate Docker integration via the new Nftables inet syswarden docker_protect chain instead of legacy DOCKER-USER.
- Shifted audit cron verification to target the new syswarden-cli update-feeds task, eliminating the 60-second ghost process loop check.

## FIXED
- Resolved a critical TUI discrepancy where legacy OS services (rsyslog and generic nftables) were triggering false-positive 'inactive' alerts on systemd-native distributions.
- Fixed an anomaly in the WAF threat-intelligence engine that prevented successful SSH authentications from being indexed and rendered into the Alerts console.
- Strict data poisoning mitigation algorithm enforcing an exact 80-character lowercase hexadecimal match for the AbuseIPDB API Key configuration vector.
- Fatal "context deadline exceeded" (OOM) memory and CPU spike during massive kernel Netlink operations.
- "Exit status 1" crashes caused by IPv6 malformed addresses in GeoIP blocklists.
- Eliminated CWE-345 vulnerabilities by dynamically verifying active SSH sockets instead of relying on user-provided environmental variables for whitelisting.
- Eradicated file permission risks by securely executing cryptographic key generations and log file manipulations entirely within native Go scopes, preventing TOCTOU attacks.
- Resolved compilation issues by normalizing struct parsing and correctly referencing the syswarden-auto.conf payload mapped to Go memory structures.
- Eliminated terminal rendering artifacts and layout shifts by isolating the screen buffer and implementing precise ANSI cursor controls in the new Go TUI.
- Corrected the aggressive logrotate midnight wipeout behavior; the OSINT Top Attackers statistics are now persistently retained and safely extracted across multiple compressed kernel log archives.
- Race condition causing the 'Could not safely determine Admin IP' error in unattended deployments.
- Missing syswarden-core daemon registration which caused systemctl failures post-install.
- Vulnerability where Docker containers could potentially bypass standard INPUT chains without proper DOCKER-USER linkage.
- Uninstaller logic leaving traces of background WAF telemetry tasks.
- In-place upgrade script stopping non-existent services.
- Eliminated goroutine lifecycle memory leaks in `uds.go` and `syswarden-tui` by implementing flawless `context.Context` cancellation and `sync.WaitGroup` tracking.
- Eradicated silent failures across `logger.go` IO operations; all writes are now strictly evaluated and wrapped.
- Removed obsolete Apache/Nginx dynamic ACL injection logic from the manager script, fully deprecating local web server dependencies in favor of the new Go Terminal User Interface (TUI).
- `nftables` service detection bug; telemetry now natively executes `nft list tables` instead of relying on `systemd` status to correctly determine if the active kernel FW is loaded.
- Corrected Whitelist array mapping in the core telemetry generator `worker.go` to properly parse `/etc/syswarden/whitelist.ipv4` natively instead of returning an empty payload, restoring `Trusted Hosts` visibility in the TUI.
- Resolved `EPROTOTYPE` (Protocol wrong type for socket) kernel transmission failures by refactoring the Native Go UDS Server (`uds.go`) to natively ingest `unixgram` datagram streams, ensuring flawless zero-copy compatibility with `rsyslog`'s `omuxsock`.
- Fixed an ISO 27001 compliance race condition where AbuseIPDB telemetry silently failed after the `syswarden-auto.conf` payload was securely wiped from disk; `syswarden-cli` now surgically extracts and locks the API Key within a dedicated `0600` `secrets.env` file.
- Implemented $O(1)$ Native Netlink IP injection for the WAF engine (`syswarden-core`); Layer 7 banned IPs are now directly injected into the `banned_ips` Nftables set with a strict 30-day kernel-level timeout natively without invoking sub-shells.

- Resolved a critical deployment race condition (Bootstrap Paradox) by enforcing `WhitelistInfra: true` via a memory-safe fallback struct in the Go orchestrator when `syswarden-auto.conf` is dynamically injected post-install.
- Fixed FPM packaging pipelines (`build_packages.sh` and GitHub Actions `package.yml`) to enforce `rsyslog` as a strict native package dependency (`-d`), guaranteeing Zero-Touch automated UDS bridge integration across all RHEL and Debian derivatives.
- Eradicated a telemetry blind spot on Fedora/RHEL architectures by natively injecting `/var/log/httpd/access_log` into the Hybrid Telemetry Worker's asynchronous tailing routine.

---
