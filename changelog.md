# Release v3.75.3

## FIXED
- TUI Timestamps: Fixed a critical bug in `syswarden-tui` where all block/ban events incorrectly displayed the current system time instead of the actual event time. The `BannedIP` payload now accurately transmits and renders the original timestamp.
- Alpine Upgrades: Fixed a bug where `syswarden update` failed to restart daemon services on Alpine Linux due to incorrect service names (`syswarden` instead of `syswarden-core`) in the `upgrade.go` routine, and added proper OpenRC fallback logic to the `.apk` `postinst.sh` packaging scripts.
---

# Release v3.75.2

## FIXED 🐛
- Alpine SSH Bruteforce: Fixed native log ingestion by adding `/var/log/messages` to the WAAP engine tail paths, ensuring real-time `sshd` failure analysis on systems without `auth.log`.
- Alpine Services: Fixed `syswarden-core` and `syswarden-webtui` failing to stop properly during OpenRC daemon restarts by appending a graceful termination timeout (`retry="TERM/5/KILL/5"`).

---

# Release v3.75.1

## FIXED 🐛
- Native Installation: Fixed Web-TUI port not opening natively on Alpine Linux/OpenRC environments. The Web Token generation sequence is now executed prior to daemon enablement, preventing immediate process crash and preventing subsequent silent daemon failures without `Restart=on-failure` capabilities.

---

# Release v3.75.0

## FIXED 🐛
- In-place Upgrade (`syswarden update`): Added automatic background service restarts (`syswarden`, `syswarden-tui`) at the end of the update process to ensure the newly installed binary and embedded Web-TUI assets are immediately loaded into memory.
- Alpine Linux Upgrade: Fixed 404 download error by aligning the requested APK filename pattern (`syswarden_%s_%s.apk`) and dynamic CPU architecture mapping with the CI/CD pipeline outputs.

---

# Release v3.74.12

## FIXED 🐛
- Rsyslog Integration (Alpine/Minimal Linux): Added proactive directory creation (`/etc/rsyslog.d/`) to prevent `no such file or directory` crashes when writing WAF Bridge and SIEM configurations natively on minimal operating systems.

---

# Release v3.74.11

## FIXED 🐛
- Code Hygiene (SAST): Removed empty branch resulting from previous hotfix to resolve `staticcheck SA9003: empty branch` error in CI pipeline.

---

# Release v3.74.10

## FIXED 🐛
- Silenced expected IP family compatibility warnings during hybrid parsing to prevent console spam and log flooding during kernel set instantiation.

---

# Release v3.74.9

## ADDED ➕
- Missing GEOIP IPv6 logic (syswarden_geoip6) explicitly instantiated and loaded into kernel for global Drop actions.

## FIXED 🐛
- Massive overhaul of Firewall List parsing (Linux & FreeBSD): Removed strict file segregation, natively allowing IPv6 addresses hidden within .ipv4 files to be correctly sorted into their respective IPv6 kernel sets (Full Hybrid Blocklist Support).

---

# Release v3.74.8

## ADDED ⚡
- **Multi-Interface Ingress Protection (L2)**: Added the `SYSWARDEN_INTERFACES` directive in `syswarden-auto.conf` to bind the ultra-fast L2 hardware drop table (`syswarden_hw_drop`) to multiple network interfaces simultaneously (e.g., `eth0,eth1,eth2`). This ensures that administrative and development channels benefit from the same anti-DDoS acceleration as the primary public interface. If unset, SysWarden safely falls back to auto-detecting the primary active interface.
- **Web-TUI Clickable URLs**: Integrated the `xterm-addon-web-links` extension into the Web-TUI frontend. Threat Intelligence URLs (like AbuseIPDB) and other links displayed in the terminal interface are now fully clickable and open seamlessly in a new browser tab with strict no-tracking policies (`noopener`, `noreferrer`).

## FIXED 🐛
- **Web-TUI Unban Execution**: Fixed a path resolution bug in the Web-TUI where the `u` (unban) shortcut failed silently. The execution environment for the systemd service lacked the `/opt/syswarden/bin` `$PATH`. The `syswarden-tui` binary now uses an absolute path to invoke `syswarden unblock`, ensuring reliable execution regardless of the parent shell's path context.

---

# Release v3.74.7

## FIXED 🐛
- **Threat Intel Feeds**: Fixed the IPv6 GeoIP blocklist URL mapping for `ipdeny.com`. The path incorrectly included `/countries/` which led to 404 Not Found errors when fetching IPv6 zones. It has been corrected to the proper `/blocks/` endpoint.

---

# Release v3.74.6

## FIXED 🐛
- **Debian Packaging Orchestration**: Fixed a logical flaw in the Debian `postinst.sh` packaging script where the `syswarden-webtui.service` systemd daemon was exclusively provisioned during package upgrades. The logic has been decoupled so the Web-TUI service is now correctly generated and enabled on all deployment paths, including fresh `.deb` installations.

---

# Release v3.74.5

## ADDED ⚡
- **Smart Dual-Stack Parser**: The CIDR validation engine (`CleanCIDRList`) is now intelligent. If you mix IPv4 and IPv6 addresses inside a single Custom Threat Intel file (e.g. `SYSWARDEN_CUSTOM_URL`), the parser will automatically extract the IPv6 addresses and route them directly into the dedicated `.ipv6` lists to be processed natively by the firewall, without breaking the IPv4 tables.

---

# Release v3.74.4

## FIXED 🐛
- **Threat Intel Engine**: Fixed a hidden bug where the `SecureDownloader` would wrongly apply IPv4-only scrubbing to `.ipv6` blocklist files, inadvertently erasing downloaded IPv6 addresses.
- **Code Hygiene**: Fixed unchecked error return values (`errcheck`) when closing OSINT `ipv4` and `ipv6` file descriptors (`f4.Close()` / `f6.Close()`) in the CLI downloader.

---

# Release v3.74.3

## ADDED ✨
- **IPv6 Native Support**: Full implementation of IPv6 compatibility across the entire Syswarden architecture (CLI, Core Firewall, and TUI). 
  - Dynamic `ip6tables` and `firewalld` family switching for Fallback Managers natively detecting IPv6 payloads.
  - Complete integration of Custom Blocklist IPv6 (`SYSWARDEN_CUSTOM_URL_IPV6`, `SYSWARDEN_CUSTOM_HASH_IPV6`).
  - Native dual-stack processing (IPv4 and IPv6 streams) for OSINT feeds (CINS, Blocklist.de) and GeoIP lists (ipdeny.com) with dedicated `CleanCIDRListV6` scrubbing logic to prevent CWE-20 vulnerabilities.
  - TUI "Top Attackers" flex ratio expanded to ensure IPv6 visibility without layout artifacts.

## FIXED 🐛
- **Syswarden-Core**: Fixed incorrect port display (`80/443`) for SSH L7-BRUTEFORCE attacks in the TOP ATTACKERS (OSINT HISTORY) table. The telemetry worker now dynamically extracts the custom `SYSWARDEN_SSH_PORT` from the `syswarden-auto.conf` configuration.

---

# Release v3.74.2

## UPDATED ♻️
- **Syswarden-TUI**: Enhanced the `WAF ALLOWED/BANNED IP REGISTRY` to format "ALLOWED SSH" events natively into readable contextual reasons (e.g. `[Timestamp] Access granted for user 'root' via public key (ED25519 SHA256:...) from IP X`).

---

# Release v3.74.1

## FIXED 🐛
- **Code Hygiene**: Fixed unchecked error return value of `conn.Close()` in `worker.go` (golangci-lint/errcheck).

---

# Release v3.74.0

## ADDED ➕
- **Syswarden-TUI**: Added a `TranslatePayload` dictionary engine that converts raw kernel and web payloads into highly readable contextual reasons (e.g. `[Timestamp] Attempted port scan on port 22 by IP X`), including a direct OSINT link to AbuseIPDB (`https://www.abuseipdb.com/check/IP`) appended explicitly.
- **Syswarden-Core**: Implemented `GetOutboundIP` in telemetry worker to dynamically identify the server's primary IP (public or internal 10.x/192.x) and supply it to the UI.

## UPDATED ♻️
- **Syswarden-TUI**: Completely removed the legacy `Noise` and `Signal` displays from the UI header in both ALLOW/BLOCK modes. They are now replaced by `IP: [ServerIP]` while maintaining the existing grid structure.
- **Syswarden-TUI**: Renamed the `TARGET (PORT/JAIL/SERVICES)` column to `TRIGGERING` for precision.
- **Syswarden-TUI**: Renamed the `TRIGGER PAYLOAD` column to `REASON (ATTEMPTED ATTACK)`.
- **Syswarden-Core**: Re-engineered the `SEVERITY` metric logic for the Top Attackers block. Instead of a percentage, the engine now calculates a rigid score (`0-100`) based on recidivism (`hits * 10`) and adds a static `+20` multiplier when highly aggressive L7 exploits (SQLi, RCE, XSS) or brute-force behavior is detected.

---

# Release v3.73.1

## FIXED 🐛
- **Syswarden-TUI**: Fixed the "L3 KERNEL BLOCKS (GLOBAL)" display value in Zero-Trust mode to show the actual L7-to-L3 explicit blocked IP count instead of 'N/A' (e.g. `50 (Zero-Trust)`).

---

# Release v3.73.0

## ADDED ➕
- **Syswarden-TUI**: Added a `SEVERITY` column in the "TOP ATTACKERS (OSINT HISTORY)" table, which dynamically calculates and displays the aggressiveness percentage (`HitCount / TotalBans`) of each attacker.

## UPDATED ♻️
- **Telemetry / TUI**: Overhauled the `Noise/Signal` calculation for the Zero-Trust (ALLOW) mode. The TUI now detects `SYSWARDEN_GEO_ALLOWED` or `SYSWARDEN_ASN_ALLOWED` and correctly overrides the Noise metric to `>99.99% (Zero-Trust)`, avoiding miscalculations and heavy CPU overhead.


---

# Release v3.72.4

## FIXED 🐛
- **Web-TUI**: Translate Web-TUI URL announcement to English.

---

# Release v3.72.3

## FIXED 🐛
- **Syswarden-auto.config**: rebuild the configuration auto.conf by default.

---

# Release v3.72.2

## FIXED 🐛
- **Security**: Auto-generate in-memory self-signed TLS certificates for Native HTTPS support (`syswarden web-tui`).
- **Web-TUI**: Fixed static asset loading (xterm.js/css) by issuing a secure session cookie after initial token validation.
- **Web-TUI**: Fixed terminal crash ("term not set") by injecting `TERM=xterm-256color` into the PTY environment.
- **Web-TUI**: Fixed WebSocket crashes by switching from TextMessage (UTF-8) to BinaryMessage to support raw VT100/ANSI payloads.
- **Web-TUI**: Fixed initial terminal rendering size by synchronizing `fitAddon.fit()` with the browser layout cycle.

---

# Release v3.72.1

## FIXED 🐛
- **Code Hygiene**: Fixed unchecked error return value of `conn.Close()` in `web_tui.go` (golangci-lint).

---

# Release v3.72.0

## ADDED ➕
- **Zero-Client Web-TUI**: Implemented a fully functional Web-Terminal interface directly served by the SysWarden daemon.
- **Zero-Client Web-TUI**: Added `syswarden web-token --rotate` to securely generate, revoke, and manage one-time access tokens.
- **Zero-Client Web-TUI**: Integrated `syswarden-webtui.service` across systemd, OpenRC, and rc.d natively.
- **Upgrade Path**: Seamless auto-initialization of Web-TUI during `syswarden update` upgrades from older versions.

## UPDATED ♻️
- **Signatures**: Updated WordPress WAF jail to block `/wp-json/batch/v1` and `rest_route=/batch/v1` vectors (https://wp2shell.com/).

---

# Release v3.71.9

## FIXED 🐛
- Fix string literal escaping syntax error in lists.go.

---

# Release v3.71.8

## FIXED 🐛
Fix syntax error in sync.go caused by nosec pragma.

---

# Release v3.71.7

## UPDATED ♻️
- **Security & Pipeline Compliance (gosec)**: Hardened file and directory creation permissions across the entire codebase. Replaced lax permissions (0640/0644/0755) with strict, CIS-compliant permissions (0600 for files, 0750 for directories). Added #nosec pragmas to resolve structural false positives and ensure a 100% green CI/CD pipeline.
- **Dependency Management**: Integrated `rsyslog-uxsock` as a hard dependency for Alpine support.

## FIXED 🐛
- **WAF Engine / Regex Precision**: Fixed a critical L7 false positive where the `haproxy-abuse` heuristic (and other rules) could accidentally trigger on raw kernel logs containing IPv6-like structures (e.g., MAC addresses). The regex extraction engine now strictly validates matched patterns using `net.ParseIP` directly within the `ahocorasick` scanner, guaranteeing that non-IP strings are instantly rejected.
- **Rsyslog & UDS Optimization**: Drastically reduced CPU overhead and WAF noise by implementing strict firewall event filtering. Rsyslog (`waf_logs_linux.go`) is now instructed to drop native Netfilter geo-blocking logs (`SYSWARDEN-GEO/ASN`) before they reach the UDS socket. Additionally, the UDS bridge natively strips any remaining `MAC=` strings from raw firewall events, entirely immunizing the Layer 7 WAF engine against L3/L4 kernel artifacts.

---

# Release v3.71.6

## FIXED 🐛
- **UI / Telemetry**: Fixed an issue where the HA-Cluster TUI Explorer displayed a hardcoded `v3.70.0` version for peer nodes. The `syswarden-core` now dynamically extracts the exact system version during TLS cluster initialization, ensuring the UI always reflects the true installed version on each node.

---

# Release v3.71.5

## FIXED 🐛
- **CLI Upgrades**: Improved the error handling for `syswarden update` when the unauthenticated GitHub API rate limit (60 requests/hour/IP) is exhausted. Instead of displaying a confusing JSON parsing error (`could not parse latest version from API`), the CLI now catches the HTTP `403 Forbidden` status and outputs a clear, human-readable rate limit warning.

---

# Release v3.71.4

## FIXED 🐛
- **Code Hygiene**: Resolved a pipeline failure (`golangci-lint`) caused by an unused `"regexp"` import in `syswarden-core/telemetry/worker.go` that was left behind after optimizing the payload parser.

---

# Release v3.71.3

## FIXED 🐛
- **SysWarden TUI / Telemetry**: Fixed a display issue in the "TOP ATTACKERS (OSINT HISTORY)" table where the Target Port would incorrectly default to `80/443` for ICMP floods or other non-TCP/UDP attacks. The telemetry worker now dynamically parses the protocol (`PROTO=ICMP`, `ESP`, `GRE`, etc.) from the kernel payload when `DPT` (Destination Port) is absent.

---

# Release v3.71.2

## FIXED 🐛
- **Installation Orchestration**: Addressed an oversight where running `syswarden install` (after generating a new configuration via `syswarden config`) would not forcefully restart the active `syswarden-core` daemon on Systemd distributions (`enable --now` only starts if inactive). `syswarden install` now explicitly executes `systemctl restart` to guarantee that new architectural changes (such as binding the HA-Cluster port 62026) are immediately hot-loaded without requiring a manual `syswarden reload` or a server reboot.

---

# Release v3.71.1

## FIXED 🐛
- **Firewall Optimizer**: Fixed an issue where selecting `keep` (Firewalld) in `syswarden-auto.conf` would leave the native `nftables` systemd service active on distributions that had it pre-enabled. The CLI will now explicitly disable `nftables.service` and `iptables.service` when `keep` is selected, ensuring absolute control is returned to Firewalld while SysWarden continues to use the native netlink API internally.

---

# Release v3.71.0

## UPGRADED 🆙
- **Security Updates**: Bumped standard Go dependencies to resolve CVE vulnerabilities flagged by Trivy during CI/CD security audits:
  - Upgraded `golang.org/x/text` to `v0.39.0` across `syswarden-cli` and `syswarden-tui` to patch CVE-2026-56852 (Infinite loop on invalid UTF-8 bytes).
  - Upgraded `golang.org/x/net` to `v0.56.0` in `syswarden-core` to patch CVE-2026-46600 (Panic when parsing invalid SVCB/HTTPS DNS RR).

## FIXED 🐛
- **SysWarden TUI**: Resolved a critical deadlock issue where the TUI could freeze on exit (`wg.Wait` blocking indefinitely on background telemetry polls) and ignore `SIGINT` signals (Ctrl+C). `syswarden-cli` wrapper now gracefully handles `SIGINT` without propagating `SIG_IGN` to child processes, guaranteeing that the terminal is always reset (`TCIFLUSH`) and artifacts (`*`) are purged regardless of how violently the TUI is killed.

---

# Release v3.70.9

## FIXED 🐛
- **SysWarden TUI**: Implement bulletproof terminal teardown and TCIFLUSH in CLI to prevent mouse artifacts on SIGINT"

---

# Release v3.70.8

## FIXED 🐛
- **Go Module Corruption**: Fixed a critical pipeline CI/CD failure where standard Go modules (`golang.org/x/net`, `x/text`, etc.) had corrupted version numbers causing `gosec` and `golangci-lint` to fail during dependency resolution. The `go.mod` and `go.sum` files for all three core components (`syswarden-cli`, `syswarden-core`, `syswarden-tui`) were fully rebuilt and synchronized to stable versions.

---

# Release v3.70.7

## FIXED 🐛
- **Plumber Compliance**: Fixed about the new naming convention "plumber-compliance to plumber-report"

---

# Release v3.70.6

## FIXED 🐛
- **TUI Mouse Artifacts**: Fixed a display bug in `syswarden-tui` where a stray asterisk (`*`) was left behind on the terminal prompt upon exiting. Explicitly disabled mouse tracking sequences and added a buffer flush delay before terminating `tcell`.

---

# Release v3.70.5

## FIXED 🐛
- **Telemetry Duplication**: Deduplicated banned IPs in the `syswarden-core` telemetry registry to ensure each IP only appears once in the TUI, keeping only its latest event and preventing infinite loop log pollution.
- **L3 Firewall (Linux)**: Fixed a critical L3 firewall bypass and infinite log loop in `nftables` by inserting blacklist drop rules before established states in the `stateful_protect` chain.
- **L3 Firewall (FreeBSD)**: Added `pfctl` state flushing when banning IPs to instantly sever active attacker sessions, preventing the state tracking bypass in `pf`.
---

# Release v3.70.4

## FIXED 🐛
- **TUI Optimistic UI Updates**: Fixed an issue where unbanning an IP from the TUI caused the interface to block for 2 seconds and the IP to temporarily remain visible due to telemetry synchronization delays. Unban actions are now completely non-blocking, and the IP is immediately filtered out of the visual registry to provide instantaneous user feedback while background processes propagate the deletion across the HA mesh and local Netlink backend. Telemetry worker returning historical unbanned IPs.

---

# Release v3.70.3

## FIXED 🐛
- **TUI Optimistic UI Updates**: Fixed an issue where unbanning an IP from the TUI caused the interface to block for 2 seconds and the IP to temporarily remain visible due to telemetry synchronization delays. Unban actions are now completely non-blocking, and the IP is immediately filtered out of the visual registry to provide instantaneous user feedback while background processes propagate the deletion across the HA mesh and local Netlink backend.

---

# Release v3.70.2

## FIXED 🐛
- **TUI Responsiveness**: Fixed a critical thread lockup in `syswarden-tui` that caused the dashboard to freeze entirely when context-switching to an unreachable P2P HA-Cluster node. Network operations (fetching telemetry) are now fully asynchronous and no longer block the main `tview` UI drawing thread.

---

# Release v3.70.1

## FIXED 🐛
- **TUI Responsiveness**: Fixed a critical thread lockup in `syswarden-tui` that caused the dashboard to freeze entirely when context-switching to an unreachable P2P HA-Cluster node. Network operations (fetching telemetry) are now fully asynchronous and no longer block the main `tview` UI drawing thread.
- **Code Hygiene (golangci-lint)**: Fixed `errcheck` linter errors in the P2P TUI codebase by properly explicitly discarding unhandled `file.Close()` and `resp.Body.Close()` return values inside deferred operations.
---

# Release v3.70.0

## ADDED ➕
- **P2P HA-Cluster TUI Mesh**: SysWarden is now completely decentralized! The TUI (`syswarden tui`) features a new interactive Zero-Trust mesh overlay. Pressing `Esc` opens a new modal to explore all active HA-Cluster nodes. Selecting a node switches your local dashboard to supervise the remote node's telemetry in real-time.
- **Dynamic HA-Status Probing**: The TUI automatically and asynchronously probes all nodes declared in `SYSWARDEN_HA_PEER_IP` to display their Hostname, OS, Version, and `ONLINE`/`OFFLINE` statuses in a dedicated explorer table.

## DELETED
- **Deprecation of SysWarden Nexus**: The Hub-and-Spoke central management server (`syswarden-nexus`) and its associated core client integration (`nexus_client.go`) have been entirely removed.
- **Removal of mTLS Enrollment**: Removed the `syswarden enroll` command and API endpoint logic. The architecture is now strictly terminal-first and peer-to-peer.

---

# Release v3.62.1

## ADDED ➕
- **Interactive TUI Unban**: Added the ability to interactively unban IPs directly from the `syswarden tui` dashboard. Selecting an IP in the "WAF ALLOWED/BANNED IP REGISTRY" table and pressing the `u` hotkey triggers a secure modal confirmation, executing the native unban safely in the background.
- **HA Cluster Unban Synchronization**: Fully synchronized the unban mechanism across the High Availability cluster. Using `syswarden unblock` or the new TUI hotkey instantly purges the IP locally and broadcasts a Zero-Trust `DELETE /ha/sync` TLS payload to all configured HA peers, ensuring real-time cluster symmetry for whitelisting.

---

# Release v3.61.7

## FIXED 🐛
- **Firewall Reliability (nftables)**: Fixed an issue on Linux (`nftables`) where an IPv6 address accidentally present in an IPv4 whitelist or blacklist file would cause a fatal `Address family for hostname not supported` crash during the atomic `nft -f` transaction. The `populateSet` logic now strictly parses and enforces the correct IP address family for each generated firewall set (e.g. `syswarden_whitelist` vs `syswarden_whitelist6`), safely ignoring incompatible entries and emitting a `[WARNING]` log.

---

# Release v3.61.6

## FIXED 🐛
- **Code Hygiene (golangci-lint)**: Fixed strict staticcheck (`ST1023`) and errcheck warnings in the C2 `nexus_client.go` to ensure OSSF Scorecard pipeline completion and SLSA compliance.

---

# Release v3.61.5

## ADDED ➕
- **C2 Beaconing (mTLS)**: SysWarden agents now natively support Command and Control (C2) beaconing through the existing mTLS telemetry channel (`nexus_client.go`).
- **Remote Configuration Read**: Administrators can now remotely read the `/opt/syswarden/syswarden-auto.conf` file directly from the Nexus Dashboard via secure C2 polling.
- **Remote Auto-Update Orchestration**: Agents can dynamically trigger self-updates via the C2 channel. The agent intelligently detects its execution context (`root` vs unprivileged) and executes `syswarden update` (or `sudo syswarden update`) accordingly, streaming the output back to the Nexus Dashboard.

# Release v3.61.4

## FIXED 🐛
- **OSSF Scorecard (Supply Chain Security)**: Addressed a High-Severity `Binary-Artifacts #103` alert by removing the stray compiled `syswarden` binary from the git index and adding strict exclusions to `.gitignore`. This enforces SLSA compliance by ensuring no executable artifacts are tracked in the source repository.

---

# Release v3.61.3

## FIXED 🐛
- Fixed a syntax error during firewall ruleset generation (`nftables` and `pf`) where comma-separated custom LAN subnets in the configuration caused malformed sets (e.g., `unexpected comma` or missing `}`). The configuration parser is now robust against spaces and trailing commas.
- Optimized the Internal Enterprise Subnets (RFC1918) logic to be unified across both `Catch-All` and `Zero-Trust` bypass modes without generating duplicate bypass rules.

---

# Release v3.61.2

## ADDED ➕
- **Full Telemetry Synchronization**: The agent now natively synchronizes its comprehensive `data.json` state directly with the Nexus server over an mTLS-secured connection.

---

# Release v3.61.1

## FIXED 🐛
- Fixed a regex parsing bug in the `syswarden alerts` (TUI) console where `[SYSWARDEN-ZERO-TRUST]` drops were incorrectly displayed as a generic `SYSWARDEN-DROP` due to a missing hyphen match.

---

# Release v3.61.0

## UPDATED ♻️
- Implemented generic RFC1918 (LAN) bypasses for the Catch-All and Zero-Trust firewall rules across native nftables, PF (FreeBSD), firewalld, ufw, and iptables wrappers, guaranteeing internal enterprise subnets are always trusted.

## FIXED 🐛
- Resolved an issue in the WAAP engine where L7 signatures for SQLi and XSS failed to match URL-encoded payloads (e.g., `+`, `%20`, `%3c`) injected into raw HTTP access logs. Added comprehensive URL-encoded attack vectors to `sigSQLi` and `sigXSS` lists.

---

# Release v3.60.6

## FIXED 🐛
- **Code Hygiene**: Patched `staticcheck` (QF1012) violation regarding `WriteString(fmt.Sprintf(...))` by replacing it with `fmt.Fprintf(...)`.

---

# Release v3.60.5

## UPDATED ♻️
- **Configuration & UX**: Completely reorganized the `syswarden-auto.conf` structure into professional categories to improve SysAdmin experience.
- **Manual**: Enriched `syswarden manual` with explicit argument formats (`<IP>`) and global flag details.
- **L2 Intrusion Detection**: Adapted the ARP Flood protection `nftables` limit rule to support massive internal infrastructures (>1000 hosts) with frequent DHCP/Broadcast queries without triggering false-positive alerts.

## FIXED 🐛
- **Auto-Completion**: Explicitly forced `DisableDescriptions = true` on the Cobra completion engine to ensure 100% `bash-completion` compatibility on RHEL 8.10+ environments.
- **L2 Anti-Spoofing**: Enforced a strict Zero-Trust ARP Spoofing detection rule that instantly drops and logs any inbound ARP requests where an attacker attempts to claim the server's own local IPs.

---

# Release v3.60.4

## FIXED 🐛
- **Code Hygiene (golangci-lint)**: Addressed multiple unchecked error warnings (`errcheck`) in `syswarden-cli/cmd/config_cmd.go` and `syswarden-cli/cmd/enroll.go` to ensure a strict clean build in the CI/CD pipeline.

---

# Release v3.60.3

## FIXED 🐛
- **Code Hygiene (golangci-lint)**: Addressed a compilation failure caused by an unused `"encoding/base64"` import in `syswarden-cli/pkg/nexus/enroll.go`, ensuring a clean build in the CI/CD pipeline.

---

# Release v3.60.2

## ADDED ➕
- **Zero-Touch mTLS Provisioning**: SysWarden Nexus now natively hosts an internal Public Key Infrastructure (PKI). Upon initial startup, it autonomously generates a Root CA and Server certificates. When an agent executes `syswarden enroll --url <URL> --token <TOKEN>`, Nexus dynamically generates a dedicated ECDSA node keypair, signs a Certificate Signing Request (CSR) against its internal CA, and securely transmits the certificates (`CertPEM`, `KeyPEM`) back to the agent in a single seamless transaction.
- **Agent Trust-On-First-Use (TOFU)**: The SysWarden CLI `syswarden enroll` orchestration has been overhauled to implement a strict Trust-On-First-Use (TOFU) model for the initial HTTPS provisioning POST request, enabling "magical" enrollment without distributing CA certificates beforehand. All subsequent telemetry is rigidly authenticated via bidirectional mTLS.
- **WAF API Protection (Nexus)**: Added native `signatures.json` heuristics (`nexus-api-protect`) to proactively shield the Nexus API (`/api/v1/enroll`, `/api/v1/telemetry`) from directory traversal and injection attempts.
- **Nexus Firewall Orchestration**: The CI/CD pipelines (`build_packages.sh`, `package.yml`) now seamlessly embed `post_install.sh` scripts using FPM. SysWarden Nexus automatically detects the native Linux firewall manager (UFW, Firewalld, Iptables) and securely opens the required TCP/8443 listener port upon installation.

---

# Release v3.60.1

## ADDED ➕
- **SysWarden Nexus Zero-Trust Telemetry (mTLS & JWT)**: Complete finalization of the telemetry loop between the Agent (`syswarden-core`) and the Server (`syswarden-nexus`). The Agent now rigorously authenticates its POST requests (`/api/v1/telemetry`) to the Nexus using an mTLS certificate (`CertPEM`/`KeyPEM`) dynamically issued during the secure HTTPS enrollment phase.
- **SysWarden Nexus SecOps UI**: Integration of a complete SPA Front-End in Vue.js / Nuxt 3 (Premium Dark Mode Glassmorphism) natively embedded (`go:embed`) into the server binary. Comprehensive protection of API routes via highly secure JWT (JSON Web Tokens) generation and validation to prevent unauthorized access to the Dashboard.
- **SysWarden Nexus CI/CD Pipelines**: Refactoring of the OSSF Scorecard CI/CD and integration of Linux packaging pipelines (`.deb`, `.rpm`) for the `syswarden-nexus` project, ensuring the deployment of the `syswarden-nexus.service`.

---

# Release v3.60.0

## ADDED ➕
- **SysWarden Nexus Central Management Integration**: The SysWarden agent now natively integrates a "Sleepy Agent" module to securely enroll and synchronize telemetry with the centralized SysWarden Nexus console via Zero-Trust mTLS (`syswarden enroll <token>`).

---

# Release v3.55.1

## FIXED 🐛
- **SaaS Monitors Whitelisting**: Fixed a major bug where `BetterStack` IPv4/IPv6 ranges downloaded by the background updater were properly whitelisted by the software L7 WAF engine but never injected into the hardware L3 firewall tables (`nftables`/`pf`). Under strict Geo-IP configurations, SaaS monitors were dropped indiscriminately at Layer 3. The daemon now seamlessly injects both IPv4 and correctly separated IPv6 SaaS subsets directly into the kernel data paths.

---

# Release v3.55.0

## ADDED ➕
- **SaaS Monitors Dynamic Whitelisting**: Added a native integration to safely auto-whitelist verified uptime monitoring providers (e.g., BetterStack) to prevent 30-day bans during high-frequency health checks. Can be controlled via `SYSWARDEN_ALLOW_SAAS_MONITORS="y"`.

---

# Release v3.53.1

## FIXED 🐛
- **Security / Code Hygiene**: Patched GO-2026-5856 (Encrypted Client Hello privacy leak in `crypto/tls`) by strictly upgrading the compiler build toolchain to Go `1.26.5` across all modules and GitHub Actions CI pipelines.

---

# Release v3.53.0

## ADDED ➕
- **WireGuard Post-Quantum Encryption (PSK)**: Native integration of Post-Quantum resistant symmetric cryptography (`PresharedKey`) is now explicitly logged during VPN generation. The `syswarden audit` engine (Linux & FreeBSD) now formally validates and certifies the presence of this active Post-Quantum defense layer to satisfy stringent NIS2 and ISO 27001 compliance requirements.

---

# Release v3.52.11

## UPDATED ♻️
- **Telemetry Risk Vectors**: Completely wired the Global Risk Vectors telemetry in `syswarden-core`. The TUI and external SIEM components now accurately report real-time aggregated metrics for `Exploits`, `Brute-Force`, `Recon`, `DDoS`, and `Abuse/Spam` categories based on actual WAF detections and bans, replacing legacy UI mock placeholders.

---

# Release v3.52.10

## UPDATED ♻️
- **Code Hygiene**: Executed comprehensive `go fmt` across the `syswarden-cli/pkg/network` module to strip invisible trailing whitespaces in `sync.go`, enforcing strict Go styling guidelines and standardizing code formatting.

---

# Release v3.52.9

## UPDATED ♻️
- **Configuration Engine**: Added missing `SYSWARDEN_ENABLE_L2`, `SYSWARDEN_ARP_PROTECT`, and `SYSWARDEN_LAN_MODE` configuration parameters to the default interactive template generated by `syswarden config` to facilitate Layer 2 anti-spoofing and local RAM optimization.

---

# Release v3.52.8

## FIXED 🐛
- **SystemD ProtectSystem Override**: Fixed a severe orchestration issue where systemd's `ProtectSystem=full` directive silently blocked `syswarden-core` from persisting bans to `/etc/syswarden/lists/`. The daemon installer now properly whitelists the directory in `ReadWritePaths`, unlocking full High-Availability synchronization and instantaneous L7 telemetry feedback.
- **CI/CD RPM Upgrade Cycle**: Fixed an edge-case in the RPM/DEB packaging pipeline (`build_packages.sh` and `package.yml`) where seamless upgrades via `syswarden update` bypassed the execution of systemd service generation. The package installer now proactively hot-patches existing systemd configurations to unlock the L7 persistence write-paths natively without requiring a full reinstall.

---

# Release v3.52.7

## FIXED 🐛
- **SystemD ProtectSystem Override**: Fixed a severe orchestration issue where systemd's `ProtectSystem=full` directive silently blocked `syswarden-core` from persisting bans to `/etc/syswarden/lists/`. The daemon installer now properly whitelists the directory in `ReadWritePaths`, unlocking full High-Availability synchronization and instantaneous L7 telemetry feedback.

---

# Release v3.52.6

## FIXED 🐛
- **WAF Auto-Bans Persistence & HA Sync**: Fixed a critical architecture bug where locally detected WAF and CATCH-ALL bans were injected natively into Netlink/Nftables (RAM) but were never persisted to the disk blocklist (`syswarden_blacklist`). This prevented them from surviving reboots, broke the TUI telemetry (which read 0), and prevented the High Availability (HA) Cluster from synchronizing local detections to peers. Local bans are now properly and atomically persisted with duplicate checking to guarantee cluster symmetry and telemetry accuracy.

---

# Release v3.52.5

## UPDATED ♻️
- **Telemetry UI & Whitelisting Metrics**: Enhanced the SysWarden Enterprise Dashboard (TUI) to explicitly display the number of L7/HA synchronized banned IPs within the L3 Kernel Blocks global value. This correctly contextualizes the Noise/Signal ratio during Zero-Trust Strict Allow postures (Whitelisting), clearly showing that previously L7 banned IPs are being systematically dropped at L3 as expected (Noise) while new WAF/Catch-All detections register as actionable threats (Signal).

---

# Release v3.52.4

## FIXED 🐛
- **HA Cluster Network Binding**: Resolved a critical conflict during `syswarden install` where the High Availability peer synchronization port (`SYSWARDEN_HA_PEER_PORT`) was not automatically opened by the local firewall engine if the HA daemon was not yet running. The firewall orchestrator now dynamically injects the HA port into the Nftables atomic transaction (Linux) and Packet Filter configuration (FreeBSD). It also silently executes fallback overrides (`ufw allow`, `firewall-cmd --add-port`, `iptables -I`) to guarantee the port is opened regardless of the underlying OS wrapper firewall.

---

# Release v3.52.3

## FIXED 🐛
- **Firewall Engine**: Fixed a critical bug in Zero-Trust mode where outbound traffic was completely blocked. The Zero-Trust verification rule has been moved from the `ingress` hook to the `input` and `forward` hooks (after stateful connection tracking), allowing the server to natively receive response packets for outbound requests while strictly dropping unauthorized new inbound connections.
- **Threat Intel Engine**: Fixed an issue where the TUI displayed a phantom count of 115,000 blocked IPs when selecting `SYSWARDEN_LIST_CHOICE=4` or `3` after a previous full installation. The engine now natively clears pre-existing Threat Intel IPv4/IPv6 files from disk when these postures are selected, ensuring the telemetry remains perfectly synchronized with the zero-list policy.

---

# Release v3.52.2

## FIXED 🐛
- **Threat Intel Engine**: Fixed a logic bug where configuring `SYSWARDEN_LIST_CHOICE=4` (none) would still trigger the mirror latency benchmark and download Data-Shield blocklists, followed by OSINT feeds. The engine now correctly enforces the "zero-list" posture by completely skipping all downloads for option `4`. Additionally, option `3` (custom URL) correctly bypasses the download of OSINT feeds, ensuring strict adherence to the specified data sources.

---

# Release v3.52.1

## FIXED 🐛
- **TUI HA-CLUSTER Telemetry Status**: Fixed a configuration parsing bug where `syswarden-core` checked for the obsolete `/etc/syswarden/syswarden.conf` path and strictly expected the boolean `"true"`. The daemon now correctly parses `/opt/syswarden/syswarden-auto.conf` (or `/usr/local/etc/...` on FreeBSD), securely stripping quotes and validating against `"y"`. This instantly resolves the issue where the High Availability module was falsely reported as `SKIPPED` despite being fully active on cluster nodes.

---

# Release v3.52.0

## ADDED ➕
- **TUI Dashboard Enhancements**: Added real-time tracking for `SYSWARDEN-HA-CLUSTER` (ACTIVE, INACTIVE, SKIPPED) and `SYSWARDEN-UPDATE-FEEDS` (featuring a live countdown timer until the next execution) directly within the `syswarden tui` dashboard. The UI now dynamically highlights active countdowns in cyan for immediate visibility.

## UPDATED ♻️
- **Naming Convention Harmonization**: Executed a comprehensive global rename across the codebase and user interfaces, standardizing `SysWarden` to `SYSWARDEN`, `Node` to `NODE`, and `Catch-All` to `CATCH-ALL` for consistent enterprise typography.

---

# Release v3.51.6

## FIXED 🐛
- **Telemetry & Live Alerts Formatting**: Cleaned up the raw payload display in `syswarden alerts` (for both TUI and non-interactive text modes) to maintain consistent formatting. The L7 WAAP alerts (`BANNED`, `DETECTED`, `SHADOW-ALERT`) no longer append the raw log line, matching the clean structure of the network layer alerts. The native extraction of protocol/port metadata and SSH usernames remains fully functional.

---

# Release v3.51.5

## FIXED 🐛
- **HA Cluster Network Binding**: Fixed a critical parser fragility in the High Availability TLS configuration reader (`ha_api.go`) that caused silent binding failures on the listening port (e.g. `62026`). The config parser is now fully immune to trailing spaces, `\r` line endings from hybrid Windows/Linux environments, and variable quote encapsulation. Added a failsafe default to guarantee the correct port is always exposed.

---

# Release v3.51.4

## UPDATED ♻️
- **Documentation**: Updated `README.md` and `Deployment-Tutorial.md` to fully reflect the new Zero-Touch TLS P2P API architecture for High Availability clustering, removing all legacy references to SSH ports and passwordless keys.
- **HA Configuration**: Cleaned up the `syswarden config` and `syswarden manual` outputs by removing obsolete SSH parameters (e.g. `SYSWARDEN_HA_STRICT_HOST_KEY`) and explicitly indicating the use of a TLS port.

## FIXED 🐛
- **Legacy Code Cleanup**: Removed the deprecated Trust On First Use (TOFU) `ssh-keyscan` logic from the CLI's cluster setup routine (`cluster.go`), ensuring the codebase is exclusively reliant on the modern TLS API.
---

# Release v3.51.2

## FIXED 🐛
- **SSH Socket Activation Compatibility**: Fixed a critical bug in the telemetry worker (`worker.go`) where it failed to capture successful SSH logins on modern distributions utilizing socket-activated SSH (like Alma Linux 10+ and Ubuntu 24.04+). Migrated the `journalctl` query from `-u sshd` (Systemd unit matching) to `-t sshd` (Syslog Identifier matching) to ensure comprehensive session logging regardless of the underlying ephemeral `sshd@<id>.service` naming scheme.

---

# Release v3.51.1

## ADDED ➕
- **Zero-Touch Auto-Whitelist (HA Cluster)**: The HA clustering engine now natively and autonomously whitelists all configured `SYSWARDEN_HA_PEER_IP` nodes upon installation or reload. This eliminates the need for manual firewall interventions, ensuring the native TLS P2P API seamlessly bypasses the default-deny ruleset during cluster bootstrapping.

---

# Release v3.51.0

## UPGRADED 🆙
- **High Availability (HA) Zero-Touch TLS P2P Clustering**: The HA synchronization architecture has been completely rewritten in native Go. It abandons the legacy SSH-based sync (and its requirement for manual key exchanges) in favor of a highly scalable, "Zero-Touch" TLS P2P API. `syswarden-core` now integrates a micro-server (`ha_api.go`) that dynamically generates self-signed certificates and strictly enforces Zero-Trust TCP IP validation against `SYSWARDEN_HA_PEER_IP` to instantly and securely broadcast banned IPs across 500+ node clusters without any user intervention.

---

# Release v3.50.5

## ADDED ➕
- **GitOps Auto-Versioning CI/CD**: Migrated the legacy local PowerShell release script into a fully autonomous GitHub Actions workflow (`auto-versioning.yml`). The version bumping process (Patch, Minor, Major, Upgrade) is now dynamically orchestrated upon push to the `main` branch based on the commit message prefix, ensuring absolute consistency across all core components.

## FIXED 🐛
- **CI/CD Pipeline Syntax Error**: Fixed a critical PowerShell 7 array instantiation error within `auto-versioning.yml` that previously caused the `Join-Path` command to fail (`Cannot convert 'System.Object[]' to the type 'System.String'`) on Ubuntu runners during path generation.
---

# Release v3.50.4

## FIXED 🐛
- **OSINT Telemetry Rate-Limiting & Cache Loss**: Resolved a critical issue in `syswarden-core` where OSINT data (Country, ASN, ISP) disappeared in the TUI after executing `syswarden reload`. The in-memory telemetry cache (`osintCache`) is now securely persisted to `/var/lib/syswarden/ui/osint_cache.json` across daemon restarts. Additionally, the HTTP request execution flow to the external OSINT API has been decoupled from the primary Mutex (`osintMu`), completely preventing sequential rate-limiting (HTTP 429) and telemetry lockups (timeout) during mass ingestion of new attacking IPs.
---

# Release v3.50.3

## ADDED ➕
- **Data-Shield Dynamic Latency Benchmark**: Engineered an autonomous, multi-threaded latency benchmarking system (`SelectFastestThreatIntelMirror`) to dynamically select the fastest Threat Intelligence mirror upon execution. The orchestration engine now pre-tests GitHub, GitLab, jsDelivr, Bitbucket, and Codeberg via HTTP `HEAD` probes, chronometers their response times, and sorts the fallback sequence strictly by optimal latency. This completely replaces the blind sequential failover, guaranteeing absolute maximum bandwidth and minimal network overhead during Zero-Trust ingestion operations.
---

# Release v3.50.2

## ADDED ➕
- **High Availability (HA) Multi-Node Support**: The `syswarden-cli ha-sync` orchestration engine natively supports resolving and synchronizing across multiple HA peer nodes simultaneously. `SYSWARDEN_HA_PEER_IP` now accepts a space- or comma-separated list of IP addresses, effortlessly projecting the active Zero-Trust blocklist state to an entire cluster ecosystem in parallel.

## FIXED 🐛
- **AbuseIPDB Configuration Reloading**: Patched a configuration drift bug where dynamically altering `SYSWARDEN_ENTERPRISE_MODE` or `SYSWARDEN_ENABLE_ABUSE` post-installation was ignored by `syswarden reload`. The orchestrator now properly executes `SetupAbuseIPDB()` during live reloads and securely zeroes out legacy `secrets.env` configurations if the service is downgraded or deactivated.
- **Threat Intelligence Mirror Resilience**: Fixed an edge-case network exhaustion bug (`context deadline exceeded`) observed on RHEL/AlmaLinux families. The orchestration engine's global context timeout has been aggressively expanded (from 2m to 15m) to guarantee that all fallback mirrors (GitHub, GitLab, jsDelivr, Bitbucket, Codeberg) can fully execute their retry loops sequentially without being prematurely terminated by the main thread.
- **High Availability (HA) TOFU Automation**: Engineered a secure Trust On First Use (TOFU) host-key exchange sequence within the `cluster.go` orchestration engine. SysWarden now autonomously utilizes native `ssh-keyscan` during HA initialization to securely pin the standby node's ED25519 public key into the local `known_hosts` vault. This completely eliminates silent `StrictHostKeyChecking` connection drops and guarantees immediate Zero-Touch synchronization across cluster nodes without any post-installation key bridging.

---

# Release v3.50.1

## FIXED 🐛
- **Threat Intelligence Mirror Resilience**: Implemented a highly resilient mirror fallback rotation (GitHub, GitLab, jsDelivr, Bitbucket, Codeberg) within the `downloader.go` orchestration engine. This natively mitigates single-point-of-failure network timeouts (e.g., Codeberg IPv6 rate-limiting) during Data-Shield ingestion by automatically failing over to the next available enterprise CDN, ensuring uninterrupted Zero-Trust L3 protection.

---

# Release v3.50.0

## ADDED ➕
- **Native IPv6 Support (WAF & L3/L4)**: SysWarden now natively supports full IPv6 mitigation. The Linux Nftables backend autonomously provisions the `banned_ips6` Set and corresponding drop rules, while the FreeBSD (`pf`) backend handles IPv6 blocks seamlessly, closing all potential IPv6 WAF bypass vectors.
- **Custom IPv6 Threat Intelligence Feeds**: Added native support for downloading and parsing custom IPv6 blocklists via `SYSWARDEN_CUSTOM_URL6` (when `SYSWARDEN_LIST_CHOICE=3`). The `downloader` orchestration engine now automatically syncs and injects these into `syswarden_blacklist6` ensuring custom enterprise defense coverage.
- **Zero-Trust Native IPv6 Whitelist**: Completely overhauled the `SYSWARDEN_WHITELIST_IPS` parsing engine (`auto_whitelist.go`). SysAdmins can now pass space-separated arrays containing both absolute IPv4 and IPv6 addresses. The engine intelligently parses and routes them to their respective backend firewall tables without breaking the legacy configuration footprint.

## UPGRADED 🆙
- **High Availability (HA) IPv6 Sync**: Expanded the `syswarden-cli ha-sync` engine to automatically synchronize the IPv6 manual blocklist (`syswarden_blacklist.ipv6`) alongside the legacy IPv4 blocklist. The HA module utilizes purely native Go SSH automation to atomically stream cross-node IPv6 threat state without bash dependencies.
- **CLI IPv6 Enforcement**: Upgraded the `syswarden block`, `syswarden unblock`, `syswarden check`, and `syswarden list` commands to natively accept, parse, and enforce full IPv6 arrays, injecting them dynamically into the kernel L3 firewall.
- **UDS Socket Hardening (LPE Prevention)**: Strictly hardened the UNIX Domain Socket permissions for `/var/run/syswarden.sock` from `0666` to `0660`. This aggressively isolates the daemon communication bridge, preventing any non-privileged user from interacting with the socket and nullifying Local Privilege Escalation (LPE) risks.
- **Code Hygiene**: Enforced strict `gofmt` formatting and standard library `net` imports across the Core engine to guarantee 100% CI/CD pipeline compliance and robust cross-platform compilation.

## FIXED 🐛
- **IPv6 Regex Precision (Aho-Corasick)**: Completely rewrote the `ExtractIP` regular expression engine to surgically capture abbreviated IPv6 formats (e.g., `fe80::1`) while strictly preventing greedy matches against standard log timestamps (e.g., `12:00:00`), ensuring Zero False Positives during IPv6 threat qualification.
- **FreeBSD Threat Intelligence Persistence (PF)**: Resolved a critical regression where the FreeBSD Packet Filter (`pf`) backend silently failed to load massive threat intelligence sets (Global Blocklist, GeoIP, ASN). SysWarden now orchestrates the `persist file` directive to force native filesystem loading for all PF tables, securely mapping up to 400,000 dual-stack CIDRs into kernel memory without overflowing the CLI execution buffer.
- **Dual-Stack ASN WHOIS Routing**: Corrected the `syswarden update-feeds` engine to natively intercept both `route:` and `route6:` objects when querying RADB (`whois.radb.net`). The ASN threat vectors are now flawlessly segmented into `.ipv4` and `.ipv6` lists and injected directly into `syswarden_asn` and `syswarden_asn6` kernel sets, guaranteeing absolute IPv6 infrastructure defense.

---

# Release v3.41.0

## UPDATED ♻️
- **Signatures Mapping / CMS Honeypot**: Renamed the generic `cms-honeypot` L7 WAAP rule to a highly specific `cms-wordpress` identifier. Realigned the Aho-Corasick payload array (`/wp-includes`, `/wp-admin`, `/wp-login.php`, `xmlrpc.php`, `wp-config.php`) to strictly target WordPress vectors, drastically improving SIEM visibility and eliminating heuristic overlaps.

## FIXED 🐛
- **L7 WAAP Signature Shadowing**: Restructured the hierarchical evaluation order within `signatures.json` to enforce a "Most Specific First" paradigm. Moved aggressive catch-all regexes (`nginx-scanner`, `laravel-login`, `generic-auth`) to the absolute bottom of the evaluation stack. This completely eliminates rule shadowing and guarantees that highly specific CVEs and service alerts (e.g., `nginx-tls`) trigger correctly before being swallowed by generic L7 patterns.
- **SQLi-XSS Payload Refactoring**: Split the monolithic `sqli-xss` Aho-Corasick rule to exclusively target SQL injection patterns (`UNION SELECT`, `CONCAT(`, `WAITFOR DELAY`, `SLEEP(`). Stripped redundant XSS and LFI vectors (`<script`, `alert(`, `../../`) that were already covered by the dedicated Zero-Overhead `owasp-a03-xss` and `l7-lfi` rules, ensuring absolute precision and Zero False Positives during heuristic analysis.
- **Regex Extraction Precision**: Fixed critical regex spacing and string boundary matching anomalies within the `haproxy-abuse`, `slowloris`, and `redis-auth` L7 rules. Ensures that WAF detection executes flawlessly across a 74/74 multi-vector signature battery test.

---

# Release v3.40.8

## FIXED 🐛
- **Engine / Regex False Positives**: Fixed a highly specific false-positive in the `ahocorasick` matching engine where the generic `<HOST>` replacement regex for IPv6 (`[a-fA-F0-9:]+`) was overly greedy and could mistakenly match log timestamps (e.g., `12:50:59`) and random port combinations, triggering incorrect L7 WAAP jails (like `haproxy-abuse`) for standard SSH blocks. The `<HOST>` placeholder now uses a strict, boundary-enforced regex to exclusively match valid IPv4 and IPv6 structures, ensuring flawless threat qualification.

---

# Release v3.40.7

## FIXED 🐛
- **Telemetry Formatting & Syslog Recursion Loop**: Resolved a critical defect where SysWarden logging its own block events into Syslog caused an infinite recursive feedback loop through the Rsyslog `waf_bridge`, inflating the `payload` field uncontrollably in the UI. Implemented a strict drop-rule for `syswarden-core` messages at the bridge layer and introduced a native `SysWardenRaw` template to strip Syslog framing (`<PRI>`, timestamp, hostname) before routing to the UDS socket. As a result, SIEM, Wazuh, and local TUI logs are now perfectly formatted with exact raw string payloads for both Web and SSH components.

---

# Release v3.40.6

## FIXED 🐛
- **HIDS / SSH Brute-Force Visibility**: Fixed a critical log forwarding omission where `syswarden-cli` only configured Rsyslog to forward Web server logs (Nginx/Apache) to the core engine socket (`waf_bridge`). The configuration (`waf_logs_linux.go` and `waf_logs_freebsd.go`) has been updated to nativey include `/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, and `/var/log/messages`, instantly restoring SysWarden's capability to detect and ban SSH brute-force attempts.

---

# Release v3.40.5

## ADDED ➕
- **Advanced Threat Intel WAAP Signatures (L7)**: Integrated new zero-day/CVE signatures (JetBrains TeamCity, Citrix Bleed, MOVEit, F5 BIG-IP) with immediate BAN enforcement. Added advanced generic payloads targeting Cloud SSRF (AWS/Azure/GCP Metadata), Java SSTI/RCE (freemarker, getRuntime), and malicious AI crawlers in DETECT mode for precise triage and low false-positive rates.
- **Deep Packet Inspection & Network Threat Intel (L3/L4)**: Drastically hardened native firewalls (Nftables for Linux/Alpine, PF for FreeBSD) by introducing kernel-level mitigation against NULL and XMAS port scans, dropping invalid IP fragments (Nmap evasion), and implementing strict UDP payload limits (dropping UDP/53 > 512 bytes) to proactively neutralize DNS exfiltration attempts.
---

# Release v3.40.4

## ADDED ➕
- **Spamhaus ASN-DROP Support**: Implemented dynamic downloading and parsing of the `asndrop.json` (JSON Lines) list. Integrated deduplication against custom ASN lists, enforcing native ASN extraction and blocking while strictly rate-limiting RADB WHOIS lookups to prevent blacklisting. The implementation safely ignores IPv6 constraints at the WHOIS parsing layer to maintain compatibility with Nftables chunking logic.

---

# Release v3.40.3

## FIXED 🐛
- **Alpine Linux Support (In-Place Upgrade)**: Fixed a critical issue where running `syswarden update` on Alpine Linux 3.23+ would fail with a missing package manager error. The `upgrade.go` engine has been updated to nativey detect and use `apk` to securely download and install `.apk` updates via `apk add --allow-untrusted`.

---

# Release v3.40.2

### FIXED

Error package and code hygiene v3.40.1

---

# Release v3.40.1

## FIXED 🐛
- **Code Hygiene (golangci-lint)**: Addressed a `staticcheck` error (`QF1003: could use tagged switch on b.Action`) in the TUI (`syswarden-tui/main.go`). The `if-else if` block for parsing telemetry actions has been optimized into a clean `switch` statement to satisfy strict continuous integration compliance and eliminate pipeline failures.

---

# Release v3.40.0

## ADDED ➕
- **Insider Threat Detection (DETECTED Mode)**: Implemented the `DETECTED` action mode for WAAP signatures. Rules tagged with `"action": "detect"` are logged natively as `DETECTED` severity without executing an L7 ban, ensuring zero-regression observability.
- **SIEM Telemetry Parsing**: Enhanced the WAF/Telemetry JSON parser and `syswarden-core/logger` to dynamically append `Severity` mapping: `BANNED=10`, `SHADOW-ALERT=8`, `DETECTED=7`, `ALLOWED=3`. This natively guarantees accurate severity routing across SIEM integrations (Wazuh, Splunk).

## UPDATED ♻️
- **TUI & Live Alerts Real-Time Display**: Overhauled `syswarden alerts` and `syswarden tui` (Dashboards) to distinctly colorize and trace `DETECTED` heuristics (Yellow) in real-time, matching SOC visibility standards.
- **Webhook Dispatcher (Discord/Slack)**: Updated the webhook integration core to uniquely style and map `DETECTED` alert vectors with a dedicated Orange/Yellow visual indicator to distinguish from active blocking.

## FIXED 🐛
- **WireGuard Persistence (#43)**: Remedied a devastating oversight where installing `syswarden v3.31.1` abruptly terminated the active WireGuard `wg0` tunnel. SysWarden now rigorously preserves pre-existing encrypted tunnels during setup.

---


# Release v3.31.1

## FIXED 🐛
- **OSINT Enrichment (Datacenter IP Ban)**: Switched the telemetry OSINT provider from `FreeIPAPI` to `ip-api.com`. `FreeIPAPI` was found to natively block HTTP requests originating from Cloud/Datacenter ASNs (like OVH) with a `403 Forbidden` error, resulting in empty data in the TUI. `ip-api.com` natively handles 45 req/min (64,800/day) and cleanly resolves IP geolocation and ASN data regardless of the hosting provider.

---

# Release v3.31.0

## ADDED ➕
- **ARM64 Support**: Native cross-compilation support for `linux/arm64` (aarch64) in CI/CD. Distribution packages (`.deb`, `.rpm`, `.apk`) and raw binaries are now seamlessly built, bundled, and released automatically to support ARM architectures (e.g., AWS Graviton, Raspberry Pi, Oracle Cloud).

## UPDATED ♻️
- **OSINT Threat Intelligence Engine**: Migrated the core IP metadata enrichment provider to `FreeIPAPI` over HTTPS (`de.freeipapi.com`). This enterprise-level transition natively supports extremely high-volume environments (60 requests/minute or ~86,000/day) without requiring API keys, eliminating previous restrictions while maintaining absolute 100% precision on Country, ASN, and ISP data in the TUI Dashboard.

---

# Release v3.30.0

## ADDED ➕
- **Alpine Linux Support**: Full native support for Alpine Linux (3.21+). The Go WAF and CLI orchestrator automatically detect Alpine at runtime and natively configure `apk` dependencies, `rc-update/rc-service` (OpenRC) system services, and route WAF/kernel logging via `/var/log/messages` (`tail -F`) instead of `journalctl`, providing a seamless and highly optimized security deployment on lightweight alpine architectures.

---

# Release v3.20.2

## FIXED 🐛
- **OSINT Enrichment**: Fixed an inconsistency in the `syswarden tui` dashboard where the "Top Attackers" table displayed a hardcoded port (`80/443`) regardless of the actual attack vector. The `enrichOSINT` telemetry engine now dynamically extracts the exact targeted port (`DPT`) directly from the firewall drop payload using robust regular expressions, ensuring perfect alignment with the "Trigger Payload" data.

---

# Release v3.20.1

## FIXED 🐛
- **Code Hygiene (golangci-lint)**: Addressed multiple CI pipeline errors flagged by `govet` and `staticcheck`. Fixed missing `%s` formatting directives in `manual.go` ANSI color output blocks.
- **Code Hygiene (golangci-lint)**: Refactored redundant `if-else` action chains into optimized `switch` statements across `alerts.go` and `worker.go` to satisfy `QF1003` staticcheck constraints.
- **Code Hygiene (golangci-lint)**: Eliminated explicit slice type declarations (`var finalData []byte = data`) in `discord.go` in favor of idiomatic type inference (`finalData := data`), resolving `ST1023` linting warnings and ensuring a flawless CI/CD green build.

---

# Release v3.20.0

## ADDED ➕
- **Insider Threat Detection (Shadow Mode)**: Implemented a robust 'Shadow Mode' framework designed specifically for zero-trust environments. When malicious L7/WAF behaviors (e.g., PrivEsc, RCE attempts, unauthorized enumeration) originate from whitelisted administrative IPs, SysWarden now silently tags the event as a `SHADOW-ALERT` instead of enforcing a ban. This prevents service disruption for legitimate admins while ensuring immediate SOC visibility into compromised credentials.
- **Honeyports (L3 Lures)**: Introduced `SYSWARDEN_HONEYPORTS`, allowing SysAdmins to seamlessly expose fake open ports natively protected by Nftables and PF. Any internal connection attempts to these decoys immediately trigger silent SOC alerts if originating from a whitelisted IP, or result in an instant ban for unauthorized IPs.
- **Unified Multi-Webhook Dispatcher**: Rewrote the webhook telemetry engine to natively support Slack, alongside Discord and MS Teams. Security Operations Centers now receive rich, color-coded, real-time threat intelligence feeds directly to their platform of choice, including explicit differentiation for `SHADOW-ALERT` events.
- **SysWarden Dashboard (TUI) Enhancements**: Expanded the terminal user interface (`syswarden tui`) and live telemetry stream (`syswarden alerts`) to natively parse and distinctly colorize `SHADOW-ALERT` and `ALLOWED` events, improving visibility for SOC analysts.

## UPDATED ♻️
- **Wazuh HIDS Integration**: Upgraded the automated Wazuh agent integration engine. SysWarden now natively injects explicit `<localfile>` blocks into `/var/ossec/etc/ossec.conf` to guarantee `waf.json` telemetry and `core.log` tracing are immediately ingested by Wazuh, maintaining 100% SIEM compliance.
- **FreeBSD Compatibility**: Ensured full compatibility for FreeBSD 14.4+ architectures, translating native Honeyport traps into compliant Packet Filter (`pf`) drop rules, guaranteeing identical enterprise-grade protection across Linux and BSD deployments.

---

# Release v3.10.3

## ADDED ➕
- **L7 WAAP Programmatic Immunity:** Developed a native, high-performance, in-memory cache module (`utils.IsWhitelisted()`) that dynamically parses and caches infrastructure IPs (`syswarden_whitelist.ipv4`, `syswarden_whitelist.ipv6`) and local loopbacks (`127.0.0.1`, `::1`). This explicitly grants absolute L7 WAAP and L3 Catch-All immunity to administrative IPs, drastically reducing CPU overhead and disk I/O bottlenecks without relying on external packages.

## FIXED 🐛
- **WordPress Administrator Self-Lockouts:** Resolved a critical bug where the asynchronous L7 WAAP daemon (`waap.go`) blindly banned authenticated administrators and legitimate local server cron jobs (e.g., `wp-cron.php` HTTP POST requests) that tripped rate-limits or payload heuristics. The WAAP engine now natively validates all requests against the programmatic immunity cache before enforcing drops or logging.

## UPDATED ♻️
- **Zero-Trust Architectural Separation:** Completely refactored the kernel firewall architectures (`firewall_linux.go` and `firewall_freebsd.go`) to physically decouple the **Infra Whitelist** (`syswarden_whitelist`) from the **Zero-Trust Allowed** countries/ASNs (`syswarden_zt_allowed`). This seals a critical logic flaw where Zero-Trust permitted countries inadvertently bypassed ThreatIntel blocklists. Infra IPs are now processed with ultimate `pass in quick` priority, while Zero-Trust ranges remain strictly subjected to all WAF and Intelligence evaluation phases.

---

# Release v3.10.2

## FIXED 🐛
- **Universal Nftables Compatibility (LXC/Proxmox):** Refactored the core atomic firewall transaction in `syswarden-cli`. The modern `destroy table` syntax, which triggers `unexpected table` syntax errors on older or strict LXC environments (e.g., Debian 11/12 on Proxmox VE), has been replaced with pre-transaction silent `nft delete table` commands. This guarantees 100% backward and forward compatibility without sacrificing atomic load safety.

---

# Release v3.10.1

## UPDATED ♻️
- **TUI & Alerts Formatting:** Enhanced `syswarden alerts` to intelligently parse raw kernel payload strings for `L3-PORTSCAN` and `L2-ARP-FLOOD` blocks. Instead of displaying the raw `dmesg` buffer, the alerts now cleanly extract and display just the relevant `PORT` or `PROTO` (e.g., `JAIL: L3-PORTSCAN | PORT: 8080`), vastly improving terminal readability.

---

# Release v3.10.0

## FIXED 🐛
- **CWE-400 (Uncontrolled Resource Consumption):** Applied a strict kernel-level rate limit (`limit rate 2/second burst 5 packets`) to the `[Catch-All]` firewall logging rule in Linux (nftables/iptables) to completely eliminate CPU exhaustion loops during aggressive volumetric port scans (e.g. Nmap, OpenVAS).
- **L3 Portscan Auto-Ban (Fail2ban Parity):** Engineered a high-performance in-memory telemetry state tracker native to Go. SysWarden now parses dropped packet logs efficiently and executes a definitive L3 native silent drop ban after 3 occurrences, instantly terminating the attacker's portscan without external dependencies.

---

# Release v3.01.0

## ADDED ➕
- **Native FreeBSD CIS Hardening:** Successfully ported the CIS Level 2 Kernel and OS-level hardening directly to FreeBSD 14+. The new architecture implements rigorous protection equivalent to Linux configurations via native sysctl overrides (`security.bsd.*` and `net.inet.tcp.blackhole=2`), without interfering with the PF engine.
- **Zero-Trust FreeBSD Profiles:** Hardened standard FreeBSD profiles (`.cshrc`, `.profile`) with the `schg` immutable file flag, matching Linux `chattr` standards.
- **FreeBSD Core Dump Restrictions:** Implemented strict memory limits (`kern.coredump=0`, `kern.sugid_coredump=0`) via `sysctl.conf` to block memory exploitation.

---

# Release v3.00.1

## FIXED 🐛
- **CI/CD Pipeline (FreeBSD Artifacts):** Resolved a failure in `package.yml` and `release-manager.yml` where `sha256sum` and GitHub Artifact uploads expected `.pkg` files, whereas FPM accurately generates `.txz` archives for FreeBSD. All pipeline references have been safely updated to `.txz`.
- **Go Cache Dependency Resolution:** Fixed a caching crash during the `actions/setup-go` workflow step by explicitly mapping `cache-dependency-path` to `go.work.sum`, since SysWarden utilizes a root-level workspace architecture.

---

# Release v3.00.0

## ADDED ➕
- FreeBSD 14+ Native Support via abstraction layer (`//go:build freebsd`).
- Full PF (Packet Filter) support for L3/L4 and L7 WAAP integration.
- Native Kernel Layer 2 ARP Spoofing Protection for FreeBSD via `sysctl` hardening (`log_arp_movements`).
- Native `rc.d` FreeBSD service orchestration integration.
- Abstracted WireGuard VPN integration using PF NAT anchor (`syswarden_wg`) and `sysrc` for FreeBSD.
- Abstracted SIEM (Wazuh/Rsyslog) bridge telemetry integration for FreeBSD paths and daemons (`/usr/local/etc/rsyslog.d`).
- Abstracted Real-Time Telemetry (Core & CLI) from Linux `journalctl` to native FreeBSD `syslog` (`/var/log/messages`).
- Package generation for `.pkg` explicitly utilizing FPM inside the GitHub CI/CD Actions pipeline.

## UPGRADED 🆙
- Refactored `pkg/system`, `pkg/network` and `pkg/integration` to securely support FreeBSD without breaking the Linux ecosystem.
- Cross-platform dependency check mechanisms adapted for `pkg` versus `apt`/`dnf`.
- Web Showcase and Wiki fully updated to reflect multi-OS integration (Linux & FreeBSD Jails/bhyve capabilities).

## FIXED 🐛
- **OSSF Scorecard (Supply Chain Security):** Addressed the High-Severity `Binary-Artifacts #91` alert by aggressively purging the local compiled test binary (`syswarden_test`) from the repository's git index and enforcing strict `.gitignore` boundaries for all Go test artifacts. This guarantees absolute compliance with SLSA and OSSF source-review guidelines.

---

# Release v2.40.0

## ADDED ➕
- **WAAP L7**: Proactive Heuristics: Integrated three new zero-overhead detection jails natively into `waap.go` (`l7-ssrf`, `l7-nosql`, `l7-api`), successfully blocking Cloud metadata exfiltration, MongoDB/CouchDB injections, and generic API/GraphQL schema enumeration without impacting performance.
- **Telemetry**: SIEM & AbuseIPDB Mapping: Dynamically integrated the new WAAP L7 jails into the `telemetry/abuse.go` AbuseIPDB reporter, natively mapping them to the Web App Attack (Category 21) logic.
- **Threat Intelligence**: Modern CVEs & Scanners: Expanded `signatures.json` with highly critical Aho-Corasick patterns targeting Java/PHP Deserialization (`ysoserial`), Ivanti/Confluence CVE paths, and aggressively dropping advanced fuzzers (`ffuf`, `kiterunner`) and novel AI crawlers (PerplexityBot, ClaudeBot).

## REMOVED
- **Layer 2**: MAC Address Filtering: Removed `SYSWARDEN_MAC_BLACKLIST` and associated filtering logic. MAC blocking is easily circumvented via spoofing and offers no real Zero-Trust boundary. Hardware Layer 2 ARP Spoofing prevention (`SYSWARDEN_ARP_PROTECT`) remains active and strictly enforced.

## UPDATED ♻️
- **WAAP L7**: Legacy Substring Engine: Fortified existing SQLi, XSS, LFI, and RCE zero-overhead arrays with advanced bypass vectors (`pg_sleep`, `php://filter`, `${lower:jndi}`).

---

# Release v2.30.2

## ADDED ➕
- **SecOps**: SysWarden Enterprise Manual: Introduced the exhaustive `syswarden manual` command. This interactive module provides comprehensive documentation on all CLI commands, `syswarden-auto.conf` configuration parameters (including Zero-Trust L3 and WAAP L7 variables), and the complete structure of the Data-Shield Threat Intelligence postures (`standard`, `critical`).

---

# Release v2.30.1

## UPDATED ♻️
- **SecOps**: SysWarden Audit Engine: The `syswarden audit` CLI command has been completely overhauled to natively recognize and validate the new Zero-Trust Strict ALLOW architecture (GeoIP and ASN). It now also actively audits the WAAP L7 Engine status, confirming Auto-Discovery mechanisms and L7 Independence capabilities.

---

# Release v2.30.0

## ADDED ➕
- **Governance**: Zero-Trust Strict ALLOW Mode for GeoIP and ASN. Introduces `SYSWARDEN_GEO_ALLOWED` and `SYSWARDEN_ASN_ALLOWED`. If configured, the engine operates in a default-deny state, blocking all inbound traffic except for the explicitly whitelisted countries or ASNs, natively merging with the hardware `syswarden_whitelist` set for O(1) processing.
- **SecOps**: WAAP L7 Independence: Even if an IP is allowed via the new Zero-Trust L3 whitelist, the WAAP engine retains absolute priority. If a whitelisted IP initiates a malicious attack (SQLi, XSS, etc.), it is immediately banned, dropped, and reported to the SIEM.
---

# Release v2.20.1

## ADDED ➕
- WAAP Auto-Discovery (Zero-Config Absolu): The WAAP engine now natively probes the file system for standard web server log directories (`/var/log/nginx`, `/var/log/apache2`, `/var/log/httpd`, `/var/log/caddy`, `/var/log/traefik`, `/var/log/lighttpd`). By setting `SYSWARDEN_BRUTEFORCE_LOGS="auto"` (the new default), SysWarden intelligently tails active web server access logs. This guarantees instant, zero-configuration L7 protection for amateur sysadmins without losing manual override capabilities for advanced users.

---

# Release v2.20.0

## ADDED ➕
- Advanced WAAP (L7) Engine: The L7 engine (`waap.go`) now performs Zero-Overhead Substring Matching for critical payload signatures, expanding defense beyond brute-force. It now natively detects and immediately bans attacks targeting SQL Injection (`l7-sqli`), Cross-Site Scripting (`l7-xss`), Local File Inclusion (`l7-lfi`), Remote Code Execution (`l7-rce`), and Malicious Scanners (`l7-scanner`), all without complex RegEx CPU overhead.
- MITRE ATT&CK Mapping: Dynamically integrated specific MITRE ATT&CK techniques in the telemetry engine to natively reflect heuristic WAF bans in the TUI (e.g., T1190 for Exploits, T1595 for Active Scanning, T1110 for Brute Force).
- AbuseIPDB Integration: Added dynamic mappings for the new WAAP jails (`l7-sqli`, `l7-rce`, etc.) to specific AbuseIPDB categories (16, 19, 21) for highly accurate Threat Intelligence reporting.
- Native JSON SIEM Integration: Rsyslog integration now explicitly leverages the `imfile` module to forward the raw WAAP telemetry (`/var/log/syswarden/waf.json`) in pure JSON format to enterprise SIEMs (Elastic, Splunk, Wazuh) without requiring complex grok decoding.

## FIXED 🐛
- TTY Fallback (Non-Interactive CLI): Implemented an intelligent fallback mechanism (`term.IsTerminal`) across `syswarden alerts` and `syswarden tui`. The interface now perfectly degrades into a clean, parseable text stream instead of panicking when executed without a pseudo-terminal (e.g., Cron, SSH without `-t`, or CI/CD pipelines).
- Webhook Asymmetry: Resolved an issue where only Kernel-level (L3) drops triggered Discord/Teams notifications. The notification payload generation is now strictly coupled with the `logger.go` core, ensuring all WAAP (L7) mitigation events are immediately broadcasted to the SOC.

---

# Release v2.10.1

## ADDED ➕
- ARP Spoofing Telemetry Integration: Natively integrated OSI Layer 2 ARP flood alerts directly into the Enterprise Dashboard (`syswarden tui`) and live alerts feed (`syswarden alerts`). The `syswarden-core` daemon now asynchronously monitors the kernel ring buffer for `[SysWarden-ARP-FLOOD]` events via `journalctl -k` and injects hardware-level attack traces seamlessly into the WAF telemetry pipeline.

---

# Release v2.10.0

## ADDED ➕
- Layer 2 Protection Engine: Implemented native OSI Layer 2 filtering capabilities leveraging NFTables netdev and arp families.
- MAC Blacklist Capability: Introduced strict MAC address blocking at the ingress hook, ensuring zero interference with L3 routing, Docker networks, or existing firewalls (UFW/Firewalld).
- ARP Flooding Protection: Integrated aggressive ARP request rate-limiting (max 10 req/s) to neutralize ARP Spoofing/Flooding attacks while maintaining full compatibility with High Availability architectures (VRRP/Keepalived).
- Configuration Variables: Added SYSWARDEN_ENABLE_L2, SYSWARDEN_MAC_BLACKLIST, SYSWARDEN_ARP_PROTECT, and SYSWARDEN_LAN_MODE to the global configuration parser.
- Local LAN Mode (Air-Gapped/Zero-Trust): Implemented SYSWARDEN_LAN_MODE. When enabled, SysWarden intelligently bypasses the download and memory injection of massive public OSINT blocklists (Data-Shield, GeoIP, ASN) to heavily optimize RAM/CPU/Bandwidth on strictly internal servers, while maintaining full internal L2/L7 defenses.

## UPGRADED 🆙
- Configuration Security: Implemented rigorous IEEE 802 Regex validation for all MAC address inputs to definitively prevent NFTables syntax poisoning and runtime crashes.

## UPDATED ♻️
- Nftables Generator: Restructured the atomic deployment engine to cleanly provision, append, and destroy the netdev and arp families upon reload.

## FIXED 🐛
- None

---

# Release v2.01.11

## FIXED 🐛
- **Missing Cron Jobs Persistent Warning**: Fixed an issue where nodes upgraded from a previously bugged version (v2.01.8) would continuously report missing background tasks during `syswarden audit`. The `syswarden reload` command, executed automatically during package upgrades, now proactively inspects and safely repairs any missing `update-feeds` and `ha-sync` cron orchestration routines.
- **CI/CD Pipeline Failure (`syswarden-cli`)**: Resolved a fatal compilation error (`undefined: strings`) in `pkg/system/uninstall.go` caused by a missing library import during the native Go cron refactoring. The build pipeline and GitHub Actions now successfully compile the executable and generate the `.deb` and `.rpm` deployment artifacts.

---

# Release v2.01.9

## FIXED 🐛
- **Cron Orchestration Idempotency Bug**: Resolved a critical logic flaw in `downloader.go` and `cluster.go` where updating SysWarden on minimalist/hardened Debian systems would permanently delete the background Threat Intelligence and HA synchronization cron jobs. The update routine now uses 100% native Go string parsing to guarantee clean, atomic modifications to the `crontab` without relying on fragile bash pipelines (`grep -v`), fully resolving the `No automated SysWarden background jobs found` warning during `syswarden audit`.

---

# Release v2.01.8

## FIXED 🐛
- **Code Hygiene (CI/CD Pipeline)**: Cleaned up phantom `"os"` package imports across multiple CLI commands (`whitelist.go`, `unwhitelist.go`, `block.go`, `unblock.go`). This resolves a strict compilation and `golangci-lint` failure encountered by GitHub Actions runners during the automated build process.

---

# Release v2.01.6

## FIXED 🐛
- **Config Parser Oversight**: Resolved a core engine issue where the `SYSWARDEN_WHITELIST_IPS` configuration parameter was successfully parsed from `syswarden-auto.conf` but skipped during the firewall compilation phase. Custom whitelists are now flawlessly injected into the Nftables `syswarden_whitelist` set upon startup and reload.

## ADDED ➕
- **Unlimited CLI Arguments**: The SysWarden CLI `whitelist`, `block`, `unwhitelist`, and `unblock` commands now natively support an unlimited number of arguments simultaneously (`syswarden block IP1 IP2 IP3...`). The strict parameter limits (e.g., `cobra.RangeArgs(1, 2)`) have been lifted, enabling instantaneous mass-processing.

---

# Release v2.01.4
- **APT Sandbox Warning (CIS2/ANSSI)**: Resolved an issue where `syswarden update` triggered an APT Notice (`_apt` user permission denied) during `.deb` upgrades on highly hardened Debian/Ubuntu servers enforcing `fs.protected_regular=2`. The update engine now natively changes the ownership of the downloaded package to the `_apt` user before installation, guaranteeing flawless and completely silent APT Sandbox compliance.

---

# Release v2.01.3

## ADDED ➕
- **Native CIDR (Subnet) Support**: The SysWarden CLI `whitelist` and `block` commands now natively accept full CIDR notations (e.g., `10.0.0.0/24`, `192.168.0.0/16`). These subnets are dynamically parsed and injected into Nftables interval sets (`flags interval; auto-merge;`), enabling O(1) matching for massive IP ranges without any performance degradation.

---

# Release v2.01.2

## FIXED 🐛
- **Ubuntu/Debian Autocompletion**: Added an automated post-installation hook in the `.deb` package (`postinst.sh`) to natively append and uncomment the `bash_completion` logic within the `root` user's `~/.bashrc`. This guarantees that the SysWarden CLI `<TAB>` autocompletion is fully functional out-of-the-box on minimal Ubuntu/Debian server environments where it is disabled by default.

---

# Release v2.01.1

## FIXED 🐛
- Resolved a `staticcheck` pipeline failure (deprecation warning) in the L7 Brute-Force module by replacing `os.SEEK_END` with the standard `io.SeekEnd` for file tailing operations, ensuring full compliance with Go 1.26 static analysis.

---

# Release v2.01.0

## ADDED ➕
- **L7 Brute-Force & Log Analytics Engine:** SysWarden now natively replaces Fail2ban. It autonomously parses application access logs (Traefik, Nginx, Apache) in real-time (`SYSWARDEN_BRUTEFORCE_LOGS`) via an asynchronous Goroutine and detects HTTP 401/403/404 abuse. It implements a sliding-window tracker and native Nftables blocking to counter L7 bruteforce attempts.
- **Native CLI Auto-Completion:** Added full auto-completion support for `bash`, `zsh`, `fish`, and `powershell`. The script is automatically deployed to `/etc/bash_completion.d/syswarden` upon installation to provide immediate `<TAB>` suggestions for all SysWarden CLI commands.

---

# Release v2.00.10

## ADDED ➕
- The `syswarden-core` WAF Engine now dynamically fetches the latest available release directly from the GitHub API (`https://api.github.com/repos/duggytuxy/syswarden/releases/latest`) and streams it to the TUI.

## FIXED 🐛
- Resolved a critical desynchronization issue where several subcomponents (like `syswarden-tui`, internal `webhooks`, and the `install.go` routines) were displaying stale, hardcoded version strings (`v2.00.0`). The automated release script (`Release-SysWarden.ps1`) has been patched to aggressively sweep and identically bump all Go files containing version strings.

---

# Release v2.00.9

## ADDED ➕
- Implemented an **Auto-Healing WAF Bridge** recovery mechanism. The `syswarden-cli reload` command now automatically and dynamically regenerates the `rsyslog` integration bridge (`99-syswarden-waf-bridge.conf`) based on the active user configuration.

## FIXED 🐛
- Updated the CI/CD `postinst.sh` lifecycle script to execute a native `syswarden reload` instead of a simple service restart during an upgrade. This guarantees that any configuration components (like firewall rules and log bridges) destructively purged by older versions are instantaneously restored without user intervention, achieving 100% Zero-Touch Upgrades.

---

# Release v2.00.8

## FIXED 🐛
- Synchronized FPM lifecycle orchestration scripts (`postinst.sh`, `prerm.sh`, `postrm.sh`) within the official GitHub Actions CI/CD pipeline (`package.yml`). This ensures that natively compiled `.rpm` and `.deb` releases correctly inherit the In-Place Upgrade capabilities, preventing `syswarden-core` downtime during automated package manager upgrades.

---

# Release v2.00.7

## FIXED 🐛
- Completely restructured the internal packaging lifecycle scripts (`prerm`, `postinst`, `postrm`) within `build_packages.sh` to natively identify and manage *In-Place Upgrade* states across both `dnf/rpm` and `apt-get/dpkg` package managers. This entirely resolves a critical flaw where `syswarden-core` services and `nftables` firewall rules were being inappropriately purged or deadlocked by the package manager during an upgrade.

---

# Release v2.00.6

## FIXED 🐛
- Remediated `golangci-lint` regressions (`errcheck`) by enforcing strict and explicit error handling on all `defer` file closure operations across the Go Native engine, maintaining compliance with Zero CWE standards.

---

# Release v2.00.5

## UPDATED ♻️
- Completely rewrote the `syswarden update` orchestration engine in native Go (`pkg/system/upgrade.go`), entirely eradicating the legacy Bash script dependency (`install.sh`). The in-place upgrade mechanism now natively detects the OS architecture, securely downloads the `.rpm` or `.deb` packages via the GitHub API into memory, and natively executes `dnf install` or `apt-get install` without relying on insecure subshells.

---

# Release v2.00.3

## FIXED 🐛
- Resolved a missing cron daemon dependency during automated unattended installations on minimal RHEL 9 and Debian environments. The `.rpm` and `.deb` deployment pipelines now strictly enforce `cronie` and `cron` dependencies natively.

---

# Release v2.00.2

## ADDED ➕
- Enterprise SIEM Forwarding: Native support for robust TCP and TLS encryption via Rsyslog's `StreamDriver` (preventing CWE-319 vulnerabilities).
- The SIEM forwarder dynamically configures TLS authentication in `anon` mode to ensure maximum compatibility with self-signed Enterprise PKIs without dropping encrypted logs.

---

# Release v2.00.1

## ADDED ➕
- Compliance & Security SBOM artifacts generated and attached to the release payload.

## UPGRADED 🆙
- All underlying Go dependencies across `syswarden-cli`, `syswarden-core`, and `syswarden-tui` modules to mitigate OSV and CVE vulnerabilities.

## UPDATED ♻️
- Removed binary artifacts from the source repository to enforce OSSF Scorecard best practices.
- Expanded `.gitignore` controls to strictly prevent accidental binary artifact contamination.

## FIXED 🐛
- Remediated `golangci-lint` regressions, including `errcheck` and `staticcheck` issues via robust error handling and `switch` block refactoring.
- Rectified `govulncheck` execution paths within `security-audit.yml` to support multi-module workspaces.
- Corrected `gh run download` logic and pathing within `release-manager.yml` to reliably fetch release assets from parallel CI/CD jobs.
- Fixed `push` event triggers in GitHub Action workflows (`package.yml`, `security-audit.yml`, `compliance.yml`) to correctly execute on version tags.

---

# Release v2.00.0

## ADDED ➕
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

## UPGRADED 🆙
- Rewrote the firewall orchestration engine to dynamically query the effective SSH port configuration via 'sshd -T' directly from the OS, guaranteeing boot-time lockout prevention even with missing configurations.
- TUI and Alert dashboards dynamically separate and categorize "ALLOWED" connections in high-contrast green.
- Telemetry worker module (`worker.go`) rewritten to decouple the dependency on `syswarden-auto.conf` file mappings.
- Nftables Kernel injection engine to an O(1) atomic aggregation transaction for 350k+ GeoIP and ASN Threat Intelligence feeds.
- The entire SysWarden platform architecture is upgraded to a 100% Native Go application. All legacy bash scripts, including the entire src/functions/ directory and build.sh scripts, were completely eradicated.
- Entire analytics core transitioned from Web UI to the high-performance Enterprise TUI Engine.
- Package manager wrapper secured with strict ISO 27001 GPG checks.
- Go backend error handling transitioned comprehensively to idiomatic `%w` context wrapping, aligning with Zero CWE and NIS2 telemetry standards.
- Refactored memory safe I/O operations by replacing deprecated `ioutil` with modern `os.ReadFile` in the core engine.

## UPDATED ♻️
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

## FIXED 🐛
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

