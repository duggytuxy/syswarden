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
