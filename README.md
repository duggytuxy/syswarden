<p align="center">
  <img src="assets/syswarden_hero.svg" alt="SysWarden">
  <br><br>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/package.yml?style=for-the-badge&logo=githubactions&logoColor=white" alt="SysWarden Builder and Packager">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="GitHub License">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Universal">
  <img src="https://img.shields.io/badge/Platform-FreeBSD_14.4+-ab2b28?style=for-the-badge&logo=freebsd&logoColor=white" alt="FreeBSD 14.4+">
  <img src="https://img.shields.io/badge/Language-100%25_Go_Native-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="100% Go Native">
  <img src="https://img.shields.io/badge/Compliance-EU_CRA_Ready-003399?style=for-the-badge&logo=shield&logoColor=white" alt="EU CRA Ready">
  <img src="https://img.shields.io/badge/Compliance-ISO27001_Ready-003399?style=for-the-badge&logo=shield&logoColor=white" alt="ISO27001 Ready">
  <img src="https://img.shields.io/badge/Compliance-NIS2_Ready-3DD407?style=for-the-badge&logo=shield&logoColor=white" alt="NIS2 Ready">

  <br>
  <br>

  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/compliance.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/compliance.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=Plumber%20Compliance" alt="Plumber Compliance">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/scorecard.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/scorecard.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=OSSF%20Scorecard%20Supply%20Chain%20Security" alt="OSSF Scorecard Supply Chain Security">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/security-audit.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=SysWarden%20Security%20Audit" alt="SysWarden Security Audit">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/dependabot/dependabot-updates">
    <img src="https://img.shields.io/badge/Dependabot-Active-025e8c?style=for-the-badge&logo=dependabot&logoColor=white" alt="Dependabot Updates">
  </a>
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?style=for-the-badge&logo=status&logoColor=white" alt="Production Ready">
</p>

# SysWarden v3 🌟

**SysWarden** is an Enterprise-grade Hardened Host Intrusion Detection & Prevention System (HIDS - HIPS) engineered in **100% Native Golang**. Designed for critical Linux infrastructures, it enforces automated CIS Level 2 hardening, integrates global Threat Intelligence, and orchestrates dynamic network defense with absolute zero-trust execution.

It acts as a ruthless first line of defense. By fusing dynamic firewall orchestration (`nftables`/`iptables`/`pf`), global Threat Intelligence ([Data-Shield IPv4](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), GeoIP, ASN), a high-speed memory-safe WAF daemon (`syswarden-core`), and SIEM alert routing natively via Go, SysWarden neutralizes threats at the network (L2/L3/L4) and application (L7) levels without exposing your kernel to shell injection risks.

> [!IMPORTANT]
> **Zero CWE Mitigation:** Re-architected entirely in Go, SysWarden v2 strongly mitigates risks of OS Command Injection (CWE-78), Memory Corruption (CWE-119), and Resource Exhaustion (CWE-400), seamlessly accelerating your **ISO 27001, NIS2, and CIS Benchmark** compliance.

## Architectural Capabilities (CNAPP / HIDS-HIPS)

**1. A "Next-Gen HIPS" (Host Intrusion Prevention System)**
At its core, SysWarden is a formidable HIPS. Unlike a traditional IDS (Intrusion Detection System) that merely alerts, SysWarden actively prevents attacks across multiple concrete OSI layers:
* **Layer 2 (Data Link)**: ARP Request Rate-Limiting to instantly kill ARP Flooding/Spoofing attacks without breaking VRRP HA setups.
* **Layer 3 & 4 (Network & Transport)**: Stateful IP, CIDR, ASN, and GeoIP filtering via the `inet` family with explicit TCP Flag anomaly detection (e.g. killing invalid SYN/FIN/RST combinations). Includes a **Zero-Trust Strict ALLOW Mode** natively dropping any IP worldwide that isn't explicitly whitelisted via GeoIP or ASN.
* **Layer 7 (Application)**: Advanced WAAP (Web Application Firewall) inspecting payloads via Zero-Overhead Substring Matching for zero-day exploits (SQLi, XSS, LFI, RCE) and HTTP 401/403/404 Brute-Force tracking via the native Go `WAAPEngine`.

**2. A CWPP (Cloud Workload Protection Platform)**
By natively integrating Docker protection (Layer 3 via the `docker_protect` chain and Layer 7 via the Aho-Corasick WAF), SysWarden secures modern workloads. Whether the server hosts a Traefik cluster, databases, or containerized APIs, SysWarden wraps the containers in a shield without ever breaking their internal routing. This perfectly mirrors the behavior of enterprise agents like CrowdStrike or Palo Alto Prisma Cloud on Linux servers.

**3. An Embedded WAAP (Web Application and API Protection)**
The legacy term "WAF" is increasingly replaced by "WAAP" as attacks aggressively target APIs. By specifically targeting Docker API abuse, authentication endpoints (Nextcloud, Proxmox, Gitlab), and application payloads (SQLi, RCE, LFI) via its `syswarden-core` Go engine, SysWarden acts as an embedded WAAP. It guarantees "Zero-Trust" even if the traffic is encrypted, by reading the access logs decrypted by your reverse proxy.

**4. A Mini-SOAR (Security Orchestration, Automation, and Response)**
SysWarden doesn't just block. It manages its own Threat Intelligence (ingesting Data-Shield, ASN, GeoIP feeds), synchronizes bans across different enterprise servers via its HA (High Availability) clustering module, and natively forwards telemetry. It autonomously orchestrates the entire incident response lifecycle.

## Enterprise-Grade Features

**100% Go Native Orchestration (Zero-Shell Execution)**
* **Absolute Security:** Deprecated all legacy Bash scripts. Firewall generation, Systemd provisioning, 
and Telemetry operations are executed entirely in Go memory, utilizing native `os/exec` wrappers to eliminate `bash 
-c` vulnerabilities.
* **Strict CIDR Validation:** Threat feeds are parsed mathematically using `net.ParseCIDR()`, instantly 
destroying malformed payloads or metadata injections (CWE-20 mitigation).
* **Asynchronous Telemetry Worker:** Replaced brittle system crons with native Go `sync.WaitGroup` 
goroutines. Telemetry and HA syncing run flawlessly in the background with strict memory leak prevention.

**Insider Threat Detection & Honeyports (Zero-Trust)**
* **Shadow Mode:** Prevents legitimate administrative lockouts. When malicious Web Application attacks (e.g. PrivEsc, RCE attempts) originate from whitelisted administrative IPs, SysWarden silently tags the event as a `SHADOW-ALERT`. Legitimate admins are not banned, preventing disruption of service, while the SOC receives immediate notifications.
* **Native L3 Honeyports:** Trap internal network scanners using `SYSWARDEN_HONEYPORTS`. Expose decoy ports (e.g. `6379`, `3306`) seamlessly integrated into the kernel firewall. Whitelisted IPs attempting access trigger shadow alerts, while external malicious IPs are instantly banned.
* **Adaptive Hybrid Telemetry Engine:** Natively bridges L7 WAF Logs using high-speed `rsyslog` UDS sockets (Ubuntu/Debian) or seamlessly falls back to a native `systemd-journald` + Direct File Tailing hybrid engine (Fedora/RHEL) ensuring zero blind spots across disparate enterprise OS architectures.
* **Layer 3/4 Catch-All Auditing:** Enforces total visibility by securely logging any packet hitting the hardware drop threshold before execution, populating the real-time observability console (`syswarden alerts`) with granular "Catch-All" traffic analytics.

**Core Network Defense (Hardware & Layer 2/3)**
* **OSI Layer 2 (ARP)**: An isolated `arp` table limits ARP requests to strictly mitigate network saturation floods natively.
* **OSI Layer 3 (IP/Routing)**: Native Go `net/http` clients securely download and sync hostile countries (GeoIP), cybercrime hosters, and rogue ASNs.

**Stateful & Protocol Optimization (Layer 3/4)**
* Implements UFW-grade stateful enforcement by silently destroying late `FIN-ACK`/`RST` packets on expired `conntrack` sessions, and strictly blocking `NEW` connections lacking the `SYN` flag.
* Modern web protocols natively supported. As a Zero-Trust Overlay, SysWarden guarantees HTTP/3 QUIC survival without stateful interference on UDP traffic.

**Application Security & Active Response (Layer 7)**
* Protects 56+ vital services (Docker, Nginx, Databases) using the ultra-fast `syswarden-core` WAF daemon.
* **Multi-Tenant Docker WAF Bridge:** Transparently streams access logs from Traefik and isolated ModSecurity containers directly into the native Go engine using an asynchronous `rsyslog` (`imfile`/`omuxsock`) bridge.
* **Native WAAP (L7) Engine:** Replaces Fail2ban entirely. Asynchronously parses raw access logs (Traefik, Nginx, Apache) in real-time. Detects advanced signatures (SQLi, XSS, LFI, RCE, Scanners) via Zero-Overhead Substring Matching for immediate blocking, and enforces native Nftables bans on abusive HTTP 401/403/404 attempts using memory-safe sliding-window tracking.
* Native SIEM integration (`syswarden-cli` injects directly to `rsyslog` over TLS/UDP).
* Sends critical bans securely to Discord/Teams webhooks natively, protected by `context.WithTimeout` against SSRF and deadlocks.

**Observability & Lifecycle Management**
* Monitor active threats via the Go-compiled **SysWarden TUI** (`syswarden-tui`), a localized, high-speed interface requiring zero open web ports.
* Manage your infrastructure via the unified `syswarden-cli` orchestrator (e.g., `syswarden install`, `syswarden update`, `syswarden uninstall`).

> [!NOTE]
> **For CISOs and CIOs (Strategic Impact):** By offloading volumetric mitigation to the network edge and forwarding only high-fidelity behavioral data natively through Go, SysWarden drastically reduces SIEM ingestion costs and guarantees unbreachable operational continuity.

## Supported Operating Systems & Firewall Backends

SysWarden dynamically adapts to the native firewall orchestration engines of modern enterprise Linux distributions. The architecture relies on deep `systemd` integration:

| Operating System | Native Firewall Engine(s) Supported | Status |
| :--- | :--- | :--- |
| **Debian 13 / 12** | `nftables`, `iptables` | Enterprise Ready |
| **Ubuntu 24.04+** | `ufw`, `nftables`, `iptables` | Enterprise Ready |
| **RHEL 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Rocky Linux / AlmaLinux 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Oracle Linux 10+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Fedora 40+** | `firewalld`, `nftables`, `iptables` | Production Ready |
| **FreeBSD 14+** | `pf` (Packet Filter) | Enterprise Ready |

## Installation Guide (v2.0 Native Deployment)

SysWarden is exclusively distributed via standard package managers (`.deb` / `.rpm`).

### 1. Enterprise Installation via Packages (.deb & .rpm)

The Go CLI and dependencies are automatically placed in `/opt/syswarden/bin/`, securely embedding the default configuration.

```bash
# 1. Fetch the latest release version automatically
VERSION=$(curl -s https://api.github.com/repos/duggytuxy/syswarden/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
V_NUM=${VERSION#v}

# 2. Download the appropriate package and its checksum
# For Debian/Ubuntu (amd64)
wget https://github.com/duggytuxy/syswarden/releases/download/${VERSION}/syswarden_${V_NUM}_amd64.deb
# For RHEL/AlmaLinux/Rocky (x86_64)
wget https://github.com/duggytuxy/syswarden/releases/download/${VERSION}/syswarden-${V_NUM}-1.x86_64.rpm
# For FreeBSD 14+ (amd64)
wget https://github.com/duggytuxy/syswarden/releases/download/${VERSION}/syswarden-${V_NUM}.txz

# Also download the checksums
wget https://github.com/duggytuxy/syswarden/releases/download/${VERSION}/SHA256SUMS.txt

# 3. Verify Integrity
sha256sum -c SHA256SUMS.txt --ignore-missing

# 4. Install the package
# For Debian/Ubuntu
sudo apt-get install -y ./syswarden_${V_NUM}_amd64.deb
# For RHEL/AlmaLinux/Rocky
sudo dnf install -y ./syswarden-${V_NUM}-1.x86_64.rpm
# For FreeBSD 14+
sudo pkg add ./syswarden-${V_NUM}.txz

# 4. Read the exhaustive SysAdmin manual to understand all Data-Shield lists and configuration parameters
sudo syswarden manual

# 5. Review and tailor the embedded configuration to your infrastructure
sudo syswarden config

# The interactive wizard (or syswarden-auto.conf) allows configuring advanced parameters, for example:
# - SYSWARDEN_ENABLE_L2="y" (Enable OSI Layer 2 ARP Spoofing Prevention)
# - SYSWARDEN_ARP_PROTECT="y" (Enable 10req/sec ARP Flood limits)
# - SYSWARDEN_LAN_MODE="y" (Enable Local LAN Mode to save RAM by skipping global OSINT downloads)
# - SYSWARDEN_BRUTEFORCE_LOGS="/var/log/traefik/access.log" (Enable L7 WAF log parsing)

# 5. Execute the Go Orchestrator to apply policies instantly
sudo syswarden install
```

### 2. Updating Configurations (Zero-Downtime)

If you modify the configuration later using `syswarden config` (e.g., to enable a SIEM, add a GeoIP block, or modify whitelists), apply the changes instantly without interrupting production traffic:

```bash
sudo syswarden reload
```

### 3. Real-Time Observability & Alerts

SysWarden provides comprehensive monitoring modes tailored for immediate action and long-term analysis. Both dashboards natively isolate and track **ALLOWED** (legitimate traffic) connections dynamically in bright green, making authorized services (e.g., successful SSH logins, Nginx/Apache 2xx requests) visually distinct from blocked threats.

**A. Live Threat Streaming (Real-Time)**
To watch every single connection attempt (L2/L3/L4 structural drops, L7 WAF bans, and validated ALLOWED services) in real-time directly from the kernel and engine logs:
```bash
sudo syswarden alerts
```

**B. Telemetry Dashboard (TUI)**
To monitor global system health, metrics, top blocked ASNs, and observe real-time legitimate service activity, launch the integrated Terminal User Interface:
```bash
sudo syswarden tui
```

### 4. Upgrading SysWarden

To check for the latest Enterprise updates and perform an automated in-place upgrade (via GitHub Releases or APT):

```bash
sudo syswarden update
```

### 5. Quick Uninstall

Safely reverse all OS hardening and kernel routing injected by SysWarden, reverting the machine to its native state in milliseconds:

```bash
sudo syswarden uninstall
```

### 6. Native Enterprise Management & Auditing

SysWarden v2 includes a comprehensive, native Golang CLI to orchestrate all firewalls and system checks directly without bash scripts.

**DevSecOps Full Audit:**
Run a complete system compliance and integration check (Rsyslog bridges, Docker routing, WAF telemetry, Cron health):
```bash
sudo syswarden audit
```

### 3. Dynamic Management
SysWarden provides an instantaneous, zero-delay CLI for incident response.

```bash
# Block or unblock an IP or CIDR Subnet instantly (e.g. 10.0.0.0/24)
sudo syswarden block <IP/CIDR>
sudo syswarden unblock <IP/CIDR>

# Whitelist an IP or CIDR globally (optional PORT)
sudo syswarden whitelist <IP/CIDR> [PORT]
sudo syswarden unwhitelist <IP/CIDR>

# Grant or revoke SSH-exclusive access
sudo syswarden allow-ssh <IP> [PORT]
sudo syswarden revoke-ssh <IP>

# Auto-detect and whitelist critical infrastructure (DNS, Gateway)
sudo syswarden whitelist-infra
```

**Diagnostics:**
```bash
# Check if an IP is blocked, whitelisted, or active in memory
sudo syswarden check <IP>

# List all active custom rules
sudo syswarden list
```

### 7. High Availability (HA) Cluster Setup

SysWarden v2.0 natively supports High Availability (HA) clustering. When an attacker is blocked on one node (L3 or L7), the ban is instantly and securely replicated to all registered peers.

**Prerequisites:**
1. Both servers must have SysWarden installed and running.
2. They must be able to communicate securely via SSH on a dedicated port (default: `62026`).
3. Passwordless SSH keys must be exchanged between the nodes for the `root` user.

**Configuration on each node:**
1. Edit your enterprise configuration via the secure CLI:
```bash
sudo syswarden config
```
2. Enable HA and add your peer IP(s) (comma-separated):
```conf
SYSWARDEN_HA_ENABLE="true"
SYSWARDEN_HA_PEERS="172.x.x.x,10.x.x.x"
SYSWARDEN_HA_PORT="62026"
```
3. Reload the configuration instantly:
```bash
sudo syswarden reload
```

**Manual Synchronization:**
While the `syswarden-core` daemon synchronizes in the background, you can also manually trigger a full blocklist push to all your peers at any time:
```bash
sudo syswarden ha-sync
```

## Documentation

To learn everything about the SysWarden ecosystem, explore detailed configurations, and read advanced usage guides, visit our [official documentation page](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial)

## Target and support

> Goal: 38.5% reached/year (Goal) to fund continuous DevSecOps improvements and infrastructure.

Developing **SysWarden** and maintaining the zero-false-positive **Data-Shield IPv4 blocklists** requires dedicated server infrastructure and non-stop threat monitoring.

Reaching this annual goal guarantees my 100% independence, funding a continuous development cycle without corporate constraints. Your support directly pays for the servers and keeps these enterprise-grade cybersecurity tools free, updated, and accessible to everyone.

Let's build a safer internet together!

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

## License

SysWarden is free and open-source software distributed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software in compliance with the license terms. [LICENSE](/LICENSE) file for more details.

*Developed and maintained by DuggyTuxy (Laurent M.).*
