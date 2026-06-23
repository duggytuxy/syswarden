<p align="center">
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/duggytuxy/syswarden/package.yml?style=for-the-badge&logo=githubactions&logoColor=white" alt="SysWarden Builder and Packager">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="GitHub License">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Universal">
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

# SysWarden v2.00.5 🚀

**SysWarden** is an Enterprise-grade Hardened Host Intrusion Detection & Prevention System (HIDS - HIPS) engineered in **100% Native Golang**. Designed for critical Linux infrastructures, it enforces automated CIS Level 2 hardening, integrates global Threat Intelligence, and orchestrates dynamic network defense with absolute zero-trust execution.

It acts as a ruthless first line of defense. By fusing dynamic firewall orchestration (`nftables`/`iptables`), global Threat Intelligence ([Data-Shield IPv4](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), GeoIP, ASN), a high-speed memory-safe WAF daemon (`syswarden-core`), and SIEM alert routing natively via Go, SysWarden neutralizes threats at the network (L2/L3/L4) and application (L7) levels without exposing your kernel to shell injection risks.

> [!IMPORTANT]
> **Zero CWE Mitigation:** Re-architected entirely in Go, SysWarden v2.00.5 strongly mitigates risks of OS Command Injection (CWE-78), Memory Corruption (CWE-119), and Resource Exhaustion (CWE-400), seamlessly accelerating your **ISO 27001, NIS2, and CIS Benchmark** compliance.

## Architectural Capabilities (CNAPP / HIDS-HIPS)

**1. A "Next-Gen HIPS" (Host Intrusion Prevention System)**
At its core, SysWarden is a formidable HIPS. Unlike a traditional IDS (Intrusion Detection System) that merely alerts, SysWarden actively prevents attacks by severing connections at the hardware level (Layer 2 / Nftables `netdev`). It acts entirely autonomously on the host system without waiting for instructions from an external hardware firewall.

**2. A CWPP (Cloud Workload Protection Platform)**
By natively integrating Docker protection (Layer 3 via the `docker_protect` chain and Layer 7 via the Aho-Corasick WAF), SysWarden secures modern workloads. Whether the server hosts a Traefik cluster, databases, or containerized APIs, SysWarden wraps the containers in a shield without ever breaking their internal routing. This perfectly mirrors the behavior of enterprise agents like CrowdStrike or Palo Alto Prisma Cloud on Linux servers.

**3. An Embedded WAAP (Web Application and API Protection)**
The legacy term "WAF" is increasingly replaced by "WAAP" as attacks aggressively target APIs. By specifically targeting Docker API abuse, authentication endpoints (Nextcloud, Proxmox, Gitlab), and application payloads (SQLi, RCE, LFI) via its `syswarden-core` Go engine, SysWarden acts as an embedded WAAP. It guarantees "Zero-Trust" even if the traffic is encrypted, by reading the access logs decrypted by your reverse proxy.

**4. A Mini-SOAR (Security Orchestration, Automation, and Response)**
SysWarden doesn't just block. It manages its own Threat Intelligence (ingesting Data-Shield, ASN, GeoIP feeds), synchronizes bans across different enterprise servers via its HA (High Availability) clustering module, and natively forwards telemetry. It autonomously orchestrates the entire incident response lifecycle.

## Enterprise-Grade Features

**100% Go Native Orchestration (Zero-Shell Execution)**
* **Absolute Security:** Deprecated all legacy Bash scripts. Firewall generation, Systemd provisioning, and Telemetry operations are executed entirely in Go memory, utilizing native `os/exec` wrappers to eliminate `bash -c` vulnerabilities.
* **Strict CIDR Validation:** Threat feeds are parsed mathematically using `net.ParseCIDR()`, instantly destroying malformed payloads or metadata injections (CWE-20 mitigation).
* **Asynchronous Telemetry Worker:** Replaced brittle system crons with native Go `sync.WaitGroup` goroutines. Telemetry and HA syncing run flawlessly in the background with strict memory leak prevention.
* **Adaptive Hybrid Telemetry Engine:** Natively bridges L7 WAF Logs using high-speed `rsyslog` UDS sockets (Ubuntu/Debian) or seamlessly falls back to a native `systemd-journald` + Direct File Tailing hybrid engine (Fedora/RHEL) ensuring zero blind spots across disparate enterprise OS architectures.
* **Layer 3/4 Catch-All Auditing:** Enforces total visibility by securely logging any packet hitting the hardware drop threshold before execution, populating the real-time observability console (`syswarden alerts`) with granular "Catch-All" traffic analytics.

**Core Network Defense (Hardware & Layer 2/3)**
* Injects Threat Intelligence directly into the `netdev` table under `nftables`. Malicious packets are destroyed right at the Network Interface Card (NIC), bypassing kernel routing to guarantee zero CPU impact during volumetric DDoS attacks.
* Native Go `net/http` clients securely download and sync hostile countries (GeoIP), cybercrime hosters, and rogue ASNs.

**Stateful & Protocol Optimization (Layer 3/4)**
* Implements UFW-grade stateful enforcement by silently destroying late `FIN-ACK`/`RST` packets on expired `conntrack` sessions, and strictly blocking `NEW` connections lacking the `SYN` flag.
* Modern web protocols natively supported. As a Zero-Trust Overlay, SysWarden guarantees HTTP/3 QUIC survival without stateful interference on UDP traffic.

**Application Security & Active Response (Layer 7)**
* Protects 56+ vital services (Docker, Nginx, Databases) using the ultra-fast `syswarden-core` WAF daemon.
* **Multi-Tenant Docker WAF Bridge:** Transparently streams access logs from Traefik and isolated ModSecurity containers directly into the native Go engine using an asynchronous `rsyslog` (`imfile`/`omuxsock`) bridge, completely eradicating Fail2ban resource bottlenecks.
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

## Installation Guide (v2.0 Native Deployment)

SysWarden is exclusively distributed via standard package managers (`.deb` / `.rpm`).

### 1. Enterprise Installation via Packages (.deb & .rpm)

The Go CLI and dependencies are automatically placed in `/opt/syswarden/bin/`, securely embedding the default configuration.

```bash
# 1. Download the appropriate package and its checksum
wget https://github.com/duggytuxy/syswarden/releases/download/<version>/*.deb or .rpm
wget https://github.com/duggytuxy/syswarden/releases/download/<version>/*.txt (SHA256SUMS)

# 2. Verify Integrity
sha256sum -c SHA256SUMS.txt --ignore-missing

# 3. Install the package
# For Debian/Ubuntu
sudo apt-get install -y ./syswarden_<version>_all.deb
# For RHEL/AlmaLinux/Rocky
sudo dnf install -y ./syswarden-<version>-1.noarch.rpm

# 4. Review and tailor the embedded configuration to your infrastructure
sudo syswarden config

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

SysWarden v2.00.5 includes a comprehensive, native Golang CLI to orchestrate all firewalls and system checks directly without bash scripts.

**DevSecOps Full Audit:**
Run a complete system compliance and integration check (Rsyslog bridges, Docker routing, WAF telemetry, Cron health):
```bash
sudo syswarden audit
```

**IP Management & Zero-Trust Bypasses:**
```bash
# Block or unblock an IP instantly
sudo syswarden block <IP>
sudo syswarden unblock <IP>

# Whitelist an IP globally (optional PORT)
sudo syswarden whitelist <IP> [PORT]
sudo syswarden unwhitelist <IP>

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
