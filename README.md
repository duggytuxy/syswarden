<p align="center">
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml/badge.svg" alt="SysWarden Security Audit">
  </a>
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/powered%20by-DuggyTuxy-darkred?logo=apachekafka">
  <img src="https://img.shields.io/badge/Status-Community--Professional-brightgreen?logo=status">
  <img src="https://img.shields.io/badge/Security-Hardened-blue?logo=security">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20AlmaLinux%20%7C%20RockyLinux%20%7C%20CENTOS%20%7C%20FEDORA-blue?logo=platform">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-0052cc?logo=license">
  <img src="https://img.shields.io/github/last-commit/duggytuxy/syswarden?label=Last%20Update&color=informational&logo=github">
</p>

<div align="center">
  <a href="https://duggytuxy.github.io/" target="_blank">Website</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://github.com/duggytuxy/syswarden/issues">Issues Tracker</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://www.linkedin.com/in/laurent-minne/" target="_blank">Linkedin</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://tryhackme.com/p/duggytuxy" target="_blank">TryHackMe</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://ko-fi.com/laurentmduggytuxy" target="_blank">Ko-Fi</a>
  <br />
</div>

<p align="center">
  <br />
  <a href="https://ko-fi.com/L4L71HRILD" target="_blank">
    <img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support me on Ko-fi">
  </a>
  <br />
</p>

![Alt](https://repobeats.axiom.co/api/embed/d909eab3c0cafb3a64294546f37a130f18a7e2f0.svg "Repobeats analytics image")

# SysWarden

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./banner-light.svg">
    <img alt="SysWarden Banner" src="./banner-dark.svg" width="100%">
  </picture>
</div>

SysWarden is an enterprise-grade, open-source firewall orchestrator designed to eliminate 99% of noisy, disruptive, and malicious internet traffic. Built around the [Data-Shield IPv4 Blocklists community](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), it dynamically integrates GeoIP filtering, [Spamhaus ASN blocking](https://www.spamhaus.org/drop/asndrop.json), and [Fail2ban](https://github.com/fail2ban/fail2ban) intrusion prevention. > Engineered for modern infrastructure, SysWarden provides hermetic Docker protection, automated [AbuseIPDB](https://www.abuseipdb.com/) reporting, and deploys a stealth [WireGuard](https://www.wireguard.com/) management VPN—all operating natively within the Linux kernel to guarantee maximum security with near-zero RAM consumption.

## What Does SysWarden Protect?

SysWarden acts as an advanced, preemptive orchestration layer for your infrastructure. By leveraging community-driven threat intelligence and dropping malicious traffic natively at the firewall level (Kernel-Space) **before** it ever reaches your applications, it provides a highly optimized, impenetrable shield for your exposed assets.

It is highly recommended for securing:

- **Public VPS & Bare Metal Servers:** Defend your SSH ports, control panels, and core services against relentless brute-force campaigns and mass-scanning. SysWarden can even deploy a stealth WireGuard VPN to make your management interfaces completely invisible to the public internet.
- **Websites & CMS (WordPress, Nginx, Apache):** Instantly filter out bad bots, vulnerability scanners, and automated exploit attempts. By blocking threats at the network edge, your web servers preserve massive amounts of CPU and RAM for legitimate visitors.
- **Public APIs & SaaS Platforms:** Protect your endpoints from aggressive data scrapers, automated abuse, and Layer 7 DDoS probes, ensuring your resources remain dedicated to real users and your SLAs stay intact.
- **Dockerized & Critical Infrastructure:** Automatically injects hermetic firewall rules directly into the `DOCKER-USER` chain, guaranteeing that your exposed containers are shielded from global threats without breaking internal routing.
- **Databases (MySQL, MongoDB, PostgreSQL):** Shield your data stores from credential stuffing, unauthorized access, and ransomware gangs using a formidable combination of massive static IP sets and dynamic Fail2ban intrusion prevention.

> By permanently silencing the internet's malicious "background noise", SysWarden ensures your infrastructure remains blazing fast, deeply secure, and focused entirely on serving real humans—while automatically reporting attackers back to the global community via AbuseIPDB.

## Architecture

```text
SysWarden (Technology Stack)
├── Core Orchestration
│   ├── Bash Scripting             # Automation, Logic & Hot-Reloading
│   └── Linux OS & Kernel          # Broad Support (Debian/Ubuntu, RHEL/Alma, Alpine)
│
├── Firewall & Networking Engine
│   ├── Nftables                   # Modern Packet Filtering (Flat Syntax & Chunking)
│   ├── IPSet + Iptables           # High-Performance Hashing (Legacy Fallback)
│   ├── Firewalld                  # Dynamic Zone Management (RHEL Ecosystem)
│   ├── Docker Integration         # Native DOCKER-USER Chain Isolation
│   └── WireGuard VPN              # Stealth Management Interface & Dynamic Clients
│
├── Active Defense & Daemons
│   ├── Python 3                   # Asynchronous Log Parsing & API Reporting Daemon
│   ├── Fail2ban                   # Dynamic Intrusion Prevention System (Custom Jails)
│   ├── Systemd / OpenRC           # OS-Specific Service & Persistence Management
│   └── Logrotate                  # Log Maintenance & Space Optimization
│
└── Threat Intelligence & Integrations
    ├── Data-Shield IPv4 Blocklist # Primary Threat Intelligence Source
    ├── Spamhaus / RADB            # Dynamic ASN Routing Data Validation
    ├── IPDeny                     # Country-Level Geo-Blocking Data Sets
    ├── AbuseIPDB API              # Community Attack Reporting (Outbound)
    └── Wazuh XDR Agent            # SIEM, File Integrity & Vulnerability Detection
```

## Key Features

- **Universal OS Support:** Auto-detects and seamlessly adapts to **Debian, Ubuntu, CentOS Stream, Fedora, AlmaLinux, Rocky Linux**, and now features a dedicated deployment pipeline for **Alpine Linux** (OpenRC).

- **Intelligent Backend Detection & Routing:** Automatically selects and configures the optimal firewall technology present on your system:
  - **Nftables (Modern Standard):** Utilizes a groundbreaking "Flat Syntax" and sequential chunking mechanism to bypass legacy AST parser limitations (segfaults) and inject massive IP sets with near-zero RAM footprint.
  - **Firewalld:** Dynamic, native zone management tailored for the RHEL/Fedora ecosystem.
  - **IPSet/Iptables:** High-performance hashing fallback for legacy distributions or minimal containerized environments.

- **Multi-Layer Threat Filtering:**
  - **Data-Shield Blocklist:** Drops over 100,000+ known malicious IPs instantly.
  - **Geo-Blocking & ASN Filtering:** Dynamically restricts traffic from high-risk countries (via IPDeny) and rogue ASNs (Spamhaus/RADB).
  - **Hermetic Docker Isolation:** Automatically secures exposed containers by injecting specialized rules into the `DOCKER-USER` chain without breaking internal bridge networking.

- **Stealth Management VPN:** Deploys a native **WireGuard** interface to hide your management ports (SSH, Admin Panels) from the public internet. Includes a built-in CLI orchestrator to instantly generate client profiles and QR codes with optimized MTU parameters for flawless connectivity.

- **Smart Mirror Selection:** Bypasses legacy ICMP Ping limitations by utilizing strict **TCP/HTTP latency checks**. This ensures you always fetch threat intelligence from the fastest available GitHub/GitLab mirror, even behind strict corporate firewalls.

- **Kernel-Safe Optimization:** Engineered to prevent kernel memory leaks and stack overflows on older distributions (e.g., Debian 11 / Kernel 5.10). Employs highly conservative memory hashing on RHEL kernels to prevent "Invalid Argument" crashes, while maximizing buffer efficiency.

- **Persistence Guaranteed:** Rules are strictly written to disk according to OS-specific standards (`/etc/nftables.conf` for Systemd, `/etc/nftables.nft` for Alpine/OpenRC, XML for Firewalld) guaranteeing absolute survival across hard reboots.

- **Autonomous Operations:** Deploys a lightweight cron job to refresh threat intelligence hourly, paired with an asynchronous Python daemon that automatically reports active attackers back to the AbuseIPDB community.

## Objectives

- **Noise Reduction & Log Clarity:** Drastically reduce log fatigue and SIEM ingestion costs (`/var/log/auth.log`, `journalctl`) by instantly dropping automated scanners, brute-forcers, and botnets at the network edge.
- **Resource & Compute Optimization:** Conserve critical CPU cycles, RAM, and bandwidth by dropping illegitimate packets natively in Kernel-Space (via Nftables/IPSet) rather than allowing user-space applications (like Nginx, Apache, or SSHD) to process them.
- **Proactive Community Security:** Shift your infrastructure from a vulnerable "Reactive" stance (waiting for localized failed logins before triggering a ban) to a fortified "Proactive" stance. By leveraging global threat intelligence, SysWarden preemptively blocks IPs that have attacked other community servers minutes ago, neutralizing threats before they even discover your IP address.

## Technical Deep Dive: Architectural Layering

> A common concern among infrastructure engineers is that deploying massive static blocklists might conflict or create race conditions with dynamic Intrusion Prevention Systems (IPS) like Fail2ban. **SysWarden elegantly resolves this through strict, sequential network layering.**

## Traffic Workflow

```text
/ (Inbound Network Traffic Flow)
├── Layer 1: Kernel-Space Shield (Preemptive Static Defense)
│   ├── Orchestrator : Nftables (Flat Syntax) / Firewalld / IPSet (Auto-detected)
│   ├── Threat Intel : 100k+ Malicious IPs, Global GeoIP & ASN Routing Data
│   ├── Edge Routing : Handled natively, including DOCKER-USER chain isolation
│   └── Action       : DROP packets silently before they ever reach User-Space
│
└── Layer 2: User-Space Applications (Permitted Traffic)
    ├── Exposed Services & Proxies
    │   ├── Custom Ports (SSH, Web, Database, APIs)
    │   ├── WireGuard    (Stealth Management Interface & VPN)
    │   └── System Logs  (e.g., /var/log/syslog, journalctl, dmesg)
    │
    └── Layer 3: Active Response (Dynamic & Behavioral Defense)
        ├── Fail2ban Engine
        │   ├── Monitor : Behavioral anomalies & Brute-force patterns across services
        │   └── Action  : Inject dynamic, localized bans into the firewall backend
        │
        ├── SysWarden Python Daemon
        │   ├── Monitor : Real-time Firewall drops & Fail2ban verdicts via buffer
        │   └── Action  : Asynchronously report telemetry back to AbuseIPDB API
        │
        └── Wazuh XDR Agent (Optional)
            ├── Monitor : File Integrity Monitoring (FIM) & Critical System Events
            └── Action  : Stream encrypted security telemetry to Wazuh SIEM
```

### 1. The Nftables Engine & Fail2ban Synergy (Debian, Ubuntu, Alpine)

- **Layer 1 (Preemptive Defense):** SysWarden leverages a modern Nftables "Flat Syntax" architecture and intelligent chunking to inject massive, high-performance sets (100k+ IPs, GeoIP, ASN). This acts as an impenetrable static shield, dropping known threat actors at the Kernel level with a near-zero memory footprint.
- **Layer 2 (Dynamic Analysis):** Fail2ban serves as the secondary behavioral net, monitoring application logs for localized, zero-day brute-force attempts.
- **The Result:** Fail2ban's CPU and RAM consumption drops to virtually zero. By letting the Nftables engine filter out the internet's "background noise" (99% of automated scans), Fail2ban only processes logs for traffic that has already passed the strict global blocklist.

### 2. The Firewalld Orchestration (RHEL, AlmaLinux, Rocky Linux)

On Enterprise Linux distributions, adhering to native `firewalld` architecture is critical for system stability and compliance.

- **Native IPSet Integration:** SysWarden programmatically defines massive, permanent `ipset` types deeply embedded within Firewalld's native XML configuration framework.
- **Rich Rule Processing:** It deploys high-priority "Rich Rules" that intercept and drop malicious traffic globally, long before packets can be routed to user-defined zones or exposed services.
- **Absolute Persistence:** Unlike legacy scripts that execute ephemeral `ipset` commands (which vanish upon a service reload), SysWarden strictly commits all configurations directly to `/etc/firewalld/`, ensuring absolute persistence across daemon reloads and hard reboots.

### 3. Community Threat Intelligence: AbuseIPDB Reporting

> SysWarden operates on the philosophy of collective defense. It deploys an asynchronous Python daemon that actively parses firewall drops and Fail2ban jails, reporting confirmed attackers back to the AbuseIPDB platform to protect servers worldwide.

- **Seamless Activation:** Simply confirm the prompt with `y` during the interactive installation phase.
- **API Authentication:** Provide your standard AbuseIPDB API key. The daemon will securely store the credentials and autonomously push telemetry, helping keep the global registry of malicious IPv4 addresses highly accurate and up to date without impacting firewall performance.

### 4. Enterprise SIEM: Wazuh XDR Agent Integration

> For organizations operating under strict compliance or utilizing centralized SIEM architectures, SysWarden includes a fully automated deployment pipeline for the **Wazuh XDR Agent**, flawlessly bridging edge firewall protection with centralized security telemetry.

- **Zero-Touch Deployment:** The orchestrator automatically identifies the host OS, securely fetches the official GPG keys and repositories, and installs the latest stable agent.
- **Dynamic Provisioning:** By supplying your [Wazuh](https://github.com/wazuh/) Manager IP, Agent Name, and Agent Group during the setup prompt, the script natively injects these exact parameters into the `ossec.conf` file—eliminating tedious manual post-install configuration.
- **Auto-Whitelisting & Continuity:** To guarantee uninterrupted log streaming, SysWarden automatically enforces high-priority bypass rules for your Wazuh Manager (ports 1514 and 1515), ensuring your SIEM traffic is never inadvertently disrupted by the overarching blocklists.

## Installation & Usage (Root Privileges Required)

> **Zero-Touch Autodiscovery:** SysWarden features an intelligent detection engine that automatically scans your environment for active services (Nginx, Apache, SSH, MongoDB) and configures the appropriate Fail2ban jails and firewall ports seamlessly. If you install a new service *after* deploying SysWarden, simply run the `update` command to dynamically generate and apply the new security layers.

### 1. System Preparation

Choose the command matching your operating system to ensure required dependencies are met.

```bash
# For Ubuntu / Debian
apt update && apt install wget -y

# For RHEL / AlmaLinux / Rocky Linux / Fedora
dnf update && dnf install wget -y

# For Alpine Linux
apk update && apk add wget
apk add --no-cache bash
```

### 2. Download & Execution

Navigate to your local binaries directory and fetch the appropriate orchestrator for your architecture.

For Universal OS (Debian / Ubuntu / RHEL ecosystem):

```bash
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v9.26/install-syswarden.sh
chmod +x install-syswarden.sh
./install-syswarden.sh
```

For Alpine Linux (OpenRC):

```bash
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v9.26/install-syswarden-alpine.sh
chmod +x install-syswarden-alpine.sh
./install-syswarden-alpine.sh
```

### 3. CLI Orchestration Commands

Once installed, SysWarden acts as a standalone CLI tool. You can manage your infrastructure security on the fly without ever editing configuration files manually.

> Note: Replace install-syswarden.sh with install-syswarden-alpine.sh if you are on Alpine.

- Trigger Threat Intelligence Sync:

```bash
./install-syswarden.sh update
```

> Forces an immediate refresh of the IPv4 blocklist, GeoIP datasets, and ASN routing tables, applying them natively to the kernel.

- Launch Live Attack Dashboard:

```bash
./install-syswarden.sh alerts
```

> Opens the real-time terminal interface displaying active drops, blocked ASNs, and Fail2ban dynamic jails.

- Add Custom IP Exception:

```bash
./install-syswarden.sh whitelist
```

> Interactively add a trusted IP address to bypass all overarching blocklists and Fail2ban monitoring.

- Add Custom IP Ban:

```bash
./install-syswarden.sh blocklist
```

> Interactively permanently ban a specific malicious IP address across all ports.

- Generate WireGuard VPN Client:

```bash
./install-syswarden.sh wireguard-client
```

> Instantly generates a new WireGuard client profile (with optimized MTU) and displays the configuration QR code in the terminal.

- Inject Docker Shield:

```bash
./install-syswarden.sh protect-docker
```

> Forces the injection of hermetic isolation rules into the DOCKER-USER iptables chain to protect exposed containers.

- Perform Core Engine Upgrade:

```bash
./install-syswarden.sh upgrade
```

> Fetches the latest SysWarden architecture from the repository and performs a seamless hot-reload without dropping active connections.

## System Architecture & File Structure

```text
/ (Root File System)
├── etc/
│   ├── syswarden.conf                      # Centralized Configuration & Environment Variables
│   ├── syswarden/                          # Local Threat Intelligence Directory
│   │   ├── whitelist.txt                   # Custom IP/CIDR Routing Exceptions
│   │   ├── blacklist.txt                   # Custom Permanent IP Bans
│   │   ├── geoip.txt                       # Dynamic IPDeny Country-Level Blocklists
│   │   └── asn.txt                         # Dynamic Spamhaus/RADB ASN Blocklists
│   ├── wireguard/                          # Stealth Management VPN Configurations
│   │   ├── wg0.conf                        # Core Server Interface Configuration
│   │   └── clients/                        # Generated Client Profiles & MTU Settings
│   ├── fail2ban/
│   │   └── jail.local                      # Custom Jails (SSH, Web, DB) Injected by SysWarden
│   ├── logrotate.d/
│   │   └── syswarden                       # Log Rotation Policy (7-day retention & compression)
│   ├── cron.d/                             # (Mapped to /etc/crontabs/root on Alpine)
│   │   └── syswarden-update                # Hourly Threat Intelligence Sync Job
│   ├── systemd/system/                     # (For Debian/Ubuntu/RHEL Ecosystem)
│   │   └── syswarden-reporter.service      # AbuseIPDB Asynchronous Daemon Service
│   └── init.d/                             # (For Alpine Linux / OpenRC Ecosystem)
│       └── syswarden-reporter              # OpenRC Daemon Service Definition
│
├── usr/local/bin/
│   ├── install-syswarden.sh                # Main CLI Orchestrator (Universal OS)
│   ├── install-syswarden-alpine.sh         # Main CLI Orchestrator (Alpine Linux)
│   ├── syswarden-auto.conf                 # Auto-configuration file
│   └── syswarden_reporter.py               # Python Log Analyzer & API Outbound Client
│
└── var/
    ├── log/
    │   ├── syswarden-install.log           # Verbose Installation, Deployment & Debug Telemetry
    │   ├── syswarden_reporter.log          # AbuseIPDB API Transaction Logs
    │   └── fail2ban.log                    # Dynamic Intrusion Prevention Daemon Logs
    └── ossec/etc/
        └── ossec.conf                      # Wazuh Agent Config (Manager IP & FIM Injected Here)
```

## Uninstallation & System Teardown (Root Privileges Required)

> SysWarden is designed to strictly respect your infrastructure. The uninstallation process performs a comprehensive and surgical teardown, ensuring no orphaned firewall rules, daemon remnants, or memory allocations are left behind.

Executing the uninstall orchestrator will autonomously:
- **Flush Firewall States:** Completely dismantle all injected Nftables, Firewalld, or IPSet blocklists, including Docker isolation rules, and restore standard traffic routing.
- **Teardown VPN Interfaces:** Safely disconnect the WireGuard `wg0` interface and remove all generated client profiles.
- **Halt Active Daemons:** Stop, disable, and remove the AbuseIPDB Python reporter (via Systemd or OpenRC) and flush Fail2ban custom jails.
- **Purge Scheduled Tasks:** Remove all associated Cron jobs and Logrotate retention policies.
- **Wipe Threat Intelligence Data:** Delete the `/etc/syswarden/` directory, configuration files, and all local IP datasets.

**For Universal OS (Debian / Ubuntu / RHEL ecosystem):**

```bash
./install-syswarden.sh uninstall
```

**For Alpine Linux (OpenRC):**

```bash
./install-syswarden-alpine.sh uninstall
```

> The Wazuh XDR agent, if deployed during installation, will remain active and untouched, as SIEM agents are managed independently from the SysWarden core firewall engine.

## Support & Sustainability

> **Help keep the tool alive**
> Developing and maintaining a high-fidelity, real-time blocklist requires significant infrastructure resources and dedicated time. Your contributions are vital to ensure the project remains sustainable, up-to-date, and free for the community.
> If you find this project useful, consider supporting its ongoing development:

* ☕ **Ko-Fi:** [https://ko-fi.com/laurentmduggytuxy](https://ko-fi.com/laurentmduggytuxy)

## ABUSEIPDB Contributor

| Duggy Tuxy |
| :---: |
| <a href="https://www.abuseipdb.com/user/133059"><img src="https://www.abuseipdb.com/contributor/133059.svg" width="350"></a> |
| *Verified Contributor* |

## License & Copyright

- **SysWarden** © 2026  
- Developed by **Duggy Tuxy (Laurent Minne)**.

"This tool is open-source software licensed under the **[GNU GPLv3 License](/LICENSE)**." 
