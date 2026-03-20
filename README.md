<p align="center">
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml/badge.svg" alt="SysWarden Security Audit">
  </a>
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/powered%20by-DuggyTuxy-darkred?logo=apachekafka">
  <img src="https://img.shields.io/badge/Status-Community--Professional-brightgreen?logo=status">
  <img src="https://img.shields.io/badge/Security-Hardened-blue?logo=security">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20AlmaLinux%20%7C%20RockyLinux%20%7C%20CentOS%20%7C%20Fedora%20%7C%20AlpineLinux-blue?logo=platform">
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
SysWarden (DevSecOps Technology Stack)
├── Core Orchestration & Security
│   ├── Bash Scripting             # OS Hardening, Automation & Zero Trust Logic
│   ├── Linux OS & Kernel          # Broad Support (Debian/Ubuntu, RHEL/Alma, Alpine)
│   └── awk & jq                   # Strict Semantic Validation & Atomic JSON Serialization
│
├── Firewall & Networking Engine
│   ├── Nftables                   # Modern Packet Filtering (Atomic Transactions)
│   ├── IPSet + Iptables           # High-Performance Hashing (Legacy Fallback)
│   ├── Firewalld                  # Dynamic Zone Management (RHEL Ecosystem)
│   ├── Docker Integration         # Native DOCKER-USER Chain Isolation
│   └── WireGuard VPN              # Stealth Management Interface & Dynamic Clients
│
├── Active Defense & Daemons
│   ├── Fail2ban                   # Dynamic IPS (Zero Trust Jails & Strict Anchoring)
│   ├── Rsyslog                    # Kernel/Auth Log Isolation (Anti-Injection Shield)
│   ├── Nginx & OpenSSL            # Hardened TLS Dashboard (Zero Trust & CSP)
│   ├── Python 3 (Daemon)          # Asynchronous AbuseIPDB API Reporting
│   ├── Systemd / OpenRC           # OS-Specific Service & Privilege Management
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

- **Strict SSH Cloaking (Zero Trust):** Enforces a mathematically absolute policy for SSH. Access is exclusively restricted to the WireGuard VPN (wg0) and Loopback (lo) interfaces. An immediate, top-priority kernel DROP rule explicitly prevents any public access, ensuring that even locally whitelisted IPs cannot bypass the VPN requirement for SSH.
- **Firewall State Machine:** CLI commands (whitelist, blocklist) operate on a strict "Single Source of Truth" model. They securely write to local persistence files, universally purge memory conflicts, and trigger the orchestrator to completely rebuild the firewall safely, preserving the strict rule hierarchy across all OS backends.
- **Universal OS Support:** Auto-detects and seamlessly adapts to Debian, Ubuntu, CentOS Stream, Fedora, AlmaLinux, Rocky Linux, and Alpine Linux (OpenRC).
- **Intelligent Backend Detection & Routing:** Automatically selects and configures the optimal firewall technology present on your system (Nftables Flat Syntax, Firewalld Rich Rules, or IPSet/Iptables).
- **Multi-Layer Threat Filtering:** Instantly drops over 100,000+ known malicious IPs, restricts traffic from high-risk countries via GeoIP, and blocks rogue ASNs via Spamhaus/RADB.
- **Hermetic Docker Isolation:** Automatically secures exposed containers by injecting specialized rules into the DOCKER-USER chain without breaking internal bridge networking.
- **Stealth Management VPN:** Deploys a native WireGuard interface to hide your management ports from the public internet, including a built-in CLI orchestrator to instantly generate client profiles and QR codes.

## Objectives

- **Noise Reduction & Log Clarity:** Drastically reduce log fatigue and SIEM ingestion costs (`/var/log/auth.log`, `journalctl`) by instantly dropping automated scanners, brute-forcers, and botnets at the network edge.
- **Resource & Compute Optimization:** Conserve critical CPU cycles, RAM, and bandwidth by dropping illegitimate packets natively in Kernel-Space rather than allowing user-space applications to process them.
- **Proactive Community Security:** Shift your infrastructure from a vulnerable "Reactive" stance to a fortified "Proactive" stance, preemptively blocking IPs that have attacked other community servers minutes ago.

## Technical Deep Dive: Architectural Layering

> A common concern among infrastructure engineers is that deploying massive static blocklists might conflict or create race conditions with dynamic Intrusion Prevention Systems (IPS) like Fail2ban. SysWarden elegantly resolves this through strict, sequential network layering.

## Traffic Workflow

```text
/ (Inbound Network Traffic Flow)
├── Layer 1: Kernel-Space Shield (Preemptive Static Defense)
│   ├── Orchestrator : Nftables (Atomic) / Firewalld / IPSet (Auto-detected)
│   ├── Threat Intel : 100k+ Malicious IPs, Global GeoIP & ASN Routing Data
│   ├── Validation   : Strict Semantic CIDR checking (Prevents Firewall Crashes)
│   ├── Edge Routing : Handled natively, including DOCKER-USER chain isolation
│   └── Action       : DROP packets silently before they ever reach User-Space
│
└── Layer 2: User-Space Applications (Permitted Traffic)
    ├── Exposed Services & Proxies
    │   ├── Custom Ports (SSH, Web, Database, APIs)
    │   ├── WireGuard    (Stealth Management Interface & VPN)
    │   └── Log Routing  : Rsyslog isolated streams (kern-firewall.log & auth-syswarden.log)
    │
    └── Layer 3: Active Response (Dynamic & Behavioral Defense)
        ├── Fail2ban Engine (Zero Trust)
        │   ├── Monitor : Isolated Rsyslog files (Log Injection Immunity & Strict Anchoring)
        │   └── Action  : Inject dynamic, localized bans into the firewall backend
        │
        ├── SysWarden Python Daemon
        │   ├── Monitor : Real-time Firewall drops & Fail2ban verdicts via buffer
        │   └── Action  : Asynchronously report telemetry back to AbuseIPDB API
        │
        └── Wazuh XDR Agent (Optional)
            ├── Monitor : File Integrity Monitoring (FIM) & Critical System Events
            └── Action  : Stream encrypted security telemetry to Wazuh SIEM
```

### 1. The Nftables Engine & Fail2ban Synergy (Debian, Ubuntu, Alpine)

- **Layer 1 (Preemptive Defense):** SysWarden leverages a modern Nftables "Flat Syntax" architecture and intelligent chunking to inject massive, high-performance sets (100k+ IPs, GeoIP, ASN). This acts as an impenetrable static shield, dropping known threat actors at the Kernel level with a near-zero memory footprint.
- **Layer 2 (Dynamic Analysis):** Fail2ban serves as the secondary behavioral net, monitoring application logs for localized, zero-day brute-force attempts.
- **The Result:** Fail2ban's CPU and RAM consumption drops to virtually zero. By letting the Nftables engine filter out the internet's "background noise", Fail2ban only processes logs for traffic that has already passed the strict global blocklist.

### 2. The Firewalld Orchestration (RHEL, AlmaLinux, Rocky Linux)

On Enterprise Linux distributions, adhering to native firewalld architecture is critical for system stability and compliance.

- **Native IPSet Integration:** SysWarden programmatically defines massive, permanent ipset types deeply embedded within Firewalld's native XML configuration framework.
- **Rich Rule Processing:** It deploys high-priority "Rich Rules" that intercept and drop malicious traffic globally.
- **Absolute Persistence:** SysWarden strictly commits all configurations directly to `/etc/firewalld/`, ensuring absolute persistence across daemon reloads and hard reboots.

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

> **Zero-Touch Autodiscovery:** SysWarden features an intelligent detection engine that automatically scans your environment for active services (Nginx, Apache, SSH, MongoDB) and configures the appropriate Fail2ban jails and firewall ports seamlessly.

### 1. System Preparation

Choose the command matching your operating system to ensure required dependencies are met.

```bash
# For Ubuntu / Debian
apt update && apt install wget -y

# For RHEL / AlmaLinux / Rocky Linux / Fedora
dnf update && dnf install wget -y

# For Alpine Linux
apk update && apk add wget bash
```

### 2. Download & Execution

Navigate to your local binaries directory and fetch the appropriate orchestrator for your architecture.

For Universal OS (Debian / Ubuntu / RHEL ecosystem):

```bash
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v1.31/install-syswarden.sh
chmod +x install-syswarden.sh
./install-syswarden.sh
```

For Alpine Linux (OpenRC):

```bash
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v1.31/install-syswarden-alpine.sh
chmod +x install-syswarden-alpine.sh
./install-syswarden-alpine.sh
```

### 3. Unattended Installation (CI/CD / Ansible)

You can bypass all interactive prompts by providing a configuration file.

Create and edit a file named `syswarden-auto.conf` using your preferred text editor (e.g., `nano` or `vim`):

```bash
nano /usr/local/bin/syswarden-auto.conf
```

Paste the following configuration into the file (exemple:)

```
# ==============================================================================
# Version=v1.31
# SYSWARDEN UNATTENDED INSTALLATION CONFIGURATION
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
#
# Usage: ./install-syswarden.sh syswarden-auto.conf
# ==============================================================================

# --- Enterprise Compliance Mode ---
# y = Strictly disables third-party telemetry/reporting (e.g., AbuseIPDB) to comply with corporate policies.
SYSWARDEN_ENTERPRISE_MODE="n"

# --- SSH Configuration ---
# Leave empty to auto-detect current active port
SYSWARDEN_SSH_PORT=""

# --- WireGuard Management VPN ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_WG="n"
SYSWARDEN_WG_PORT="51820"
SYSWARDEN_WG_SUBNET="10.66.66.0/24"

# --- Docker Integration ---
# y = Enable, n = Disable
SYSWARDEN_USE_DOCKER="n"

# --- OS Hardening ---
# y = Enable, n = Disable (Strict restrictions for privileged groups & Cron. Recommended for NEW servers only)
SYSWARDEN_HARDENING="n"

# --- Blocklist Selection ---
# 1 = Standard, 2 = Critical, 3 = Custom, 4 = None
SYSWARDEN_LIST_CHOICE="1"
# If choice is 3, provide the URL below
SYSWARDEN_CUSTOM_URL=""

# --- Geo-Blocking ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_GEO="n"
# Space-separated country codes (e.g., "ru cn kp ir")
SYSWARDEN_GEO_CODES="ru cn kp ir br vn in by ng bd pe mx ua my ph lt id af al bd by bo cl hr ec hk il kz lb my md pk ph qa sa sd tm uz zm zw ye"

# --- ASN Blocking ---
# Enable the ASN blocking module
SYSWARDEN_ENABLE_ASN="y"

# Master List (VPNs, Proxies, Linode, Tor Exit Nodes/Bulletproof Hosters)
SYSWARDEN_ASN_LIST="AS30823 AS210644 AS200593 AS202425 AS215540 AS9009 AS20473 AS60068 AS212238 AS16276 AS62282 AS14061 AS24940 AS398324 AS31173 AS11878 AS32097 AS43948 AS62240 AS16265 AS3223 AS53667 AS200651 AS58224 AS57821 AS199524 AS51852 AS197540"

# Include Spamhaus ASN-DROP list for known cybercriminal infrastructures
SYSWARDEN_USE_SPAMHAUS="y"

# --- AbuseIPDB Reporting ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_ABUSE="n"
SYSWARDEN_ABUSE_API_KEY=""
SYSWARDEN_REPORT_F2B="y"
SYSWARDEN_REPORT_FW="y"

# --- Wazuh Agent ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_WAZUH="n"
SYSWARDEN_WAZUH_IP=""
SYSWARDEN_WAZUH_NAME=""
SYSWARDEN_WAZUH_GROUP="default"
SYSWARDEN_WAZUH_COMM_PORT="1514"
SYSWARDEN_WAZUH_ENROLL_PORT="1515"
```

Pass the file as an argument (use the alpine script if applicable):

```bash
./install-syswarden.sh syswarden-auto.conf

or

./install-syswarden-alpine.sh syswarden-auto.conf
```

### 4. Enterprise Telemetry Dashboard Access

SysWarden v1.20+ introduces a hardened, enterprise-grade Nginx reverse proxy to serve the real-time Telemetry Dashboard. The legacy Python daemon has been permanently retired. For maximum security, the dashboard strictly enforces HTTPS using an auto-generated RSA 4096-bit self-signed certificate and employs Zero Trust IP restrictions.

**Accessing the Dashboard**
Open your browser and navigate to: `https://<YOUR_SERVER_IP>:9999`

> **Note:** Because the dashboard uses a self-signed cryptographic certificate, your browser will display a security warning (e.g., `NET::ERR_CERT_AUTHORITY_INVALID`). This is expected and highly secure. You must accept the risk/bypass the warning to proceed to the interface.

**Zero Trust Access Control**
The dashboard is completely locked down at the web server level. Even though port 9999 is open in the OS firewall, Nginx will instantly drop incoming requests (HTTP 403 Forbidden) from any IP that is not explicitly authorized in its configuration.

* **Scenario A: WireGuard VPN Enabled (Recommended)**
  If you chose to deploy the stealth management VPN during installation, your entire WireGuard subnet (e.g., `10.66.66.0/24`) is natively authorized. Simply connect to your WireGuard client profile and access the dashboard securely.

* **Scenario B: Direct Public Access**
  During installation, the orchestrator automatically detects and whitelists your current Admin SSH IP address. You can access the dashboard directly over the internet from this specific IP. 
  
  *If your public IP changes (e.g., dynamic residential IP or moving to a café), you will be locked out. You must explicitly authorize your new public IP using the management CLI: `syswarden-mng whitelist <NEW_IP>` followed by `syswarden-mng reload` to synchronize Nginx.*

### 5. CLI Orchestration Commands

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

- Add Fail2ban jails after new services installed:

```bash
./install-syswarden.sh fail2ban-jails
```

> Dynamically discover active services and reload Fail2ban jails without disruption.

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

### 6. Day-to-Day Operations (syswarden-mng)

SysWarden includes a dedicated, secure Command Line Interface for daily firewall management. `syswarden-mng` allows administrators to hot-swap rules across all security layers (Persistence, Kernel Firewall, and Fail2ban) without requiring a full system reload.

#### Management Commands

```bash
syswarden-mng [COMMAND] [IP]
```

- **`check <IP>`**: Performs a full XDR diagnostic of an IP across local storage, Layer 3 (Kernel Firewall), and Layer 7 (Fail2ban jails).
- **`block <IP>`**: Instantly drops the IP at the kernel level and adds it to the persistent secure blocklist.
- **`unblock <IP>`**: Surgically purges the IP from the persistence file, the active kernel set, and grants global Fail2ban amnesty.
- **`whitelist <IP>`**: Grants absolute VIP access, bypassing all firewall restrictions dynamically.
- **`list`**: Displays all manually whitelisted and blocked IP addresses.
- **`reload`**: Safely triggers a full orchestrator synchronization.

> **Security Hardening**: The CLI enforces strict semantic CIDR/IPv4 validation (awk-based) to prevent firewall crashes caused by malformed IP injections. It also automatically locks down custom list files with `0600` permissions to prevent local enumeration by unprivileged users.

### 7. Continuous Compliance & Security Audit (syswarden-audit.sh)

Deploying a secure framework requires continuous validation. SysWarden ships with a standalone Purple Team compliance script designed to verify that all DevSecOps security locks remain active and untampered post-installation.

#### Running the Audit

```bash
./syswarden-audit.sh
```

#### Audit Scope

- **OS Hardening & Privilege Separation**: Validates crontab lockdowns (`/etc/cron.allow`), ensures standard users are removed from privileged groups (`wheel`, `sudo`, `adm`), and checks for immutable flags (`+i`) on user profiles to prevent SSH backdoors.
- **Log Routing & Anti-Injection**: Confirms the active status of Rsyslog and verifies the creation and strict permissions (`0600`) of isolated Netfilter and Auth logs.
- **Kernel Shield & Threat Intel**: Validates the presence of the active global blocklist payload and verifies that SysWarden rules are correctly prioritized in the detected backend (Nftables, Firewalld, UFW, or Iptables). Features context-aware configuration parsing to accurately validate GeoIP, manual ASN routing, and Spamhaus defenses without penalizing intentionally bypassed modules.
- **Zero Trust Fail2ban Engine**: Audits the Fail2ban IPC socket, checks for the absence of conflicting OS default configurations, verifies strict regex anchoring (`^%(__prefix_line)s`) to prevent log spoofing, and validates dynamic Infrastructure Whitelisting (Anti-Self-DoS).
- **Telemetry Sandboxing**: Ensures the UI Python wrapper is deployed with strict HTTP security headers and that telemetry payload data (`data.json`) is strictly restricted to the `nobody` user.
- **Zero Trust Remote Access & Cloaking**: Independently validates the strict "Priority Guillotine" (Global SSH Drop), verifies WireGuard gateway readiness, and natively authenticates Day-2 dynamic SSH bypasses (`allow-ssh`) as legitimate infrastructure exceptions.
- **Deterministic Scoring Engine**: Utilizes flattened kernel-state buffer parsing to eliminate multi-line tearing, ensuring 100% deterministic, flake-free execution and mathematically pure compliance percentages.

> **SIEM Integration**: Audit results are displayed in the console and simultaneously written to a secure, standardized log file at `/var/log/syswarden-audit.log` for easy ingestion by monitoring platforms.

## System Architecture & File Structure

```text
/ (Root File System)
├── etc/
│   ├── syswarden.conf                      # Centralized Configuration & Environment Variables
│   ├── syswarden/                          # Local Threat Intelligence Directory
│   │   ├── whitelist.txt                   # Custom IP/CIDR Routing Exceptions
│   │   ├── blocklist.txt                   # Custom Permanent IP Bans
│   │   ├── geoip.txt                       # Dynamic IPDeny Country-Level Blocklists
│   │   ├── asn.txt                         # Dynamic Spamhaus/RADB ASN Blocklists
│   │   └── ui/                             # Serverless Dashboard Web Root
│   │       └── data.json                   # Atomic Telemetry Payload (Restricted 0600)
│   ├── wireguard/                          # Stealth Management VPN Configurations
│   │   ├── wg0.conf                        # Core Server Interface Configuration
│   │   └── clients/                        # Generated Client Profiles & MTU Settings
│   ├── fail2ban/
│   │   └── jail.local                      # Zero Trust Jails (Conflicting OS defaults purged)
│   ├── logrotate.d/
│   │   └── syswarden                       # Log Rotation Policy
│   ├── cron.allow                          # OS Hardening (Task scheduler restricted to root)
│   ├── cron.d/                             # (Mapped to /etc/crontabs/root on Alpine)
│   │   └── syswarden-update                # Hourly Threat Intelligence Sync Job
│   ├── systemd/system/                     # (For Debian/Ubuntu/RHEL Ecosystem)
│   │   ├── syswarden-reporter.service      # AbuseIPDB Daemon (DynamicUser Sandboxed)
│   │   └── syswarden-ui.service            # Telemetry Dashboard (DynamicUser Sandboxed)
│   └── init.d/                             # (For Alpine Linux / OpenRC Ecosystem)
│       ├── syswarden-reporter              # OpenRC AbuseIPDB Service
│       └── syswarden-ui                    # OpenRC Dashboard Service (Run as nobody)
│
├── usr/local/bin/
│   ├── install-syswarden.sh                # Main CLI Orchestrator (Universal OS)
│   ├── install-syswarden-alpine.sh         # Main CLI Orchestrator (Alpine Linux)
│   ├── syswarden-telemetry.sh              # Decoupled jq JSON Generator (Cron)
│   ├── syswarden-ui-server.py              # Secure Python HTTP Wrapper (Strict Headers)
│   └── syswarden_reporter.py               # Python Log Analyzer & API Outbound Client
│
└── var/
    ├── log/
    │   ├── kern-firewall.log               # Isolated Nftables/Iptables Drops (Anti-Injection)
    │   ├── auth-syswarden.log              # Isolated PAM/Sudo Auth logs (Anti-Injection)
    │   ├── syswarden-install.log           # Verbose Installation & Debug Telemetry
    │   └── fail2ban.log                    # Dynamic Intrusion Prevention Logs
    └── ossec/etc/
        └── ossec.conf                      # Wazuh Agent Config
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
