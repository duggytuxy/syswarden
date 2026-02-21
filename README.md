<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?style=for-the-badge&logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/powered%20by-DuggyTuxy-darkred?style=for-the-badge&logo=apachekafka">
  <img src="https://img.shields.io/badge/Status-Community--Professional-brightgreen?style=for-the-badge&logo=status">
  <img src="https://img.shields.io/badge/Security-Hardened-blue?style=for-the-badge&logo=security">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20AlmaLinux%20%7C%20RockyLinux%20%7C%20CENTOS%20%7C%20FEDORA-blue?style=for-the-badge&logo=platform">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-0052cc?style=for-the-badge&logo=license">
  <img src="https://img.shields.io/github/last-commit/duggytuxy/syswarden?label=Last%20Update&color=informational&style=for-the-badge&logo=github">
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

<div align="center">

[![SysWarden Security Audit](https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml/badge.svg)](https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml)
</div>

![Alt](https://repobeats.axiom.co/api/embed/d909eab3c0cafb3a64294546f37a130f18a7e2f0.svg "Repobeats analytics image")

# SysWarden

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="./banner-light.svg">
    <img alt="SysWarden Banner" src="./banner-dark.svg" width="100%">
  </picture>
</div>

SysWarden is a tool based on the **[Data-Shield IPv4 Blocklists Community](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist)**, **[Wazuh](https://github.com/wazuh)** and **[Fail2ban](https://github.com/fail2ban/fail2ban)** that blocks up to 99% of noisy, disruptive, and malicious IP addresses and focuses on real signals.

## What Does SysWarden Protect

SysWarden acts as an advanced, preemptive shield for your infrastructure. By dropping known malicious traffic at the firewall (kernel) level **before** it even reaches your applications, it provides a crucial extra layer of security for any exposed asset.

- It is highly recommended for securing:

  - **Public VPS & Dedicated Servers:** Protect your SSH ports, control panels, and core system services from relentless brute-force attacks and automated mass-scanning.
  - **Websites & CMS (WordPress, Magento, etc.):** Block bad bots, vulnerability scanners, and exploit attempts targeting your web servers (Nginx/Apache) before they consume your CPU and RAM.
  - **Public APIs & SaaS Platforms:** Keep your application resources dedicated to legitimate users. Prevent endpoint abuse, scrapers, and Layer 7 DDoS probes.
  - **Critical Infrastructure:** Add a robust perimeter defense for your business-critical applications and internal tools exposed to the internet.
  - **Databases (MySQL, MongoDB, PostgreSQL):** Shield your exposed or partially exposed data stores from credential stuffing, unauthorized access attempts, and ransomware gangs.

> By eliminating the "background noise" of the internet, SysWarden ensures your servers remain fast, clean, and focused on serving real humans.

## Architecture

```
🛠️ SysWarden (Technology Stack)
├── 🐚 Core Orchestration
│   ├── 📜 Bash Scripting           # Automation, Installation & Logic
│   └── 🐧 Linux Kernel             # OS Support (Debian/Ubuntu & RHEL/Alma)
│
├── 🧱 Firewall Backend (Auto-Detection)
│   ├── 🛡️ Nftables                 # Modern Packet Filtering (Debian 10+)
│   ├── 🔥 Firewalld                # Dynamic Zone Management (RHEL 8/9)
│   └── ⚡ IPSet + Iptables         # High-Performance Hashing (Legacy)
│
├── 👮 Active Defense & Logs
│   ├── 🐍 Python 3                 # Log Parsing & API Connector
│   ├── 🚫 Fail2ban                 # Intrusion Prevention System (Jails)
│   ├── 📝 Systemd / Journalctl     # Service Management & Logging
│   └── ♻️ Logrotate                # Log Maintenance & Compression
│
└── ☁️ External Integrations
    ├── 📦 Data-Shield Repo         # Threat Intelligence Source (Git)
    ├── 📡 AbuseIPDB API            # Community Reporting (Outbound)
    └── 🦁 Wazuh XDR Agent          # SIEM & Vulnerability Detection
```

## Key Features

- **Universal OS Support:** Auto-detects and adapts to **Debian, Ubuntu, CentOS Stream, Fedora, AlmaLinux, and Rocky Linux**.

- **Intelligent Backend Detection:** Automatically selects the best firewall technology present on your system:
  - **Firewalld** (CentOS Stream/Fedora/Alma/Rocky native integration)
  - **Nftables** (Modern Debian/Ubuntu standard)
  - **IPSet/Iptables** (Legacy support)
  
- **Smart Mirror Selection:** Replaced ICMP Pings with **TCP/HTTP latency checks** to bypass firewall restrictions on GitHub/GitLab, ensuring you always download from the fastest mirror.

- **Kernel-Safe Optimization:**
  - Enables high-performance memory hashing (`hashsize`) on Debian/Ubuntu.
  - Uses conservative, stability-first settings on RHEL/Rocky kernels to prevent "Invalid Argument" crashes.
  
- **Persistence Guaranteed:** Rules are written to disk (XML for Firewalld, persistent saves for Netfilter), surviving reboots instantly.

- **Auto-Update:** Installs a cron job to refresh the blocklist hourly.

## Objectives

- **Noise Reduction:** Drastically reduce the size of system logs (`/var/log/auth.log`, `journalctl`) by blocking scanners at the door.
- **Resource Saving:** Save CPU cycles and bandwidth by dropping packets at the kernel level rather than letting application servers (Nginx, SSHD) handle them.
- **Proactive Security:** Move from a "Reactive" stance (wait for 5 failed logins -> Ban) to a "Proactive" stance (Ban the IP because it attacked a server in another country 10 minutes ago).

## Technical Deep Dive: Integration Logic
> Many admins worry that installing a massive blocklist might conflict with Fail2ban. **SysWarden solves this via layering.**

## Workflow

```
📡 / (Network Traffic Flow)
├── 🛡️ Layer 1: Firewall Shield (Static Defense)
│   ├── 🧱 Engine: Nftables / Firewalld / Ipset (Auto-detected)
│   ├── 📄 Blocklist: ~95k - 100k IPs (Data-Shield Source)
│   └── 🚫 Action: DROP packet before reaching services
│
└── 🖥️ Layer 2: User Space (Allowed Traffic)
    ├── 📁 Services & Logs
    │   ├── 🔓 SSH / Web / Database (Custom Ports Allowed)
    │   ├── 📝 System Logs: /var/log/syslog & journalctl
    │   └── ♻️ Maintenance: Logrotate (Daily cleanup, 7-day retention)
    │
    └── 📁 Layer 3: Active Response (Dynamic Defense)
        ├── 👮 Fail2ban Service
        │   ├── 🔍 Watch: Brute-force patterns (SSH, Nginx, etc.)
        │   └── ⚡ Action: Ban Dynamic IP locally
        │
        ├── 🐍 SysWarden Reporter
        │   ├── 🔍 Watch: Firewall Drops & Fail2ban Bans
        │   └── 📡 Action: Report to AbuseIPDB API
        │
        └── 🦁 Wazuh Agent
            ├── 🔍 Watch: File Integrity & System Events
            └── 📨 Action: Forward alerts to Wazuh SIEM
```

### 1. The Nftables + Fail2ban Synergy (Debian/Ubuntu)

- **Data-Shield (Layer 1):** Creates a high-performance Nftables `set` containing ~100k IPs. This acts as a static shield, dropping known bad actors instantly using extremely efficient kernel-level lookups.
- **Fail2ban (Layer 2):** Continues to monitor logs for *new*, unknown attackers.
- **Result:** Fail2ban uses less CPU because Data-Shield filters out the "background noise" (99% of automated scans) before Fail2ban even has to parse a log line.

### 2. The Firewalld + Fail2ban Synergy (RHEL/Alma/Rocky)

On Enterprise Linux, proper integration with `firewalld` is critical.

- **Native Sets:** SysWarden creates a permanent `ipset` type within Firewalld's configuration logic.
- **Rich Rules:** It applies a "Rich Rule" that drops traffic from this set *before* it reaches your zones or services.
- **Persistence:** Unlike simple scripts that run `ipset` commands (which vanish on reload), SysWarden writes the configuration to `/etc/firewalld/`, ensuring the protection persists across service reloads and server reboots.

### 3. AbuseIPDB reporting
> In a community setting, during the script installation phase, it is possible to report triggered and confirmed alerts to ABUSEIPDB in order to keep the database of malicious IP addresses up to date.

- **Enable the option** Simply confirm with `y` when prompted during installation.
- **API key** Paste your AbuseIPDB API key to automatically report malicious IPs and contribute to the community database.

### 4. Wazuh Agent Integration
> For organizations using a SIEM, SysWarden includes an interactive module to deploy the **Wazuh XDR Agent** effortlessly, bridging local protection with centralized monitoring.

- **Seamless Deployment:** The script automatically detects your OS, installs the official GPG keys/repositories, and deploys the latest agent version.
- **Smart Configuration:** By simply providing your Manager IP, Agent Name, and Group during the prompt, the script injects the configuration immediately—no manual editing of `ossec.conf` required.
- **Auto-Whitelisting:** To ensure uninterrupted log forwarding, SysWarden creates a high-priority exception rule allowing traffic to/from your Wazuh Manager (ports 1514/1515) to bypass the strict blocklist.

## How to Install (root)
> This script automatically detects installed services (Nginx, Apache, MongoDB) and configures protections accordingly. If a service is installed AFTER SysWarden, simply run the update command or rerun the installer to activate the new jails.

```bash
# For Ubuntu/Debian
apt update && apt upgrade -y
apt install wget -y

# For Rocky/AlmaLinux/CentOS Stream/Fedora
dnf update -y
dnf install wget -y

# install script
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v8.00/install-syswarden.sh
chmod +x install-syswarden.sh
./install-syswarden.sh

# Update configurations and Blocklists
./install-syswarden.sh update

# View Alerts
./install-syswarden.sh alerts

# Whitelist an IP
./install-syswarden.sh whitelist

# Block an IP
./install-syswarden.sh blocklist

# Docker protection
./install-syswarden.sh protect-docker

# SysWarden Upgrade Checker
././install-syswarden.sh upgrade
```

```
📂 / (Root System)
├── 📁 etc/
│   ├── 📄 syswarden.conf                   # Main Configuration (Auto-generated)
│   ├── 📁 fail2ban/
│   │   └── 📄 jail.local                   # Custom Jails (SSH, Web, DB) injected by SysWarden
│   ├── 📁 logrotate.d/
│   │   └── 📄 syswarden                    # Log Rotation Config (7-day retention & compression)
│   ├── 📁 cron.d/
│   │   └── 📄 syswarden-update             # Hourly Update Job
│   └── 📁 systemd/system/
│       └── 📄 syswarden-reporter.service
├── 📁 usr/local/bin/
│   ├── 📜 install-syswarden.sh             # Main Script (CLI Tool)
│   └── 🐍 syswarden_reporter.py            # Python Log Analyzer
└── 📁 var/
    ├── 📁 log/
    │   ├── 📄 syswarden-install.log        # Installation & Debug Logs
    │   └── 📄 fail2ban.log                 # Banned IPs logs
    └── 📁 ossec/etc/
        └── 📄 ossec.conf                   # Wazuh Agent Config (Manager IP & Ports injected here)
```

## Uninstallation (root)

```bash
./install-syswarden.sh uninstall
```

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
