<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?style=for-the-badge&logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?style=for-the-badge&logo=status">
  <img src="https://img.shields.io/badge/Security-Zero_Trust-darkred?style=for-the-badge&logo=security">
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-yellow?style=for-the-badge&logo=license">
</p>

# 🛡️ SysWarden

**An ultra-lightweight DevSecOps firewall orchestrator for Linux.** SysWarden proactively drops 97% of malicious internet traffic by fusing Data-Shield IPv4 blocklists, GeoIP, Spamhaus ASN, Cybercrime Hosters, dynamic Fail2ban jails with a near-zero memory footprint.

---

## ⚡ Core Capabilities

* **Drop 97% of background noise** and scanner traffic instantly at the kernel level.
* **Cloak your SSH port** and administration panels behind an invisible WireGuard VPN.
* **Block hostile countries** and rogue Autonomous System Numbers (ASN) automatically.
* **Protect 46+ services dynamically** (Docker, Nginx, Databases, CMS) via heavily optimized Fail2ban jails.
* **Monitor live threats** through a secure, self-hosted, and responsive Web Dashboard.
* **Report attackers automatically** to the global AbuseIPDB network.

## 🐧 Supported Environments

SysWarden is built to run flawlessly across modern Linux infrastructures:
* **Universal (systemd):** Debian 12+, Ubuntu 22.04+, AlmaLinux, Rocky Linux, CentOS Stream, Fedora.
* **Alpine Linux (OpenRC):** Highly optimized for lightweight containers and edge nodes.
* **Slackware (BSD-init):** Full native support with pure UNIX flat-file tailing.

---

## 🚀 Quick Start

Deploying enterprise-grade security takes less than 10 minutes.

**1. Clone the repository:**
```bash
git clone [https://github.com/duggytuxy/syswarden.git](https://github.com/duggytuxy/syswarden.git)
cd syswarden
chmod +x *.sh
```

**2. Execute the installer matching your OS:**

*For Debian, Ubuntu, RHEL, AlmaLinux & Rocky Linux:*

```bash
./install-syswarden.sh
```

*Alpine Linux:*

```bash
./install-syswarden-alpine.sh
```

*For Slackware (beta 4):*

```bash
./install-syswarden-slackware.sh
```

## 🛠️ Management & Auditing Tools

SysWarden comes with dedicated built-in utilities to maintain and verify your infrastructure's security lifecycle:

* **`syswarden-manager.sh`**: The core administration utility. Use it to manually trigger threat-intel updates, manage your IP whitelists/blocklists, and check the firewall's operational status.
* **`syswarden-audit.sh`**: A comprehensive DevSecOps auditing tool designed to evaluate your server's security posture, analyze logs, and verify SysWarden's architectural integrity.

## 📊 The Fortress Dashboard

SysWarden includes a built-in, secure HTTPS UI to monitor your server's telemetry in real-time. It operates seamlessly without heavy database requirements.

* Track live Layer 3 (Kernel) & Layer 7 (Fail2ban) blocks.
* Analyze your top OSINT attackers.
* Review active jail allocations and memory usage.

*(Accessible via `https://<YOUR_SERVER_IP>:9999` after installation).*

## 🛡️ Target: €3,000/year to fuel continuous DevSecOps innovation

Developing **SysWarden** and curating the zero-false-positive **Data-Shield IPv4 Blocklists** requires dedicated server infrastructure and non-stop threat monitoring. 

Reaching this annual goal guarantees my 100% independence, funding a continuous development cycle without corporate constraints. Your support directly pays for the servers and keeps these enterprise-grade cybersecurity tools free, updated, and accessible to everyone. 

Let's build a safer internet together!

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

---
*Powered by DuggyTuxy (Laurent M.) - Securing the Open Source community.*