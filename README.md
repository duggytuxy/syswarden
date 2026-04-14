<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?style=for-the-badge&logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?style=for-the-badge&logo=status">
  <img src="https://img.shields.io/badge/Security-Zero_Trust-darkred?style=for-the-badge&logo=security">
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-yellow?style=for-the-badge&logo=license">
</p>

# SysWarden

**SysWarden** is an ultra-lightweight **Host-based Security Orchestrator** for Linux. Acting as a powerful alternative to eBPF/XDP, it drops malicious packets directly at the hardware level (Layer 2) to prevent CPU overhead

By fusing [Data-Shield IPv4 blocklists](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), CINS Army, Blocklist.de, GeoIP, ASN tracking, a dynamic L7 WAF (Fail2ban), and a strict Zero-Trust Catch-All policy, it neutralizes 97% of internet noise with a near-zero memory footprint. 

> Built for critical infrastructures, SysWarden enforces automated server hardening to accelerate your ISO 27001 and NIS2 compliance.

## Enterprise-Grade Features

**Core Network Defense (Hardware & Layer 2/3)**
* **Layer 2 Acceleration (eBPF/XDP Alternative):** Injects threat intelligence directly into a dedicated `nftables` `netdev` table. Malicious packets are dropped at the NIC ingress hook, entirely bypassing kernel routing and `conntrack` for zero CPU overhead during volumetric DDoS attacks.
* **Pre-Routing Shield (Legacy OS):** For older environments, utilizes the `iptables` `raw PREROUTING` chain to shatter massive automated scans before memory-heavy state tracking is allocated.
* **Global Threat Intelligence:** Automatically blocks hostile countries (GeoIP), Cybercrime Hosters, and rogue Autonomous System Numbers (ASN) to drop 97% of internet background noise instantly.

**Application Security & Active Response (Layer 7)**
* **Dynamic L7 WAF:** Protects 51+ vital services (Docker, Nginx, Databases, CMS) using heavily optimized Fail2ban jails with a near-zero memory footprint.
* **Automated Retaliation:** Natively integrates with the global AbuseIPDB network to proactively report attackers and share telemetry.

**Zero-Trust & Compliance Architecture**
* **Service Cloaking:** Hides your SSH port and administrative panels behind a seamlessly deployed, invisible WireGuard VPN tunnel.
* **Smart SIEM Log Forwarding:** Natively integrates with `rsyslog` (Universal/Alpine) and `syslogd` (Slackware) to forward only high-value, behavioral Layer 7 bans to your SOC/SIEM (Wazuh). Intentionally filters out L3 noise to prevent index saturation, accelerating **ISO 27001 and NIS2 compliance**.
* **High Availability (HA) Cluster Sync:** Securely replicates threat intelligence states, whitelists, and configurations to standby nodes via an automated, SSH-encrypted cron job.

**Observability & Lifecycle Management**
* **Real-Time Telemetry:** Monitor live threats, blocked IPs, and system health through a secure, self-hosted Web Dashboard and a dedicated CLI interface.
* **"Scorched Earth" Rollback:** The uninstallation routine performs a deep, surgical cleanup. It ensures the absolute eradication of custom `netdev` and `raw` tables, instantly restoring the OS networking stack to its pristine original state without requiring a reboot.

## Hardware-Aware Zero-Trust Architecture

SysWarden does not simply append rules to standard firewall chains; it fundamentally alters the Linux networking stack to neutralize threats before they consume system resources:

1. **Layer 2 Ingress Drop (Priority -500):** Utilizing the `nftables` `netdev` family (or `iptables raw PREROUTING`), global OSINT blocklists, hostile ASNs, and GeoIP blocks are enforced directly at the Network Interface Card (NIC) hook. Malicious packets are destroyed before reaching the kernel routing or `conntrack` modules, preventing state-table exhaustion and CPU overhead.
2. **Stateful Fast-Path (Priority 0):** Legitimate established connections and dynamic container traffic (e.g., Docker's `DOCKER-USER` chain) are prioritized. This stateful bypass guarantees zero latency for your production application traffic.
3. **Behavioral L7 Defense (Dynamic WAF):** The active defense layer analyzes application logs (Nginx, SSH, Databases) in real-time. Behavioral anomalies—such as brute-force attempts, SQLi, or LFI—trigger instant, surgical IP bans that dynamically synchronize with the underlying Layer 3/2 drop tables.
4. **Zero-Trust "Catch-All":** The attack surface is entirely sealed. Any incoming traffic not explicitly whitelisted by the administrator or the automated service discovery engine is silently dropped and logged, enforcing a mathematically strict Zero-Trust policy.

## Supported Environments

SysWarden is built to run flawlessly across modern Linux infrastructures:
* **Universal (systemd):** Debian 13+, Ubuntu 24.04+, AlmaLinux, Rocky Linux, CentOS Stream, Fedora.
* **Alpine Linux (OpenRC):** Highly optimized for lightweight containers and edge nodes.
* **Slackware (BSD-init):** Full native support with pure UNIX flat-file tailing.

## The Fortress Dashboard (Web & CLI)

SysWarden provides dual-layer observability, ensuring you maintain complete situational awareness over your server's security posture without the overhead of heavy databases (like ELK or InfluxDB).

**Secure Web Interface**
* **Live Threat Telemetry:** Track dynamic Layer 7 (Fail2ban) behavioral bans in real-time.
* **Attacker Profiling:** Visualize top OSINT offenders, blocked ASNs, and GeoIP interception statistics.
* **Resource Monitoring:** Review active jail allocations and the near-zero memory footprint of the underlying Nftables/IPtables engines.
* *(Self-hosted and securely accessible via `https://<YOUR_SERVER_IP>:9999` post-installation).*

**Interactive CLI & Orchestration**
* **Terminal Dashboard:** Manage your infrastructure directly from the shell using the `syswarden-manager` (instant visibility into blocked IPs, whitelists, and rule idempotency).
* **Rich Installation Alerts:** The core orchestration scripts (`install-syswarden.sh alerts`) provide structured, color-coded logging for instant feedback on OS hardening, SIEM (Wazuh) integration, and Zero-Trust policy enforcement.

## Quick Start

Deploying enterprise-grade security takes less than 10 minutes.

**1. Clone the repository:**
```bash
git clone https://github.com/duggytuxy/syswarden.git
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

## Quick uninstall

Uninstall Syswarden properly while keeping your original settings.

```bash
./install-syswarden*.sh uninstall
```

## Documentation

To learn everything about the SysWarden ecosystem, explore detailed configurations, and read advanced usage guides, please visit our dedicated [documentation page](https://syswarden.io/docs/)

## Target and support

> €3,000/year to fuel continuous DevSecOps improvements and integrations

Developing **SysWarden** and curating the zero-false-positive **Data-Shield IPv4 Blocklists** requires dedicated server infrastructure and non-stop threat monitoring. 

Reaching this annual goal guarantees my 100% independence, funding a continuous development cycle without corporate constraints. Your support directly pays for the servers and keeps these enterprise-grade cybersecurity tools free, updated, and accessible to everyone. 

Let's build a safer internet together!

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

## License

SysWarden is free and open-source software licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software in compliance with the license terms. See the [LICENSE](/LICENSE) file for more details.

*Powered by DuggyTuxy (Laurent M.) - Securing the Open Source community.*