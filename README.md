<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?style=for-the-badge&logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?style=for-the-badge&logo=status">
  <img src="https://img.shields.io/badge/Security-Zero_Trust-darkred?style=for-the-badge&logo=security">
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-yellow?style=for-the-badge&logo=license">
</p>

# SysWarden

**An ultra-lightweight DevSecOps firewall orchestrator for Linux.** SysWarden (ver: v2.10) proactively drops 97% of malicious internet traffic by fusing [Data-Shield IPv4 blocklists](https://duggytuxy.github.io/), [IPdeny](https://www.ipdeny.com/ipblocks/), [Spamhaus ASN](https://www.spamhaus.org/drop/asndrop.json), [CINS Army](https://cinsscore.com/list/ci-badguys.txt), [Blocklist.de](https://www.blocklist.de/en/index.html), and dynamic [Fail2ban](https://github.com/fail2ban/fail2ban) jails with a near-zero memory footprint.

## Enterprise-Grade Features

* **Drop 97% of background noise** and scanner traffic instantly.
* **Layer 2 Hardware Acceleration (Nftables):** Threat intelligence lists are injected directly into a dedicated `netdev` table. Malicious packets are dropped at the Network Interface Card (NIC) ingress hook, bypassing the kernel routing and connection tracking modules entirely for zero CPU overhead during volumetric DDoS attacks.
* **Pre-Routing Acceleration (IPtables):** Legacy environments benefit from the `raw PREROUTING` chain, dropping massive automated scans before memory-heavy state tracking (`conntrack`) is allocated.
* **Exclusive SIEM Log Forwarding:** Natively integrates with `rsyslog` (Universal/Alpine) and `syslogd` (Slackware) to forward only Layer 7 behavioral bans (Fail2ban) to an external SOC/SIEM (ISO 27001 / NIS2 compliant), deliberately filtering out noisy Layer 3 blocks to prevent index saturation.
* **High Availability (HA) Cluster Sync:** Securely replicates threat intelligence states, whitelists, and configurations to a standby node via an automated, SSH-encrypted cron job (`syswarden-sync.sh`).
* **Scorched Earth Uninstallation:** The uninstall routine performs a deep rollback, ensuring absolute eradication of `netdev` and `raw` tables, instantly restoring the OS networking stack to its pristine original state without requiring a reboot.
* **Cloak your SSH port** and administration panels behind an invisible WireGuard VPN.
* **Block hostile countries**, Cybercrime Hosters and rogue Autonomous System Numbers (ASN) automatically.
* **Protect 51+ services dynamically** (Docker, Nginx, Databases, CMS) via heavily optimized Fail2ban jails.
* **Monitor live threats** through a secure, self-hosted, and responsive Web Dashboard and CLI Dashboard.
* **Report attackers automatically** to the global AbuseIPDB network.

## Hardware-Aware Zero Trust Architecture

SysWarden does not simply append rules to standard firewall chains; it fundamentally alters how the Linux kernel handles incoming traffic:

1. **Hardware Ingress Drop (Priority -500):** Using the Nftables `netdev` family (or IPtables `raw PREROUTING`), known malicious IPs from global blocklists, Spamhaus ASNs, and GeoIP restrictions are terminated at the absolute edge of the network interface.
2. **Stateful Bypass (Priority 0):** Established connections and containerized traffic (Docker `DOCKER-USER` chain) are processed first to ensure zero latency for legitimate application traffic.
3. **Layer 7 Active Defense:** Fail2ban analyzes application logs (Nginx, Apache, SSH, DevOps tools) and dynamically orchestrates bans against behavioral anomalies (SQLi, LFI, Brute-force).
4. **Catch-All Guillotine:** Any traffic not explicitly allowed by the administrator or the automated service discovery engine is dropped and logged, enforcing strict Zero Trust.

## Supported Environments

SysWarden is built to run flawlessly across modern Linux infrastructures:
* **Universal (systemd):** Debian 13+, Ubuntu 24.04+, AlmaLinux, Rocky Linux, CentOS Stream, Fedora.
* **Alpine Linux (OpenRC):** Highly optimized for lightweight containers and edge nodes.
* **Slackware (BSD-init):** Full native support with pure UNIX flat-file tailing.

## Management & Auditing Tools

SysWarden comes with dedicated built-in utilities to maintain and verify your infrastructure's security lifecycle:

* **`syswarden-manager.sh`**: The core administration utility. Use it to manually trigger threat-intel updates, manage your IP whitelists/blocklists, and check the firewall's operational status.
* **`syswarden-audit.sh`**: A comprehensive DevSecOps auditing tool designed to evaluate your server's security posture, analyze logs, and verify SysWarden's architectural integrity.

## Compliance Auditing

SysWarden includes a strict DevSecOps auditing script (`syswarden-audit.sh`) designed to generate compliance reports for ISO 27001 and NIS2. It maps the active system against expected Zero Trust benchmarks:

* **Phase 1-2:** OS Hardening, Privilege Separation, and Log Anti-Injection.
* **Phase 3-4:** Hardware Layer 2 Shielding, Threat Intelligence, and Layer 7 Active Defense.
* **Phase 5-7:** Enterprise Dashboard Telemetry, Zero Trust VPN Cloaking, and Exposed Services mapping (CSPM).
* **Phase 8:** Enterprise SOC Integration. Verifies SIEM log forwarding paths and High Availability (HA) cluster replication.
* **Phase 9:** Firewall Idempotency. Scans for ghost rules and duplicated configurations post-update.

## The Fortress Dashboard

SysWarden includes a built-in, secure HTTPS UI to monitor your server's telemetry in real-time. It operates seamlessly without heavy database requirements.

* Track live Layer 3 (Kernel) & Layer 7 (Fail2ban) blocks.
* Analyze your top OSINT attackers.
* Review active jail allocations and memory usage.

*(Accessible via `https://<YOUR_SERVER_IP>:9999` after installation).*

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

## Automated Deployments (CI/CD & Fleet Management)

For large-scale infrastructures and Infrastructure as Code (IaC) environments, SysWarden supports true zero-touch, unattended installations via the **`syswarden-auto.conf`** file.

* **Pre-define** your custom SSH ports, WireGuard subnets, API keys, and target blocklists without requiring any interactive prompts.
* **Seamlessly** integrate SysWarden into your CI/CD pipelines, Ansible playbooks, Terraform modules, or cloud-init bootstrap scripts.
* **Simply** edit the `syswarden-auto.conf` template with your environmental variables and execute the installer with the `syswarden-auto.conf` flag:

```bash
./install-syswarden*.sh syswarden-auto.conf
```

## Day-2 Operations (SysWarden Manager)

The `syswarden-manager.sh` CLI allows administrators to perform surgical operations on the active firewall without interrupting service. All operations dynamically target the hardware acceleration layers (`netdev` or `raw PREROUTING`) to ensure consistency.

* `check <IP>`: Full XDR diagnostic. Checks local storage, HA sync state, Layer 3 hardware tables, and Layer 7 active behavioral jails.
* `block <IP>`: Hot-injects an IP directly into the kernel's Layer 2 drop set and ensures persistence.
* `whitelist <IP>`: Grants absolute VIP access. Injects a bypass rule at the hardware ingress level and updates the Nginx Dashboard ACL.
* `allow-ssh <IP> [PORT]`: Punctures a targeted hole in the stealth VPN perimeter to allow direct SSH access for a specific IP.
* `unblock <IP>` / `revoke-ssh <IP>`: Reverts access and safely purges records from hardware memory sets without flushing the entire firewall.

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