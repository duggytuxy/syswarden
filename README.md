<!-- Location: Top of README.md -->
<!-- Replace the existing <p align="center"> block with this updated version -->
<p align="center">
  <!-- GitHub Actions Workflows -->
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml/badge.svg" alt="SysWarden Security Audit">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/dependabot/dependabot-updates">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/dependabot/dependabot-updates/badge.svg" alt="Dependabot Updates">
  </a>

  <!-- Dynamic GitHub License -->
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?logo=license" alt="GitHub License">
  </a>

  <!-- Custom Project Badges (Classic Style) -->
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?logo=opensourceinitiative" alt="Open Source">
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?logo=status" alt="Production Ready">
  <img src="https://img.shields.io/badge/Security-Zero_Trust-darkred?logo=security" alt="Zero Trust">
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?logo=linux" alt="Linux Universal">
</p>

# SysWarden

**SysWarden** is an ultra-lightweight **Enterprise Host-based Security Orchestrator (HIDS / HIPS)** for Linux. Acting as a powerful alternative to eBPF/XDP, it drops malicious packets directly at the hardware level (Layer 2/3) to prevent CPU overhead.

By fusing [Data-Shield IPv4 blocklists](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), CINS Army, Blocklist.de, GeoIP, ASN tracking, a dynamic L7 WAF (Fail2ban), and real-time SIEM logging, SysWarden transforms any bare-metal server or VM into a Zero-Trust fortress within seconds.

> **Deprecation Notice: Alpine Linux Support**
> Effective immediately, support for Alpine Linux is officially deprecated. The dedicated Alpine installation script has been removed. SysWarden is evolving into a pure Enterprise HIDS. While Alpine remains an industry standard for lightweight containers, enterprise bare-metal servers and virtual machines—which SysWarden is designed to protect at the host level—are predominantly driven by the Systemd-based ecosystems (RHEL, Debian, Ubuntu). Unifying the architecture around `systemd` allows for deeper security integrations and ensures maximum reliability and compliance for production environments.

> Built for critical infrastructures, SysWarden enforces automated server hardening to accelerate your ISO 27001 and NIS2 compliance.

## Enterprise-Grade Features

**Core Network Defense (Hardware & Layer 2/3)**
* **Layer 2/3 Acceleration (eBPF/XDP Alternative):** Injects threat intelligence directly into a dedicated `nftables` `netdev` table. Malicious packets are dropped at the NIC ingress hook, entirely bypassing kernel routing and `conntrack` for zero CPU overhead during volumetric DDoS attacks.
* **Pre-Routing Shield (Legacy OS):** For older environments, utilizes the `iptables` `raw PREROUTING` chain to shatter massive automated scans before memory-heavy state tracking is allocated.
* **Global Threat Intelligence:** Automatically blocks hostile countries (GeoIP), Cybercrime Hosters, and rogue Autonomous System Numbers (ASN) to drop 97% of internet background noise instantly.

**Application Security & Active Response (Layer 7)**
* **Dynamic L7 WAF:** Protects 51+ vital services (Docker, Nginx, Databases, CMS) using heavily optimized Fail2ban jails with a near-zero memory footprint.
* **Standalone ModSecurity WAF:** Seamlessly integrates [OWASP ModSecurity (v3.0.15 standalone)](https://github.com/owasp-modsecurity/ModSecurity) via the `syswarden-waf.sh` script, providing advanced HTTP traffic inspection and Layer 7 threat mitigation.
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

1. **Layer 2/3 Ingress Drop (Priority -500):** Utilizing the `nftables` `netdev` family (or `iptables raw PREROUTING`), global OSINT blocklists, hostile ASNs, and GeoIP blocks are enforced directly at the Network Interface Card (NIC) hook. Malicious packets are destroyed before reaching the kernel routing or `conntrack` modules, preventing state-table exhaustion and CPU overhead.
2. **Stateful Fast-Path (Priority 0):** Legitimate established connections and dynamic container traffic (e.g., Docker's `DOCKER-USER` chain) are prioritized. This stateful bypass guarantees zero latency for your production application traffic.
3. **Behavioral L7 Defense (Dynamic WAF):** The active defense layer analyzes application logs (Nginx, SSH, Databases) in real-time. Behavioral anomalies—such as brute-force attempts, SQLi, or LFI—trigger instant, surgical IP bans that dynamically synchronize with the underlying Layer 3/2 drop tables.
4. **Zero-Trust "Catch-All":** The attack surface is entirely sealed. Any incoming traffic not explicitly whitelisted by the administrator or the automated service discovery engine is silently dropped and logged, enforcing a mathematically strict Zero-Trust policy.

## Supported Environments

SysWarden is built to run flawlessly across modern Linux infrastructures:
* **Universal (systemd):** Debian 13+, Ubuntu 24.04+, AlmaLinux, Rocky Linux, CentOS Stream, Fedora.

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

## Installation Guide

SysWarden is distributed as a pre-compiled, self-contained shell script. All complex modules are bundled into a single deployment artifact. 

It supports two installation methods: a standard interactive mode and an Enterprise Zero-Trust mode for environments requiring strict supply chain validation.

### 1. Quick Installation (Standard)

Download the execution script and run it as root. Supported OS: *Debian 12+, Ubuntu 24.04+, RHEL 9+, Fedora 43+, CentOS Stream, AlmaLinux 10+ & Rocky Linux 9+*.

```bash
wget https://github.com/duggytuxy/syswarden/releases/latest/download/install-syswarden.sh
chmod +x install-syswarden.sh
sudo ./install-syswarden.sh
```

### 2. Enterprise Installation (Zero-Trust / SLSA Level 3)

SysWarden releases are cryptographically signed using GitHub Artifact Attestations to guarantee supply chain integrity. For environments compliant with ISO 27001 or NIS2, it is strictly recommended to verify the script's provenance before execution.

```bash
# 1. Download the release bundle
wget https://github.com/duggytuxy/syswarden/releases/latest/download/syswarden-release.tar.gz

# 2. Verify the cryptographic attestation using the official GitHub CLI
gh attestation verify syswarden-release.tar.gz --owner duggytuxy

# 3. If the verification is successful (exit code 0), extract and run
tar -xzf syswarden-release.tar.gz
chmod +x install-syswarden.sh
sudo ./install-syswarden.sh
```

### 3. Automated / Headless Deployment (CI/CD)

SysWarden can be deployed without any user interaction using a configuration file, ideal for Ansible, Terraform, or Cloud-init deployments.

```bash
# Secure the configuration file permissions
chmod 600 syswarden-auto.conf

# Execute the silent installation
sudo ./install-syswarden.sh syswarden-auto.conf
```

### 4.Quick uninstall

Uninstall Syswarden properly while keeping your original settings.

```bash
./install-syswarden.sh uninstall
```

## Documentation

To learn everything about the SysWarden ecosystem, explore detailed configurations, and read advanced usage guides, please visit our dedicated [documentation page](https://syswarden.io/docs/)

## Target and support

> €3,500/year to fuel continuous DevSecOps improvements and integrations

Developing **SysWarden** and curating the zero-false-positive **Data-Shield IPv4 Blocklists** requires dedicated server infrastructure and non-stop threat monitoring. 

Reaching this annual goal guarantees my 100% independence, funding a continuous development cycle without corporate constraints. Your support directly pays for the servers and keeps these enterprise-grade cybersecurity tools free, updated, and accessible to everyone. 

Let's build a safer internet together!

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

## License

SysWarden is free and open-source software licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software in compliance with the license terms. See the [LICENSE](/LICENSE) file for more details.

*Powered by DuggyTuxy (Laurent M.).*
