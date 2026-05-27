<p align="center">
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/package.yml/badge.svg" alt="SysWarden Builder and Packager">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/duggytuxy/syswarden?logo=license" alt="GitHub License">
  </a>
  <img src="https://img.shields.io/badge/Platform-Linux_Universal-0052cc?logo=linux" alt="Linux Universal">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?logo=opensourceinitiative" alt="Open Source">
  <img src="https://img.shields.io/badge/Status-Production_Ready-blue?logo=status" alt="Production Ready">

  <br>

  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/compliance.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/compliance.yml/badge.svg" alt="Plumber Compliance">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/scorecard.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/scorecard.yml/badge.svg" alt="OSSF Scorecard Supply Chain Security">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/security-audit.yml/badge.svg" alt="SysWarden Security Audit">
  </a>
  <a href="https://github.com/duggytuxy/syswarden/actions/workflows/dependabot/dependabot-updates">
    <img src="https://github.com/duggytuxy/syswarden/actions/workflows/dependabot/dependabot-updates/badge.svg" alt="Dependabot Updates">
  </a>
  <img src="https://img.shields.io/badge/Security-Default_Deny-darkred?logo=security" alt="Default-Deny">
  <img src="https://img.shields.io/badge/Compliance-EU_CRA_Ready-003399?logo=shield&logoColor=white" alt="EU CRA Ready">
</p>

# SysWarden

**SysWarden** is an Enterprise-grade Default-Deny Host Intrusion Prevention System (HIPS) designed for critical Linux infrastructure. It enforces automated a part of CIS Level 2 hardening, integrates global Threat Intelligence, and orchestrates dynamic network defense with a near-zero performance overhead.

It acts as a ruthless first line of defense. By fusing dynamic firewall orchestration (`nftables`/`iptables`), global Threat Intelligence ([Data-Shield IPv4](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist), GeoIP, ASN), a reactive HIPS (optimized Fail2ban), and SIEM alert routing, SysWarden filters out Internet "background noise" and neutralizes threats at the network (L2/L3/L4) and application (L7) levels. It perfectly complements modern EDR/XDR architectures by drastically reducing their analysis surface and the server's CPU load.

> [!IMPORTANT]
> Designed for critical infrastructures, SysWarden automates server hardening to accelerate your **ISO 27001, NIS2, and CIS Benchmark** compliance.

## Enterprise-Grade Features

**Core Network Defense (Hardware & Layer 2/3)**
* **L2/L3 Ingress Acceleration:** Injects Threat Intelligence directly into the `netdev` table under `nftables` (or `raw PREROUTING` under `iptables`). Malicious packets are destroyed right at the Network Interface Card (NIC), entirely bypassing kernel routing and the `conntrack` module to guarantee zero CPU impact during volumetric DDoS attacks.
* **Global Threat Intelligence:** Automatically blocks hostile countries (GeoIP), known cybercrime hosters, and rogue Autonomous System Numbers (ASN), instantly eliminating 97% of unwanted traffic.

**Stateful & Protocol Optimization (Layer 3/4)**
* **CGNAT & TCP State Purification:** Implements UFW-grade stateful enforcement by silently destroying late `FIN-ACK`/`RST` packets on expired `conntrack` sessions, and strictly blocking `NEW` connections lacking the `SYN` flag. This absolutely eradicates log pollution and false-positive portscan detections on active service ports, crucial for highly federated and mobile-heavy environments.
* **Dynamic QUIC / HTTP3 Provisioning:** Modern web protocols are natively supported. SysWarden automatically binds and provisions `UDP/443` whenever `TCP/443` is permitted, preventing aggressive QUIC handshake drops at the Zero-Trust Catch-All layer and ensuring seamless HTTP/3 operation behind the firewall.

**Application Security & Active Response (Layer 7)**
* **Dynamic L7 HIPS / WAF:** Protects 50+ vital services (Docker, Nginx, Databases, CMS) using deeply restructured and hardened Fail2ban "jails", ensuring a near-zero memory footprint and deadly accuracy (payload escaping, bypass prevention).
* **Standalone ModSecurity:** Seamlessly integrates [OWASP ModSecurity (v3.0.15)](https://github.com/owasp-modsecurity/ModSecurity) via the `syswarden-waf.sh` component, providing deep HTTP traffic inspection.
* **Automated Retaliation:** Natively interfaces with the AbuseIPDB network to proactively report attackers and share telemetry.

**Default-Deny & Compliance Architecture**
* **CIS Benchmark Level 2 (Defense-in-Depth):** Optional surgical hardening of the kernel (eBPF, ASLR, source routing), memory (core dumps limits), SSH, and filesystems. It strictly conforms to CIS Level 2 requirements without breaking modern containerized production stacks.
* **Service Cloaking:** Hides your SSH port and administrative interfaces behind a stealthy WireGuard VPN tunnel, deployed seamlessly.
* **Smart SIEM Routing:** Integrates with `rsyslog` to natively forward only high-value behavioral bans (Layer 7) to your SOC/SIEM (e.g., Wazuh). Intentionally filters out Layer 3 noise to prevent index saturation and control ingestion costs.
* **High Availability (HA) Cluster Sync:** Securely replicates Threat Intelligence states, whitelists, and configurations to passive nodes via an SSH-encrypted cron job.

**Observability & Lifecycle Management**
* **Real-Time Telemetry:** Monitor active threats, blocked IPs, and system health via a secure, Dashboard TUI and a dedicated CLI interface.
* **"Scorched Earth" Surgical Rollback:** The uninstallation routine performs a deep cleanup. It safely reverts all CIS Level 2 configurations (sysctl, modprobe, cron permissions), eradicates custom `netdev` and `raw` tables, and instantly restores the OS to its pristine original state without requiring a reboot.

> [!NOTE]
> **For CISOs and CIOs (Strategic Impact):** This architecture translates zero-trust policies into strict technical controls. By offloading volumetric mitigation to the network edge (L2/L3/L4) and forwarding only high-fidelity Layer 7 behavioral data, SysWarden drastically reduces SIEM ingestion costs, prevents kernel resource exhaustion, and guarantees operational continuity under hostile conditions.

## Hardware-Aware Default-Deny Architecture

> [!IMPORTANT]
> SysWarden doesn't just stack firewall rules; it orchestrates the Linux network stack to neutralize threats before they consume your resources:

1. **L2/L3 Ingress Drop (Priority -500):** OSINT blocklists, hostile ASNs, and GeoIP filtering are applied at the lowest hardware level (NIC Ingress hook). Packets are destroyed before entering kernel routing or state tracking (`conntrack`), preventing memory exhaustion and guaranteeing zero CPU impact during volumetric attacks.
2. **Stateful Purification (Priority -10):** Prevents log flooding and false-positive portscan detections in highly federated networks (CGNAT). Silently destroys late `FIN-ACK`/`RST` packets on expired `conntrack` sessions, and strictly drops invalid TCP connection noise (e.g., `NEW` packets lacking the `SYN` flag).
3. **Stateful Fast-Path (Priority 0):** Legitimate established connections, dynamic container traffic (e.g., `DOCKER-USER` chain), and Web Protocol Datagrams (HTTP/3 QUIC mapped to UDP/443) are prioritized. This stateful bypass guarantees zero latency for your production application traffic.
4. **Behavioral L7 Defense (HIPS):** The active defense layer analyzes application logs (via `systemd` journald) in real time. Any behavioral anomaly (brute-force, SQLi, LFI) triggers a surgical "AllPorts" ban that dynamically synchronizes the IP with the hardware drop tables.
5. **Default-Deny "Catch-All":** The attack surface is hermetically sealed. Any incoming traffic not explicitly authorized by the administrator or the automatic service discovery engine is silently dropped, enforcing a strict Default-Deny doctrine.

## Supported Operating Systems & Firewall Backends

SysWarden dynamically adapts to the native firewall orchestration engines of modern enterprise Linux distributions. The architecture relies on deep `systemd` integration and natively binds to the following ecosystems:

| Operating System | Native Firewall Engine(s) Supported | Status |
| :--- | :--- | :--- |
| **Debian 13 (Trixie)** | `nftables`, `iptables` | Enterprise Ready |
| **Debian 12 (Bookworm)** | `nftables`, `iptables` | Enterprise Ready |
| **Ubuntu 24.04+** | `ufw`, `nftables`, `iptables` | Enterprise Ready |
| **RHEL 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Rocky Linux 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **AlmaLinux 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Oracle Linux 10+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **CentOS Stream 9+** | `firewalld`, `nftables`, `iptables` | Enterprise Ready |
| **Fedora 40+** | `firewalld`, `nftables`, `iptables` | Production Ready |

## The "Fortress" Dashboard (TUI & CLI)

> [!NOTE]
> SysWarden provides unified terminal-based observability, ensuring total situational awareness without the bloat of a complex database (like ELK or InfluxDB) or exposing vulnerable web ports.

**Interactive TUI Dashboard**
* **Live Threat Telemetry:** Track L7 behavioral bans in real time directly from your console.
* **Attacker Profiling:** Visualize top OSINT offenders, blocked ASNs, and GeoIP interception stats, leveraging a secure, localized `data.json` engine.
* **Resource Monitoring:** Monitor the near-zero memory footprint of the underlying firewall engine.
* *(Fully integrated within the terminal to maintain a strict zero-trust attack surface without exposing port 9999).*

**Orchestration & Interactive CLI**
* **Terminal Management:** Manage your infrastructure directly from the shell via `syswarden-manager` (instant visibility into blocks, whitelists, and rule idempotency).
* **Structured Installation Logs:** The deployment process provides precise, color-coded visual feedback on OS hardening, SIEM integration, and the successful application of Default-Deny policies.

## Strategic Roadmap

> [!NOTE]
> The development lifecycle of SysWarden follows a strict DevSecOps pipeline aimed at reinforcing the observability and interoperability of the Default-Deny architecture.

| Version | Milestone Target | Status |
| :---: | :--- | :---: |
| **v0.36.0** | Attack Surface Reduction: Migration from Dashboard UI to isolated Terminal UI (TUI) via `syswarden tui`. | ✅ |
| **v0.37.0** | Enterprise SIEM Integration: Syslog output standardization for deterministic log ingestion. | ✅ |
| **v0.38.0** | Bugs hunting for FW | ✅ |
| **v0.39.0** | Bugs hunting for TUI | ✅ |
| **v0.40.0** | WebHook integration | ♨️ |

## Installation Guide

SysWarden is distributed as a pre-compiled, self-contained shell script. All complex modules are bundled into a single deployment artifact.

Two installation methods are supported: a standard interactive mode, and an "Enterprise Default-Deny" mode for environments requiring strict supply chain validation.

### 1. Quick Installation (Standard)

> [!IMPORTANT]
> Supported OS: *Debian 12+, Ubuntu 24.04+, RHEL 9+, Oracle Linux 10+, Fedora 43+, CentOS Stream, AlmaLinux 10+ & Rocky Linux 9+*.

```bash
# Clone the repository and enter the directory (as root)
cd /usr/local/bin
git clone https://github.com/duggytuxy/syswarden.git
cd syswarden || exit

# Make the builder executable and compile the artifact
chmod +x build.sh
./build.sh

# Navigate to the distribution folder and execute the installation
cd dist/ || exit
./install-syswarden.sh
```

### 2. Quick Installation (Package .deb & .rpm)

```bash
# Download the appropriate package for your distribution and its associated checksum file from the assets below
wget https://github.com/duggytuxy/syswarden/releases/download/<version>/*.deb
or
wget https://github.com/duggytuxy/syswarden/releases/download/<version>/*.rpm
and
wget https://github.com/duggytuxy/syswarden/releases/download/<version>/*.txt (SHA256SUMS)

# Verify Integrity
sha256sum -c SHA256SUMS.txt --ignore-missing

# For Debian/Ubuntu systems
apt-get install -y ./syswarden_<version>_all.deb

## Review or modify the auto-configuration file if needed before execution and install the solution
nano /opt/syswarden/syswarden-auto.conf
syswarden /opt/syswarden/syswarden-auto.conf

# For RHEL/AlmaLinux/Rocky systems
dnf install -y ./syswarden-<version>-1.noarch.rpm

## Review or modify the auto-configuration file if needed before execution and install the solution
nano /opt/syswarden/syswarden-auto.conf
syswarden /opt/syswarden/syswarden-auto.conf
```

### 3. Enterprise Installation (Default-Deny / SLSA Level 3)

SysWarden releases are cryptographically signed using GitHub Artifact Attestations to guarantee supply chain integrity. For environments compliant with ISO 27001 or NIS2, it is imperative to verify the script's provenance before execution.

```bash
# 1. Download the release bundle
cd /usr/local/bin
wget https://github.com/duggytuxy/syswarden/releases/latest/download/syswarden-release.tar.gz

# 2. Verify the cryptographic attestation using the official GitHub CLI
gh attestation verify syswarden-release.tar.gz --owner duggytuxy

# 3. If the verification is successful (exit code 0), extract and run
tar -xzf syswarden-release.tar.gz
chmod +x install-syswarden.sh
./install-syswarden.sh
```

### 4. Automated / Headless Deployment (CI/CD)

SysWarden can be deployed without any human interaction using a configuration file, ideal for Ansible, Terraform, or Cloud-init pipelines.

```bash
# Copy the configuration template to the distribution directory
cp syswarden-auto.conf dist/

# Navigate to the distribution directory
cd dist/ || exit

# Secure the configuration file permissions
chmod 600 syswarden-auto.conf (modify if needed)

# Execute the silent installation with root privileges
./install-syswarden.sh syswarden-auto.conf
```

### 5.Quick uninstall (root)

Properly uninstalls SysWarden while preserving your original, legitimate network settings.

```bash
./install-syswarden.sh uninstall
```

## Documentation

To learn everything about the SysWarden ecosystem, explore detailed configurations, and read advanced usage guides, visit our [official documentation page](https://github.com/duggytuxy/syswarden/wiki/Deployment-Tutorial)

## Target and support

> Goal: €5,000/year to fund continuous DevSecOps improvements and infrastructure.

Developing **SysWarden** and maintaining the zero-false-positive **Data-Shield IPv4 blocklists** requires dedicated server infrastructure and non-stop threat monitoring.

Reaching this annual goal guarantees my 100% independence, funding a continuous development cycle without corporate constraints. Your support directly pays for the servers and keeps these enterprise-grade cybersecurity tools free, updated, and accessible to everyone.

Let's build a safer internet together!

[![Support on Ko-Fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/laurentmduggytuxy)

## License

SysWarden is free and open-source software distributed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software in compliance with the license terms. [LICENSE](/LICENSE) file for more details.

*Developed and maintained by DuggyTuxy (Laurent M.).*
