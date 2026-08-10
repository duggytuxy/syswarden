package config

const DefaultConfig = `# ==============================================================================
# Version=v3.90.8
# SYSWARDEN UNATTENDED INSTALLATION CONFIGURATION
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Usage: syswarden config
# ==============================================================================

# ==========================================
# [1] SYSTEM & CORE
# ==========================================
# --- WAAP Enforcement Mode ---
# "enforcing" = Actively bans malicious IPs via Nftables/Iptables.
# "audit"     = Dry-Run/Shadow mode. Analyzes and logs threats [SIMULATED-BAN] without blocking.
SYSWARDEN_ENFORCEMENT_MODE="enforcing"

# --- Enterprise Compliance Mode ---
# y = Strictly disables third-party telemetry/reporting (e.g., AbuseIPDB) to comply with corporate policies.
SYSWARDEN_ENTERPRISE_MODE="n"

# --- Firewall Engine Optimization (RHEL/Alma/Fedora) ---
# If firewalld is detected, SYSWARDEN can replace it for extreme performance.
# "nftables" = Replace with pure Nftables (Recommended for massive blocklists)
# "iptables" = Replace with classic Iptables (Via iptables-services)
# "keep"     = Do not modify Firewalld (Warning: Reloads will be very slow)
SYSWARDEN_FIREWALL_BACKEND="nftables"

# --- OS Hardening ---
# y = Enable, n = Disable (Strict restrictions for privileged groups & Cron. Recommended for NEW servers only)
SYSWARDEN_HARDENING="y"

# Enable advanced CIS Benchmark Level 2 hardening (Defense-in-Depth)
# Recommended for exposed production servers, may restrict certain specific modules.
APPLY_CIS_L2_HARDENING="y"

# --- SSH Configuration ---
# Leave empty to auto-detect current active port
SYSWARDEN_SSH_PORT=""

# --- Security & Lifecycle Management ---
# y = Securely wipe this configuration file (shred) from disk after successful installation.
# MANDATORY for ISO 27001 compliance to prevent API keys from lingering in plaintext.
SYSWARDEN_SECURE_WIPE_CONF="n"


# ==========================================
# [2] ZERO-TRUST NETWORK CONTROLS
# ==========================================
# Auto-whitelist critical infrastructure (DNS, Gateway, DHCP, Cloud Metadata)
# Highly recommended to prevent server lockout when using aggressive ASN/GEO blocklists.
SYSWARDEN_WHITELIST_INFRA="y"

# Explicitly trust internal enterprise subnets to bypass L4 Catch-All rules.
# Space-separated list in CIDR format (Default: RFC1918)
SYSWARDEN_LAN_SUBNETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

# Space-separated list of IPv4/IPv6 addresses to automatically whitelist (e.g., "192.***.*.*** 203.*.***.***")
# Extremely useful for CI/CD, Ansible, or Cloud-init deployments to prevent admin lock-out.
SYSWARDEN_WHITELIST_IPS=""

# --- SaaS Monitors Auto-Whitelist ---
# y = Enable dynamic whitelisting for verified monitoring services (BetterStack, UptimeRobot, etc.)
# Highly recommended to prevent false positive bans triggered by frequent health checks.
SYSWARDEN_ALLOW_SAAS_MONITORS="y"

# --- Geo-Blocking ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_GEO="y"
# Space-separated country codes to DROP (e.g., "ru cn kp ir")
SYSWARDEN_GEO_CODES=""
# ZERO-TRUST MODE: Space-separated country codes to ALLOW. If defined, ALL OTHER COUNTRIES WILL BE DROPPED.
SYSWARDEN_GEO_ALLOWED=""

# --- ASN Blocking ---
# Enable the ASN blocking module
SYSWARDEN_ENABLE_ASN="y"
# Master List (VPNs, Proxies, Linode, Tor Exit Nodes/Bulletproof Hosters) to DROP
SYSWARDEN_ASN_LIST=""
# ZERO-TRUST MODE: Space-separated ASN codes to ALLOW. If defined, ALL OTHER ASNs WILL BE DROPPED.
SYSWARDEN_ASN_ALLOWED=""


# ==========================================
# [3] THREAT INTELLIGENCE & LISTS
# ==========================================
# 1 = Standard, 2 = Critical, 3 = Custom, 4 = None
SYSWARDEN_LIST_CHOICE="1"

# Include Spamhaus ASN-DROP list for known cybercriminal infrastructures
SYSWARDEN_USE_SPAMHAUS="n"

# If choice is 3, provide the URL below. MUST be HTTPS. HTTP schemes will be rejected.
SYSWARDEN_CUSTOM_URL=""
# Prevent supply chain poisoning: Provide the expected SHA256 hash of the custom list (Optional but recommended for NIS2)
SYSWARDEN_CUSTOM_HASH=""

# If choice is 3, provide the IPv6 URL below.
SYSWARDEN_CUSTOM_URL_IPV6=""
# Prevent supply chain poisoning: Provide the expected SHA256 hash of the custom IPv6 list
SYSWARDEN_CUSTOM_HASH_IPV6=""


# ==========================================
# [4] WAAP L7 ENGINE & LOGS
# ==========================================
# Space-separated list of application access logs to tail (e.g., Traefik, Nginx, Apache)
# SYSWARDEN will natively parse these files in real-time to detect advanced exploits (SQLi, XSS, RCE, LFI)
# and automatically track HTTP 401/403/404 bruteforce thresholds.
# Use "auto" to automatically discover Nginx, Apache, Caddy, Traefik, or HTTPD logs.
# Leave empty ("") to completely disable the L7 WAAP Engine.
SYSWARDEN_BRUTEFORCE_LOGS="auto"
# Number of authentication failures/forbidden errors allowed before an IP is banned at L3
SYSWARDEN_BRUTEFORCE_THRESHOLD="5"
# Sliding window in seconds for the threshold
SYSWARDEN_BRUTEFORCE_WINDOW="60"

# --- Docker Multi-Tenant WAF Integration ---
# Wildcard path to aggregate logs from all external WAF containers (Self-DoS prevention & Multi-tenant)
# Crucial for multi-tenant architectures (e.g., Traefik + Multiple ModSecurity WAFs)
# Leave empty for standard single-node installations
SYSWARDEN_MODSEC_LOGS="/var/log/modsec/*.log"


# ==========================================
# [5] INTRUSION DETECTION & L2
# ==========================================
# --- Honeyports (Insider Threat / PrivEsc Detection) ---
# Active ONLY if SYSWARDEN_LAN_MODE="y" or manually verified.
# SYSWARDEN natively blocks and traces any connection attempt to these ports as a malicious Lateral Movement.
SYSWARDEN_HONEYPORTS="6379,23"

# --- Local Network & L2 Protection ---
# Enable OSI Layer 2 ARP Spoofing Prevention
SYSWARDEN_ENABLE_L2="y"
# Enable 500req/sec ARP Flood limits (Enterprise LAN adjusted)
SYSWARDEN_ARP_PROTECT="y"
# Enable Local LAN Mode to save RAM by skipping global OSINT downloads
SYSWARDEN_LAN_MODE="n"


# ==========================================
# [6] HIGH AVAILABILITY & VPN
# ==========================================
# --- HA Cluster Sync ---
# y = Enable, n = Disable (Replicates state to a standby node over encrypted channels)
SYSWARDEN_HA_ENABLED="y"
# HA Shared Secret Token for API Authentication (Must be identical on all nodes)
SYSWARDEN_HA_TOKEN=""
# Standby NODE IP (Automatically whitelisted for TLS P2P API)
SYSWARDEN_HA_PEER_IP=""
# Standby NODE TLS Port
SYSWARDEN_HA_PEER_PORT="62026"

# --- WireGuard Management VPN ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_WG="n"
SYSWARDEN_WG_PORT="51820"
SYSWARDEN_WG_SUBNET="10.66.66.0/24"


# ==========================================
# [7] WEB-TUI DASHBOARD
# ==========================================
# Secure token for Web-TUI authentication. Generated automatically by 'syswarden web-token' if empty.
SYSWARDEN_WEB_TOKEN=""

# ==========================================
# [8] SIEM & EXTERNAL INTEGRATIONS
# ==========================================
# --- SIEM Log Forwarding (ISO 27001 / NIS2 COMPLIANT) ---
# y = Enable, n = Disable (Forwards attack logs to an external SIEM via Rsyslog)
SYSWARDEN_SIEM_ENABLED="n"
SYSWARDEN_SIEM_IP=""
SYSWARDEN_SIEM_PORT="6514"
# REQUIRED FOR COMPLIANCE: "tls" is highly recommended over standard "tcp" or "udp"
SYSWARDEN_SIEM_PROTO="tls"
# Path to the CA certificate for mutual TLS (mTLS) or server validation
SYSWARDEN_SIEM_TLS_CA="/etc/ssl/certs/ca-certificates.crt"

# --- AbuseIPDB Reporting ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_ABUSE="n"
SYSWARDEN_ABUSE_API_KEY=""

# --- WebHook Notifications (Discord / Teams / Slack) ---
# y = Enable, n = Disable (Sends L7/WAF ban events to a Webhook)
SYSWARDEN_ENABLE_WEBHOOK="n"
SYSWARDEN_WEBHOOK_URL_DISCORD=""
SYSWARDEN_WEBHOOK_URL_TEAMS=""
SYSWARDEN_WEBHOOK_URL_SLACK=""

# --- Wazuh Agent ---
# y = Enable, n = Disable
SYSWARDEN_ENABLE_WAZUH="n"
SYSWARDEN_WAZUH_IP=""
SYSWARDEN_WAZUH_NAME=""
SYSWARDEN_WAZUH_GROUP="default"
SYSWARDEN_WAZUH_COMM_PORT="1514"
SYSWARDEN_WAZUH_ENROLL_PORT="1515"
`
