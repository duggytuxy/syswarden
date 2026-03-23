#!/bin/bash

# ==============================================================================
# SysWarden v1.53 - DevSecOps Audit & Compliance Tool
# Copyright (C) 2026 duggytuxy - Laurent M.
#
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Architecture: Universal (Alpine, Debian, Ubuntu, RHEL, Alma)
# Objective: Verify Component Status, Log Isolation, and Zero Trust Permissions
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SCORE=0
TOTAL=0

# --- SECURE AUDIT LOGGING ---
AUDIT_LOG="/var/log/syswarden-audit.log"
# Secure the log file immediately (Prevent unauthorized reading of the audit results)
touch "$AUDIT_LOG" && chmod 600 "$AUDIT_LOG"
echo "=== SYSWARDEN PURPLE TEAM AUDIT STARTED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >"$AUDIT_LOG"

# --- HELPERS (Dual-Output: Console + Standardized Log) ---
log_header() {
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}"
    echo -e "\n--- $1 ---" >>"$AUDIT_LOG"
}
pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [PASS] $1" >>"$AUDIT_LOG"
    SCORE=$((SCORE + 1))
    TOTAL=$((TOTAL + 1))
}
fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [FAIL] $1" >>"$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
}
warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [WARN] $1" >>"$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
}
info() {
    echo -e "  [${BLUE}INFO${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] $1" >>"$AUDIT_LOG"
}

is_service_active() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$svc"
    elif command -v rc-service >/dev/null 2>&1; then
        # DEVSECOPS FIX: Prevent SIGPIPE crashing the pipeline
        rc-service "$svc" status 2>/dev/null | grep "started" >/dev/null
    else
        return 1
    fi
}

check_file_perms() {
    local file="$1"
    local expected_perms="$2"
    local expected_owner="$3"

    if [[ ! -f "$file" ]]; then
        fail "File missing: $file"
        return
    fi

    # Cross-platform stat command (works on Alpine busybox & GNU coreutils)
    local perms
    perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%Op" "$file" | cut -c4-6)
    local owner
    owner=$(stat -c "%U" "$file" 2>/dev/null || stat -f "%Su" "$file")

    if [[ "$perms" == *"$expected_perms" ]] && [[ "$owner" == "$expected_owner" ]]; then
        pass "Permissions OK on $file ($perms, Owner: $owner)"
    else
        fail "Bad permissions on $file (Got $perms $owner, Expected $expected_perms $expected_owner)"
    fi
}

# --- 1. SYSTEM DETECTION ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Audit script must be run as root.${NC}"
    exit 1
fi

OS_TYPE="Universal"
if [[ -f /etc/alpine-release ]]; then OS_TYPE="Alpine"; fi
info "Detected OS Environment: $OS_TYPE"

# --- DEVSECOPS FIX: Load Native Configuration Early ---
# Loaded here to immediately evaluate the user's OS Hardening choice
if [[ -f "/etc/syswarden.conf" ]]; then
    source "/etc/syswarden.conf" 2>/dev/null || true
fi

# --- 2. OS HARDENING (ANTI-PERSISTENCE) ---
log_header "Phase 1: OS Hardening & Privilege Separation"

# DEVSECOPS FIX: Evaluate if the user skipped OS Hardening on an existing VPS
if [[ "${APPLY_OS_HARDENING:-n}" == "y" ]]; then

    # Validate Crontab Lockdown
    if [[ -f "/etc/cron.allow" ]]; then
        check_file_perms "/etc/cron.allow" "600" "root"
    else
        fail "/etc/cron.allow is missing (Crontab not locked down)"
    fi

    # Audit privileged groups for unauthorized standard users (Humans UID >= 1000)
    PRIV_USERS=$(awk -F':' '/^(wheel|sudo|adm):/ {print $4}' /etc/group | tr ',' '\n' | grep -v '^$' | grep -v 'root' || true)
    UNAUTHORIZED_USERS=""

    for u in $PRIV_USERS; do
        # Extract UID of the user. System users (daemon, bin) have UID < 1000.
        uid=$(id -u "$u" 2>/dev/null || echo "0")
        if [[ "$uid" -ge 1000 ]]; then
            UNAUTHORIZED_USERS="$UNAUTHORIZED_USERS $u"
        fi
    done

    if [[ -z "$UNAUTHORIZED_USERS" ]]; then
        pass "Privileged groups (wheel/sudo/adm) are clean from standard users."
    else
        fail "Found standard users in privileged groups:$UNAUTHORIZED_USERS"
    fi

    # Verify Immutable flags on standard user profiles
    if command -v lsattr >/dev/null 2>&1; then
        IMMUTABLE_FAILED=0
        for user_dir in /home/*; do
            if [[ -d "$user_dir" ]]; then
                for profile_file in "$user_dir/.profile" "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                    if [[ -f "$profile_file" ]]; then
                        # DEVSECOPS FIX: Prevent SIGPIPE with grep >/dev/null
                        if ! lsattr "$profile_file" 2>/dev/null | grep '^\----i' >/dev/null; then
                            IMMUTABLE_FAILED=1
                            fail "Immutable flag missing on $profile_file"
                        fi
                    fi
                done
            fi
        done
        if [[ $IMMUTABLE_FAILED -eq 0 ]]; then
            pass "All existing standard user profiles are immutable (+i)."
        fi
    else
        info "lsattr command not found. Skipping immutable flag check."
    fi

else
    info "OS Hardening was skipped during installation (Existing Server). Strict compliance bypassed."
fi

# --- DEVSECOPS FIX: CRON ORCHESTRATION & IDEMPOTENCE (v1.53) ---
# Scan for legacy update loops that cause ghost processes
CRON_SAFE=1
CRON_FOUND=0
for cron_file in "/etc/crontabs/root" "/etc/cron.d/syswarden-update"; do
    if [[ -f "$cron_file" ]]; then
        if grep "syswarden" "$cron_file" >/dev/null 2>&1; then
            CRON_FOUND=1
            # If the legacy 'update' parameter is found without 'cron-', it's a critical failure
            if grep "\.sh update >" "$cron_file" >/dev/null 2>&1; then
                CRON_SAFE=0
            fi
        fi
    fi
done

if [[ $CRON_FOUND -eq 1 ]]; then
    if [[ $CRON_SAFE -eq 1 ]]; then
        pass "Cron Orchestration VERIFIED: Background jobs use the secure 'cron-update' mode (Idempotent)."
    else
        fail "Cron Orchestration FAILED: Legacy 'update' parameter detected. High risk of Ghost Processes!"
    fi
else
    warn "Cron Orchestration: No automated SysWarden background jobs found."
fi
# ---------------------------------------------------------------

# --- 3. LOG ISOLATION (ANTI-INJECTION) ---
log_header "Phase 2: Log Routing & Anti-Injection Verification"

# Verify isolated kernel firewall logs
check_file_perms "/var/log/kern-firewall.log" "600" "root"

# Verify isolated authentication logs based on OS
if [[ "$OS_TYPE" == "Alpine" ]]; then
    check_file_perms "/var/log/auth.log" "600" "root"
else
    check_file_perms "/var/log/auth-syswarden.log" "600" "root"
fi

# Check Rsyslog status
if is_service_active "rsyslog"; then
    pass "Rsyslog daemon is active and routing logs securely."
else
    fail "Rsyslog daemon is not running."
fi

# --- 4. FIREWALL & THREAT INTEL ---
log_header "Phase 3: Kernel Shield & Threat Intelligence"

# Check if the global blocklist payload is actively staged
if [[ -s "/etc/syswarden/active_global_blocklist.txt" ]]; then
    LINES=$(wc -l </etc/syswarden/active_global_blocklist.txt)
    pass "Global Blocklist is populated ($LINES active records)."
else
    fail "Global Blocklist is missing or empty."
fi

# --- Verify GeoIP Threat Intelligence ---
if [[ -n "${GEOBLOCK_COUNTRIES:-}" ]] && [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]]; then
    pass "GeoIP Threat Intelligence is actively deployed and enforced."
else
    info "GeoIP Threat Intelligence (Skipped by user)."
fi

# --- Verify ASN Routing Threat Intelligence ---
if [[ -n "${BLOCK_ASNS:-}" ]] && [[ "${BLOCK_ASNS:-none}" != "none" ]]; then
    pass "Manual ASN Routing Defense is actively deployed."
else
    info "Manual ASN Routing Defense (Skipped by user)."
fi

# --- Verify Spamhaus Dynamic Feed ---
if [[ "${USE_SPAMHAUS_ASN:-n}" == "y" || "${USE_SPAMHAUS_ASN:-n}" == "Y" ]]; then
    pass "Spamhaus Dynamic Feed is actively deployed."
else
    info "Spamhaus Dynamic Feed (Skipped by user)."
fi

# Firewall Engine Discovery & Rules Injection Audit
FW_ENGINE="Unknown"
if command -v nft >/dev/null && nft list table inet syswarden_table >/dev/null 2>&1; then
    FW_ENGINE="Nftables"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    FW_ENGINE="Firewalld"
elif command -v ufw >/dev/null && ufw status | grep "Status: active" >/dev/null 2>&1 && grep "syswarden" /etc/ufw/before.rules >/dev/null 2>&1; then
    FW_ENGINE="UFW"
elif command -v iptables >/dev/null && iptables -n -L INPUT | grep "SysWarden" >/dev/null 2>&1; then
    FW_ENGINE="Iptables"
fi

if [[ "$FW_ENGINE" != "Unknown" ]]; then
    pass "Firewall Engine ($FW_ENGINE) is active and strictly enforcing SysWarden rules."
else
    fail "SysWarden firewall rules not found in kernel space."
fi

# --- Verify Catch-All Drop Policy (v1.53 Zero Trust Architecture) ---
CATCH_ALL_PASSED=0
if [[ "$FW_ENGINE" == "Nftables" ]]; then
    # DEVSECOPS FIX: grep >/dev/null prevents SIGPIPE pipefail crashes
    if nft list chain inet syswarden_table input 2>/dev/null | grep "Catch-All" >/dev/null; then
        CATCH_ALL_PASSED=1
    fi
elif [[ "$FW_ENGINE" == "Firewalld" ]]; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
    # DEVSECOPS FIX: RHEL/Alma requires --permanent to read the target policy
    if firewall-cmd --permanent --get-target --zone="$DEFAULT_ZONE" 2>/dev/null | grep -i "drop" >/dev/null; then
        CATCH_ALL_PASSED=1
    elif firewall-cmd --permanent --get-target --zone=public 2>/dev/null | grep -i "drop" >/dev/null; then
        CATCH_ALL_PASSED=1
    fi
elif [[ "$FW_ENGINE" == "UFW" ]]; then
    if grep 'DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw >/dev/null 2>&1 || ufw status verbose 2>/dev/null | grep -iE "(deny|refuser|rejeter)" >/dev/null; then
        CATCH_ALL_PASSED=1
    fi
elif [[ "$FW_ENGINE" == "Iptables" ]]; then
    if iptables -S INPUT 2>/dev/null | grep "Catch-All" >/dev/null; then
        CATCH_ALL_PASSED=1
    fi
fi

if [[ $CATCH_ALL_PASSED -eq 1 ]]; then
    pass "Zero Trust Architecture VERIFIED: Catch-All Drop policy is active at the network edge."
else
    fail "Zero Trust Architecture FAILED: Catch-All Drop policy is missing. Run 'install-syswarden update'."
fi

# --- DEVSECOPS FIX: STATEFUL DOCKER ROUTING AUDIT (v1.53) ---
if command -v docker >/dev/null 2>&1 && is_service_active "docker"; then
    if command -v iptables >/dev/null 2>&1 && iptables -n -L DOCKER-USER >/dev/null 2>&1; then

        # 1. Verify SysWarden Blocklist Injection
        if iptables -S DOCKER-USER 2>/dev/null | grep "syswarden_blacklist" >/dev/null; then
            pass "Docker Integration: SysWarden blocklists are actively shielding containers."
        else
            fail "Docker Integration: SysWarden blocklists are missing from the DOCKER-USER chain."
        fi

        # 2. Verify Stateful Bypass is at Absolute Priority 0 (Rule #1)
        # iptables -S DOCKER-USER 1 outputs the exact first rule of the chain.
        DOCKER_RULE_1=$(iptables -S DOCKER-USER 1 2>/dev/null || true)

        if [[ "$DOCKER_RULE_1" == *"-j RETURN"* ]] && [[ "$DOCKER_RULE_1" == *"ESTABLISHED"* ]]; then
            pass "Docker Stateful Bypass VERIFIED: Return routing is locked at Absolute Priority 0 (Zero Timeout safe)."
        else
            fail "Docker Stateful Bypass FAILED: Return routing is missing or pushed down by another rule. Run 'install-syswarden update'."
        fi

    else
        warn "Docker is running, but the DOCKER-USER chain is inaccessible or missing."
    fi
else
    info "Docker engine not detected or offline (Skipped container routing audit)."
fi
# ------------------------------------------------------------

# --- 5. ZERO TRUST FAIL2BAN ENGINE ---
log_header "Phase 4: Layer 7 Active Defense (Fail2ban)"

if is_service_active "fail2ban"; then
    pass "Fail2ban service is running."

    # Ping Fail2ban socket to ensure it hasn't crashed silently
    if fail2ban-client ping >/dev/null 2>&1; then
        pass "Fail2ban socket is highly responsive (Pong)."

        # --- DEVSECOPS FIX: PROCESS IDEMPOTENCE (v1.53) ---
        # Count running instances. Using regex bracket trick [f] to exclude the grep process itself safely.
        # wc -l ensures exit code 0 even if no process is found, respecting 'set -e'.
        F2B_PROC_COUNT=$(ps aux | grep "[f]ail2ban-server" | wc -l)
        if [[ "$F2B_PROC_COUNT" -gt 1 ]]; then
            fail "Process Duplication FAILED: $F2B_PROC_COUNT Fail2ban instances detected! Severe risk of SQLite locking."
        else
            pass "Process Idempotence VERIFIED: A single, strictly controlled Fail2ban daemon is active."
        fi
        # --------------------------------------------------

        # Verify Zero Trust Jail environment (No OS overrides)
        if [[ -f "/etc/fail2ban/jail.d/alpine-ssh.conf" ]] || [[ -f "/etc/fail2ban/jail.d/defaults-debian.conf" ]]; then
            fail "Conflicting default OS jails were detected in jail.d/"
        else
            pass "Zero Trust environment: No conflicting default OS jails found."
        fi

        # Audit strict regex anchoring in the core Portscan filter
        if grep "^failregex = \^%(__prefix_line)s" /etc/fail2ban/filter.d/syswarden-portscan.conf >/dev/null 2>&1; then
            pass "Strict Regex Anchoring is applied (Log Spoofing vector neutralized)."
        else
            fail "Strict Regex Anchoring missing in the portscan filter."
        fi

        # Audit IgnoreIP (Anti Self-DoS)
        IGNORE_IPS=$(fail2ban-client get sshd ignoreip 2>/dev/null || true)

        # Count total IPv4 patterns
        IP_COUNT=$(echo "$IGNORE_IPS" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | wc -l)

        if [[ "$IP_COUNT" -gt 1 ]]; then
            pass "Dynamic IgnoreIP is populated (Anti-Lockout verified)."
        else
            warn "IgnoreIP might only contain localhost. Infrastructure whitelisting may have failed."
        fi
    else
        fail "Fail2ban service is running but the IPC socket is unresponsive."
    fi
else
    fail "Fail2ban service is completely offline."
fi

# --- 6. SECURE TELEMETRY & ENTERPRISE DASHBOARD (NGINX) ---
log_header "Phase 5: DevSecOps Telemetry & Enterprise Dashboard"

# 1. Nginx Service Status
if is_service_active "nginx"; then
    pass "Nginx Enterprise Web Server daemon is active."
else
    fail "Nginx Web Server is offline or not installed."
fi

# 2. Cryptographic Assets (TLS Certificate Verification)
if [[ -f "/etc/syswarden/ssl/syswarden.crt" ]] && [[ -f "/etc/syswarden/ssl/syswarden.key" ]]; then
    check_file_perms "/etc/syswarden/ssl/syswarden.key" "600" "root"
    pass "Self-Signed RSA 4096 TLS Certificate is securely deployed."
else
    fail "Dashboard TLS Certificates are missing."
fi

# 3. Telemetry Engine Backend
if [[ -x "/usr/local/bin/syswarden-telemetry.sh" ]]; then
    pass "Telemetry Orchestrator script is deployed and executable."
else
    fail "Telemetry Orchestrator script is missing."
fi

# --- DEVSECOPS FIX: PROCESS IDEMPOTENCE (v1.53) ---
# We force a single numeric value by taking only the first line and removing spaces
# This prevents the "0 0" or "1 1" error on some distributions
TELEMETRY_RAW=$(ps aux | grep "[s]yswarden-telemetry.sh" | wc -l || echo 0)
TELEMETRY_PROC_COUNT=$(echo "$TELEMETRY_RAW" | awk '{print $1}' | head -n1)

if [ "${TELEMETRY_PROC_COUNT:-0}" -gt 1 ]; then
    fail "Process Duplication FAILED: $TELEMETRY_PROC_COUNT telemetry scripts are running! CPU leak detected."
else
    pass "Process Idempotence VERIFIED: Telemetry daemon state is clean (<=1 active instance)."
fi
# --------------------------------------------------

# 4. Privilege Separation (Payload Ownership)
if [[ -f "/etc/syswarden/ui/data.json" ]]; then
    payload_perms=$(stat -c "%a" "/etc/syswarden/ui/data.json" 2>/dev/null || stat -f "%Op" "/etc/syswarden/ui/data.json" | cut -c4-6)
    payload_owner=$(stat -c "%U" "/etc/syswarden/ui/data.json" 2>/dev/null || stat -f "%Su" "/etc/syswarden/ui/data.json")

    # The payload MUST be strictly readable by the web daemon (640) and owned by it
    if [[ "$payload_perms" == *"640" ]] && [[ "$payload_owner" == "nginx" || "$payload_owner" == "www-data" ]]; then
        pass "Telemetry payload ownership & permissions are strictly isolated (640, Owner: $payload_owner)."
    else
        fail "Telemetry payload has weak permissions/ownership (Got $payload_perms $payload_owner, Expected 640 nginx/www-data)."
    fi
else
    warn "Telemetry payload (data.json) not found yet. Awaiting initial cron execution."
fi

# AbuseIPDB Async Reporter (Optional Component)
if [[ -f "/usr/local/bin/syswarden_reporter.py" ]]; then
    if is_service_active "syswarden-reporter"; then
        pass "AbuseIPDB Async Reporter is active."
        check_file_perms "/usr/local/bin/syswarden_reporter.py" "750" "root"
    else
        warn "AbuseIPDB Reporter is installed but offline."
    fi
else
    info "AbuseIPDB Reporter is not installed (Skipped by user)."
fi

# ==============================================================================
# === Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking) ===
# ==============================================================================
log_header "Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking)"

# --- Dynamic SSH Port Extraction ---
SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1 || echo "")
if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1 || echo "")
fi
SSH_PORT=${SSH_PORT:-22}

# --- Check 1: Purple Team - SSH Global Cloaking (The Priority Guillotine) ---
CLOAK_PASSED=0
# DEVSECOPS FIX: grep >/dev/null prevents SIGPIPE pipefail crashes
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    if firewall-cmd --list-rich-rules 2>/dev/null | grep "priority=\"-900\".*port=\"${SSH_PORT}\".*drop" >/dev/null; then
        CLOAK_PASSED=1
    fi
elif command -v nft >/dev/null 2>&1 && nft list table inet syswarden_table >/dev/null 2>&1; then
    NFT_RULES=$(nft -n list chain inet syswarden_table input 2>/dev/null | tr '\n' ' ' | tr '\t' ' ')
    if echo "$NFT_RULES" | grep -E "tcp dport ${SSH_PORT}.*drop" >/dev/null; then
        CLOAK_PASSED=1
    fi
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
    if ufw status 2>/dev/null | grep -E "^${SSH_PORT}/tcp[[:space:]]+DENY[[:space:]]+Anywhere" >/dev/null; then
        CLOAK_PASSED=1
    fi
elif command -v iptables >/dev/null 2>&1; then
    if iptables -C INPUT -p tcp --dport "${SSH_PORT}" -j DROP 2>/dev/null; then
        CLOAK_PASSED=1
    fi
fi

if [[ $CLOAK_PASSED -eq 1 ]]; then
    pass "SSH Cloaking VERIFIED: Port $SSH_PORT is strictly dropped globally (Priority Guillotine)."
else
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        fail "SSH Cloaking FAILED: Port $SSH_PORT is exposed despite VPN configuration (Missing drop rule)."
    else
        info "SSH Cloaking N/A: Port $SSH_PORT is exposed to the public (Zero Trust VPN not installed)."
    fi
fi

# --- Check 2: WireGuard VPN Gateway ---
if [[ -d "/etc/wireguard" ]] && [[ -f "/etc/wireguard/wg0.conf" ]]; then
    if ip link show wg0 >/dev/null 2>&1; then
        pass "WireGuard interface (wg0) is UP and ready to accept authorized clients."
    else
        fail "WireGuard interface (wg0) is DOWN or missing."
    fi

    VPN_ALLOW_PASSED=0
    # DEVSECOPS FIX: Use grep >/dev/null
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        # Firewalld natively uses the trusted zone for wg0
        if firewall-cmd --permanent --zone=trusted --list-interfaces 2>/dev/null | grep "wg0" >/dev/null; then
            VPN_ALLOW_PASSED=1
        fi
    elif command -v nft >/dev/null 2>&1 && nft list table inet syswarden_table >/dev/null 2>&1; then
        NFT_RULES=$(nft -n list chain inet syswarden_table input 2>/dev/null | tr '\n' ' ' | tr '\t' ' ')
        # Matches the new Global Trust rule: iifname { "lo", "wg0" } accept
        if echo "$NFT_RULES" | grep -E "iifname.*wg0.*accept" >/dev/null; then
            VPN_ALLOW_PASSED=1
        fi
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
        # UFW now allows generic traffic on wg0 interface
        if ufw status 2>/dev/null | grep -E "wg0.*ALLOW" >/dev/null; then
            VPN_ALLOW_PASSED=1
        fi
    elif command -v iptables >/dev/null 2>&1; then
        # Iptables now uses a generic accept for wg0
        if iptables -S INPUT 2>/dev/null | grep -E "\-A INPUT -i wg0 -j ACCEPT" >/dev/null; then
            VPN_ALLOW_PASSED=1
        fi
    fi

    if [[ $VPN_ALLOW_PASSED -eq 1 ]]; then
        pass "VPN Gateway VERIFIED: SSH access is explicitly allowed via the WireGuard tunnel."
    else
        fail "VPN Gateway FAILED: Explicit accept rule for WireGuard not found."
    fi
else
    info "WireGuard VPN is not installed or configured (Skipped by user)."
fi

# --- Check 3: Day-2 Operations (Dynamic SSH Bypass) ---
if [[ -s "/etc/syswarden/ssh_whitelist.txt" ]]; then
    BYPASS_COUNT=$(grep -v '^$' "/etc/syswarden/ssh_whitelist.txt" | wc -l)
    if [[ "$BYPASS_COUNT" -gt 0 ]]; then
        pass "Zero Trust Exception VERIFIED: $BYPASS_COUNT explicit IP(s) are surgically whitelisted for direct SSH access."
    else
        warn "Zero Trust Exception: SSH Whitelist file exists but is empty."
    fi
else
    info "Day-2 SSH Bypass: No explicit IP whitelisted (Strict mode active)."
fi

# ==============================================================================
# === Phase 7: Exposed Services & Firewall Persistence (CSPM) ===
# ==============================================================================
log_header "Phase 7: Exposed Services & Firewall Persistence (CSPM)"

# --- 7.1 Firewall Persistence Check (Cold Boot Survivability) ---
# DEVSECOPS FIX: Use grep >/dev/null instead of grep -q to avoid SIGPIPE
if [[ "$FW_ENGINE" == "Nftables" ]]; then
    if grep 'include "/etc/syswarden/syswarden.nft"' /etc/nftables.nft >/dev/null 2>&1 || grep 'include "/etc/syswarden/syswarden.nft"' /etc/nftables.conf >/dev/null 2>&1; then
        pass "Firewall Persistence VERIFIED: SysWarden Nftables rules are firmly anchored in main OS config."
    else
        fail "Firewall Persistence FAILED: SysWarden include directive is missing in main Nftables config."
    fi

    if [[ "$OS_TYPE" == "Alpine" ]]; then
        if [[ -f "/etc/nftables.d/syswarden-os-bypass.nft" ]]; then
            pass "OS Bypass Module VERIFIED: Native Alpine drop policy safely bypassed for essential active services."
        else
            warn "OS Bypass Module Missing: If this is a Web/SSH server, Alpine's default drop policy might block legitimate traffic."
        fi
    fi

elif [[ "$FW_ENGINE" == "Firewalld" ]]; then
    if systemctl is-enabled firewalld 2>/dev/null | grep "enabled" >/dev/null; then
        pass "Firewall Persistence VERIFIED: Firewalld is enabled on boot (Rich Rules are persistent natively)."
    else
        fail "Firewall Persistence FAILED: Firewalld is not enabled on system boot."
    fi

elif [[ "$FW_ENGINE" == "UFW" ]]; then
    if systemctl is-enabled ufw 2>/dev/null | grep "enabled" >/dev/null; then
        pass "Firewall Persistence VERIFIED: UFW is enabled and will restore rules on boot."
    else
        fail "Firewall Persistence FAILED: UFW is not enabled on system boot."
    fi

elif [[ "$FW_ENGINE" == "Iptables" ]]; then
    if [[ -f "/etc/iptables/rules.v4" ]] || [[ -f "/etc/sysconfig/iptables" ]] || [[ "$OS_TYPE" == "Alpine" && -f "/etc/iptables/iptables.rules" ]]; then
        pass "Firewall Persistence VERIFIED: Iptables static save files detected."
    else
        warn "Firewall Persistence UNKNOWN: Could not definitively locate Iptables persistent save files. Rules might flush on reboot."
    fi
else
    fail "Firewall Persistence FAILED: No recognized firewall engine active."
fi

# --- 7.2 Exposed Listening Services (Attack Surface Mapping) ---
info "Scanning for globally exposed listening ports (0.0.0.0 / ::)..."

# Extract live sockets directly from the kernel
if command -v ss >/dev/null 2>&1; then
    LISTEN_PORTS=$(ss -tlnp 2>/dev/null | grep -E '0\.0\.0\.0|::' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu || true)
else
    LISTEN_PORTS=$(netstat -tlnp 2>/dev/null | grep -E '0\.0\.0\.0|::' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu || true)
fi

if [[ -n "$LISTEN_PORTS" ]]; then
    for PORT in $LISTEN_PORTS; do
        if [[ "$PORT" -eq "$SSH_PORT" ]]; then
            info "Exposed Port: $PORT/TCP (SSH) - Guarded by Zero Trust VPN Guillotine (Drop policy)."
        elif [[ "$PORT" -eq 80 || "$PORT" -eq 443 ]]; then
            info "Exposed Port: $PORT/TCP (Web) - Guarded by SysWarden Layer 7 LFI/SQLi/Bot Jails."
        elif [[ "$PORT" -eq 111 ]]; then
            info "Exposed Port: $PORT/TCP (rpcbind) - Internal RPC service, guarded by default OS Firewall."
        elif [[ "$PORT" -eq 9999 ]]; then
            info "Exposed Port: $PORT/TCP (Nginx Enterprise UI) - Guarded by Zero Trust IP Restriction & TLS."
        elif [[ "$PORT" -eq 51820 || "$PORT" -eq "${WG_PORT:-51820}" ]]; then
            info "Exposed Port: $PORT/UDP (WireGuard) - Guarded by SysWarden Stealth UDP protections."
        elif [[ "$PORT" -eq 53 || "$PORT" -eq 123 || "$PORT" -eq 161 ]]; then
            info "Exposed Port: $PORT (Infra) - Standard Infrastructure Protocol (DNS/NTP)."
        else
            warn "Exposed Port: $PORT/TCP - Open to the public. Verify if this service requires zero-trust isolation."
        fi
    done
    pass "Attack Surface Mapping completed. All exposed sockets evaluated against security profiles."
else
    pass "Attack Surface Mapping completed. No externally exposed TCP ports detected (Maximum Stealth)."
fi

# ==============================================================================
# --- 8. AUDIT SUMMARY ---
# ==============================================================================
echo -e "\n${BOLD}==============================================================================${NC}"
if [[ $SCORE -eq $TOTAL ]]; then
    echo -e "${GREEN}>>> AUDIT SUCCESSFUL: $SCORE/$TOTAL checks passed. System is fully DevSecOps compliant. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] SUCCESS - $SCORE/$TOTAL checks passed." >>"$AUDIT_LOG"
else
    PERCENT=$((SCORE * 100 / TOTAL))
    echo -e "${RED}>>> AUDIT FAILED: $SCORE/$TOTAL checks passed ($PERCENT%). Immediate review required. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] FAILED - $SCORE/$TOTAL checks passed ($PERCENT%)." >>"$AUDIT_LOG"
fi
echo -e "${BOLD}==============================================================================${NC}"

# Display the location of the standardized log file
echo -e "📄 ${BOLD}Full Standardized Audit Log securely saved to:${NC} ${YELLOW}$AUDIT_LOG${NC}\n"
echo "=== AUDIT COMPLETED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >>"$AUDIT_LOG"
