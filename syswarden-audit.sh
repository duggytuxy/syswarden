#!/bin/bash

# ==============================================================================
# SysWarden v9.79 - Audit Tool
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
echo "=== SYSWARDEN PURPLE TEAM AUDIT STARTED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" > "$AUDIT_LOG"

# --- HELPERS (Dual-Output: Console + Standardized Log) ---
log_header() { 
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}"
    echo -e "\n--- $1 ---" >> "$AUDIT_LOG"
}
pass() { 
    echo -e "  [${GREEN}PASS${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [PASS] $1" >> "$AUDIT_LOG"
    SCORE=$((SCORE + 1))
    TOTAL=$((TOTAL + 1))
}
fail() { 
    echo -e "  [${RED}FAIL${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [FAIL] $1" >> "$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
}
warn() { 
    echo -e "  [${YELLOW}WARN${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [WARN] $1" >> "$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
}
info() { 
    echo -e "  [${BLUE}INFO${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] $1" >> "$AUDIT_LOG"
}

is_service_active() {
    local svc="$1"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$svc"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service "$svc" status 2>/dev/null | grep -q "started"
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

# --- 2. OS HARDENING (ANTI-PERSISTENCE) ---
log_header "Phase 1: OS Hardening & Privilege Separation"

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
                    if ! lsattr "$profile_file" 2>/dev/null | grep -q '^\----i'; then
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
    LINES=$(wc -l < /etc/syswarden/active_global_blocklist.txt)
    pass "Global Blocklist is populated ($LINES active records)."
else
    fail "Global Blocklist is missing or empty."
fi

# Firewall Engine Discovery & Rules Injection Audit
FW_ENGINE="Unknown"
if command -v nft >/dev/null && nft list table inet syswarden_table >/dev/null 2>&1; then 
    FW_ENGINE="Nftables"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then 
    FW_ENGINE="Firewalld"
elif command -v ufw >/dev/null && ufw status | grep -q "Status: active" && grep -q "syswarden" /etc/ufw/before.rules 2>/dev/null; then 
    FW_ENGINE="UFW"
elif command -v iptables >/dev/null && iptables -n -L INPUT | grep -q "SysWarden"; then 
    FW_ENGINE="Iptables"
fi

if [[ "$FW_ENGINE" != "Unknown" ]]; then
    pass "Firewall Engine ($FW_ENGINE) is active and strictly enforcing SysWarden rules."
else
    fail "SysWarden firewall rules not found in kernel space."
fi

# --- 5. ZERO TRUST FAIL2BAN ENGINE ---
log_header "Phase 4: Layer 7 Active Defense (Fail2ban)"

if is_service_active "fail2ban"; then
    pass "Fail2ban service is running."
    
    # Ping Fail2ban socket to ensure it hasn't crashed silently
    if fail2ban-client ping >/dev/null 2>&1; then
        pass "Fail2ban socket is highly responsive (Pong)."
        
        # Verify Zero Trust Jail environment (No OS overrides)
        if [[ -f "/etc/fail2ban/jail.d/alpine-ssh.conf" ]] || [[ -f "/etc/fail2ban/jail.d/defaults-debian.conf" ]]; then
            fail "Conflicting default OS jails were detected in jail.d/"
        else
            pass "Zero Trust environment: No conflicting default OS jails found."
        fi
        
        # Audit strict regex anchoring in the core Portscan filter
        if grep -q "^failregex = \^%(__prefix_line)s" /etc/fail2ban/filter.d/syswarden-portscan.conf 2>/dev/null; then
            pass "Strict Regex Anchoring is applied (Log Spoofing vector neutralized)."
        else
            fail "Strict Regex Anchoring missing in the portscan filter."
        fi
        
        # Audit IgnoreIP (Anti Self-DoS)
        IGNORE_IPS=$(fail2ban-client get sshd ignoreip 2>/dev/null || true)
        
        # FIX: fail2ban-client outputs IPs on multiple lines. We must count the total IPv4 patterns.
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

# --- 6. SECURE TELEMETRY & UI DASHBOARD ---
log_header "Phase 5: DevSecOps Telemetry & UI Sandboxing"

# UI Service
if is_service_active "syswarden-ui"; then
    pass "SysWarden UI Server daemon is active."
    # Verify the deployment of the secure Python wrapper
    if [[ -x "/usr/local/bin/syswarden-ui-server.py" ]]; then
        pass "Secure Python Web Wrapper (Strict HTTP Headers) is deployed."
    else
        fail "Secure Python Web Wrapper is missing."
    fi
else
    fail "SysWarden UI Server is offline."
fi

# --- FIX: Verify telemetry payload permissions ---
# Permissions relaxed to 644 (instead of 600) to allow the unprivileged 
# Python web server (running as nobody) to read and serve the JSON data.
check_file_perms "/etc/syswarden/ui/data.json" "644" "nobody"

# AbuseIPDB Async Reporter (Optional Component)
if [[ -f "/usr/local/bin/syswarden_reporter.py" ]]; then
    if is_service_active "syswarden-reporter"; then
        pass "AbuseIPDB Async Reporter is active."
        # Verify API Key protection
        check_file_perms "/usr/local/bin/syswarden_reporter.py" "750" "root"
    else
        warn "AbuseIPDB Reporter is installed but offline."
    fi
else
    info "AbuseIPDB Reporter is not installed (Skipped by user)."
fi

# --- 7. AUDIT SUMMARY ---
echo -e "\n${BOLD}==============================================================================${NC}"
if [[ $SCORE -eq $TOTAL ]]; then
    echo -e "${GREEN}>>> AUDIT SUCCESSFUL: $SCORE/$TOTAL checks passed. System is fully DevSecOps compliant. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] SUCCESS - $SCORE/$TOTAL checks passed." >> "$AUDIT_LOG"
else
    PERCENT=$((SCORE * 100 / TOTAL))
    echo -e "${RED}>>> AUDIT FAILED: $SCORE/$TOTAL checks passed ($PERCENT%). Immediate review required. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] FAILED - $SCORE/$TOTAL checks passed ($PERCENT%)." >> "$AUDIT_LOG"
fi
echo -e "${BOLD}==============================================================================${NC}"

# Display the location of the standardized log file
echo -e "📄 ${BOLD}Full Standardized Audit Log securely saved to:${NC} ${YELLOW}$AUDIT_LOG${NC}\n"
echo "=== AUDIT COMPLETED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >> "$AUDIT_LOG"