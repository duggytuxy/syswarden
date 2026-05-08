#!/bin/bash

# ==============================================================================
# SysWarden v0.29.5 - DevSecOps Audit & Compliance Tool
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
# Architecture: Universal (Alpine, Debian, Ubuntu, RHEL, Alma, Slackware)
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
touch "$AUDIT_LOG" && chmod 600 "$AUDIT_LOG"
echo "=== SYSWARDEN PURPLE TEAM AUDIT STARTED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >"$AUDIT_LOG"

# --- HELPERS (Dual-Output: Console + Standardized Log + 2s Pacing) ---
log_header() {
    echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}"
    echo -e "\n--- $1 ---" >>"$AUDIT_LOG"
    sleep 1
}
pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [PASS] $1" >>"$AUDIT_LOG"
    SCORE=$((SCORE + 1))
    TOTAL=$((TOTAL + 1))
    sleep 2
}
fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [FAIL] $1" >>"$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
    sleep 2
}
warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [WARN] $1" >>"$AUDIT_LOG"
    TOTAL=$((TOTAL + 1))
    sleep 2
}
info() {
    echo -e "  [${BLUE}INFO${NC}] $1"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [INFO] $1" >>"$AUDIT_LOG"
    sleep 2
}

# --- HOTFIX: SLACKWARE NATIVE PROCESS DETECTION ---
is_service_active() {
    local svc="$1"
    if [[ "$OS_TYPE" == "Slackware" ]]; then
        case "$svc" in
            rsyslog | syslog | syslogd) ps -ef 2>/dev/null | grep "[s]yslogd\|[r]syslogd" >/dev/null ;;
            fail2ban) ps -ef 2>/dev/null | grep "[f]ail2ban-server" >/dev/null ;;
            nginx) ps -ef 2>/dev/null | grep "[n]ginx" >/dev/null ;;
            syswarden-reporter) ps -ef 2>/dev/null | grep "[s]yswarden_reporter.py" >/dev/null ;;
            docker) ps -ef 2>/dev/null | grep "[d]ockerd" >/dev/null ;;
            *) return 1 ;;
        esac
        return $?
    elif command -v systemctl >/dev/null 2>&1; then
        systemctl is-active --quiet "$svc"
    elif command -v rc-service >/dev/null 2>&1; then
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

# ==============================================================================
# --- 1. SYSTEM DETECTION & GLOBAL VARIABLES ---
# ==============================================================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: Audit script must be run as root.${NC}"
    exit 1
fi

OS_TYPE="Universal"
if [[ -f /etc/alpine-release ]]; then OS_TYPE="Alpine"; fi
if [[ -f /etc/slackware-version ]]; then OS_TYPE="Slackware"; fi
info "Detected OS Environment: $OS_TYPE"

if [[ -f "/etc/syswarden.conf" ]]; then
    source "/etc/syswarden.conf" 2>/dev/null || true
fi

# Pre-detect Firewall Engine globally to prevent crashes in partial audits
FW_ENGINE="Unknown"
if command -v nft >/dev/null && { nft list table inet syswarden_table >/dev/null 2>&1 || nft list table netdev syswarden_hw_drop >/dev/null 2>&1; }; then
    FW_ENGINE="Nftables"
elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    FW_ENGINE="Firewalld"
elif command -v ufw >/dev/null && ufw status | grep "Status: active" >/dev/null 2>&1 && grep "syswarden" /etc/ufw/before.rules >/dev/null 2>&1; then
    FW_ENGINE="UFW"
elif command -v iptables >/dev/null && { iptables -t raw -n -L PREROUTING 2>/dev/null | grep "SysWarden" >/dev/null 2>&1 || iptables -n -L INPUT | grep "SysWarden" >/dev/null 2>&1; }; then
    FW_ENGINE="Iptables"
fi

# Pre-detect SSH Port globally
SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1 || echo "")
if [[ -z "$SSH_PORT" ]]; then
    SSH_PORT=$(netstat -tlnp 2>/dev/null | grep sshd | awk '{print $4}' | awk -F':' '{print $NF}' | head -n 1 || echo "")
fi
SSH_PORT=${SSH_PORT:-22}
CLOAK_PASSED=0 # Default to 0 for downstream phases

# ==============================================================================
# --- DEVSECOPS: AUDIT EXECUTION MODE (Interactive Menu) ---
# ==============================================================================
RUN_ALL=0
USER_PHASES=""

echo -e "\n${BOLD}==============================================================================${NC}"
echo -e "${BLUE} SysWarden DevSecOps Audit - Execution Mode${NC}"
echo -e "${BOLD}==============================================================================${NC}"
echo -e "  1) Complete Audit Scan (All Phases 1-8)"
echo -e "  2) Custom Audit Scan (Select multiple specific phases)"
echo -e "${BOLD}==============================================================================${NC}"

# Strict Input Validation Loop
while true; do
    read -rp "Select an option [1-2]: " AUDIT_MODE
    if [[ "$AUDIT_MODE" =~ ^[1-2]$ ]]; then
        break
    else
        echo -e "${RED}Invalid selection. Please enter 1 or 2.${NC}"
    fi
done

if [[ "$AUDIT_MODE" == "1" ]]; then
    RUN_ALL=1
    echo -e "${GREEN}>>> Initializing Complete Audit Scan... <<<${NC}\n"
elif [[ "$AUDIT_MODE" == "2" ]]; then
    echo -e "\n${YELLOW}Select the specific phases you want to audit:${NC}"
    echo -e "  1) Phase 1: OS Hardening & Privilege Separation"
    echo -e "  2) Phase 2: Log Routing & Anti-Injection Verification"
    echo -e "  3) Phase 3: Kernel Shield & Threat Intelligence"
    echo -e "  4) Phase 4: Layer 7 Active Defense (Fail2ban)"
    echo -e "  5) Phase 5: DevSecOps Telemetry & Enterprise Dashboard"
    echo -e "  6) Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking)"
    echo -e "  7) Phase 7: Exposed Services & Firewall Persistence (CSPM)"
    echo -e "  8) Phase 8: Enterprise SOC & High Availability (HA Cluster)"
    echo -e "  9) Phase 9: Ghost Rules & Firewall Idempotency (Anti-Duplication)"
    echo ""

    # Strict Input Validation Loop for Multiple Phases
    while true; do
        read -rp "Enter phase numbers separated by space (e.g., 1 3 9): " RAW_PHASES

        # Sanitize input
        CLEAN_PHASES=$(echo "$RAW_PHASES" | tr ',' ' ' | tr -s ' ')

        # Regex validation
        if [[ "$CLEAN_PHASES" =~ ^[1-9\ ]+$ ]]; then
            if [[ -n "${CLEAN_PHASES// /}" ]]; then
                USER_PHASES=" $CLEAN_PHASES "
                break
            fi
        fi
        echo -e "${RED}Invalid input. Please enter valid phase numbers (1-8) separated by spaces.${NC}"
    done

    DISPLAY_PHASES=$(echo "$CLEAN_PHASES" | tr ' ' '\n' | sort -nu | tr '\n' ' ' | sed 's/ $//')
    echo -e "${GREEN}>>> Initializing Custom Audit Scan (Phases: $DISPLAY_PHASES)... <<<${NC}\n"
fi

# ==============================================================================
# --- Phase 1: OS Hardening & Privilege Separation ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 1 "* ]]; then
    log_header "Phase 1: OS Hardening & Privilege Separation"

    if [[ "${APPLY_OS_HARDENING:-n}" == "y" ]]; then

        # HOTFIX: OS-Specific Cron Allow Path
        if [[ "$OS_TYPE" == "Slackware" ]]; then
            if [[ -f "/var/spool/cron/cron.allow" ]]; then
                check_file_perms "/var/spool/cron/cron.allow" "600" "root"
            else
                fail "/var/spool/cron/cron.allow is missing (Crontab not locked down)"
            fi
        else
            if [[ -f "/etc/cron.allow" ]]; then
                check_file_perms "/etc/cron.allow" "600" "root"
            else
                fail "/etc/cron.allow is missing (Crontab not locked down)"
            fi
        fi

        PRIV_USERS=$(awk -F':' '/^(wheel|sudo|adm):/ {print $4}' /etc/group | tr ',' '\n' | grep -v '^$' | grep -v 'root' || true)
        UNAUTHORIZED_USERS=""

        for u in $PRIV_USERS; do
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

        if command -v lsattr >/dev/null 2>&1; then
            IMMUTABLE_FAILED=0
            for user_dir in /home/*; do
                if [[ -d "$user_dir" ]]; then
                    for profile_file in "$user_dir/.profile" "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                        if [[ -f "$profile_file" ]]; then
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

    CRON_SAFE=1
    CRON_COUNT=0
    SEEN_CRON_FILES=""

    for cron_file in "/etc/crontabs/root" "/var/spool/cron/crontabs/root" "/etc/cron.d/syswarden-update"; do
        if [[ -f "$cron_file" ]]; then
            real_path=$(realpath "$cron_file" 2>/dev/null || readlink -f "$cron_file" 2>/dev/null || echo "$cron_file")
            if echo "$SEEN_CRON_FILES" | grep -q "$real_path"; then continue; fi
            SEEN_CRON_FILES="$SEEN_CRON_FILES $real_path"

            file_count=$(grep -v "^[[:space:]]*#" "$cron_file" 2>/dev/null | { grep -c "syswarden.*update" || true; })
            CRON_COUNT=$((CRON_COUNT + file_count))

            if grep -v "^[[:space:]]*#" "$cron_file" 2>/dev/null | grep "\.sh update >" >/dev/null 2>&1; then
                CRON_SAFE=0
            fi
        fi
    done

    if [[ $CRON_COUNT -eq 1 ]]; then
        if [[ $CRON_SAFE -eq 1 ]]; then
            pass "Cron Orchestration VERIFIED: Exactly one secure 'cron-update' background job is active (Absolute cleanliness)."
        else
            fail "Cron Orchestration FAILED: Legacy 'update' parameter detected. High risk of Ghost Processes!"
        fi
    elif [[ $CRON_COUNT -gt 1 ]]; then
        fail "Cron Duplication FAILED: $CRON_COUNT SysWarden cron jobs detected! Idempotency violated."
    else
        warn "Cron Orchestration: No automated SysWarden background jobs found."
    fi
fi

# ==============================================================================
# --- Phase 2: Log Routing & Anti-Injection Verification ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 2 "* ]]; then
    log_header "Phase 2: Log Routing & Anti-Injection Verification"

    check_file_perms "/var/log/kern-firewall.log" "600" "root"

    if [[ "$OS_TYPE" == "Alpine" ]]; then
        check_file_perms "/var/log/auth.log" "600" "root"
    else
        check_file_perms "/var/log/auth-syswarden.log" "600" "root"
    fi

    # HOTFIX: Support for native syslogd on Slackware
    if [[ "$OS_TYPE" == "Slackware" ]]; then
        if is_service_active "syslog"; then
            pass "Syslogd daemon (Native Slackware) is active and routing logs securely."
        else
            fail "Syslogd daemon is not running."
        fi
    else
        if is_service_active "rsyslog"; then
            pass "Rsyslog daemon is active and routing logs securely."
        else
            fail "Rsyslog daemon is not running."
        fi
    fi
fi

# ==============================================================================
# --- Phase 3: Kernel Shield & Threat Intelligence ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 3 "* ]]; then
    log_header "Phase 3: Kernel Shield & Threat Intelligence"

    if [[ -s "/etc/syswarden/active_global_blocklist.txt" ]]; then
        LINES=$(wc -l </etc/syswarden/active_global_blocklist.txt)
        pass "Global Blocklist is populated ($LINES active records)."
    else
        fail "Global Blocklist is missing or empty."
    fi

    if [[ -n "${GEOBLOCK_COUNTRIES:-}" ]] && [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]]; then
        pass "GeoIP Threat Intelligence is actively deployed and enforced."
    else
        info "GeoIP Threat Intelligence (Skipped by user)."
    fi

    if [[ -n "${BLOCK_ASNS:-}" ]] && [[ "${BLOCK_ASNS:-none}" != "none" ]]; then
        pass "Manual ASN Routing Defense is actively deployed."
    else
        info "Manual ASN Routing Defense (Skipped by user)."
    fi

    if [[ "${USE_SPAMHAUS_ASN:-n}" == "y" || "${USE_SPAMHAUS_ASN:-n}" == "Y" ]]; then
        pass "Spamhaus Dynamic Feed is actively deployed."
    else
        info "Spamhaus Dynamic Feed (Skipped by user)."
    fi

    if [[ "$FW_ENGINE" != "Unknown" ]]; then
        pass "Firewall Engine ($FW_ENGINE) is active and strictly enforcing SysWarden rules."

        if [[ "$FW_ENGINE" == "Nftables" ]]; then
            # FIX: Double incr. removed
            if nft list table netdev syswarden_hw_drop >/dev/null 2>&1; then
                pass "Nftables Layer 2 Hardware Acceleration (netdev syswarden_hw_drop) is ACTIVE."
            else
                fail "Nftables Layer 2 Hardware Acceleration is MISSING or failed to load."
            fi
        elif [[ "$FW_ENGINE" == "Iptables" ]]; then
            # FIX: Double incr. removed
            if iptables -t raw -n -L PREROUTING 2>/dev/null | grep -q "SysWarden-BLOCK"; then
                pass "IPtables Layer 3 Pre-Routing (table raw) IPS acceleration is ACTIVE."
            else
                warn "IPtables is active but using slower Layer 3 INPUT instead of Pre-Routing."
            fi
        fi
    else
        fail "SysWarden firewall rules not found in kernel space."
    fi

    CATCH_ALL_PASSED=0
    if [[ "$FW_ENGINE" == "Nftables" ]]; then
        if nft list chain inet syswarden_table input_backend 2>/dev/null | grep "Catch-All" >/dev/null; then
            CATCH_ALL_PASSED=1
        elif [[ "$OS_TYPE" == "Alpine" ]] && nft list chain inet filter input 2>/dev/null | grep -E "policy[[:space:]]+drop" >/dev/null; then
            CATCH_ALL_PASSED=1
        elif nft list chain inet syswarden_table input 2>/dev/null | grep "Catch-All" >/dev/null; then
            CATCH_ALL_PASSED=1
        fi
    elif [[ "$FW_ENGINE" == "Firewalld" ]]; then
        DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
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

    if command -v docker >/dev/null 2>&1 && is_service_active "docker"; then
        if command -v iptables >/dev/null 2>&1 && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            if iptables -S DOCKER-USER 2>/dev/null | grep "syswarden_blacklist" >/dev/null; then
                pass "Docker Integration: SysWarden blocklists are actively shielding containers."
            else
                fail "Docker Integration: SysWarden blocklists are missing from the DOCKER-USER chain."
            fi

            DOCKER_RULE_1=$(iptables -S DOCKER-USER 1 2>/dev/null || true)
            if [[ "$DOCKER_RULE_1" == *"-j RETURN"* ]] && [[ "$DOCKER_RULE_1" == *"ESTABLISHED"* ]]; then
                pass "Docker Stateful Bypass VERIFIED: Return routing is locked at Absolute Priority 0."
            else
                fail "Docker Stateful Bypass FAILED: Return routing is missing or pushed down by another rule."
            fi
        else
            warn "Docker is running, but the DOCKER-USER chain is inaccessible or missing."
        fi
    else
        info "Docker engine not detected or offline (Skipped container routing audit)."
    fi
fi

# ==============================================================================
# --- Phase 4: Layer 7 Active Defense (Fail2ban) ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 4 "* ]]; then
    log_header "Phase 4: Layer 7 Active Defense (Fail2ban)"

    if is_service_active "fail2ban"; then
        pass "Fail2ban service is running."

        if fail2ban-client ping >/dev/null 2>&1; then
            pass "Fail2ban socket is highly responsive (Pong)."

            F2B_PROC_COUNT=$(ps aux | grep "[f]ail2ban-server" | wc -l)
            if [[ "$F2B_PROC_COUNT" -gt 1 ]]; then
                fail "Process Duplication FAILED: $F2B_PROC_COUNT Fail2ban instances detected! Severe risk of SQLite locking."
            else
                pass "Process Idempotence VERIFIED: A single, strictly controlled Fail2ban daemon is active."
            fi

            if [[ -f "/etc/fail2ban/jail.d/alpine-ssh.conf" ]] || [[ -f "/etc/fail2ban/jail.d/defaults-debian.conf" ]]; then
                fail "Conflicting default OS jails were detected in jail.d/"
            else
                pass "Zero Trust environment: No conflicting default OS jails found."
            fi

            if grep "^failregex = \^%(__prefix_line)s" /etc/fail2ban/filter.d/syswarden-portscan.conf >/dev/null 2>&1; then
                pass "Strict Regex Anchoring is applied (Log Spoofing vector neutralized)."
            else
                fail "Strict Regex Anchoring missing in the portscan filter."
            fi

            # --- PURPLE TEAM / MODSECURITY CHECK ---
            if [[ -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]]; then
                if fail2ban-client status 2>/dev/null | grep -q "syswarden-modsec"; then
                    pass "Purple Team Integration VERIFIED: ModSecurity WAF jail (syswarden-modsec) is active."
                else
                    fail "Purple Team Integration FAILED: ModSecurity filter exists but jail is inactive."
                fi
            else
                info "Purple Team Integration N/A: ModSecurity WAF not detected."
            fi

            IGNORE_IPS=$(fail2ban-client get sshd ignoreip 2>/dev/null || true)
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
fi

# ==============================================================================
# --- Phase 5: DevSecOps Telemetry & Enterprise Dashboard ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 5 "* ]]; then
    log_header "Phase 5: DevSecOps Telemetry & Enterprise Dashboard"

    if is_service_active "nginx"; then
        pass "Nginx Enterprise Web Server daemon is active."
    else
        fail "Nginx Web Server is offline or not installed."
    fi

    if [[ -f "/etc/syswarden/ssl/syswarden.crt" ]] && [[ -f "/etc/syswarden/ssl/syswarden.key" ]]; then
        check_file_perms "/etc/syswarden/ssl/syswarden.key" "600" "root"
        pass "Self-Signed RSA 4096 TLS Certificate is securely deployed."
    else
        fail "Dashboard TLS Certificates are missing."
    fi

    if [[ -x "/usr/local/bin/syswarden-telemetry.sh" ]]; then
        pass "Telemetry Orchestrator script is deployed and executable."
    else
        fail "Telemetry Orchestrator script is missing."
    fi

    if is_service_active "apache2" || is_service_active "httpd"; then
        pass "Apache Enterprise Web Server daemon is active."
    elif is_service_active "nginx"; then
        pass "Nginx Enterprise Web Server daemon is active."
    else
        fail "No Supported Web Server (Apache/Nginx) is offline or not installed."
    fi

    info "Initiating Deep-Scan for Telemetry Idempotence (60s cron overlap observation)..."
    TELEMETRY_GHOST_DETECTED=0

    for i in {60..1}; do
        printf "\r  [~] Monitoring process stack... %02ds remaining " "$i"

        TELEMETRY_RAW=$(ps -ef | grep "[s]yswarden-telemetry.sh" | grep -vE "sh -c|CROND|grep" || true)

        TELEMETRY_PROC_COUNT=$(echo "$TELEMETRY_RAW" | awk '{
            if ($2 != "") pids[$2]=$3 
        } 
        END {
            count=0; 
            for (p in pids) { 
                if (!(pids[p] in pids)) count++ 
            }; 
            print count+0
        }')

        if [ "${TELEMETRY_PROC_COUNT:-0}" -gt 1 ]; then
            TELEMETRY_GHOST_DETECTED=1
            break
        fi
        sleep 1
    done
    echo ""

    if [ "$TELEMETRY_GHOST_DETECTED" -eq 1 ]; then
        fail "Process Duplication FAILED: $TELEMETRY_PROC_COUNT telemetry instances detected! CPU leak triggered during cron cycle."
    else
        pass "Process Idempotence VERIFIED: Telemetry daemon state is stable (<=1 active instance) over a full cron cycle."
    fi

    if [[ -f "/etc/syswarden/ui/data.json" ]]; then
        payload_perms=$(stat -c "%a" "/etc/syswarden/ui/data.json" 2>/dev/null || stat -f "%Op" "/etc/syswarden/ui/data.json" | cut -c4-6)
        payload_owner=$(stat -c "%U" "/etc/syswarden/ui/data.json" 2>/dev/null || stat -f "%Su" "/etc/syswarden/ui/data.json")

        if [[ "$payload_perms" == *"640" ]] && [[ "$payload_owner" == "nginx" || "$payload_owner" == "www-data" || "$payload_owner" == "nobody" ]]; then
            pass "Telemetry payload ownership & permissions are strictly isolated (640, Owner: $payload_owner)."
        else
            fail "Telemetry payload has weak permissions/ownership (Got $payload_perms $payload_owner, Expected 640)."
        fi
    else
        warn "Telemetry payload (data.json) not found yet. Awaiting initial cron execution."
    fi

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
fi

# ==============================================================================
# --- Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking) ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 6 "* ]]; then
    log_header "Phase 6: Zero Trust Remote Access (VPN & SSH Cloaking)"

    if command -v firewall-cmd >/dev/null 2>&1 && is_service_active "firewalld" 2>/dev/null; then
        if firewall-cmd --list-rich-rules 2>/dev/null | grep "priority=\"-900\".*port=\"${SSH_PORT}\".*drop" >/dev/null; then
            CLOAK_PASSED=1
        fi
    elif command -v nft >/dev/null 2>&1 && nft list table inet syswarden_table >/dev/null 2>&1; then
        NFT_RULES=""
        if nft list chain inet syswarden_table input_frontline >/dev/null 2>&1; then
            NFT_RULES=$(nft -n list chain inet syswarden_table input_frontline 2>/dev/null | tr '\n' ' ' | tr '\t' ' ' || echo "")
        elif nft list chain inet syswarden_table input >/dev/null 2>&1; then
            NFT_RULES=$(nft -n list chain inet syswarden_table input 2>/dev/null | tr '\n' ' ' | tr '\t' ' ' || echo "")
        fi

        if [[ -n "$NFT_RULES" ]] && echo "$NFT_RULES" | grep -E "tcp dport ${SSH_PORT}.*drop" >/dev/null; then
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

    if [[ -d "/etc/wireguard" ]] && [[ -f "/etc/wireguard/wg0.conf" ]]; then
        if ip link show wg0 >/dev/null 2>&1; then
            pass "WireGuard interface (wg0) is UP and ready to accept authorized clients."
        else
            fail "WireGuard interface (wg0) is DOWN or missing."
        fi

        VPN_ALLOW_PASSED=0
        if command -v firewall-cmd >/dev/null 2>&1 && is_service_active "firewalld" 2>/dev/null; then
            if firewall-cmd --permanent --zone=trusted --list-interfaces 2>/dev/null | grep "wg0" >/dev/null; then
                VPN_ALLOW_PASSED=1
            fi
        elif command -v nft >/dev/null 2>&1 && nft list table inet syswarden_table >/dev/null 2>&1; then
            NFT_RULES=""
            if nft list chain inet syswarden_table input_frontline >/dev/null 2>&1; then
                NFT_RULES=$(nft -n list chain inet syswarden_table input_frontline 2>/dev/null | tr '\n' ' ' | tr '\t' ' ' || echo "")
            elif nft list chain inet syswarden_table input >/dev/null 2>&1; then
                NFT_RULES=$(nft -n list chain inet syswarden_table input 2>/dev/null | tr '\n' ' ' | tr '\t' ' ' || echo "")
            fi

            if [[ -n "$NFT_RULES" ]] && echo "$NFT_RULES" | grep -E "iifname.*wg0.*accept" >/dev/null; then
                VPN_ALLOW_PASSED=1
            fi
        elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep "Status: active" >/dev/null; then
            if ufw status 2>/dev/null | grep -E "wg0.*ALLOW" >/dev/null; then
                VPN_ALLOW_PASSED=1
            fi
        elif command -v iptables >/dev/null 2>&1; then
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
fi

# ==============================================================================
# --- Phase 7: Exposed Services & Firewall Persistence (CSPM) ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 7 "* ]]; then
    log_header "Phase 7: Exposed Services & Firewall Persistence (CSPM)"

    # HOTFIX: Persistence check specifically for Slackware RC Hooks
    if [[ "$OS_TYPE" == "Slackware" ]]; then
        if [[ -x "/etc/rc.d/rc.syswarden-firewall" ]] && grep -q "/etc/rc.d/rc.syswarden-firewall" /etc/rc.d/rc.local 2>/dev/null; then
            pass "Firewall Persistence VERIFIED: Slackware rc.local securely triggers SysWarden ($FW_ENGINE) on boot."
        else
            fail "Firewall Persistence FAILED: Slackware rc.local integration is missing or rc.syswarden-firewall is not executable."
        fi
    elif [[ "$FW_ENGINE" == "Nftables" ]]; then
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
        if is_service_active "firewalld" 2>/dev/null; then
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

    info "Scanning for globally exposed listening ports (0.0.0.0 / ::)..."

    DISCOVERED_PORTS=""
    if [[ -f "/etc/nftables.d/syswarden-os-bypass.nft" ]]; then
        RAW_PORTS=$(grep "Auto-allow Discovered Services" /etc/nftables.d/syswarden-os-bypass.nft | grep -oE '\{[^\}]+\}' | tr -d '{} ' || true)
        DISCOVERED_PORTS=$(echo "$RAW_PORTS" | tr ',' '\n')
    fi

    # PRE-CACHE FIREWALL STATE
    FW_NFT_CACHE=""
    FW_IPT_CACHE=""
    FW_UFW_CACHE=""
    FW_FWD_CACHE=""

    if command -v nft >/dev/null 2>&1; then FW_NFT_CACHE=$(nft list ruleset 2>/dev/null || true); fi
    if command -v iptables-save >/dev/null 2>&1; then FW_IPT_CACHE=$(iptables-save 2>/dev/null || true); fi
    if command -v ufw >/dev/null 2>&1; then FW_UFW_CACHE=$(ufw status 2>/dev/null || true); fi
    if command -v firewall-cmd >/dev/null 2>&1; then FW_FWD_CACHE=$(firewall-cmd --list-rich-rules 2>/dev/null || true); fi

    if command -v ss >/dev/null 2>&1; then
        LISTEN_PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -vE '^(127\.|::1|\[::1\])' | awk -F':' '{print $NF}' | grep -E '^[0-9]+$' | sort -nu || true)
    else
        LISTEN_PORTS=$(netstat -tlnp 2>/dev/null | awk '/^tcp/ {print $4}' | grep -vE '^(127\.|::1|\[::1\])' | awk -F':' '{print $NF}' | grep -E '^[0-9]+$' | sort -nu || true)
    fi

    if [[ -n "$LISTEN_PORTS" ]]; then
        for PORT in $LISTEN_PORTS; do

            DELIBERATE=0
            if [[ -n "$DISCOVERED_PORTS" ]]; then
                for dp in $DISCOVERED_PORTS; do
                    if [[ -n "$dp" ]] && [[ "$PORT" -eq "$dp" ]]; then
                        DELIBERATE=1
                        break
                    fi
                done
            fi

            IP_RESTRICTED=0
            F2B_GUARDED=0

            if [[ -n "$FW_NFT_CACHE" ]] && echo "$FW_NFT_CACHE" | grep -E "tcp dport $PORT\b" | grep -qE "ip saddr|ip6 saddr"; then
                IP_RESTRICTED=1
            elif [[ -n "$FW_IPT_CACHE" ]] && echo "$FW_IPT_CACHE" | grep -E "dport $PORT\b" | grep -E "\-s |source " | grep -qv "0.0.0.0/0"; then
                IP_RESTRICTED=1
            elif [[ -n "$FW_UFW_CACHE" ]] && echo "$FW_UFW_CACHE" | grep -E "^$PORT/tcp\b" | grep -qv "Anywhere"; then
                IP_RESTRICTED=1
            elif [[ -n "$FW_FWD_CACHE" ]] && echo "$FW_FWD_CACHE" | grep "port=\"$PORT\"" | grep -q "source"; then
                IP_RESTRICTED=1
            fi

            if command -v fail2ban-client >/dev/null 2>&1; then
                if [[ -n "$FW_IPT_CACHE" ]] && echo "$FW_IPT_CACHE" | grep -iE "f2b-|fail2ban" | grep -qE "dport $PORT\b"; then
                    F2B_GUARDED=1
                elif [[ -n "$FW_NFT_CACHE" ]] && echo "$FW_NFT_CACHE" | grep -iE "f2b-|fail2ban" | grep -qE "dport $PORT\b"; then
                    F2B_GUARDED=1
                fi
            fi

            if [[ "$PORT" -eq "$SSH_PORT" ]]; then
                if [[ ${CLOAK_PASSED:-0} -eq 1 ]]; then
                    info "Exposed Port: $PORT/TCP (SSH) - Guarded by Zero Trust VPN Guillotine (Drop policy)."
                else
                    info "Exposed Port: $PORT/TCP (SSH) - Publicly exposed (Guarded by Fail2ban sshd jail)."
                fi
            elif [[ "$PORT" -eq 80 || "$PORT" -eq 443 ]]; then
                info "Exposed Port: $PORT/TCP (Web) - Guarded by SysWarden Layer 7 LFI/SQLi/Bot Jails."
            elif [[ "$PORT" -eq 3306 || "$PORT" -eq 5432 || "$PORT" -eq 27017 || "$PORT" -eq 6379 ]]; then
                info "Exposed Port: $PORT/TCP (Database) - Guarded by Fail2ban Layer 7 Jails & Custom Firewall Rules."
            elif [[ "$PORT" -eq 21 ]]; then
                info "Exposed Port: $PORT/TCP (FTP Honeypot) - Guarded by Fail2ban vsftpd jail."
            elif [[ "$PORT" -eq 23 ]]; then
                info "Exposed Port: $PORT/TCP (Telnet Honeypot) - Guarded by Fail2ban Mirai/IoT jail."
            elif [[ "$PORT" -eq 111 ]]; then
                info "Exposed Port: $PORT/TCP (rpcbind) - Internal RPC service, guarded by default OS Firewall."
            elif [[ "$PORT" -eq 9999 ]]; then
                info "Exposed Port: $PORT/TCP (Nginx Enterprise UI) - Guarded by Zero Trust IP Restriction & TLS."
            elif [[ "$PORT" -eq 51820 || "$PORT" -eq "${WG_PORT:-51820}" ]]; then
                info "Exposed Port: $PORT/UDP (WireGuard) - Guarded by SysWarden Stealth UDP protections."
            elif [[ "$PORT" -eq 53 || "$PORT" -eq 123 || "$PORT" -eq 161 ]]; then
                info "Exposed Port: $PORT (Infra) - Standard Infrastructure Protocol (DNS/NTP)."
            elif [[ $DELIBERATE -eq 1 ]]; then
                if [[ $IP_RESTRICTED -eq 1 ]]; then
                    info "Exposed Port: $PORT/TCP (User Service) - Guarded by Zero Trust IP Restriction."
                elif [[ $F2B_GUARDED -eq 1 ]]; then
                    info "Exposed Port: $PORT/TCP (User Service) - Guarded by Fail2ban Layer 7 Jails & Custom Firewall Rules."
                else
                    info "Exposed Port: $PORT/TCP (User Service) - Guarded by default OS Firewall."
                fi
            else
                if [[ $IP_RESTRICTED -eq 1 ]]; then
                    info "Exposed Port: $PORT/TCP (Manual Service) - Guarded by Zero Trust IP Restriction (Not in Bypass Table)."
                elif [[ $F2B_GUARDED -eq 1 ]]; then
                    info "Exposed Port: $PORT/TCP (Manual Service) - Guarded by Fail2ban Layer 7 Jails & Custom Firewall Rules."
                else
                    warn "Exposed Port: $PORT/TCP (Unknown/Public) - Open to the public. Verify if this service requires zero-trust isolation."
                fi
            fi
        done
        pass "Attack Surface Mapping completed. All exposed sockets evaluated against security profiles."
    else
        pass "Attack Surface Mapping completed. No externally exposed TCP ports detected (Maximum Stealth)."
    fi
fi

# ==============================================================================
# --- Phase 8: Enterprise SOC & HA Integration ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 8 "* ]]; then
    log_header "Phase 8: Enterprise SOC & HA Integration"

    # 1. HA Cluster Sync
    if [[ -f "/usr/local/bin/syswarden-sync.sh" ]]; then
        # FIX: Double incr. removed
        if crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
            pass "HA Cluster Sync is ACTIVE and securely scheduled in Cron."
        else
            fail "HA Cluster Sync script exists but is missing from Cron schedule."
        fi
    else
        info "HA Cluster Sync is not configured (Skipped by user)."
    fi

    # 2. SIEM Log Forwarding (Rsyslog)
    if [[ -f "/etc/rsyslog.d/99-syswarden-siem.conf" ]]; then
        # FIX: Double incr. removed
        if grep -q "@@\|@" "/etc/rsyslog.d/99-syswarden-siem.conf"; then
            pass "SIEM Log Forwarding (ISO 27001/NIS2) is ACTIVE and configured."
        else
            fail "SIEM Log Forwarding configuration exists but lacks a valid target destination."
        fi
    else
        info "SIEM Log Forwarding is not configured (Skipped by user)."
    fi
fi

# ==============================================================================
# --- Phase 9: Ghost Rules & Firewall Idempotency (Anti-Duplication) ---
# ==============================================================================
if [[ "$RUN_ALL" -eq 1 || "$USER_PHASES" == *" 9 "* ]]; then
    log_header "Phase 9: Ghost Rules & Firewall Idempotency (Anti-Duplication)"

    GHOST_DETECTED=0

    if [[ "$FW_ENGINE" == "Nftables" ]]; then
        if nft list chain inet filter input >/dev/null 2>&1; then
            DUP_WG=$(nft list chain inet filter input 2>/dev/null | { grep -E "udp dport ${WG_PORT:-51820} accept" || true; } | wc -l)
            if [[ "$DUP_WG" -gt 1 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: $DUP_WG duplicate WireGuard rules detected in OS filter chain."
            fi

            GLOBAL_DUPS=$(nft list chain inet filter input 2>/dev/null | grep -vE '(type|hook|priority|{|})' | sed 's/^[ \t]*//' | { grep -v '^$' || true; } | sort | uniq -cd | wc -l)
            if [[ "$GLOBAL_DUPS" -gt 0 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: OS/Firewall update anomaly detected. $GLOBAL_DUPS exact duplicated rule(s) found in Nftables filter chain."
            fi
        fi

        if nft list chain inet syswarden_table input_backend >/dev/null 2>&1; then
            DUP_9999=$(nft list chain inet syswarden_table input_backend 2>/dev/null | { grep -E "tcp dport 9999 accept" || true; } | wc -l)
            if [[ "$DUP_9999" -gt 1 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: $DUP_9999 duplicate Dashboard (9999) rules detected in SysWarden backend."
            fi
        elif nft list chain inet syswarden_table input >/dev/null 2>&1; then
            DUP_9999=$(nft list chain inet syswarden_table input 2>/dev/null | { grep -E "tcp dport 9999 accept" || true; } | wc -l)
            if [[ "$DUP_9999" -gt 1 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: $DUP_9999 duplicate Dashboard (9999) rules detected in SysWarden input chain."
            fi
        fi

    elif [[ "$FW_ENGINE" == "Iptables" || "$FW_ENGINE" == "UFW" || "$FW_ENGINE" == "Firewalld" ]]; then
        if command -v iptables >/dev/null 2>&1; then
            DUP_9999=$(iptables -S INPUT 2>/dev/null | { grep "\--dport 9999 -j ACCEPT" || true; } | wc -l)
            DUP_SSH=$(iptables -S INPUT 2>/dev/null | { grep "\--dport ${SSH_PORT:-22} -j ACCEPT" || true; } | { grep -v "\-s" || true; } | wc -l)

            if [[ "$DUP_9999" -gt 1 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: $DUP_9999 duplicate Dashboard (9999) rules detected in Iptables."
            fi
            if [[ "$DUP_SSH" -gt 1 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: $DUP_SSH duplicate SSH allow rules detected in Iptables."
            fi

            GLOBAL_DUPS=$(iptables -S INPUT 2>/dev/null | { grep "^-A" || true; } | sort | uniq -cd | wc -l)
            if [[ "$GLOBAL_DUPS" -gt 0 ]]; then
                GHOST_DETECTED=1
                fail "Ghost Rules FAILED: OS/Firewall update anomaly detected. $GLOBAL_DUPS exact duplicated rule(s) found in Iptables INPUT chain."
            fi
        fi
    fi

    if [[ $GHOST_DETECTED -eq 0 ]]; then
        pass "Firewall Stack Idempotency VERIFIED: No ghost rules or uncontrolled duplicates detected post-update."
    fi
fi

# ==============================================================================
# --- 10. AUDIT SUMMARY ---
# ==============================================================================
echo -e "\n${BOLD}==============================================================================${NC}"

# HOTFIX: Prevent Division by Zero
if [[ $TOTAL -eq 0 ]]; then
    echo -e "${YELLOW}>>> AUDIT SKIPPED: No checks were performed or Phase was empty. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] SKIPPED - No checks performed." >>"$AUDIT_LOG"
elif [[ $SCORE -eq $TOTAL ]]; then
    echo -e "${GREEN}>>> AUDIT SUCCESSFUL: $SCORE/$TOTAL checks passed. System is fully DevSecOps compliant. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] SUCCESS - $SCORE/$TOTAL checks passed." >>"$AUDIT_LOG"
else
    PERCENT=$((SCORE * 100 / TOTAL))
    echo -e "${RED}>>> AUDIT FAILED: $SCORE/$TOTAL checks passed ($PERCENT%). Immediate review required. <<<${NC}"
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [RESULT] FAILED - $SCORE/$TOTAL checks passed ($PERCENT%)." >>"$AUDIT_LOG"
fi

echo -e "${BOLD}==============================================================================${NC}"

echo -e "📄 ${BOLD}Full Standardized Audit Log securely saved to:${NC} ${YELLOW}$AUDIT_LOG${NC}\n"
echo "=== AUDIT COMPLETED: $(date -u +"%Y-%m-%dT%H:%M:%SZ") ===" >>"$AUDIT_LOG"
