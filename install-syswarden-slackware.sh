#!/bin/bash

# SysWarden - Advanced Firewall & Blocklist Orchestrator
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

# --- SAFETY FIRST ---
set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"
TMP_DIR=$(mktemp -d)
# shellcheck disable=SC2034
VERSION="v2.15"
ACTIVE_PORTS=""
SYSWARDEN_DIR="/etc/syswarden"
WHITELIST_FILE="$SYSWARDEN_DIR/whitelist.txt"
BLOCKLIST_FILE="$SYSWARDEN_DIR/blocklist.txt"
GEOIP_SET_NAME="syswarden_geoip"
GEOIP_FILE="$SYSWARDEN_DIR/geoip.txt"
ASN_SET_NAME="syswarden_asn"
ASN_FILE="$SYSWARDEN_DIR/asn.txt"

# --- LIST URLS ---
# shellcheck disable=SC2034
declare -A URLS_STANDARD
URLS_STANDARD[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt"

# shellcheck disable=SC2034
declare -A URLS_CRITICAL
URLS_CRITICAL[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt"

: "${URLS_STANDARD[@]}"
: "${URLS_CRITICAL[@]}"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root.${NC}"
        exit 1
    fi
}

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

detect_os_backend() {
    log "INFO" "Detecting Operating System and Firewall Backend..."

    if [[ ! -f /etc/slackware-version ]]; then
        log "WARN" "This script is highly optimized for Slackware. Proceed with caution on other OS."
    fi

    if command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    elif command -v iptables >/dev/null 2>&1; then
        FIREWALL_BACKEND="iptables"
    else
        log "ERROR" "No supported firewall (nftables/iptables) found in kernel."
        exit 1
    fi

    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Checking Slackware dependencies (SBo)..."
    local missing_common=()

    if [[ ! -f "$CONF_FILE" ]]; then
        touch "$CONF_FILE"
        chmod 600 "$CONF_FILE"
    fi

    if ! command -v curl >/dev/null; then missing_common+=("curl"); fi
    if ! command -v python3 >/dev/null; then missing_common+=("python3"); fi
    if ! command -v whois >/dev/null; then missing_common+=("whois"); fi
    if ! command -v jq >/dev/null; then missing_common+=("jq"); fi
    if ! command -v nginx >/dev/null; then missing_common+=("nginx"); fi
    if ! command -v openssl >/dev/null; then missing_common+=("openssl"); fi
    if ! command -v fail2ban-client >/dev/null; then missing_common+=("fail2ban"); fi
    if ! command -v wg >/dev/null; then missing_common+=("wireguard-tools"); fi
    if ! command -v qrencode >/dev/null; then missing_common+=("qrencode"); fi
    if ! command -v rsync >/dev/null; then missing_common+=("rsync"); fi
    if ! command -v ssh >/dev/null; then missing_common+=("openssh"); fi

    if [[ ${#missing_common[@]} -gt 0 ]]; then
        log "WARN" "Missing dependencies detected: ${missing_common[*]}"
        echo -e "${YELLOW}SysWarden needs to compile the following packages: ${missing_common[*]}${NC}"
        read -p "Do you want SysWarden to automatically compile them via sbopkg? (This may take 15-30 mins) [y/N]: " auto_build

        if [[ "$auto_build" =~ ^[Yy]$ ]]; then
            if ! command -v sbopkg >/dev/null; then
                log "INFO" "sbopkg not found. Downloading and installing sbopkg..."
                curl -sS -L "https://github.com/sbopkg/sbopkg/releases/download/0.38.2/sbopkg-0.38.2-noarch-1_wsr.tgz" -o /tmp/sbopkg.tgz || true
                if [[ -s /tmp/sbopkg.tgz ]]; then
                    installpkg /tmp/sbopkg.tgz >/dev/null 2>&1
                    rm -f /tmp/sbopkg.tgz
                    log "INFO" "Syncing SlackBuilds repository tree..."
                    sbopkg -r >/dev/null 2>&1 || true
                else
                    log "ERROR" "Failed to download sbopkg. Please install it manually."
                    exit 1
                fi
            fi

            for pkg in "${missing_common[@]}"; do
                log "INFO" "Compiling $pkg via sbopkg (Please wait, do not interrupt)..."
                sbopkg -B -i "$pkg" >/dev/null 2>&1 || log "WARN" "sbopkg encountered a potential issue with $pkg."
            done
        else
            log "ERROR" "CRITICAL MISSING DEPENDENCIES: ${missing_common[*]}"
            echo -e "${RED}Slackware does not automatically resolve third-party packages.${NC}"
            exit 1
        fi
    fi

    # Preemptive Nginx Log Creation
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log /var/log/nginx/error.log
    chmod 640 /var/log/nginx/*.log 2>/dev/null || true

    # Python Requests check
    if ! python3 -c "import requests" 2>/dev/null; then
        log "WARN" "Python 'requests' module missing. Attempting to install via pip..."
        if command -v pip3 >/dev/null; then
            pip3 install requests || true
        else
            log "ERROR" "pip3 missing. AbuseIPDB reporting will fail."
        fi
    fi

    # Pure UNIX Syslog Check (Slackware defaults to syslogd)
    if [[ -f /etc/syslog.conf ]]; then
        log "INFO" "Configuring Slackware syslogd for firewall isolation..."
        sed -i '/kern-firewall\.log/d' /etc/syslog.conf
        sed -i '/auth-syswarden\.log/d' /etc/syslog.conf

        echo "kern.* /var/log/kern-firewall.log" >>/etc/syslog.conf
        echo "auth.* /var/log/auth-syswarden.log" >>/etc/syslog.conf

        touch /var/log/kern-firewall.log /var/log/auth-syswarden.log
        chmod 600 /var/log/kern-firewall.log /var/log/auth-syswarden.log

        if [[ -x /etc/rc.d/rc.syslog ]]; then
            /etc/rc.d/rc.syslog restart 2>/dev/null || true
        fi
    fi

    log "INFO" "All dependencies check complete."
}

define_ssh_port() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SSH_PORT:-}" ]]; then SSH_PORT=22; fi
        log "INFO" "Update Mode: Preserving SSH Port $SSH_PORT"
        return
    fi

    echo -e "\n${BLUE}=== Step: SSH Configuration ===${NC}"

    local detected_port=22
    if command -v sshd >/dev/null; then
        local parsed_port
        parsed_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}')
        if [[ "$parsed_port" =~ ^[0-9]+$ ]] && [ "$parsed_port" -ge 1 ] && [ "$parsed_port" -le 65535 ]; then
            detected_port="$parsed_port"
        fi
    fi

    if [[ "${1:-}" == "auto" ]]; then
        SSH_PORT=${SYSWARDEN_SSH_PORT:-$detected_port}
    else
        read -p "Please enter your current SSH Port [Default: $detected_port]: " input_port
        SSH_PORT=${input_port:-$detected_port}
    fi

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        SSH_PORT=22
    fi

    if [[ -f /etc/ssh/sshd_config ]]; then
        log "INFO" "Ensuring SSH TCP Forwarding is strictly DISABLED..."
        sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
        sed -i 's/^[[:space:]]*AllowTcpForwarding[[:space:]]*yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
        if [[ -x /etc/rc.d/rc.sshd ]]; then
            /etc/rc.d/rc.sshd restart 2>/dev/null || true
        fi
    fi

    echo "SSH_PORT='$SSH_PORT'" >>"$CONF_FILE"
}

define_wireguard() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_WIREGUARD:-}" ]]; then USE_WIREGUARD="n"; fi
        return
    fi

    echo -e "\n${BLUE}=== Step: WireGuard Management VPN ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        input_wg=${SYSWARDEN_ENABLE_WG:-n}
    else
        echo -e "${YELLOW}Deploy an ultra-secure, invisible WireGuard VPN for administration?${NC}"
        read -p "Enable WireGuard Management VPN? (y/N): " input_wg
    fi

    if [[ "$input_wg" =~ ^[Yy]$ ]]; then
        USE_WIREGUARD="y"
        if [[ "${1:-}" == "auto" ]]; then
            WG_PORT=${SYSWARDEN_WG_PORT:-51820}
            WG_SUBNET=${SYSWARDEN_WG_SUBNET:-"10.66.66.0/24"}
        else
            read -p "Enter WireGuard Port [Default: 51820]: " input_wg_port
            WG_PORT=${input_wg_port:-51820}
            read -p "Enter VPN Subnet (CIDR) [Default: 10.66.66.0/24]: " input_wg_subnet
            WG_SUBNET=${input_wg_subnet:-"10.66.66.0/24"}
        fi
        mkdir -p /etc/wireguard
    else
        USE_WIREGUARD="n"
    fi

    echo "USE_WIREGUARD='$USE_WIREGUARD'" >>"$CONF_FILE"
    if [[ "$USE_WIREGUARD" == "y" ]]; then
        echo "WG_PORT='$WG_PORT'" >>"$CONF_FILE"
        echo "WG_SUBNET='$WG_SUBNET'" >>"$CONF_FILE"
    fi
}

define_docker_integration() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_DOCKER:-}" ]]; then USE_DOCKER="n"; fi
        return
    fi

    echo -e "\n${BLUE}=== Step: Docker Integration ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        input_docker=${SYSWARDEN_USE_DOCKER:-n}
    else
        read -p "Do you use Docker on this server? (y/N): " input_docker
    fi

    if [[ "$input_docker" =~ ^[Yy]$ ]]; then
        USE_DOCKER="y"
    else
        USE_DOCKER="n"
    fi
    echo "USE_DOCKER='$USE_DOCKER'" >>"$CONF_FILE"
}

define_os_hardening() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${APPLY_OS_HARDENING:-}" ]]; then APPLY_OS_HARDENING="n"; fi
        return
    fi

    echo -e "\n${BLUE}=== Step: OS Security & Hardening ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        input_hard=${SYSWARDEN_HARDENING:-n}
    else
        read -p "Apply strict OS Hardening (Restrict wheel & adm)? [y/N]: " input_hard
    fi

    if [[ "$input_hard" =~ ^[Yy]$ ]]; then
        APPLY_OS_HARDENING="y"
    else
        APPLY_OS_HARDENING="n"
    fi
    echo "APPLY_OS_HARDENING='$APPLY_OS_HARDENING'" >>"$CONF_FILE"
}

apply_os_hardening() {
    if [[ "${APPLY_OS_HARDENING:-n}" != "y" ]]; then return; fi

    log "INFO" "Applying strict OS hardening for Slackware..."
    echo "root" >/var/spool/cron/cron.allow
    chmod 600 /var/spool/cron/cron.allow
    rm -f /var/spool/cron/cron.deny 2>/dev/null || true

    mkdir -p "$SYSWARDEN_DIR"
    local current_admin="${SUDO_USER:-}"

    for grp in wheel adm; do
        if grep -q "^${grp}:" /etc/group 2>/dev/null; then
            local members
            members=$(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group)
            if [[ -n "$members" && "$members" != "root" ]]; then
                echo "${grp}:${members}" >>"$SYSWARDEN_DIR/group_backup.txt"
            fi
            for user in $(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group | tr ',' ' ' 2>/dev/null); do
                if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                    if [[ -n "$current_admin" ]] && [[ "$user" == "$current_admin" ]]; then continue; fi
                    gpasswd -d "$user" "$grp" >/dev/null 2>&1 || true
                fi
            done
        fi
    done
}

auto_whitelist_admin() {
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    local admin_ip=""

    if [[ -n "${SSH_CLIENT:-}" ]]; then
        admin_ip=$(echo "$SSH_CLIENT" | awk '{print $1}' || true)
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        admin_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}' || true)
    fi

    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if command -v ss >/dev/null; then
            admin_ip=$(ss -tnp 2>/dev/null | grep -i 'estab' | grep -i 'sshd' | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        admin_ip=$(who 2>/dev/null | awk '{print $5}' | tr -d '()' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
    fi

    if [[ "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$admin_ip" != "127.0.0.1" ]]; then
        local is_vpn_ip=0
        if [[ -n "${WG_SUBNET:-}" ]]; then
            local subnet_base
            subnet_base=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
            if [[ "$admin_ip" == "${subnet_base}."* ]]; then is_vpn_ip=1; fi
        fi

        if [[ $is_vpn_ip -eq 0 ]]; then
            if ! grep -q "^${admin_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting current admin SSH session IP: $admin_ip"
                echo "$admin_ip" >>"$WHITELIST_FILE"
            fi
        fi
    fi
}

process_auto_whitelist() {
    # Only execute in auto mode and if the variable is populated
    if [[ "${1:-}" != "auto" ]] || [[ -z "${SYSWARDEN_WHITELIST_IPS:-}" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Processing Automated Whitelist ===${NC}"
    log "INFO" "Processing custom Whitelist from auto-configuration..."

    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    # --- HOTFIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global strict IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------

    for ip in $SYSWARDEN_WHITELIST_IPS; do
        # Ignore empty strings
        if [[ -z "$ip" ]]; then continue; fi

        # --- SECURITY FIX: STRICT IPV4 VALIDATION ---
        # Prevents malicious or malformed strings from crashing the firewall daemon
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$ip" != "127.0.0.1" ]]; then
            if ! grep -q "^${ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-configuration: Whitelisting IP $ip"
                echo "$ip" >>"$WHITELIST_FILE"
            else
                log "INFO" "Auto-configuration: IP $ip is already whitelisted."
            fi
        else
            log "WARN" "Auto-configuration: Invalid IP format skipped -> '$ip'"
        fi
    done

    # Restore strict security IFS
    IFS="$OLD_IFS"
}

select_list_type() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        return
    fi

    echo -e "\n${BLUE}=== Step 1: Select Blocklist Type ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        choice=${SYSWARDEN_LIST_CHOICE:-1}
    else
        echo "1) Standard List (~85,000 IPs) - Recommended for Web Servers"
        echo "2) Critical List (~100,000 IPs) - Recommended for High Security"
        echo "3) Custom List"
        echo "4) No List (Geo-Blocking / Local rules only)"
        read -p "Enter choice [1/2/3/4]: " choice
    fi

    case "$choice" in
        1) LIST_TYPE="Standard" ;;
        2) LIST_TYPE="Critical" ;;
        3)
            LIST_TYPE="Custom"
            read -p "Enter full URL: " CUSTOM_URL
            ;;
        4) LIST_TYPE="None" ;;
        *) LIST_TYPE="Standard" ;;
    esac

    echo "LIST_TYPE='$LIST_TYPE'" >>"$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >>"$CONF_FILE"; fi
}

define_geoblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${GEOBLOCK_COUNTRIES:-}" ]]; then GEOBLOCK_COUNTRIES="none"; fi
        return
    fi
    echo -e "\n${BLUE}=== Step: Geo-Blocking ===${NC}"
    read -p "Enable Geo-Blocking? (y/N): " input_geo
    if [[ "$input_geo" =~ ^[Yy]$ ]]; then
        read -p "Enter country codes [Default: ru cn kp ir]: " geo_codes
        GEOBLOCK_COUNTRIES=${geo_codes:-ru cn kp ir}
        GEOBLOCK_COUNTRIES=$(echo "$GEOBLOCK_COUNTRIES" | tr '[:upper:]' '[:lower:]')
    else
        GEOBLOCK_COUNTRIES="none"
    fi
    echo "GEOBLOCK_COUNTRIES='$GEOBLOCK_COUNTRIES'" >>"$CONF_FILE"
}

define_asnblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${BLOCK_ASNS:-}" ]]; then BLOCK_ASNS="none"; fi
        if [[ -z "${USE_SPAMHAUS_ASN:-}" ]]; then USE_SPAMHAUS_ASN="y"; fi
        return
    fi
    echo -e "\n${BLUE}=== Step: ASN Blocking ===${NC}"
    read -p "Enable ASN Blocking? (y/N): " input_asn
    if [[ "$input_asn" =~ ^[Yy]$ ]]; then
        read -p "Enter custom ASNs (Leave empty for none): " asn_list
        read -p "Include Spamhaus ASN-DROP list? (Y/n): " use_spamhaus
        BLOCK_ASNS=${asn_list:-none}
        USE_SPAMHAUS_ASN=${use_spamhaus:-y}
        if [[ "$USE_SPAMHAUS_ASN" =~ ^[Nn]$ ]]; then USE_SPAMHAUS_ASN="n"; else USE_SPAMHAUS_ASN="y"; fi
        if [[ "$BLOCK_ASNS" != "none" ]]; then BLOCK_ASNS=$(echo "$BLOCK_ASNS" | tr '[:lower:]' '[:upper:]'); fi
    else
        BLOCK_ASNS="none"
        USE_SPAMHAUS_ASN="n"
    fi
    echo "BLOCK_ASNS='$BLOCK_ASNS'" >>"$CONF_FILE"
    echo "USE_SPAMHAUS_ASN='$USE_SPAMHAUS_ASN'" >>"$CONF_FILE"
}

define_ha_cluster() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${HA_ENABLED:-}" ]]; then HA_ENABLED="n"; fi
        log "INFO" "Update Mode: Preserving HA Cluster setting ($HA_ENABLED)"
        return
    fi

    echo -e "\n${BLUE}=== Step: High Availability Cluster (HA Sync) ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        HA_ENABLED=${SYSWARDEN_HA_ENABLED:-n}
        HA_PEER_IP=${SYSWARDEN_HA_PEER_IP:-""}
        log "INFO" "Auto Mode: HA choice loaded via env var."
    else
        echo "SysWarden can automatically replicate its threat intelligence state to a standby node."
        read -p "Enable HA Cluster Sync? (y/N): " input_ha
        if [[ "$input_ha" =~ ^[Yy]$ ]]; then
            HA_ENABLED="y"
            read -p "Enter Standby Node IP (Must be accessible via SSH keys): " HA_PEER_IP
        else
            HA_ENABLED="n"
        fi
    fi

    echo "HA_ENABLED='$HA_ENABLED'" >>"$CONF_FILE"
    if [[ "$HA_ENABLED" == "y" ]] && [[ -n "$HA_PEER_IP" ]]; then
        echo "HA_PEER_IP='$HA_PEER_IP'" >>"$CONF_FILE"
        log "INFO" "Configuring HA Synchronization Engine..."
        local SYNC_SCRIPT="/usr/local/bin/syswarden-sync.sh"
        cat <<EOF >"$SYNC_SCRIPT"
#!/bin/bash
PEER="$HA_PEER_IP"
SSH_PORT="${SSH_PORT:-22}"
rsync -a -e "ssh -p \$SSH_PORT -o StrictHostKeyChecking=no" /etc/syswarden/whitelist.txt /etc/syswarden/blocklist.txt root@\$PEER:/etc/syswarden/ 2>/dev/null
ssh -p \$SSH_PORT -o StrictHostKeyChecking=no root@\$PEER "/usr/local/bin/syswarden-telemetry.sh >/dev/null 2>&1" 2>/dev/null
EOF
        chmod +x "$SYNC_SCRIPT"
        if ! crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
            (
                crontab -l 2>/dev/null || true
                echo "*/30 * * * * $SYNC_SCRIPT >/dev/null 2>&1"
            ) | crontab -
        fi
        log "INFO" "HA Cluster Sync ENABLED. Target: $HA_PEER_IP"
    fi
}

setup_siem_logging() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SIEM_ENABLED:-}" ]]; then SIEM_ENABLED="n"; fi
        log "INFO" "Update Mode: Preserving SIEM setting ($SIEM_ENABLED)"
        return
    fi

    echo -e "\n${BLUE}=== Step: SIEM Log Forwarding (ISO 27001/NIS2) ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        SIEM_ENABLED=${SYSWARDEN_SIEM_ENABLED:-n}
        SIEM_IP=${SYSWARDEN_SIEM_IP:-""}
        SIEM_PORT=${SYSWARDEN_SIEM_PORT:-514}
        SIEM_PROTO=${SYSWARDEN_SIEM_PROTO:-udp}
    else
        echo "Forward EXCLUSIVELY Fail2ban L7 attack logs to an external SIEM?"
        read -p "Enable SIEM Forwarding? (y/N): " response_siem
        if [[ "$response_siem" =~ ^[Yy]$ ]]; then
            SIEM_ENABLED="y"
            read -p "Enter SIEM IP/Hostname: " SIEM_IP
            read -p "Enter SIEM Port [Default: 514]: " SIEM_PORT
            SIEM_PORT=${SIEM_PORT:-514}
            read -p "Enter SIEM Protocol (tcp/udp) [Default: udp]: " SIEM_PROTO
            SIEM_PROTO=${SIEM_PROTO:-udp}
            SIEM_PROTO=$(echo "$SIEM_PROTO" | tr '[:upper:]' '[:lower:]')
        else
            SIEM_ENABLED="n"
        fi
    fi

    echo "SIEM_ENABLED='$SIEM_ENABLED'" >>"$CONF_FILE"
    if [[ "$SIEM_ENABLED" == "y" ]] && [[ -n "$SIEM_IP" ]]; then
        echo "SIEM_IP='$SIEM_IP'" >>"$CONF_FILE"
        echo "SIEM_PORT='$SIEM_PORT'" >>"$CONF_FILE"
        echo "SIEM_PROTO='$SIEM_PROTO'" >>"$CONF_FILE"

        log "INFO" "Deploying native Slackware SIEM Forwarder daemon (Fail2ban only)..."

        # Clean old syslog.conf injection if present from previous versions
        sed -i '/@'"$SIEM_IP"'/d' /etc/syslog.conf 2>/dev/null || true
        if [[ -x /etc/rc.d/rc.syslog ]]; then /etc/rc.d/rc.syslog restart 2>/dev/null || true; fi

        # Create standalone bash forwarder script
        cat <<'EOF' >/usr/local/bin/syswarden-siem.sh
#!/bin/bash
TARGET_IP="$1"
TARGET_PORT="$2"
PROTO="$3"

tail -F -n 0 /var/log/fail2ban.log 2>/dev/null | while read -r line; do
    syslog_msg="<188>$(date +'%b %d %H:%M:%S') $(hostname) fail2ban: $line"
    if [[ "$PROTO" == "tcp" ]]; then
        echo "$syslog_msg" > "/dev/tcp/$TARGET_IP/$TARGET_PORT" 2>/dev/null || true
    else
        echo "$syslog_msg" > "/dev/udp/$TARGET_IP/$TARGET_PORT" 2>/dev/null || true
    fi
done
EOF
        chmod +x /usr/local/bin/syswarden-siem.sh

        # Create Slackware init script
        cat <<EOF >/etc/rc.d/rc.syswarden-siem
#!/bin/bash
PIDFILE="/var/run/syswarden-siem.pid"
case "\$1" in
    start)
        if [ ! -f \$PIDFILE ]; then
            nohup /usr/local/bin/syswarden-siem.sh "$SIEM_IP" "$SIEM_PORT" "$SIEM_PROTO" >/dev/null 2>&1 &
            echo \$! > \$PIDFILE
        fi
        ;;
    stop)
        if [ -f \$PIDFILE ]; then
            kill \$(cat \$PIDFILE) 2>/dev/null || true
            rm -f \$PIDFILE
        fi
        ;;
    restart)
        \$0 stop
        sleep 1
        \$0 start
        ;;
esac
EOF
        chmod +x /etc/rc.d/rc.syswarden-siem

        # Ensure persistence in rc.local
        if ! grep -q "/etc/rc.d/rc.syswarden-siem" /etc/rc.d/rc.local 2>/dev/null; then
            echo "if [ -x /etc/rc.d/rc.syswarden-siem ]; then /etc/rc.d/rc.syswarden-siem start; fi" >>/etc/rc.d/rc.local
        fi

        # Start daemon
        /etc/rc.d/rc.syswarden-siem restart >/dev/null 2>&1
        log "INFO" "SIEM Log Forwarding is ACTIVE via Daemon. (Target: $SIEM_IP:$SIEM_PORT/$SIEM_PROTO)"
    else
        log "INFO" "SIEM Log Forwarding DISABLED."
        if [[ -x /etc/rc.d/rc.syswarden-siem ]]; then /etc/rc.d/rc.syswarden-siem stop >/dev/null 2>&1 || true; fi
        rm -f /etc/rc.d/rc.syswarden-siem /usr/local/bin/syswarden-siem.sh
        if [[ -f /etc/rc.d/rc.local ]]; then sed -i '/rc\.syswarden-siem/d' /etc/rc.d/rc.local 2>/dev/null || true; fi
    fi
}

measure_latency() {
    local url="$1"
    local time_sec
    time_sec=$(curl -o /dev/null -s -w '%{time_connect}\n' --connect-timeout 2 "$url" || echo "error")
    if [[ "$time_sec" == "error" ]] || [[ -z "$time_sec" ]]; then echo "9999"; else echo "$time_sec" | awk '{print int($1 * 1000)}' 2>/dev/null || echo "9999"; fi
}

select_mirror() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        return
    fi
    if [[ "$LIST_TYPE" == "Custom" ]]; then
        SELECTED_URL="$CUSTOM_URL"
        echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
        return
    fi
    if [[ "$LIST_TYPE" == "None" ]]; then
        SELECTED_URL="none"
        echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
        return
    fi

    log "INFO" "Benchmarking mirrors..."
    declare -n URL_MAP
    if [[ "$LIST_TYPE" == "Standard" ]]; then URL_MAP=URLS_STANDARD; else URL_MAP=URLS_CRITICAL; fi

    local fastest_time=10000
    local fastest_url=""
    for name in "${!URL_MAP[@]}"; do
        url="${URL_MAP[$name]}"
        time=$(measure_latency "$url")
        if [[ "$time" -ne 9999 ]] && ((time < fastest_time)); then
            fastest_time=$time
            fastest_url=$url
        fi
    done
    SELECTED_URL=${fastest_url:-${URL_MAP[Codeberg]}}
    echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
}

download_list() {
    log "INFO" "Fetching list from $SELECTED_URL..."
    if [[ "$SELECTED_URL" == "none" ]]; then
        touch "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        return
    fi
    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        tr -d '\r' <"$output_file" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >"$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
    else
        log "ERROR" "Failed to download blocklist."
        exit 1
    fi
}

download_osint() {
    if [[ "${LIST_TYPE:-Standard}" == "None" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading Free OSINT Threat Feeds ===${NC}"
    log "INFO" "Fetching CINS Army & Blocklist.de threat feeds..."

    local osint_raw="$TMP_DIR/osint_raw.txt"
    : >"$osint_raw"

    # 1. CINS Army (CI Army) - Active Botnets & Scanners
    echo -n "Fetching CINS Army badguys list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://cinsscore.com/list/ci-badguys.txt" >>"$osint_raw"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log "WARN" "Failed to download CINS Army list."
    fi

    # 2. Blocklist.de - Bruteforce & SSH/Web Attacks
    echo -n "Fetching Blocklist.de (All) list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://lists.blocklist.de/lists/all.txt" >>"$osint_raw"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log "WARN" "Failed to download Blocklist.de list."
    fi

    # 3. Thorough cleaning and atomic fusion
    if [[ -s "$osint_raw" ]]; then
        log "INFO" "Sanitizing OSINT IPs and merging with the main blocklist..."

        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION ---
        # Ensures that only valid IPv4 addresses are passed to the firewall engine (Anti-Crash)
        tr -d '\r' <"$osint_raw" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >>"$FINAL_LIST"
        # -----------------------------------------------------

        log "INFO" "OSINT feeds successfully merged into the core firewall memory."
    else
        log "WARN" "OSINT feeds are empty. Continuing with standard blocklist."
    fi
}

download_geoip() {
    if [[ "${GEOBLOCK_COUNTRIES:-none}" == "none" ]]; then return; fi
    mkdir -p "$TMP_DIR" "$SYSWARDEN_DIR"
    : >"$TMP_DIR/geoip_raw.txt"
    for country in $(echo "$GEOBLOCK_COUNTRIES" | tr ' ' '\n'); do
        if [[ -z "$country" ]]; then continue; fi
        echo -e "${BLUE} -> Fetching GeoIP zone: ${country^^}...${NC}"
        curl -sS -L --retry 3 --connect-timeout 5 "https://www.ipdeny.com/ipblocks/data/countries/${country}.zone" >>"$TMP_DIR/geoip_raw.txt" || true
    done
    if [[ -s "$TMP_DIR/geoip_raw.txt" ]]; then
        awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' "$TMP_DIR/geoip_raw.txt" | sort -u >"$GEOIP_FILE"
    else
        touch "$GEOIP_FILE"
    fi
}

download_asn() {
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then return; fi
    mkdir -p "$TMP_DIR" "$SYSWARDEN_DIR"
    : >"$TMP_DIR/asn_raw.txt"

    if [[ "${USE_SPAMHAUS_ASN:-y}" == "y" ]]; then
        local spamhaus_asns
        spamhaus_asns=$(curl -sS -L -A "Mozilla/5.0" --retry 2 --connect-timeout 5 "https://www.spamhaus.org/drop/asndrop.json" 2>/dev/null | grep -Eo '"asn":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+' | sed 's/^/AS/' | tr '\n' ' ' || true)
        if [[ -n "$spamhaus_asns" ]]; then
            if [[ "$BLOCK_ASNS" == "none" ]] || [[ "$BLOCK_ASNS" == "auto" ]]; then BLOCK_ASNS="$spamhaus_asns"; else BLOCK_ASNS="$BLOCK_ASNS $spamhaus_asns"; fi
        fi
    fi

    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    local combined_asns
    combined_asns=$(echo "$BLOCK_ASNS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

    for asn in $combined_asns; do
        if [[ -z "$asn" ]] || [[ "$asn" == "auto" ]] || [[ "$asn" == "none" ]]; then continue; fi
        if [[ ! "$asn" =~ ^AS[0-9]+$ ]]; then
            local clean_num="${asn//[!0-9]/}"
            if [[ -z "$clean_num" ]]; then continue; fi
            asn="AS${clean_num}"
        fi

        echo -e "${BLUE} -> Resolving ASN routes: ${asn}...${NC}"
        local whois_out=""
        for _ in 1 2 3; do
            whois_out=$(whois -h whois.radb.net -- "-i origin $asn" 2>&1 || true)
            if [[ "$whois_out" == *"Connection reset by peer"* ]] || [[ "$whois_out" == *"Timeout"* ]] || [[ "$whois_out" == *"refused"* ]]; then
                sleep 2
                continue
            fi
            break
        done
        echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >>"$TMP_DIR/asn_raw.txt" || true
        sleep 0.5
    done
    IFS="$OLD_IFS"

    if [[ -s "$TMP_DIR/asn_raw.txt" ]]; then
        python3 -c '
import sys, ipaddress
nets = []
for line in sys.stdin:
    line = line.strip()
    if line and ":" not in line:
        try: nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError: pass
for net in ipaddress.collapse_addresses(nets):
    print(net)' <"$TMP_DIR/asn_raw.txt" >"$ASN_FILE"
    else
        touch "$ASN_FILE"
    fi
}

discover_active_services() {
    log "INFO" "Scanning User-Space for actively listening TCP services..."
    local detected_ports=""

    if command -v ss >/dev/null; then
        detected_ports=$(ss -tlnH 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    elif command -v netstat >/dev/null; then
        detected_ports=$(netstat -tln 2>/dev/null | grep '^tcp' | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    fi

    if command -v telnetd >/dev/null 2>&1 || command -v in.telnetd >/dev/null 2>&1; then
        detected_ports=$(printf "%s\n23" "$detected_ports" | grep -v '^$' | sort -nu)
    fi

    if [[ -n "$detected_ports" ]]; then
        ACTIVE_PORTS=$(echo "$detected_ports" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
    else
        ACTIVE_PORTS="none"
    fi
}

apply_firewall_rules() {
    log "INFO" "Applying Firewall Rules ($FIREWALL_BACKEND) via Slackware BSD-init style..."
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE"

    cat "$BLOCKLIST_FILE" >>"$FINAL_LIST"
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" >"$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi
    cp "$FINAL_LIST" "$SYSWARDEN_DIR/active_global_blocklist.txt"

    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        local ACTIVE_IF
        ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

        cat <<EOF >"$TMP_DIR/syswarden.nft"
table inet syswarden_table
delete table inet syswarden_table
table netdev syswarden_hw_drop
delete table netdev syswarden_hw_drop

table netdev syswarden_hw_drop {
    set $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then echo "    set $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"; fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then echo "    set $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"; fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    chain ingress_frontline {
        type filter hook ingress device "$ACTIVE_IF" priority -500; policy accept;
EOF
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "        ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
            done <"$WHITELIST_FILE"
        fi
        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " drop
EOF
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then echo "        ip saddr @$GEOIP_SET_NAME log prefix \"[SysWarden-GEO] \" drop" >>"$TMP_DIR/syswarden.nft"; fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then echo "        ip saddr @$ASN_SET_NAME log prefix \"[SysWarden-ASN] \" drop" >>"$TMP_DIR/syswarden.nft"; fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }
}

table inet syswarden_table {
    chain input_frontline {
        type filter hook input priority filter - 10; policy accept;
        ct state established,related accept
EOF
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "        ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
            done <"$WHITELIST_FILE"
        fi
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept" >>"$TMP_DIR/syswarden.nft"
            echo "        tcp dport ${SSH_PORT:-22} log prefix \"[SysWarden-SSH-DROP] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi
        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }

    chain input_backend {
        type filter hook input priority filter + 10; policy drop;
        ct state established,related accept
        iifname "lo" accept
        ip protocol icmp accept
EOF

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            echo "        tcp dport { ${SSH_PORT:-22}, 9999, $ACTIVE_PORTS } accept" >>"$TMP_DIR/syswarden.nft"
        else
            echo "        tcp dport { ${SSH_PORT:-22}, 9999 } accept" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        log prefix "[SysWarden-BLOCK] [Catch-All] " drop
    }
}
EOF

        # --- HOTFIX: AWK BATCH INJECTION (Anti-ARG_MAX & Anti-OOM) ---

        if [[ -s "$FINAL_LIST" ]]; then
            awk -v set_name="$SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 2500) { printf " }\n"; c=0 }
            }
            END { if (c > 0) printf " }\n" }' "$FINAL_LIST" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            awk -v set_name="$GEOIP_SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 2500) { printf " }\n"; c=0 }
            }
            END { if (c > 0) printf " }\n" }' "$GEOIP_FILE" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            awk -v set_name="$ASN_SET_NAME" '
            BEGIN { c=0 }
            {
                if ($1 == "") next;
                if (c == 0) printf "add element netdev syswarden_hw_drop %s { %s", set_name, $1
                else printf ", %s", $1
                c++
                if (c >= 2500) { printf " }\n"; c=0 }
            }
            END { if (c > 0) printf " }\n" }' "$ASN_FILE" >>"$TMP_DIR/syswarden.nft"
        fi
        # --------------------------------------------------------------------

        nft -f "$TMP_DIR/syswarden.nft"

        # --- SLACKWARE INIT SCRIPT ---
        cp "$TMP_DIR/syswarden.nft" /etc/syswarden/syswarden.nft
        cat <<'EOF' >/etc/rc.d/rc.syswarden-firewall
#!/bin/bash
nft -f /etc/syswarden/syswarden.nft
EOF
        chmod +x /etc/rc.d/rc.syswarden-firewall

        if ! grep -q "/etc/rc.d/rc.syswarden-firewall" /etc/rc.d/rc.local 2>/dev/null; then
            echo "if [ -x /etc/rc.d/rc.syswarden-firewall ]; then /etc/rc.d/rc.syswarden-firewall start; fi" >>/etc/rc.d/rc.local
            chmod +x /etc/rc.d/rc.local
        fi

    elif [[ "$FIREWALL_BACKEND" == "iptables" ]]; then
        # Fallback Iptables implementation for Slackware
        log "INFO" "Applying Iptables via rc.local..."
        # Ensure ipsets exist
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!
        fi

        # We save it so it can be restored on boot
        ipset save >/etc/syswarden/ipsets.save

        # Core Rules
        iptables -F INPUT
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                iptables -A INPUT -s "$wl_ip" -j ACCEPT
            done <"$WHITELIST_FILE"
        fi

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            iptables -A INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP
            iptables -A INPUT -i wg0 -j ACCEPT
            iptables -A INPUT -p udp --dport "${WG_PORT:-51820}" -j ACCEPT
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            iptables -t raw -A PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            iptables -t raw -A PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            iptables -t raw -A PREROUTING -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            iptables -t raw -A PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP
        fi

        iptables -t raw -A PREROUTING -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
        iptables -t raw -A PREROUTING -m set --match-set "$SET_NAME" src -j DROP

        iptables -A INPUT -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            iptables -A INPUT -p tcp -m multiport --dports "$ACTIVE_PORTS" -j ACCEPT
        fi

        iptables -A INPUT -p tcp --dport 9999 -j ACCEPT
        iptables -A INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] "
        iptables -A INPUT -j DROP

        iptables-save >/etc/syswarden/iptables.save

        cat <<'EOF' >/etc/rc.d/rc.syswarden-firewall
#!/bin/bash
if [ -f /etc/syswarden/ipsets.save ]; then ipset restore -! < /etc/syswarden/ipsets.save; fi
if [ -f /etc/syswarden/iptables.save ]; then iptables-restore < /etc/syswarden/iptables.save; fi
EOF
        chmod +x /etc/rc.d/rc.syswarden-firewall

        if ! grep -q "/etc/rc.d/rc.syswarden-firewall" /etc/rc.d/rc.local 2>/dev/null; then
            echo "if [ -x /etc/rc.d/rc.syswarden-firewall ]; then /etc/rc.d/rc.syswarden-firewall start; fi" >>/etc/rc.d/rc.local
            chmod +x /etc/rc.d/rc.local
        fi
    fi
}

configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Slackware Native)..."

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
# DEVSECOPS FIX: Prevent SQLite database bloat and memory exhaustion.
# Synchronized to 8 days (691200s) to perfectly match the 1-week findtime of the 'recidive' jail.
dbpurgeage = 691200
EOF

        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            f2b_action="nftables-multiport"
        fi

        # --- FIX: DYNAMIC FAIL2BAN INFRASTRUCTURE WHITELIST (ANTI SELF-DOS) ---
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"
        local public_ip
        public_ip=$(ip -4 addr show | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | grep -v '127.0.0.1' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi
        local local_subnets
        local_subnets=$(ip -4 route | grep -v default | awk '{print $1}' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi
        local dns_ips
        if [[ -f /etc/resolv.conf ]]; then
            dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi
        if [[ -s "$WHITELIST_FILE" ]]; then
            local wl_ips
            wl_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            f2b_ignoreip="$f2b_ignoreip $wl_ips"
        fi

        # Slackware uses syslogd (messages, secure) and auto/polling backend natively
        # HOTFIX: Backup existing jail.local before overwriting
        if [[ -f /etc/fail2ban/jail.local && ! -f /etc/fail2ban/jail.local.syswarden-bak ]]; then cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.syswarden-bak; fi

        cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
banaction = $f2b_action

[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $f2b_action
maxretry = 3
findtime = 1w
bantime  = 4w

[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-22}
logpath = /var/log/messages
backend = auto
EOF

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
failregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Ban|Found) <HOST>\s*$
ignoreregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Restore )?(?:Unban|unban) <HOST>\s*$
EOF
        fi

        # ALL 46 JAILS PORTED FROM UNIVERSAL v1.76 FOR SLACKWARE

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            # HOTFIX: Self-healing native filter
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-http-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/nginx-http-auth.conf
[Definition]
failregex = ^ \[error\] \d+#\d+: \*\d+ user "\S+":? (password mismatch|was not found in "[^\"]*"), client: <HOST>, server: \S+, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"(?:, referrer: "\S+")?\s*$
ignoreregex = 
EOF
            fi
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"(GET|POST|HEAD).*\" (400|401|403|404|444) .*$\nignoreregex =" >/etc/fail2ban/filter.d/nginx-scanner.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
backend = auto

[nginx-scanner]
enabled = true
port    = http,https
filter  = nginx-scanner
logpath = /var/log/nginx/access.log
backend = auto
maxretry = 15
bantime  = 24h
EOF
        fi

        # 5. DYNAMIC DETECTION: APACHE
        APACHE_LOG=""
        APACHE_ACCESS=""
        if [[ -f "/var/log/httpd/error_log" ]]; then
            APACHE_LOG="/var/log/httpd/error_log"
            APACHE_ACCESS="/var/log/httpd/access_log"
        fi
        if [[ -n "$APACHE_LOG" ]]; then
            # HOTFIX: Self-healing native filter
            if [[ ! -f "/etc/fail2ban/filter.d/apache-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/apache-auth.conf
[Definition]
failregex = ^\[[^\]]+\] \[error\] \[client <HOST>\] user .* not found(: )?
            ^\[[^\]]+\] \[error\] \[client <HOST>\] user .* password mismatch(: )?
ignoreregex = 
EOF
            fi
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"(GET|POST|HEAD) .+\" (400|401|403|404) .+\$\nignoreregex =" >/etc/fail2ban/filter.d/apache-scanner.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[apache-auth]
enabled = true
port = http,https
logpath = $APACHE_LOG
backend = auto

[apache-scanner]
enabled = true
port    = http,https
filter  = apache-scanner
logpath = $APACHE_ACCESS
backend = auto
maxretry = 15
bantime  = 24h
EOF
        fi

        # 6. DYNAMIC DETECTION: MONGODB
        if [[ -f "/var/log/mongodb/mongod.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).* <HOST>(:[0-9]+)?.*\$\nignoreregex =" >/etc/fail2ban/filter.d/mongodb-guard.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[mongodb-guard]
enabled = true
port = 27017
filter = mongodb-guard
logpath = /var/log/mongodb/mongod.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 7. DYNAMIC DETECTION: MARIADB / MYSQL
        MARIADB_LOG=""
        if [[ -f "/var/log/mysql/error.log" ]]; then MARIADB_LOG="/var/log/mysql/error.log"; fi
        if [[ -n "$MARIADB_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*[Aa]ccess denied for user .*@'<HOST>'.*\$\nignoreregex =" >/etc/fail2ban/filter.d/mariadb-auth.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[mariadb-auth]
enabled = true
port = 3306
filter = mariadb-auth
logpath = $MARIADB_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 8. DYNAMIC DETECTION: POSTFIX (SMTP)
        POSTFIX_LOG=""
        if [[ -f "/var/log/maillog" ]]; then POSTFIX_LOG="/var/log/maillog"; fi
        if [[ -n "$POSTFIX_LOG" ]]; then
            cat <<EOF >>/etc/fail2ban/jail.local

[postfix]
enabled = true
mode    = aggressive
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto

[postfix-sasl]
enabled = true
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 9. DYNAMIC DETECTION: VSFTPD (FTP)
        if [[ -f "/var/log/vsftpd.log" ]]; then
            cat <<EOF >>/etc/fail2ban/jail.local

[vsftpd]
enabled = true
port    = ftp,ftp-data,ftps,20,21
logpath = /var/log/vsftpd.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 10. DYNAMIC DETECTION: WORDPRESS (WP-LOGIN)
        WP_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then
            WP_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi
        if [[ -n "$WP_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"POST .*(wp-login\.php|xmlrpc\.php) HTTP.*\" 200\nignoreregex =" >/etc/fail2ban/filter.d/wordpress-auth.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[wordpress-auth]
enabled = true
port = http,https
filter = wordpress-auth
logpath = $WP_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 10.5. DYNAMIC DETECTION: DRUPAL CMS
        DRUPAL_LOG="$WP_LOG"
        if [[ -n "$DRUPAL_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/user/login|\?q=user/login) HTTP.*" 200.*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[drupal-auth]
enabled  = true
port     = http,https
filter   = drupal-auth
logpath  = $DRUPAL_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 11. DYNAMIC DETECTION: NEXTCLOUD
        NC_LOG=""
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then
                NC_LOG="$path"
                break
            fi
        done
        if [[ -n "$NC_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Login failed: .* \(Remote IP: '<HOST>'\).*$\nignoreregex =" >/etc/fail2ban/filter.d/nextcloud.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[nextcloud]
enabled = true
port    = http,https
filter  = nextcloud
logpath = $NC_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 12. DYNAMIC DETECTION: ASTERISK (VOIP)
        ASTERISK_LOG=""
        if [[ -f "/var/log/asterisk/messages" ]]; then
            ASTERISK_LOG="/var/log/asterisk/messages"
        elif [[ -f "/var/log/asterisk/full" ]]; then ASTERISK_LOG="/var/log/asterisk/full"; fi
        if [[ -n "$ASTERISK_LOG" ]]; then
            cat <<EOF >>/etc/fail2ban/jail.local

[asterisk]
enabled  = true
filter   = asterisk
port     = 5060,5061
logpath  = $ASTERISK_LOG
maxretry = 5
bantime  = 24h
EOF
        fi

        # 13. DYNAMIC DETECTION: ZABBIX
        if [[ -f "/var/log/zabbix/zabbix_server.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/zabbix-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*failed login of user .* from <HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/zabbix-auth.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[zabbix-auth]
enabled = true
port    = http,https,10050,10051
filter  = zabbix-auth
logpath = /var/log/zabbix/zabbix_server.log
maxretry = 3
bantime  = 24h
EOF
        fi

        # 14. DYNAMIC DETECTION: HAPROXY
        if [[ -f "/var/log/haproxy.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/haproxy-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:\d+ .+(400|403|404|429) .+\$\nignoreregex =" >/etc/fail2ban/filter.d/haproxy-guard.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[haproxy-guard]
enabled = true
port    = http,https,8080
filter  = haproxy-guard
logpath = /var/log/haproxy.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 15. DYNAMIC DETECTION: WIREGUARD
        if [[ -d "/etc/wireguard" ]]; then
            WG_LOG=""
            if [[ -f "/var/log/kern-firewall.log" ]]; then
                WG_LOG="/var/log/kern-firewall.log"
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi
            if [[ -n "$WG_LOG" ]]; then
                if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                    echo -e "[Definition]\nfailregex = ^.*wireguard: .* Handshake for peer .* \\(<HOST>:[0-9]+\\) did not complete.*\$\nignoreregex =" >/etc/fail2ban/filter.d/wireguard.conf
                fi
                cat <<EOF >>/etc/fail2ban/jail.local

[wireguard]
enabled = true
port    = 51820
protocol= udp
filter  = wireguard
logpath = $WG_LOG
maxretry = 5
bantime  = 24h
EOF
            fi
        fi

        # 16. DYNAMIC DETECTION: PHPMYADMIN
        PMA_LOG="$WP_LOG"
        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                    echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"POST .*phpmyadmin.* HTTP.*\" 200\nignoreregex =" >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
                fi
                cat <<EOF >>/etc/fail2ban/jail.local

[phpmyadmin-custom]
enabled = true
port    = http,https
filter  = phpmyadmin-custom
logpath = $PMA_LOG
maxretry = 3
bantime  = 24h
EOF
            fi
        fi

        # 17. DYNAMIC DETECTION: LARAVEL
        LARAVEL_LOG=""
        for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
            if [[ -f "$path" ]]; then
                LARAVEL_LOG="$path"
                break
            fi
        done
        if [[ -n "$LARAVEL_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/laravel-auth.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[laravel-auth]
enabled = true
port    = http,https
filter  = laravel-auth
logpath = $LARAVEL_LOG
maxretry = 5
bantime  = 24h
EOF
        fi

        # 18. DYNAMIC DETECTION: GRAFANA
        if [[ -f "/var/log/grafana/grafana.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/grafana-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/grafana-auth.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[grafana-auth]
enabled = true
port    = 3000,http,https
filter  = grafana-auth
logpath = /var/log/grafana/grafana.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 19. DYNAMIC DETECTION: SENDMAIL
        SM_LOG=""
        if [[ -f "/var/log/maillog" ]]; then SM_LOG="/var/log/maillog"; fi
        if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
            # HOTFIX: Self-healing native filters
            if [[ ! -f "/etc/fail2ban/filter.d/sendmail-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/sendmail-auth.conf
[Definition]
failregex = ^.*sendmail\[\d+\]: .*: \[<HOST>\] .*: AUTH=server, relay=.*, authid=.*, status=.*(?:fail|NO|temporarily).*$
ignoreregex = 
EOF
            fi
            if [[ ! -f "/etc/fail2ban/filter.d/sendmail-reject.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/sendmail-reject.conf
[Definition]
failregex = ^.*sendmail\[\d+\]: .*: ruleset=check_rcpt, arg1=.*, relay=.* \[<HOST>\], reject=.*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[sendmail-auth]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 3
bantime  = 24h

[sendmail-reject]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 20. DYNAMIC DETECTION: SQUID PROXY
        if [[ -f "/var/log/squid/access.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/squid-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" >/etc/fail2ban/filter.d/squid-custom.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[squid-custom]
enabled = true
port    = 3128,8080
filter  = squid-custom
logpath = /var/log/squid/access.log
maxretry = 5
bantime  = 24h
EOF
        fi

        # 21. DYNAMIC DETECTION: DOVECOT (IMAP/POP3)
        DOVECOT_LOG=""
        if [[ -f "/var/log/maillog" ]]; then DOVECOT_LOG="/var/log/maillog"; fi
        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            if [[ ! -f "/etc/fail2ban/filter.d/dovecot-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*\$\nignoreregex =" >/etc/fail2ban/filter.d/dovecot-custom.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[dovecot-custom]
enabled = true
port    = pop3,pop3s,imap,imaps,submission,465,587
filter  = dovecot-custom
logpath = $DOVECOT_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 22. DYNAMIC DETECTION: OPENVPN
        OVPN_LOG=""
        if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn/openvpn.log"
        elif [[ -f "/var/log/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn.log"
        elif [[ -f "/var/log/messages" ]]; then OVPN_LOG="/var/log/messages"; fi
        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*\$\nignoreregex =" >/etc/fail2ban/filter.d/openvpn-custom.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[openvpn-custom]
enabled = true
port    = 1194
protocol= udp
filter  = openvpn-custom
logpath = $OVPN_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 23. DYNAMIC DETECTION: GITEA / FORGEJO
        GITEA_LOG=""
        if [[ -f "/var/log/gitea/gitea.log" ]]; then
            GITEA_LOG="/var/log/gitea/gitea.log"
        elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then GITEA_LOG="/var/log/forgejo/forgejo.log"; fi
        if [[ -n "$GITEA_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Failed authentication attempt for .* from <HOST>:.*\$\nignoreregex =" >/etc/fail2ban/filter.d/gitea-custom.conf
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[gitea-custom]
enabled = true
port    = http,https,3000
filter  = gitea-custom
logpath = $GITEA_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 24. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth-syswarden.log" ]]; then
            AUTH_LOG="/var/log/auth-syswarden.log"
        elif [[ -f "/var/log/secure" ]]; then AUTH_LOG="/var/log/secure"; fi
        if [[ -n "$AUTH_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-privesc.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-privesc.conf
[Definition]
failregex = ^.*(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^.*(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^.* PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-privesc]
enabled = true
port    = 0:65535
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 25. DYNAMIC DETECTION: CI/CD & DEVOPS INFRASTRUCTURE (JENKINS / GITLAB)
        if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jenkins.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-jenkins]
enabled  = true
port     = http,https,8080
filter   = syswarden-jenkins
logpath  = /var/log/jenkins/jenkins.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        GITLAB_LOG=""
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
            GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi
        if [[ -n "$GITLAB_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-gitlab]
enabled  = true
port     = http,https
filter   = syswarden-gitlab
logpath  = $GITLAB_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 26. DYNAMIC DETECTION: CRITICAL MIDDLEWARES (REDIS / RABBITMQ)
        REDIS_LOG=""
        if [[ -f "/var/log/redis/redis-server.log" ]]; then
            REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi
        if [[ -n "$REDIS_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-redis.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-redis.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Non-greedy matching (.*?) prevents ReDoS on massive log lines
failregex = ^.*? <HOST>:\d+ .*? [Aa]uthentication failed.*$
            ^.*? Client <HOST>:\d+ disconnected, .*? [Aa]uthentication.*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-redis]
enabled  = true
port     = 6379
filter   = syswarden-redis
logpath  = $REDIS_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        RABBIT_LOG=""
        if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"; fi
        if [[ -n "$RABBIT_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-rabbitmq.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-rabbitmq.conf
[Definition]
failregex = ^.*?HTTP access denied: .*? from <HOST>.*$
            ^.*?AMQP connection <HOST>:\d+ .*? failed: .*?authentication failure.*$
            ^.*?<HOST>:\d+ .*? (?:invalid credentials|authentication failed).*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-rabbitmq]
enabled  = true
port     = 5672,15672
filter   = syswarden-rabbitmq
logpath  = $RABBIT_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        # 27. DYNAMIC DETECTION: PORT SCANNERS & LATERAL MOVEMENT (NMAP / MASSCAN)
        FIREWALL_LOG=""
        if [[ -f "/var/log/kern-firewall.log" ]]; then
            FIREWALL_LOG="/var/log/kern-firewall.log"
        elif [[ -f "/var/log/messages" ]]; then FIREWALL_LOG="/var/log/messages"; fi

        if [[ -n "$FIREWALL_LOG" ]]; then
            log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."

            # Always overwrite to ensure the latest threat signatures are active
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-portscan.conf
[INCLUDES]
before = common.conf

[Definition]
# DEVSECOPS OPTIMIZATION: Strict prefix anchoring to strictly prevent user-space Log Injection
failregex = ^%(__prefix_line)s(?:kernel:\s+)?(?:\[\s*\d+\.\d+\]\s+)?\[SysWarden-BLOCK\].*?SRC=<HOST> 
ignoreregex = 
EOF

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Port Scanner & Lateral Movement Protection ---
[syswarden-portscan]
enabled  = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port     = 0:65535
filter   = syswarden-portscan
logpath  = $FIREWALL_LOG
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
        fi

        # 28. DYNAMIC DETECTION: SENSITIVE FILE INTEGRITY & AUDITD ANOMALIES
        AUDIT_LOG="/var/log/audit/audit.log"
        if command -v auditd >/dev/null 2>&1 && [[ -f "$AUDIT_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-auditd.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-auditd]
enabled  = true
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 29. DYNAMIC DETECTION: RCE & REVERSE SHELL PAYLOADS
        RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "/var/log/httpd/access_log"; do
            if [[ -f "$log_file" ]]; then RCE_LOGS="$RCE_LOGS $log_file"; fi
        done
        RCE_LOGS=$(echo "$RCE_LOGS" | xargs)

        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc\s+-e|nc\x2520-e|nc\s+-c|curl\s+http|curl\x2520http|wget\s+http|wget\x2520http|python\s+-c|php\s+-r|;\s*bash\s+-i|&\s*bash\s+-i).*" .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 24h
EOF
        fi

        # 30. DYNAMIC DETECTION: MALICIOUS AI BOTS & SCRAPERS
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) .*" \d{3} .* ".*(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai).*".*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-aibots]
enabled  = true
port     = http,https
filter   = syswarden-aibots
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 31. DYNAMIC DETECTION: MALICIOUS SCANNERS & PENTEST TOOLS
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) .*" \d{3} .* ".*(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf).*".*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-badbots]
enabled  = true
port     = http,https
filter   = syswarden-badbots
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 32. DYNAMIC DETECTION: LAYER 7 DDOS (HTTP FLOOD)
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-httpflood.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) .*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

# --- Layer 7 DDoS & HTTP Flood Protection ---
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $RCE_LOGS
backend  = auto
# Enterprise Policy: 300 requests in 5 seconds allows Python I/O buffer to process floods without Self-DoS
maxretry = 300
findtime = 5
bantime  = 24h
EOF
        fi

        # 33. DYNAMIC DETECTION: WEBSHELL UPLOADS (LFI / RFI)
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads).*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?.*)? HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-webshell]
enabled  = true
port     = http,https
filter   = syswarden-webshell
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 34. DYNAMIC DETECTION: SQL INJECTION (SQLi) & XSS PAYLOADS
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sqli-xss.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F).*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-sqli-xss]
enabled  = true
port     = http,https
filter   = syswarden-sqli-xss
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 35. DYNAMIC DETECTION: STEALTH SECRETS & CONFIG HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-secretshunter.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-secretshunter.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/\.env[^ ]*|/\.git/?.*|/\.aws/?.*|/\.ssh/?.*|/id_rsa[^ ]*|/id_ed25519[^ ]*|/[^ ]*\.(?:sql|bak|swp|db|sqlite3?)(?:\.gz|\.zip)?|/docker-compose\.ya?ml|/wp-config\.php\.(?:bak|save|old|txt|zip)) HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-secretshunter]
enabled  = true
port     = http,https
filter   = syswarden-secretshunter
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 36. DYNAMIC DETECTION: SSRF & CLOUD METADATA EXFILTRATION
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:169\.254\.169\.254|latest/meta-data|metadata\.google\.internal|/v1/user-data|/metadata/v1).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 37. DYNAMIC DETECTION: JNDI, LOG4J & SSTI PAYLOADS
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Consolidated regex paths for reduced CPU cyclic overhead
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*?(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] ".*?" \d{3} .*? "(?:\$\{jndi:|\x2524\x257Bjndi:).*?"$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-jndi-ssti]
enabled  = true
port     = http,https
filter   = syswarden-jndi-ssti
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 38. DYNAMIC DETECTION: API MAPPING & SWAGGER HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) .*(?:/swagger-ui[^ ]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ ]*|/graphiql|/graphql/schema) HTTP/.*" (403|404) .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-apimapper]
enabled  = true
port     = http,https
filter   = syswarden-apimapper
logpath  = $RCE_LOGS
backend  = auto
maxretry = 2
bantime  = 48h
EOF
        fi

        # 38.5. DYNAMIC DETECTION: BEHAVIORAL IDOR ENUMERATION & API BRUTE-FORCING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Behavioral IDOR Guard."

            # Create Filter for IDOR (Insecure Direct Object Reference) Enumeration
            # Targets massive enumeration on sensitive endpoints (/api, /user, /invoice, /doc)
            # Triggers on access errors (401, 403) or not found objects (404)
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-idor-enum.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-idor-enum.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH) .*(?:/api/v[0-9]+/|/users?/|/profile/|/invoices?/|/downloads?/|/docs?/|/id/|/view\?id=)[a-zA-Z0-9_-]+/?.* HTTP/.*" (401|403|404) .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Behavioral IDOR Enumeration & API Brute-Forcing Protection ---
[syswarden-idor-enum]
enabled  = true
port     = http,https
filter   = syswarden-idor-enum
logpath  = $RCE_LOGS
backend  = auto
# Policy: 15 direct reference errors within 10 seconds = Targeted offensive scan
maxretry = 15
findtime = 10
bantime  = 24h
EOF
        fi

        # 39. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*?(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb)).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-lfi-advanced]
enabled  = true
port     = http,https
filter   = syswarden-lfi-advanced
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 40. DYNAMIC DETECTION: VAULTWARDEN (BITWARDEN COMPATIBLE PASSWORD MANAGER)
        VW_LOG=""
        for path in "/var/log/vaultwarden/vaultwarden.log" "/vw-data/vaultwarden.log" "/opt/vaultwarden/vaultwarden.log"; do
            if [[ -f "$path" ]]; then
                VW_LOG="$path"
                break
            fi
        done
        if [[ -n "$VW_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-vaultwarden.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-vaultwarden.conf
[Definition]
failregex = ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Invalid password.*from <HOST>.*\s*$
            ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Client IP: <HOST>.*\s*$
            ^.*\[(?:ERROR|WARN)\].*Failed login attempt.*from <HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-vaultwarden]
enabled  = true
port     = http,https,80,443,8080
filter   = syswarden-vaultwarden
logpath  = $VW_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 41. DYNAMIC DETECTION: IAM & SSO (AUTHELIA / AUTHENTIK)
        SSO_LOG=""
        for path in "/var/log/authelia/authelia.log" "/var/log/authentik/authentik.log" "/opt/authelia/authelia.log" "/opt/authentik/authentik.log"; do
            if [[ -f "$path" ]]; then
                SSO_LOG="$path"
                break
            fi
        done
        if [[ -n "$SSO_LOG" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sso.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sso.conf
[Definition]
failregex = ^.*(?:level=error|level=\"error\").*msg=\"Authentication failed\".*remote_ip=\"<HOST>\".*$
            ^.*(?:\"event\":\"Failed login\"|event=\'Failed login\').*(?:\"client_ip\":\"<HOST>\"|\"remote_ip\":\"<HOST>\").*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-sso]
enabled  = true
port     = http,https
filter   = syswarden-sso
logpath  = $SSO_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 42. DYNAMIC DETECTION: BEHAVIORAL SILENT SCANNERS (DIRBUSTER/GOBUSTER)
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-silent-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-silent-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PROPFIND) .*" (?:400|401|403|404|405|444) .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-silent-scanner]
enabled  = true
port     = http,https
filter   = syswarden-silent-scanner
logpath  = $RCE_LOGS
backend  = auto
maxretry = 20
findtime = 10
bantime  = 48h
EOF
        fi

        # 43. DYNAMIC DETECTION: OPEN PROXY PROBING & EXOTIC HTTP METHOD ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) .*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//.*" \d{3} .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-proxy-abuse]
enabled  = true
port     = http,https
filter   = syswarden-proxy-abuse
logpath  = $RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
        fi

        # 44. DYNAMIC DETECTION: TELNET HONEYPOT & IOT BOTNETS (MIRAI/GAFGYT)
        TELNET_LOG=""
        for log_file in "/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/auth-syswarden.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$TELNET_LOG" ]]; then
                    TELNET_LOG="$log_file"
                else
                    # shellcheck disable=SC1003
                    TELNET_LOG+=$'\n          '"$log_file"
                fi
            fi
        done
        if [[ -n "$TELNET_LOG" ]] && { command -v telnetd >/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -qE ':(23)\b'; }; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-telnet.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-telnet.conf
[Definition]
failregex = ^.*(?:in\.telnetd|telnetd)(?:\[\d+\])?: connect from (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+FAILED LOGIN.*(?:FROM|from) (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+.*(?:authentication failure|invalid password).*rhost=(?:::f{4}:)?<HOST>.*\s*$
            ^.*pam_unix\(login:auth\): authentication failure;.*rhost=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-telnet]
enabled  = true
port     = 23,telnet
filter   = syswarden-telnet
logpath  = $TELNET_LOG
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 48h
EOF
        fi

        # 45. DYNAMIC DETECTION: GENERIC BRUTE-FORCE & PASSWORD SPRAYING (HTML/PHP LOGINS)
        # Relies on $RCE_LOGS aggregated earlier in the script
        if [[ -n "${RCE_LOGS:-}" ]]; then
            log "INFO" "Web access logs detected. Enabling Generic Brute-Force & Password Spraying Guard."

            # Create Filter for generic login endpoints
            # Catches POST requests to common auth endpoints returning 200 (form reload on fail), 401, or 403
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-generic-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-generic-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/login|/sign-in|/signin|/log-in|/auth|/authenticate|/admin/login|/user/login|/member/login)[^ ]*(?:\.php|\.html|\.htm|\.jsp|\.aspx)? HTTP/.*" (?:200|401|403) .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Generic Web Authentication Brute-Force & Password Spraying Protection ---
[syswarden-generic-auth]
enabled  = true
port     = http,https
filter   = syswarden-generic-auth
logpath  = $RCE_LOGS
backend  = auto
# Policy: 5 failed login attempts (or password spraying hits) within 10 minutes = 24h ban
maxretry = 5
findtime = 10m
bantime  = 24h
EOF
        fi

        # 46. DYNAMIC DETECTION: ODOO ERP
        ODOO_LOG=""
        # Search for standard Odoo log files
        if [[ -f "/var/log/odoo/odoo-server.log" ]]; then
            ODOO_LOG="/var/log/odoo/odoo-server.log"
        elif [[ -f "/var/log/odoo/odoo.log" ]]; then
            ODOO_LOG="/var/log/odoo/odoo.log"
        fi

        if [[ -n "$ODOO_LOG" ]]; then
            log "INFO" "Odoo ERP logs detected. Enabling Odoo Guard."

            # Create Filter for Odoo Authentication Failures
            # Catches standard Werkzeug auth errors across Odoo v12 to v17
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-odoo.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-odoo.conf
[Definition]
failregex = ^.* \d+ INFO \S+ odoo\.addons\.base\.models\.res_users: Login failed for db:.* login:.* from <HOST>
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Odoo ERP Protection ---
[syswarden-odoo]
enabled  = true
port     = http,https,8069
filter   = syswarden-odoo
logpath  = $ODOO_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        # 47. DYNAMIC DETECTION: PRESTASHOP E-COMMERCE
        if [[ -n "$RCE_LOGS" ]]; then
            # PrestaShop often runs on the main web server logs
            # We check if it's potentially a web hosting server
            log "INFO" "Web access logs detected. Enabling PrestaShop Guard."

            # Create Filter for PrestaShop Backoffice Brute-Force
            # The admin URL is dynamic, but it always POSTs to a controller named AdminLogin
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-prestashop.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-prestashop.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST /[^ ]*index\.php\?.*controller=AdminLogin.* HTTP/.*" 200 .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- PrestaShop E-Commerce Protection ---
[syswarden-prestashop]
enabled  = true
port     = http,https
filter   = syswarden-prestashop
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 48. DYNAMIC DETECTION: ATLASSIAN JIRA & CONFLUENCE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Atlassian Guard."

            # Create Filter for Jira and Confluence Auth Failures
            # Catches: Jira (/login.jsp, /rest/auth) and Confluence (/dologin.action)
            # HTTP 200 (Form reload), 401 (Unauthorized API), 403 (Forbidden API)
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-atlassian.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-atlassian.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/login\.jsp|/dologin\.action|/rest/auth/\d+/session) HTTP/.*" (?:401|403|200) .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Atlassian Jira & Confluence Protection ---
[syswarden-atlassian]
enabled  = true
port     = http,https,8080,8090
filter   = syswarden-atlassian
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
        fi

        # --- HOTFIX: Ensure daemon is executable on Slackware ---
        if [[ -f /etc/rc.d/rc.fail2ban ]]; then
            chmod +x /etc/rc.d/rc.fail2ban
        fi

        if [[ -x /etc/rc.d/rc.fail2ban ]]; then
            /etc/rc.d/rc.fail2ban restart </dev/null 2>/dev/null || true
        else
            fail2ban-client reload </dev/null 2>/dev/null || fail2ban-client start </dev/null 2>/dev/null || true
        fi
    fi
}

setup_wireguard() {
    if [[ "${USE_WIREGUARD:-n}" != "y" ]]; then return; fi
    log "INFO" "Configuring WireGuard VPN for Slackware..."

    if [[ -f "/etc/wireguard/wg0.conf" ]]; then return; fi

    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard /etc/wireguard/clients

    echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/99-syswarden-wireguard.conf
    sysctl -p /etc/sysctl.d/99-syswarden-wireguard.conf >/dev/null 2>&1 || true

    (
        umask 077
        SERVER_PRIV=$(wg genkey)
        SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
        CLIENT_PRIV=$(wg genkey)
        CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
        PRESHARED_KEY=$(wg genpsk)

        ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"
        SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || echo "127.0.0.1")

        SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)

        POSTUP=""
        POSTDOWN=""
        if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            POSTUP="nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname \"$ACTIVE_IF\" masquerade'; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname \"wg0\" accept'; nft 'insert rule inet filter forward oifname \"wg0\" accept'"
            POSTDOWN="nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname \"wg0\" accept 2>/dev/null || true; nft delete rule inet filter forward oifname \"wg0\" accept 2>/dev/null || true"
        else
            POSTUP="iptables -t nat -I POSTROUTING 1 -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT"
            POSTDOWN="iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true"
        fi

        cat <<EOF >/etc/wireguard/wg0.conf
[Interface]
Address = ${SUBNET_BASE}.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
PostUp = $POSTUP
PostDown = $POSTDOWN

[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${SUBNET_BASE}.2/32
EOF

        cat <<EOF >/etc/wireguard/clients/admin-pc.conf
[Interface]
PrivateKey = $CLIENT_PRIV
Address = ${SUBNET_BASE}.2/24
MTU = 1360
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    )

    cat <<'EOF' >/etc/rc.d/rc.wireguard
#!/bin/bash
case "$1" in
    start) wg-quick up wg0 ;;
    stop) wg-quick down wg0 ;;
    restart) wg-quick down wg0; wg-quick up wg0 ;;
esac
EOF
    chmod +x /etc/rc.d/rc.wireguard

    if ! grep -q "/etc/rc.d/rc.wireguard" /etc/rc.d/rc.local 2>/dev/null; then
        echo "if [ -x /etc/rc.d/rc.wireguard ]; then /etc/rc.d/rc.wireguard start; fi" >>/etc/rc.d/rc.local
    fi
    /etc/rc.d/rc.wireguard start 2>/dev/null || true
}

display_wireguard_qr() {
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -f "/etc/wireguard/clients/admin-pc.conf" ]]; then
        echo -e "\n${RED}========================================================================${NC}"
        echo -e "${YELLOW}           WIREGUARD MANAGEMENT VPN - SCAN TO CONNECT${NC}"
        echo -e "${RED}========================================================================${NC}\n"
        if command -v qrencode >/dev/null; then
            qrencode -t ansiutf8 </etc/wireguard/clients/admin-pc.conf
        else
            echo -e "${YELLOW}[!] qrencode not installed. Cannot display QR code. Please copy config manually.${NC}"
        fi
        echo -e "\n${GREEN}[✔] Client Configuration File Saved At:${NC} /etc/wireguard/clients/admin-pc.conf"
    fi
}

display_dashboard_info() {
    local public_ip
    public_ip=$(curl -4 -s ifconfig.me 2>/dev/null || echo "127.0.0.1")
    echo -e "\n${BLUE}========================================================================${NC}"
    echo -e "${GREEN}  [✔] SYSWARDEN DASHBOARD IS LIVE${NC}"
    echo -e "${BLUE}========================================================================${NC}"
    echo -e "Access your telemetry interface securely via your web browser:"
    echo -e "${YELLOW}URL:${NC} https://${public_ip}:9999"
    echo -e "${YELLOW}Note:${NC} A self-signed SSL certificate is used. You must accept the security warning."
}

setup_abuse_reporting() {
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_ABUSE:-n}
    else
        read -p "Enable AbuseIPDB reporting? (y/N): " response
    fi

    if [[ "$response" =~ ^[Yy]$ ]]; then

        # --- HOTFIX: Strict Validation with CI/CD Auto-Mode support ---
        if [[ "${1:-}" == "auto" ]]; then
            USER_API_KEY=${SYSWARDEN_ABUSE_API_KEY:-""}
            if [[ -n "$USER_API_KEY" && ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                echo "ERROR: Auto Mode: Invalid SYSWARDEN_ABUSE_API_KEY format."
                echo "Must be exactly 80 lowercase letters/numbers. Skipping setup."
                return
            fi
        else
            while true; do
                read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
                if [[ -z "$USER_API_KEY" ]]; then
                    break
                elif [[ ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                    echo "ERROR: Invalid API Key format. It must contain exactly 80 lowercase letters and numbers."
                else
                    echo "[✔] API Key syntax validated."
                    break
                fi
            done
        fi
        # ---------------------------------------------------------------------

        if [[ -z "$USER_API_KEY" ]]; then return; fi

        cat <<'EOF' >/usr/local/bin/syswarden_reporter.py
#!/usr/bin/env python3
import subprocess
import select
import re
import requests
import time
import ipaddress
import socket
import threading
import json
import os

API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900
CACHE_FILE = "/var/lib/syswarden/abuse_cache.json"

reported_cache = {}
cache_lock = threading.Lock()

def load_cache():
    global reported_cache
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                reported_cache = json.load(f)
        except Exception:
            reported_cache = {}

def save_cache():
    try:
        with cache_lock:
            with open(CACHE_FILE, 'w') as f:
                json.dump(reported_cache, f)
    except Exception as e:
        pass

def clean_cache():
    current_time = time.time()
    with cache_lock:
        expired = [ip for ip, ts in reported_cache.items() if current_time - ts > REPORT_INTERVAL]
        for ip in expired:
            del reported_cache[ip]
    if expired: save_cache()

def send_report(ip, categories, comment):
    current_time = time.time()
    try: ipaddress.ip_address(ip)
    except ValueError: return

    with cache_lock:
        if ip in reported_cache and (current_time - reported_cache[ip] < REPORT_INTERVAL): return 
        reported_cache[ip] = current_time
    save_cache()
    
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    full_comment = f"[{socket.gethostname()}] {comment}"
    params = {'ip': ip, 'categories': categories, 'comment': full_comment}

    try:
        response = requests.post(url, params=params, headers=headers)
        if response.status_code == 200: clean_cache()
        elif response.status_code == 429: clean_cache()
        else:
            with cache_lock:
                if ip in reported_cache: del reported_cache[ip]
            save_cache()
    except Exception:
        with cache_lock:
            if ip in reported_cache: del reported_cache[ip]
        save_cache()

def monitor_logs():
    load_cache()
    # HOTFIX: Pure UNIX flat-file tailing for Slackware (Replaces journalctl)
    f = subprocess.Popen(['tail', '-F', '-q', '/var/log/kern-firewall.log', '/var/log/fail2ban.log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    regex_fw = re.compile(r"\[SysWarden-(BLOCK|DOCKER)\].*SRC=([\d\.]+).*DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            if not line: continue

            # --- FIREWALL LOGIC ---
            if ENABLE_FW:
                match_fw = regex_fw.search(line)
                if match_fw:
                    ip = match_fw.group(2)
                    try:
                        port = int(match_fw.group(3))
                    except ValueError:
                        port = 0
                    
                    # Base: Scanning for open ports and vulnerable services (Cat 14)
                    cats = ["14"]
                    attack_type = "Port Scan / Probing"

                    if port in [80, 443, 4443, 8080, 8443]: cats.extend(["15", "21"]); attack_type = "Web Attack"
                    elif port in [22, 2222, 22222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                    elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT Attack"
                    elif port == 88: cats.extend(["15", "18"]); attack_type = "Kerberos Attack"
                    elif port in [139, 445]: cats.extend(["15", "18"]); attack_type = "SMB/Possible Ransomware Attack"
                    elif port in [389, 636]: cats.extend(["15", "18"]); attack_type = "LDAP/LDAPS Attack"
                    elif port in [1433, 3306, 5432, 27017, 6379, 9200, 11211]: cats.extend(["15", "18"]); attack_type = "Database/Cache Attack"
                    elif port in [8006, 9090, 3000, 2375, 2376]: cats.extend(["15", "21"]); attack_type = "Infra/DevOps Attack"
                    elif port == 4444: cats.extend(["15", "20"]); attack_type = "Possible C2 Host"
                    elif port in [3389, 5900]: cats.extend(["18"]); attack_type = "RDP/VNC Attack"
                    elif port == 21: cats.extend(["5", "18"]); attack_type = "FTP Attack"
                    elif port in [25, 110, 143, 465, 587, 993, 995]: cats.extend(["11", "18"]); attack_type = "Mail Service Attack"
                    elif port in [1080, 3128, 8118]: cats.extend(["9", "15"]); attack_type = "Open Proxy Probe"
                    elif port in [5060, 5061]: cats.extend(["8", "18"]); attack_type = "SIP/VoIP Attack"
                    elif port in [1194, 51820, 51821]: cats.extend(["15", "18"]); attack_type = "VPN Probe"

                    cats = list(set(cats)) # Deduplicate array before sending
                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type})")).start()
                    continue

            # --- FAIL2BAN LOGIC (Layer 7) ---
            if ENABLE_F2B:
                match_f2b = regex_f2b.search(line)
                if match_f2b and "SysWarden-BLOCK" not in line:
                    jail = match_f2b.group(1).lower()
                    ip = match_f2b.group(2)
                    
                    cats = []
                    
                    # 1. Web Vulnerability Scanners & Pentest Tools
                    if any(x in jail for x in ["badbot", "scanner", "apimapper", "secretshunter", "idor"]): cats.extend(["14", "15", "19", "21"])
                    # 2. SQLi & XSS
                    elif "sqli" in jail or "xss" in jail: cats.extend(["15", "16", "21"])
                    # 3. RCE, WebShells, LFI/RFI, SSRF, JNDI
                    elif any(x in jail for x in ["revshell", "webshell", "lfi", "ssrf", "jndi"]): cats.extend(["15", "21"])
                    # 4. Layer 7 DDoS (HTTP Flood)
                    elif "httpflood" in jail: cats.extend(["4", "21"])
                    # 5. AI Bots & Scrapers
                    elif "aibot" in jail: cats.extend(["19", "21"])
                    # 6. Proxy Abuse / Tunneling
                    elif any(x in jail for x in ["proxy-abuse", "squid", "haproxy"]): cats.extend(["9", "15", "21"])
                    # 7. SSH Brute-Force
                    elif "ssh" in jail: cats.extend(["18", "22"])
                    # 8. FTP Brute-Force
                    elif "vsftpd" in jail or "ftp" in jail: cats.extend(["5", "18"])
                    # 9. Mail Service Abuse
                    elif any(x in jail for x in ["postfix", "sendmail", "dovecot"]): cats.extend(["11", "18"])
                    # 10. Database & Middleware Brute-Force
                    elif any(x in jail for x in ["mariadb", "mongodb", "redis", "rabbitmq"]): cats.extend(["15", "18"])
                    # 11. Privilege Escalation & Auditd
                    elif any(x in jail for x in ["privesc", "auditd", "proxmox"]): cats.extend(["15", "18"])
                    # 12. Web App Logins (Auth/CMS/SSO/Generic)
                    elif any(x in jail for x in ["auth", "generic-auth", "wordpress", "drupal", "nextcloud", "phpmyadmin", "laravel", "grafana", "zabbix", "gitea", "cockpit", "vaultwarden", "sso", "odoo", "prestashop", "atlassian"]): cats.extend(["18", "21"])
                    # 13. VPN 
                    elif "wireguard" in jail or "openvpn" in jail: cats.extend(["15", "18"])
                    # 14. VoIP
                    elif "asterisk" in jail: cats.extend(["8", "18"])
                    # 15. Portscan
                    elif "portscan" in jail: cats.extend(["14"])
                    # 16. Persistent Attacker (Recidive) / Horizontal Movement
                    elif "recidive" in jail: cats.extend(["14", "15", "18"])
                    # 17. Fallback
                    else: cats.extend(["15", "18"])

                    cats = list(set(cats)) # Deduplicate array before sending
                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {match_f2b.group(1)})")).start()

if __name__ == "__main__":
    monitor_logs()
EOF
        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        chown root:root /usr/local/bin/syswarden_reporter.py
        chmod 750 /usr/local/bin/syswarden_reporter.py
        mkdir -p /var/lib/syswarden

        # SLACKWARE NATIVE DAEMON
        cat <<'EOF' >/etc/rc.d/rc.syswarden-reporter
#!/bin/bash
PIDFILE="/var/run/syswarden-reporter.pid"
case "$1" in
    start)
        if [ ! -f $PIDFILE ]; then
            nohup /usr/local/bin/syswarden_reporter.py >/dev/null 2>&1 &
            echo $! > $PIDFILE
        fi
        ;;
    stop)
        if [ -f $PIDFILE ]; then
            kill $(cat $PIDFILE) 2>/dev/null || true
            rm -f $PIDFILE
        fi
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
esac
EOF
        chmod +x /etc/rc.d/rc.syswarden-reporter
        if ! grep -q "/etc/rc.d/rc.syswarden-reporter" /etc/rc.d/rc.local 2>/dev/null; then
            echo "if [ -x /etc/rc.d/rc.syswarden-reporter ]; then /etc/rc.d/rc.syswarden-reporter start; fi" >>/etc/rc.d/rc.local
        fi
        /etc/rc.d/rc.syswarden-reporter restart
    fi
}

setup_telemetry_backend() {
    log "INFO" "Installation of the advanced telemetry engine (Slackware)..."
    local BIN_PATH="/usr/local/bin/syswarden-telemetry.sh"
    local UI_DIR="/etc/syswarden/ui"

    cat <<'EOF' >"$BIN_PATH"
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'
trap 'wait' EXIT

exec 9>"/tmp/syswarden-telemetry.lock"
if ! flock -n 9; then exit 0; fi

SYSWARDEN_DIR="/etc/syswarden"
UI_DIR="/etc/syswarden/ui"
TMP_FILE="$UI_DIR/data.json.tmp"
DATA_FILE="$UI_DIR/data.json"
mkdir -p "$UI_DIR"

SYS_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SYS_HOSTNAME=$(hostname)
SYS_UPTIME=$(awk '{d=int($1/86400); h=int(($1%86400)/3600); m=int(($1%3600)/60); if(d>0) printf "%dd %dh %dm", d, h, m; else printf "%dh %dm", h, m}' /proc/uptime 2>/dev/null || echo "Unknown")
SYS_LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}' || echo "0, 0, 0")
SYS_RAM_USED=$(free -m 2>/dev/null | awk '/^Mem:/{print $3}')
SYS_RAM_USED=${SYS_RAM_USED:-0}
SYS_RAM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
SYS_RAM_TOTAL=${SYS_RAM_TOTAL:-0}

L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"; BANNED_IPS_JSON="[]"

if command -v fail2ban-client >/dev/null && timeout 2 fail2ban-client ping >/dev/null 2>&1; then
    JAIL_LIST=$(timeout 2 fail2ban-client status 2>/dev/null | awk -F'Jail list:[ \t]*' '/Jail list:/ {print $2}' | tr -d ' ' | tr ',' '\n' || true)
    for JAIL in $JAIL_LIST; do
        [[ -z "$JAIL" ]] && continue
        L7_ACTIVE_JAILS=$((L7_ACTIVE_JAILS + 1))
        STATUS_OUT=$(timeout 3 fail2ban-client status "$JAIL" 2>/dev/null || echo "")
        if [[ -n "$STATUS_OUT" ]]; then
            BANNED_COUNT=$(echo "$STATUS_OUT" | awk '/Currently banned:/ {print $4}' || echo "0")
            BANNED_COUNT=${BANNED_COUNT:-0}
            L7_TOTAL_BANNED=$((L7_TOTAL_BANNED + BANNED_COUNT))
            if [[ "$BANNED_COUNT" -gt 0 ]]; then
                JAILS_JSON=$(echo "$JAILS_JSON" | jq --arg n "$JAIL" --argjson c "$BANNED_COUNT" '. + [{"name": $n, "count": $c}]')
                BANNED_IPS=$(echo "$STATUS_OUT" | awk -F'Banned IP list:[ \t]*' '/Banned IP list:/ {print $2}' | tr -d ',' | tr ' ' '\n' | tail -n 50 || true)
                for IP in $BANNED_IPS; do
                    if [[ -n "$IP" ]]; then
                        BANNED_IPS_JSON=$(echo "$BANNED_IPS_JSON" | jq --arg ip "$IP" --arg j "$JAIL" '. + [{"ip": $ip, "jail": $j}]')
                    fi
                done
            fi
        fi
    done
fi

TOP_ATTACKERS_JSON="[]"
TOP_STATS=$(cat /var/log/fail2ban.log 2>/dev/null | grep -E "\] (Restore )?Ban " | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr | head -n 10 || true)
if [[ -n "$TOP_STATS" ]]; then
    while IFS=" " read -r count ip; do
        if [[ -n "$ip" && -n "$count" ]]; then
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --argjson c "$count" '. + [{"ip": $ip, "count": $c}]')
        fi
    done <<< "$TOP_STATS"
fi

WHITELIST_COUNT=0; WL_JSON="[]"
if [[ -f "$SYSWARDEN_DIR/whitelist.txt" ]]; then
    WHITELIST_COUNT=$(grep -cvE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    WL_IPS=$(grep -vE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    for IP in $WL_IPS; do [[ -n "$IP" ]] && WL_JSON=$(echo "$WL_JSON" | jq --arg ip "$IP" '. + [$ip]'); done
fi

jq -n \
  --arg ts "$SYS_TIMESTAMP" \
  --arg host "$SYS_HOSTNAME" \
  --arg up "$SYS_UPTIME" \
  --arg load "$SYS_LOAD" \
  --argjson ru "$SYS_RAM_USED" \
  --argjson rt "$SYS_RAM_TOTAL" \
  --argjson lg "$L3_GLOBAL" \
  --argjson lgeo "$L3_GEOIP" \
  --argjson lasn "$L3_ASN" \
  --argjson ltb "$L7_TOTAL_BANNED" \
  --argjson laj "$L7_ACTIVE_JAILS" \
  --argjson jj "$JAILS_JSON" \
  --argjson bip "$BANNED_IPS_JSON" \
  --argjson top "$TOP_ATTACKERS_JSON" \
  --argjson wlc "$WHITELIST_COUNT" \
  --argjson wlip "$WL_JSON" \
'{
  timestamp: $ts,
  system: { hostname: $host, uptime: $up, load_average: $load, ram_used_mb: $ru, ram_total_mb: $rt },
  layer3: { global_blocked: $lg, geoip_blocked: $lgeo, asn_blocked: $lasn },
  layer7: { total_banned: $ltb, active_jails: $laj, jails_data: $jj, banned_ips: $bip, top_attackers: $top },
  whitelist: { active_ips: $wlc, ips: $wlip }
}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$DATA_FILE"
chown nobody:nobody "$DATA_FILE" 2>/dev/null || chown nginx:nginx "$DATA_FILE" 2>/dev/null || true
chmod 640 "$DATA_FILE"
EOF

    chmod +x "$BIN_PATH"

    # Slackware Cron Injection
    if ! crontab -l 2>/dev/null | grep "$BIN_PATH" >/dev/null; then
        (
            crontab -l 2>/dev/null || true
            echo "* * * * * $BIN_PATH >/dev/null 2>&1"
        ) | crontab -
    fi
    "$BIN_PATH" || true
}

# ==============================================================================
# SYSWARDEN v2.15 - NGINX SECURE DASHBOARD (ENTERPRISE SAAS UI / SPA / CSP)
# ==============================================================================
function generate_dashboard() {
    log "INFO" "Generating the Enterprise SaaS Nginx Dashboard (SPA/Sidebar/CSP)..."

    local UI_DIR="/etc/syswarden/ui"
    mkdir -p "$UI_DIR"

    # HOTFIX: Directory Traversal for Nginx worker
    chmod 755 /etc/syswarden
    chmod 755 "$UI_DIR"

    # --- HOTFIX: DOWNLOAD LOCAL FONTS ---
    log "INFO" "Downloading local JetBrains Mono fonts..."
    wget -qO "$UI_DIR/JetBrainsMono-Regular.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Regular.woff2" || true
    wget -qO "$UI_DIR/JetBrainsMono-Bold.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Bold.woff2" || true

    for font in "$UI_DIR"/*.woff2; do
        if [[ -f "$font" ]]; then
            size=$(stat -c%s "$font" 2>/dev/null || stat -f%z "$font" 2>/dev/null || echo "0")
            if [[ "$size" -lt 10000 ]]; then rm -f "$font"; fi
        fi
    done
    chmod 644 "$UI_DIR"/*.woff2 2>/dev/null || true
    # -------------------------------------------

    # 1. Generating the HTML file (Enterprise Sidebar Structure)
    cat <<'EOF' >"$UI_DIR/index.html"
<!DOCTYPE html>
<html lang="en" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>SysWarden | Enterprise Console</title>
    
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
    
    <style>
        /* --- LOCAL FONTS --- */
        @font-face { font-family: 'JetBrains Mono'; src: url('JetBrainsMono-Regular.woff2') format('woff2'); font-weight: normal; font-style: normal; font-display: swap; }
        @font-face { font-family: 'JetBrains Mono'; src: url('JetBrainsMono-Bold.woff2') format('woff2'); font-weight: bold; font-style: normal; font-display: swap; }

        /* --- SAAS THEME DEFINITIONS --- */
        :root[data-bs-theme="light"] {
            --sw-bg: #f3f4f6;
            --sw-sidebar-bg: #ffffff;
            --sw-card-bg: #ffffff;
            --sw-border: #e5e7eb;
            --sw-text: #1f2937;
            --sw-text-muted: #6b7280;
            --sw-brand-text: #111827;
            --sw-brand-icon: #2563eb;
            --sw-sidebar-hover: #f3f4f6;
            --sw-sidebar-active: #eff6ff;
            --sw-sidebar-active-text: #1d4ed8;
        }
        :root[data-bs-theme="dark"] {
            --sw-bg: #09090b;
            --sw-sidebar-bg: #121214;
            --sw-card-bg: #18181b;
            --sw-border: #27272a;
            --sw-text: #f4f4f5;
            --sw-text-muted: #a1a1aa;
            --sw-brand-text: #ffffff;
            --sw-brand-icon: #eab308;
            --sw-sidebar-hover: #27272a;
            --sw-sidebar-active: #27272a;
            --sw-sidebar-active-text: #fafafa;
        }

        /* --- APP LAYOUT (APP-LIKE FEEL) --- */
        body { 
            font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            background-color: var(--sw-bg); color: var(--sw-text);
            transition: background-color 0.3s ease, color 0.3s ease;
            -webkit-font-smoothing: antialiased;
            overflow: hidden; /* Lock body scrolling, scroll only main view */
        }
        .font-mono { font-family: 'JetBrains Mono', monospace !important; }

        /* --- SIDEBAR COMPONENT --- */
        .sidebar {
            width: 280px; height: 100vh;
            background-color: var(--sw-sidebar-bg); border-right: 1px solid var(--sw-border);
            display: flex; flex-direction: column; transition: all 0.3s ease; z-index: 1040;
        }
        .nav-item-sw {
            display: flex; align-items: center; gap: 12px; padding: 10px 16px;
            color: var(--sw-text-muted); text-decoration: none; border-radius: 8px;
            font-weight: 500; font-size: 0.95rem; transition: all 0.2s ease; margin-bottom: 4px;
        }
        .nav-item-sw:hover { background-color: var(--sw-sidebar-hover); color: var(--sw-text); }
        .nav-item-sw.active { background-color: var(--sw-sidebar-active); color: var(--sw-sidebar-active-text); font-weight: 600; }
        .nav-item-sw svg { opacity: 0.7; }
        .nav-item-sw.active svg { opacity: 1; }

        /* --- MAIN VIEWPORT & SPA ROUTING --- */
        .main-wrapper { flex-grow: 1; height: 100vh; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; }
        .view-section { display: none; opacity: 0; transition: opacity 0.3s ease-in-out; }
        .view-section.active { display: block; opacity: 1; }

        /* --- CARDS & UI COMPONENTS --- */
        .card { background-color: var(--sw-card-bg); border: 1px solid var(--sw-border); border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .card-header { border-bottom: 1px solid var(--sw-border); font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; font-size: 0.80rem; color: var(--sw-text-muted); }
        .stat-value { font-size: clamp(1.2rem, 1.6vw, 1.6rem); font-weight: 800; line-height: 1.1; letter-spacing: -0.5px; }
        .stat-label { font-size: 0.80rem; text-transform: uppercase; letter-spacing: 1px; color: var(--sw-text-muted); font-weight: 600; }
        .table-container { max-height: 350px; overflow-y: auto; }
        .chart-wrapper { position: relative; height: 320px; width: 100%; }

        /* Scrollbars */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--sw-border); border-radius: 10px; }
        
        /* Overrides */
        .table { --bs-table-bg: transparent !important; }
        .table > :not(caption) > * > * { background-color: transparent !important; }
        .ip-font { font-size: 85% !important; }

        /* Mobile Sidebar Overrides */
        @media (max-width: 991px) {
            .sidebar { position: fixed; transform: translateX(-100%); }
            .sidebar.show { transform: translateX(0); }
            .sidebar-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1030; }
            .sidebar-overlay.show { display: block; }
        }
    </style>
</head>
<body class="d-flex">

    <div class="sidebar-overlay" id="sidebarOverlay"></div>

    <aside class="sidebar py-4 px-3 d-flex flex-column" id="sidebar">
        <div class="d-flex align-items-center gap-2 px-2 mb-5">
            <svg style="color: var(--sw-brand-icon);" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <span class="fs-5 fw-bold" style="color: var(--sw-brand-text); letter-spacing: -0.5px;">SYSWARDEN</span>
            <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25 rounded-pill font-mono small ms-auto">v2.15</span>
        </div>

        <nav class="flex-grow-1">
            <div class="text-uppercase font-mono small text-muted px-2 mb-2" style="font-size: 0.7rem; letter-spacing: 1px;">Analytics</div>
            <a href="#overview" class="nav-item-sw active" data-view="overview">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                Overview
            </a>
            <a href="#threats" class="nav-item-sw" data-view="threats">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
                Threat Intel
            </a>
            <a href="#system" class="nav-item-sw" data-view="system">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                System Health
            </a>
        </nav>

        <div class="mt-auto border-top pt-4" style="border-color: var(--sw-border) !important;">
            <div class="d-flex flex-column gap-2 px-2">
                <div class="font-mono small text-muted d-flex align-items-center gap-2">
                    <div class="spinner-grow spinner-grow-sm text-success" style="width: 8px; height: 8px;" role="status"></div>
                    <span id="sys-hostname" class="text-truncate">Node...</span>
                </div>
                <div class="font-mono text-muted d-flex align-items-center gap-2 mb-3" style="font-size: 0.75rem;" id="last-update">Syncing...</div>
                
                <select class="form-select form-select-sm w-100 rounded-2 font-mono shadow-sm" id="theme-switcher" style="background-color: var(--sw-card-bg); border-color: var(--sw-border); color: var(--sw-text);">
                    <option value="auto">🖥️ Auto Theme</option>
                    <option value="dark">🌙 Dark Mode</option>
                    <option value="light">☀️ Light Mode</option>
                </select>
            </div>
        </div>
    </aside>

    <main class="main-wrapper bg-body-tertiary">
        
        <div class="d-lg-none d-flex align-items-center justify-content-between p-3 bg-body border-bottom sticky-top">
            <div class="d-flex align-items-center gap-2">
                <svg style="color: var(--sw-brand-icon);" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                <span class="fw-bold">SYSWARDEN</span>
            </div>
            <button class="btn btn-sm border-0" id="mobileMenuBtn">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>
            </button>
        </div>

        <div class="container-fluid px-xl-5 px-4 py-5">
            
            <div id="view-overview" class="view-section active">
                <h4 class="mb-4 fw-bold">Overview</h4>
                
                <div class="row g-4 mb-4">
                    <div class="col-xxl-4 col-lg-6">
                        <div class="card h-100">
                            <div class="card-body p-4">
                                <div class="stat-label mb-3">L3 Kernel Blocks (Global)</div>
                                <div class="stat-value text-success font-mono mb-3" id="l3-global">0</div>
                                <div class="d-flex justify-content-between border-top pt-3 font-mono small text-muted" style="border-color: var(--sw-border) !important;">
                                    <span>GeoIP: <strong class="text-body" id="l3-geoip">0</strong></span>
                                    <span>ASN: <strong class="text-body" id="l3-asn">0</strong></span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xxl-4 col-lg-6">
                        <div class="card h-100">
                            <div class="card-body p-4">
                                <div class="stat-label mb-3">L7 Active Bans (Fail2ban)</div>
                                <div class="stat-value text-danger font-mono mb-3" id="l7-banned">0</div>
                                <div class="d-flex justify-content-between border-top pt-3 font-mono small text-muted" style="border-color: var(--sw-border) !important;">
                                    <span>Active Guard Jails:</span>
                                    <strong class="text-body" id="l7-jails">0</strong>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="col-xxl-4 col-lg-12">
                        <div class="card h-100">
                            <div class="card-body p-4">
                                <div class="d-flex justify-content-between align-items-start mb-3">
                                    <div class="stat-label">Trusted Hosts (Whitelist)</div>
                                    <span class="badge bg-success bg-opacity-10 text-success rounded-pill font-mono" id="wl-count">0</span>
                                </div>
                                <div class="table-container pe-2 font-mono small text-success" style="max-height: 70px;">
                                    <ul class="list-unstyled mb-0" id="whitelist-ips-list"></ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card mb-4">
                    <div class="card-header bg-transparent pt-4 pb-0 px-4 d-flex align-items-center gap-2">
                        <span class="text-danger">📈</span> L7 Threat Telemetry (Live Timeline)
                    </div>
                    <div class="card-body p-4">
                        <div class="chart-wrapper">
                            <canvas id="threatChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <div id="view-threats" class="view-section">
                <h4 class="mb-4 fw-bold">Threat Intelligence</h4>
                
                <div class="row g-4">
                    <div class="col-xl-6">
                        <div class="card h-100">
                            <div class="card-header bg-transparent pt-4 pb-3 px-4">🎯 Top Attackers (OSINT History)</div>
                            <div class="card-body p-0">
                                <div class="table-responsive table-container px-3 pb-3">
                                    <table class="table table-sm table-borderless table-hover align-middle mb-0">
                                        <thead class="border-bottom" style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2;">
                                            <tr>
                                                <th class="text-muted small fw-normal pb-2">IP ADDRESS</th>
                                                <th class="text-end text-muted small fw-normal pb-2">HITS</th>
                                            </tr>
                                        </thead>
                                        <tbody id="top-ips-list"></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-xl-6">
                        <div class="card h-100">
                            <div class="card-header bg-transparent pt-4 pb-3 px-4">🏢 Jails Load Distribution</div>
                            <div class="card-body px-4 pt-0">
                                <ul class="list-group list-group-flush font-mono small border-0" id="top-jails-list"></ul>
                            </div>
                        </div>
                    </div>

                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-transparent pt-4 pb-3 px-4">🔴 L7 Banned IP Registry (Live Jail Allocations)</div>
                            <div class="card-body p-0">
                                <div class="table-responsive table-container px-3 pb-3" style="max-height: 450px;">
                                    <table class="table table-sm table-borderless table-hover align-middle mb-0">
                                        <thead class="border-bottom" style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2;">
                                            <tr>
                                                <th class="text-muted small fw-normal pb-2">IP ADDRESS</th>
                                                <th class="text-end text-muted small fw-normal pb-2">TARGET JAIL</th>
                                            </tr>
                                        </thead>
                                        <tbody id="banned-ips-list"></tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div id="view-system" class="view-section">
                <h4 class="mb-4 fw-bold">System Health</h4>
                
                <div class="row g-4">
                    <div class="col-xl-6">
                        <div class="card h-100">
                            <div class="card-body p-4">
                                <div class="d-flex justify-content-between align-items-start mb-4">
                                    <div class="stat-label">Node Status</div>
                                    <span class="badge bg-secondary rounded-pill font-mono" id="sys-uptime">--</span>
                                </div>
                                <div class="mb-4">
                                    <div class="text-muted small text-uppercase fw-bold mb-2">CPU Load Average (1, 5, 15m)</div>
                                    <div class="stat-value font-mono" id="sys-load">--</div>
                                </div>
                                <div>
                                    <div class="d-flex justify-content-between small text-muted mb-2 font-mono fw-bold">
                                        <span>RAM Utilization</span>
                                        <span id="sys-ram">-- MB</span>
                                    </div>
                                    <div class="progress" style="height: 8px; background-color: var(--sw-border);" id="ram-progress-container">
                                        <div class="progress-bar bg-primary" role="progressbar" id="ram-progress" style="width: 0%;"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="app.js"></script>
</body>
</html>
EOF

    # 2. Generating the JS Logic (SPA Routing & Performance Engine)
    cat <<'EOF' >"$UI_DIR/app.js"
let threatChart = null;
const MAX_DATA_POINTS = 40;

document.addEventListener('DOMContentLoaded', () => {
    
    // --- SPA ROUTER (VIRTUAL NAVIGATION) ---
    const navItems = document.querySelectorAll('.nav-item-sw');
    const viewSections = document.querySelectorAll('.view-section');

    function switchView(targetViewId) {
        // Update active class on nav links
        navItems.forEach(item => {
            item.classList.remove('active');
            if(item.getAttribute('data-view') === targetViewId) {
                item.classList.add('active');
            }
        });
        
        // Switch sections with fade
        viewSections.forEach(section => {
            if(section.id === 'view-' + targetViewId) {
                section.style.display = 'block';
                // small delay for css transition to trigger
                setTimeout(() => section.classList.add('active'), 50);
            } else {
                section.classList.remove('active');
                setTimeout(() => section.style.display = 'none', 300); // match css transition
            }
        });

        // Save state
        localStorage.setItem('syswarden-view', targetViewId);
        
        // Close mobile menu if open
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        if(sidebar.classList.contains('show')){
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        }
    }

    // Bind clicks
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchView(item.getAttribute('data-view'));
        });
    });

    // Restore last view or default to overview
    const savedView = localStorage.getItem('syswarden-view') || 'overview';
    switchView(savedView);

    // --- MOBILE MENU LOGIC ---
    document.getElementById('mobileMenuBtn').addEventListener('click', () => {
        document.getElementById('sidebar').classList.add('show');
        document.getElementById('sidebarOverlay').classList.add('show');
    });
    document.getElementById('sidebarOverlay').addEventListener('click', () => {
        document.getElementById('sidebar').classList.remove('show');
        document.getElementById('sidebarOverlay').classList.remove('show');
    });

    // --- ADVANCED THEME ENGINE ---
    const themeSwitcher = document.getElementById('theme-switcher');
    
    const setTheme = (theme) => {
        let activeTheme = theme;
        if (theme === 'auto') {
            activeTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        }
        document.documentElement.setAttribute('data-bs-theme', activeTheme);
        updateChartTheme(activeTheme);
    };

    const currentTheme = localStorage.getItem('syswarden-theme') || 'auto';
    themeSwitcher.value = currentTheme;
    setTheme(currentTheme);

    themeSwitcher.addEventListener('change', (e) => {
        localStorage.setItem('syswarden-theme', e.target.value);
        setTheme(e.target.value);
    });

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (localStorage.getItem('syswarden-theme') === 'auto') setTheme('auto');
    });

    // --- CHART.JS INITIALIZATION ---
    const chartData = {
        labels: [],
        datasets: [{
            label: 'L7 Blocked Threats', data: [],
            borderColor: '#3b82f6', backgroundColor: 'rgba(59, 130, 246, 0.1)',
            borderWidth: 2, fill: true, tension: 0.4,
            pointBackgroundColor: '#3b82f6', pointBorderColor: '#fff',
            pointRadius: 0, pointHoverRadius: 6, pointHitRadius: 10
        }]
    };

    try {
        const ctx = document.getElementById('threatChart').getContext('2d');
        threatChart = new Chart(ctx, {
            type: 'line', data: chartData,
            options: {
                responsive: true, maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { 
                    legend: { display: false },
                    tooltip: {
                        animation: false, titleFont: { family: 'JetBrains Mono', size: 13, weight: 'bold' },
                        bodyFont: { family: 'JetBrains Mono', size: 12 }, padding: 12, cornerRadius: 8, displayColors: false
                    }
                },
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true, ticks: { font: { family: 'JetBrains Mono', size: 11 } }, border: { display: false } }
                },
                animation: { duration: 0 }
            }
        });
    } catch (e) { console.warn("Chart.js init failed:", e); }

    function updateChartTheme(theme) {
        if (!threatChart) return;
        const isDark = theme === 'dark';
        const gridColor = isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)';
        const textColor = isDark ? '#a1a1aa' : '#6b7280';
        
        threatChart.options.scales.y.grid = { color: gridColor };
        threatChart.options.scales.y.ticks.color = textColor;
        threatChart.options.plugins.tooltip.backgroundColor = isDark ? 'rgba(24, 24, 27, 0.95)' : 'rgba(255, 255, 255, 0.95)';
        threatChart.options.plugins.tooltip.titleColor = isDark ? '#fff' : '#000';
        threatChart.options.plugins.tooltip.bodyColor = isDark ? '#a1a1aa' : '#4b5563';
        threatChart.options.plugins.tooltip.borderColor = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
        threatChart.options.plugins.tooltip.borderWidth = 1;
        threatChart.update();
    }

    // --- DATA INGESTION ENGINE ---
    async function fetchTelemetry() {
        try {
            const response = await fetch(`data.json?t=${new Date().getTime()}`);
            if (!response.ok) throw new Error('HTTP request failed');
            const data = await response.json();

            // 1. System Metrics
            document.getElementById('sys-hostname').innerText = data.system.hostname;
            document.getElementById('sys-uptime').innerText = data.system.uptime;
            
            const ramUsed = parseInt(data.system.ram_used_mb) || 0;
            const ramTotal = parseInt(data.system.ram_total_mb) || 1;
            const ramPercent = Math.round((ramUsed / ramTotal) * 100);
            document.getElementById('sys-ram').innerText = `${ramUsed.toLocaleString()} / ${ramTotal.toLocaleString()} MB`;
            const ramBar = document.getElementById('ram-progress');
            ramBar.style.width = `${ramPercent}%`;
            ramBar.className = `progress-bar ${ramPercent > 85 ? 'bg-danger' : ramPercent > 60 ? 'bg-warning' : 'bg-primary'}`;

            const sysLoadEl = document.getElementById('sys-load');
            sysLoadEl.innerText = data.system.load_average;
            const load1m = parseFloat(data.system.load_average.split(',')[0]);
            sysLoadEl.classList.remove('text-success', 'text-warning', 'text-danger');
            sysLoadEl.classList.add(load1m <= 0.35 ? 'text-success' : load1m <= 0.70 ? 'text-warning' : 'text-danger');

            // 2. Layer 3 & 7 Metrics
            document.getElementById('l3-global').innerText = parseInt(data.layer3.global_blocked).toLocaleString();
            document.getElementById('l3-geoip').innerText = parseInt(data.layer3.geoip_blocked).toLocaleString();
            document.getElementById('l3-asn').innerText = parseInt(data.layer3.asn_blocked).toLocaleString();
            document.getElementById('l7-banned').innerText = parseInt(data.layer7.total_banned).toLocaleString();
            document.getElementById('l7-jails').innerText = data.layer7.active_jails;
            document.getElementById('wl-count').innerText = data.whitelist.active_ips;

            // Renderers
            document.getElementById('whitelist-ips-list').innerHTML = data.whitelist.ips.map(ip => `<li class="mb-1 opacity-75">${ip}</li>`).join('');

            const topIpsEl = document.getElementById('top-ips-list');
            if(data.layer7.top_attackers.length > 0) {
                topIpsEl.innerHTML = data.layer7.top_attackers.map(attacker => `
                    <tr>
                        <td class="font-mono"><a href="https://www.abuseipdb.com/check/${attacker.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none text-danger fw-bold opacity-75 ip-font">${attacker.ip}</a></td>
                        <td class="text-end font-mono fw-bold text-body-secondary">${attacker.count.toLocaleString()}</td>
                    </tr>`).join('');
            } else { topIpsEl.innerHTML = `<tr><td colspan="2" class="text-center text-muted small py-4">No attackers recorded.</td></tr>`; }

            const jailsEl = document.getElementById('top-jails-list');
            if(data.layer7.jails_data.length > 0) {
                jailsEl.innerHTML = [...data.layer7.jails_data].sort((a, b) => b.count - a.count).map(jail => `
                    <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent px-0 border-bottom border-secondary border-opacity-10 py-3">
                        <span class="text-body-secondary fw-medium">${jail.name}</span>
                        <span class="badge bg-secondary bg-opacity-25 text-body rounded-pill">${jail.count}</span>
                    </li>`).join('');
            } else { jailsEl.innerHTML = `<li class="list-group-item bg-transparent text-muted small border-0 px-0">No active jails loaded.</li>`; }

            const bannedEl = document.getElementById('banned-ips-list');
            if(data.layer7.banned_ips.length > 0) {
                bannedEl.innerHTML = [...data.layer7.banned_ips].reverse().map(entry => {
                    const isRecidive = entry.jail.includes('recidive');
                    return `<tr>
                        <td class="font-mono"><a href="https://www.abuseipdb.com/check/${entry.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none text-danger fw-bold opacity-75 ip-font">${entry.ip}</a></td>
                        <td class="text-end font-mono"><span class="badge ${isRecidive ? 'bg-danger text-white' : 'bg-secondary bg-opacity-25 text-body'} fw-normal">${entry.jail}</span></td>
                    </tr>`;
                }).join('');
            } else { bannedEl.innerHTML = `<tr><td colspan="2" class="text-center text-muted small py-5">Registry is empty. Architecture is secure.</td></tr>`; }

            // Chart Updater
            const now = new Date();
            const timeString = now.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
            document.getElementById('last-update').innerHTML = `Sync: ${timeString}`;

            if (threatChart) {
                chartData.labels.push(timeString);
                chartData.datasets[0].data.push(data.layer7.total_banned);
                if (chartData.labels.length > MAX_DATA_POINTS) {
                    chartData.labels.shift();
                    chartData.datasets[0].data.shift();
                }
                threatChart.update();
            }
        } catch (error) {
            console.error("Telemetry Sync Error:", error);
            document.getElementById('last-update').innerHTML = `<span class="text-danger">Offline</span>`;
        }
    }

    fetchTelemetry();
    setInterval(fetchTelemetry, 5000);
});
EOF

    chmod 644 "$UI_DIR/index.html" "$UI_DIR/app.js"

    # --- 3. CRYPTOGRAPHY (Self-Signed TLS) ---
    local SSL_DIR="/etc/syswarden/ssl"
    mkdir -p "$SSL_DIR"
    if [[ ! -f "$SSL_DIR/syswarden.crt" ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout "$SSL_DIR/syswarden.key" -out "$SSL_DIR/syswarden.crt" -subj "/CN=syswarden-dashboard" 2>/dev/null
        chmod 600 "$SSL_DIR/syswarden.key"
    fi

    # --- 4. SLACKWARE NGINX CONFIG INJECTION ---
    local NGINX_CONF="/etc/nginx/conf.d/syswarden-ui.conf"
    mkdir -p /etc/nginx/conf.d

    local NGINX_ALLOW_RULES=""
    if [[ -s "$WHITELIST_FILE" ]]; then
        # HOTFIX: Read securely and strip hidden carriage returns (\r) to prevent Nginx fatal syntax crashes
        while IFS= read -r wl_ip || [[ -n "$wl_ip" ]]; do
            wl_ip=$(echo "$wl_ip" | tr -d '\r' | awk '{$1=$1};1')
            if [[ -z "$wl_ip" ]] || [[ "$wl_ip" =~ ^# ]]; then continue; fi
            NGINX_ALLOW_RULES+="    allow $wl_ip;\n"
        done <"$WHITELIST_FILE"
    fi
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -n "${WG_SUBNET:-}" ]]; then
        NGINX_ALLOW_RULES+="    allow ${WG_SUBNET};\n"
    fi
    NGINX_ALLOW_RULES+="    allow 127.0.0.1;\n    deny all;"

    cat <<EOF >"$NGINX_CONF"
server {
    # Using 'listen ... http2' ensures compatibility with older and newer Nginx versions
    listen 9999 ssl http2;
    server_name _;
    
    ssl_certificate $SSL_DIR/syswarden.crt;
    ssl_certificate_key $SSL_DIR/syswarden.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root $UI_DIR;
    index index.html;
    
    # --- HOTFIX: EXPLICIT MIME TYPES ---
    include mime.types;
    types {
        font/woff2 woff2;
    }

$(echo -e "$NGINX_ALLOW_RULES")

    # --- Strict Security Headers (Updated CSP for Bootstrap & ChartJS Source Maps) ---
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    server_tokens off;

    location / { try_files \$uri \$uri/ =404; }
    location ~ /\. { deny all; }
}
EOF

    # --- HOTFIX: Dynamically patch native Slackware nginx.conf ---
    if [[ -f /etc/nginx/nginx.conf ]]; then
        if ! grep -q "include /etc/nginx/conf.d/\*.conf;" /etc/nginx/nginx.conf; then
            log "INFO" "Patching native /etc/nginx/nginx.conf to include syswarden dashboard..."
            sed -i 's/http {/http {\n    include \/etc\/nginx\/conf.d\/\*.conf;/g' /etc/nginx/nginx.conf || true
        fi
    fi

    # --- HOTFIX: Safely reload or restart Nginx (Zero Downtime) ---
    if [[ -f /etc/rc.d/rc.nginx ]]; then
        chmod +x /etc/rc.d/rc.nginx
    fi

    if command -v nginx >/dev/null 2>&1; then
        if nginx -t >/dev/null 2>&1; then
            log "INFO" "Reloading Nginx gracefully..."
            nginx -s reload 2>/dev/null || /etc/rc.d/rc.nginx restart 2>/dev/null || true
        else
            log "ERROR" "Nginx configuration syntax error. Preserving old config to avoid crash."
            /etc/rc.d/rc.nginx restart 2>/dev/null || true
        fi
    elif [[ -x /etc/rc.d/rc.nginx ]]; then
        /etc/rc.d/rc.nginx restart 2>/dev/null || true
    fi

    # --- HOTFIX: DYNAMIC IP RESOLUTION ---
    # 1. Tries to get the Public IPv4 via curl or wget
    # 2. Fallbacks to the primary active local IP via routing table if offline
    # 3. Failsafe to '<YOUR_IP>' if everything else fails
    local SERVER_IP
    SERVER_IP=$(curl -sL4 https://ifconfig.me 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") print $(i+1)}' | head -n 1 || echo "<YOUR_IP>")

    log "INFO" "Dashboard UI secured by Nginx at https://${SERVER_IP}:9999"
}

show_alerts() {
    echo -e "\n${BLUE}=========================================================================================${NC}"
    echo -e "${GREEN}                        SYSWARDEN CLI DASHBOARD (Live Alerts)                            ${NC}"
    echo -e "${BLUE}=========================================================================================${NC}"

    if [[ ! -f "/var/log/kern-firewall.log" ]] && [[ ! -f "/var/log/fail2ban.log" ]]; then
        echo -e "${RED}[!] Error: Telemetry logs not found. Is SysWarden fully installed?${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[i] Tailing live Threat Intelligence Logs... (Press Ctrl+C to stop)${NC}\n"

    # --- TABLE HEADER ---
    printf "\033[1m\033[36m%-19s | %-16s | %-10s | %-15s | %s\033[0m\n" "TIMESTAMP" "MODULE" "ACTION" "SOURCE IP" "TARGET (PORT/JAIL)"
    echo -e "${BLUE}--------------------+------------------+------------+-----------------+--------------------${NC}"

    # Read-only live tail parsed by awk for tabular DevSecOps visualization
    tail -F -q /var/log/kern-firewall.log /var/log/fail2ban.log 2>/dev/null | awk '
    BEGIN {
        # HOTFIX: Map syslog months to ISO numbers and fetch current year
        m["Jan"]="01"; m["Feb"]="02"; m["Mar"]="03"; m["Apr"]="04"; m["May"]="05"; m["Jun"]="06";
        m["Jul"]="07"; m["Aug"]="08"; m["Sep"]="09"; m["Oct"]="10"; m["Nov"]="11"; m["Dec"]="12";
        "date +%Y" | getline current_year; close("date +%Y")
    }
    /SysWarden-BLOCK|SysWarden-GEO|SysWarden-ASN|Catch-All/ {
        # Transform traditional syslog date (Apr 2 12:56:01) to ISO (YYYY-MM-DD 12:56:01)
        if ($1 in m) {
            date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
        } else {
            date = $1 " " $2 " " $3
        }
        
        match($0, /\[SysWarden-[A-Za-z-]+\]/)
        module = substr($0, RSTART+1, RLENGTH-2)
        if ($0 ~ /Catch-All/) module = "SysWarden-CATCH"
        
        match($0, /SRC=[0-9\.]+/)
        src = substr($0, RSTART+4, RLENGTH-4)
        if (src == "") src = "N/A"
        
        match($0, /DPT=[0-9]+/)
        dpt = substr($0, RSTART+4, RLENGTH-4)
        if (dpt == "") dpt = "N/A"
        
        # Color coding: Grey Date, Blue Module, Red Action, Yellow IP, Cyan Target
        printf "\033[1;30m%-19s\033[0m | \033[1;34m%-16s\033[0m | \033[1;31m%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36mPORT: %s\033[0m\n", date, module, "BLOCKED", src, dpt
        fflush(stdout)
        next
    }
    /Ban |Found / && !/Restore/ {
        date = $1 " " $2
        sub(/,.*/, "", date)
        
        match($0, /\[[a-zA-Z0-9_-]+\] (Found|Ban)/)
        str = substr($0, RSTART, RLENGTH)
        
        match(str, /\[[a-zA-Z0-9_-]+\]/)
        jail = substr(str, RSTART+1, RLENGTH-2)
        
        act = ($0 ~ /Ban /) ? "BANNED" : "DETECTED"
        act_color = ($0 ~ /Ban /) ? "\033[1;31m" : "\033[1;35m"
        
        match($0, /(Found|Ban) [0-9\.]+/)
        ip = substr($0, RSTART, RLENGTH)
        sub(/(Found|Ban) /, "", ip)
        
        printf "\033[1;30m%-19s\033[0m | \033[1;35m%-16s\033[0m | %s%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36mJAIL: %s\033[0m\n", date, "FAIL2BAN WAF", act_color, act, ip, jail
        fflush(stdout)
    }' || true
}

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden (Slackware) ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation (Rollback & Scorched Earth)..."

    # --- 1. PROCESS PURGE ---
    pkill -9 -f syswarden-telemetry 2>/dev/null || true
    pkill -9 -f syswarden_reporter 2>/dev/null || true

    # --- 2. RESTORE OS HARDENING (Privileges) ---
    if [[ -f "$SYSWARDEN_DIR/group_backup.txt" ]]; then
        log "INFO" "Restoring user privileges (wheel/adm groups)..."
        while IFS=':' read -r grp members; do
            for user in $(echo "$members" | tr ',' ' '); do
                [[ -n "$user" ]] && gpasswd -a "$user" "$grp" >/dev/null 2>&1 || true
            done
        done <"$SYSWARDEN_DIR/group_backup.txt"
    fi

    # --- 3. RESTORE SYSLOG CONF ---
    if [[ -f /etc/syslog.conf ]]; then
        sed -i '/kern-firewall\.log/d' /etc/syslog.conf
        sed -i '/auth-syswarden\.log/d' /etc/syslog.conf
        if [[ -x /etc/rc.d/rc.syslog ]]; then /etc/rc.d/rc.syslog restart 2>/dev/null || true; fi
    fi

    # --- 4. REMOVE DAEMONS & SERVICES ---
    if [[ -x /etc/rc.d/rc.syswarden-reporter ]]; then /etc/rc.d/rc.syswarden-reporter stop 2>/dev/null || true; fi
    rm -f /etc/rc.d/rc.syswarden-reporter /usr/local/bin/syswarden_reporter.py

    rm -f /usr/local/bin/syswarden-sync.sh
    rm -f /etc/rc.d/rc.syswarden-siem /usr/local/bin/syswarden-siem.sh

    if [[ -x /etc/rc.d/rc.wireguard ]]; then /etc/rc.d/rc.wireguard stop 2>/dev/null || true; fi
    rm -f /etc/rc.d/rc.wireguard /etc/wireguard/wg0.conf
    rm -rf /etc/wireguard/clients

    # Clear rc.local entries
    if [[ -f /etc/rc.d/rc.local ]]; then
        sed -i '/rc\.syswarden-firewall/d' /etc/rc.d/rc.local
        sed -i '/rc\.syswarden-reporter/d' /etc/rc.d/rc.local
        sed -i '/rc\.wireguard/d' /etc/rc.d/rc.local
    fi

    # --- 5. SURGICAL FIREWALL REMOVAL ---
    if command -v nft >/dev/null 2>&1; then
        nft delete table netdev syswarden_hw_drop 2>/dev/null || true
        nft delete table inet syswarden_table 2>/dev/null || true
        nft delete table inet syswarden_wg 2>/dev/null || true
    elif command -v iptables >/dev/null 2>&1; then
        iptables-save | grep -v 'SysWarden' | iptables-restore 2>/dev/null || true
        iptables -t raw -S PREROUTING 2>/dev/null | grep -v 'SysWarden' | iptables-restore -c -T raw 2>/dev/null || true
        ipset destroy $SET_NAME 2>/dev/null || true
        ipset destroy $GEOIP_SET_NAME 2>/dev/null || true
        ipset destroy $ASN_SET_NAME 2>/dev/null || true
    fi
    if [[ -x /etc/rc.d/rc.syswarden-firewall ]]; then /etc/rc.d/rc.syswarden-firewall stop 2>/dev/null || true; fi
    rm -f /etc/rc.d/rc.syswarden-firewall

    # --- 6. CRON CLEANUP ---
    if [[ -f /etc/crontabs/root ]]; then sed -i '/syswarden/d' /etc/crontabs/root 2>/dev/null || true; fi
    if [[ -f /var/spool/cron/crontabs/root ]]; then sed -i '/syswarden/d' /var/spool/cron/crontabs/root 2>/dev/null || true; fi

    # --- 7. FAIL2BAN CLEANUP ---
    rm -f /var/lib/fail2ban/fail2ban.sqlite3
    : >/var/log/fail2ban.log
    rm -f /etc/fail2ban/jail.local /etc/fail2ban/fail2ban.local
    rm -f /etc/fail2ban/filter.d/syswarden-*.conf /etc/fail2ban/filter.d/*-custom.conf /etc/fail2ban/filter.d/*-scanner.conf /etc/fail2ban/filter.d/mongodb-guard.conf /etc/fail2ban/filter.d/haproxy-guard.conf /etc/fail2ban/filter.d/mariadb-auth.conf /etc/fail2ban/filter.d/wordpress-auth.conf /etc/fail2ban/filter.d/drupal-auth.conf /etc/fail2ban/filter.d/nextcloud.conf /etc/fail2ban/filter.d/zabbix-auth.conf /etc/fail2ban/filter.d/laravel-auth.conf /etc/fail2ban/filter.d/grafana-auth.conf
    # Restore original jail.local if we had one
    if [[ -f /etc/fail2ban/jail.local.syswarden-bak ]]; then mv /etc/fail2ban/jail.local.syswarden-bak /etc/fail2ban/jail.local; fi
    if [[ -x /etc/rc.d/rc.fail2ban ]]; then /etc/rc.d/rc.fail2ban restart </dev/null 2>/dev/null || true; fi

    # --- 8. NGINX CLEANUP ---
    rm -f /etc/nginx/conf.d/syswarden-ui.conf
    if [[ -x /etc/rc.d/rc.nginx ]]; then /etc/rc.d/rc.nginx restart 2>/dev/null || true; fi

    # --- 9. SCORCHED EARTH (Files & Folders) ---
    rm -rf /etc/syswarden
    rm -f /usr/local/bin/syswarden-telemetry.sh
    rm -f /var/log/kern-firewall.log /var/log/auth-syswarden.log

    echo -e "${GREEN}Uninstallation complete. System restored to initial state.${NC}"
    echo -e "${YELLOW}[i] A reboot is recommended to ensure all network routes are completely flushed.${NC}"
    exit 0
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
MODE="${1:-install}"

# --- HOTFIX: Intercept 'alerts' mode for CLI Dashboard ---
if [[ "$MODE" == "alerts" ]]; then
    check_root
    show_alerts
    exit 0
fi
# ----------------------------------------------------------------

if [[ "$MODE" == "uninstall" ]]; then
    check_root
    uninstall_syswarden
fi

# --- CLI UI: Premium ASCII Banner ---
if [[ "$MODE" != "update" ]] && [[ "$MODE" != "uninstall" ]]; then
    clear
    echo -e "${BLUE}===================================================================================${NC}"
    echo -e "${RED} ██████╗██╗   ██╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗${NC}"
    echo -e "${RED}██╔════╝╚██╗ ██╔╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║${NC}"
    echo -e "${RED}███████╗ ╚████╔╝ ███████╗██║ █╗ ██║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║${NC}"
    echo -e "${RED}╚════██║  ╚██╔╝  ╚════██║██║███╗██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║${NC}"
    echo -e "${RED}███████║   ██║   ███████║╚███╔███╔╝██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║${NC}"
    echo -e "${RED}╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝${NC}"
    echo -e "${BLUE}===================================================================================${NC}"
    echo -e "${GREEN}               Advanced Firewall & Blocklist Orchestrator | v2.15                  ${NC}"
    echo -e "${BLUE}===================================================================================${NC}\n"
fi

check_root
detect_os_backend

if [[ "$MODE" != "update" ]]; then
    : >"$CONF_FILE"
    install_dependencies
    auto_whitelist_admin
    process_auto_whitelist "$MODE"

    # --- DEVSECOPS: PRE-FLIGHT CHECKLIST (Interactive Mode Only) ---
    if [[ "$MODE" != "auto" ]]; then
        BOLD='\033[1m'
        CYAN='\033[0;36m'
        clear
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v2.15 - PRE-FLIGHT CHECKLIST                     ${NC}"
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "Before proceeding with the deployment, please ensure you have the following"
        echo -e "information ready. If you lack any required data, press [Ctrl+C] to abort,"
        echo -e "gather the info, and restart the script.\n"

        echo -e "${BOLD}1. SSH CONFIGURATION${NC}"
        echo -e "   You will need to confirm the custom SSH port used to connect to this server."

        echo -e "\n${BOLD}2. WIREGUARD VPN${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Decide if you need a stealth admin VPN. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}3. OS HARDENING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Strict restrictions for privileged groups (Wheel/Adm). Recommended for NEW servers only."

        echo -e "\n${BOLD}4. GEOIP BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   ISO country codes to drop instantly (e.g., RU,CN,KP)."
        echo -e "   Reference: ${CYAN}https://www.ipdeny.com/ipblocks/${NC}"

        echo -e "\n${BOLD}5. ASN BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Target Autonomous System Numbers to drop (e.g., AS1234, AS5678)."
        echo -e "   Reference: ${CYAN}https://www.spamhaus.org/drop/asndrop.json${NC}"

        echo -e "\n${BOLD}6. HA CLUSTER SYNC${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Standby Node IP for automatic threat intelligence replication."

        echo -e "\n${BOLD}7. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] None (Geo/ASN Only)"

        echo -e "\n${BOLD}8. SIEM LOG FORWARDING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   External SIEM IP and Port (Native Syslogd Integration)."

        echo -e "\n${BOLD}9. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."
        echo -e "   Get one at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"

        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        read -p "$(echo -e "${YELLOW}Press [ENTER] to begin the configuration, or [Ctrl+C] to abort... ${NC}")"
        echo ""
        log "INFO" "Pre-Flight Checklist acknowledged. Starting interactive configuration..."
    fi
    # ---------------------------------------------------------------

    define_ssh_port "$MODE"
    define_wireguard "$MODE"
    define_os_hardening "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
    define_ha_cluster "$MODE"
    setup_siem_logging "$MODE"
    select_list_type "$MODE"
    select_mirror "$MODE"
    download_list
    download_osint
    download_geoip
    download_asn
    discover_active_services
    apply_firewall_rules
    configure_fail2ban
    setup_abuse_reporting "$MODE"
    setup_telemetry_backend
    generate_dashboard
    apply_os_hardening
    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL (Slackware Edition)${NC}"
    echo -e "${YELLOW}Please ensure your Nginx configuration includes /etc/nginx/conf.d/*.conf${NC}"
    display_dashboard_info
    display_wireguard_qr
else
    # Update logic
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # --- HOTFIX: Ensure all configuration defaults & whitelists are applied during update ---
    define_ssh_port "update"
    define_wireguard "update"
    define_os_hardening "update"
    define_geoblocking "update"
    define_asnblocking "update"
    define_ha_cluster "update"
    setup_siem_logging "update"
    select_list_type "update"
    select_mirror "update"

    auto_whitelist_admin
    process_auto_whitelist "update"
    # -----------------------------------------------------------------------------------------------

    download_list
    download_osint
    download_geoip
    download_asn
    discover_active_services
    apply_firewall_rules
    configure_fail2ban
    setup_telemetry_backend
    generate_dashboard
    display_dashboard_info
    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
fi
