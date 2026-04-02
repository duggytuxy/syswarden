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
VERSION="v1.86"
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

    # --- DEVSECOPS FIX: TEMPORARY IFS RESTORE ---
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
        cat <<EOF >"$TMP_DIR/syswarden.nft"
table inet syswarden_table
delete table inet syswarden_table
table inet syswarden_table {
    set $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "    set $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "    set $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
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

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "        ip saddr @$GEOIP_SET_NAME log prefix \"[SysWarden-GEO] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "        ip saddr @$ASN_SET_NAME log prefix \"[SysWarden-ASN] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " drop
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

        if [[ -s "$FINAL_LIST" ]]; then
            cat "$FINAL_LIST" | xargs -n 5000 | while read -r chunk; do
                echo "add element inet syswarden_table $SET_NAME { $(echo "$chunk" | tr ' ' ',') }" >>"$TMP_DIR/syswarden.nft"
            done
        fi
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat "$GEOIP_FILE" | xargs -n 5000 | while read -r chunk; do
                echo "add element inet syswarden_table $GEOIP_SET_NAME { $(echo "$chunk" | tr ' ' ',') }" >>"$TMP_DIR/syswarden.nft"
            done
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat "$ASN_FILE" | xargs -n 5000 | while read -r chunk; do
                echo "add element inet syswarden_table $ASN_SET_NAME { $(echo "$chunk" | tr ' ' ',') }" >>"$TMP_DIR/syswarden.nft"
            done
        fi

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
            iptables -A INPUT -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            iptables -A INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            iptables -A INPUT -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            iptables -A INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP
        fi

        iptables -A INPUT -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
        iptables -A INPUT -m set --match-set "$SET_NAME" src -j DROP

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

        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
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
        # DEVSECOPS FIX: Backup existing jail.local before overwriting
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
            # DEVSECOPS FIX: Self-healing native filter
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
            # DEVSECOPS FIX: Self-healing native filter
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
            # DEVSECOPS FIX: Self-healing native filters
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
failregex = ^.* <HOST>:[0-9]+ .* [Aa]uthentication failed.*\s*$
            ^.* Client <HOST>:[0-9]+ disconnected, .* [Aa]uthentication.*\s*$
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
failregex = ^.*HTTP access denied: .* from <HOST>.*\s*$
            ^.*AMQP connection <HOST>:[0-9]+ .* failed: .*authentication failure.*\s*$
            ^.*<HOST>:[0-9]+ .* (?:invalid credentials|authentication failed).*\s*$
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
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-portscan.conf
[INCLUDES]
before = common.conf
[Definition]
failregex = ^%(__prefix_line)s(?:kernel: |\[[0-9. ]+\] ).*\[SysWarden-BLOCK\].*SRC=<HOST> .*$
ignoreregex = 
EOF
            cat <<EOF >>/etc/fail2ban/jail.local

[syswarden-portscan]
enabled  = true
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

[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $RCE_LOGS
backend  = auto
maxretry = 150
findtime = 2
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
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] ".*" \d{3} .* "(?:\$\{jndi:|\x2524\x257Bjndi:).*"$
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

        # 39. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/passwd|\x252Fetc\x252Fpasswd|/etc/shadow|/windows/win\.ini|/windows/system32|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb)).* HTTP/.*" \d{3} .*$
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

        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
        fi

        # --- DEVSECOPS FIX: Ensure daemon is executable on Slackware ---
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

        # --- DEVSECOPS FIX: Strict Validation with CI/CD Auto-Mode support ---
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
    # DEVSECOPS FIX: Pure UNIX flat-file tailing for Slackware (Replaces journalctl)
    f = subprocess.Popen(['tail', '-F', '-q', '/var/log/kern-firewall.log', '/var/log/fail2ban.log'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    regex_fw = re.compile(r"\[SysWarden-(BLOCK|DOCKER)\].*SRC=([\d\.]+).*DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            if not line: continue

            match_fw = regex_fw.search(line)
            if match_fw:
                ip = match_fw.group(2)
                try: port = int(match_fw.group(3))
                except ValueError: port = 0
                cats = ["14"]
                if port in [80, 443, 8080]: cats.extend(["15", "21"])
                elif port in [22, 2222]: cats.extend(["18", "22"])
                threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall (Port {port})")).start()
                continue

            match_f2b = regex_f2b.search(line)
            if match_f2b and "SysWarden-BLOCK" not in line:
                jail = match_f2b.group(1).lower()
                ip = match_f2b.group(2)
                cats = ["18"]
                if "scanner" in jail: cats.extend(["14", "15", "21"])
                threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {jail})")).start()

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

generate_dashboard() {
    log "INFO" "Generating Dashboard UI..."
    local UI_DIR="/etc/syswarden/ui"
    mkdir -p "$UI_DIR"
    chmod 755 /etc/syswarden "$UI_DIR"

    # --- DEVSECOPS FIX: DOWNLOAD LOCAL FONTS ---
    wget -qO "$UI_DIR/JetBrainsMono-Regular.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Regular.woff2" || true
    wget -qO "$UI_DIR/JetBrainsMono-Bold.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Bold.woff2" || true
    chmod 644 "$UI_DIR"/*.woff2 2>/dev/null || true
    # -------------------------------------------

    cat <<'EOF' >"$UI_DIR/index.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SysWarden | Fortress Dashboard</title>
    
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
    
    <style>
        /* --- HYPER MODERN DEVSECOPS THEME (Bento Box + Glassmorphism) --- */
        
        /* Font Integration */
        @font-face {
            font-family: 'JetBrains Mono';
            src: url('JetBrainsMono-Regular.woff2') format('woff2');
            font-weight: normal; font-style: normal; font-display: swap;
        }
        @font-face {
            font-family: 'JetBrains Mono';
            src: url('JetBrainsMono-Bold.woff2') format('woff2');
            font-weight: bold; font-style: normal; font-display: swap;
        }

        /* Color Variables - Deep Dark Cyberpunk */
        :root {
            --bg-base: #030305;               /* Ultra deep dark background */
            --bg-panel: rgba(18, 18, 22, 0.65); /* Glassmorphism base */
            --bg-panel-hover: rgba(25, 25, 30, 0.85);
            --text-main: #f8fafc;
            --text-muted: #8b9bb4;
            --border: rgba(255, 255, 255, 0.06);
            --border-highlight: rgba(255, 255, 255, 0.15);
            --brand: #ff003c;                 /* Red Neon */
            --brand-glow: rgba(255, 0, 60, 0.2);
            --success: #00ff88;               /* Matrix Green */
            --success-glow: rgba(0, 255, 136, 0.2);
            --accent: #00d8ff;                /* Blue Neon */
            --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
        }

        /* Reset & Base */
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: var(--font-mono); }
        
        body {
            background-color: var(--bg-base); 
            /* Subtle Cyberpunk Grid Background */
            background-image: 
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 30px 30px;
            color: var(--text-main);
            line-height: 1.5;
            min-height: 100vh;
            position: relative;
            overflow-x: hidden;
        }

        /* --- ORBS & HALO EFFECTS (Background) --- */
        body::before, body::after {
            content: ''; position: fixed; border-radius: 50%; filter: blur(120px);
            z-index: -1; opacity: 0.35; pointer-events: none;
        }
        body::before {
            top: -15%; left: -10%; width: 50vw; height: 50vh;
            background: radial-gradient(circle, var(--brand-glow) 0%, transparent 70%);
        }
        body::after {
            bottom: -20%; right: -10%; width: 60vw; height: 60vh;
            background: radial-gradient(circle, rgba(0, 216, 255, 0.15) 0%, transparent 70%);
        }

        a { color: var(--brand); text-decoration: none; transition: all 0.2s; }
        a:hover { color: var(--accent); text-shadow: 0 0 8px var(--accent); }

        /* Modern Fine Scrollbar */
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--accent); box-shadow: 0 0 10px var(--accent); }

        /* Typography & Utilities */
        .text-sm { font-size: 0.875rem; }
        .text-xs { font-size: 0.75rem; }
        .text-brand { color: var(--brand); text-shadow: 0 0 10px var(--brand-glow); }
        .text-success { color: var(--success); text-shadow: 0 0 10px var(--success-glow); }
        .text-accent { color: var(--accent); }
        .text-muted { color: var(--text-muted); }
        .font-bold { font-weight: bold; }
        .uppercase { text-transform: uppercase; }
        .tracking-widest { letter-spacing: 0.1em; }
        .mt-4 { margin-top: 1rem; }
        .mb-4 { margin-bottom: 1rem; }
        .mb-8 { margin-bottom: 2rem; }
        .flex-align { display: flex; align-items: center; gap: 0.75rem; }
        .flex-between { display: flex; justify-content: space-between; align-items: center; }

        /* Layout & Bento Grids */
        .container { max-width: 1350px; margin: 0 auto; padding: 0 1.5rem; }
        .grid { display: grid; gap: 1.25rem; }
        .grid-4 { grid-template-columns: repeat(4, 1fr); }
        .grid-3 { grid-template-columns: repeat(3, 1fr); }
        .grid-2 { grid-template-columns: repeat(2, 1fr); }
        .chart-span { grid-column: span 2; }

        @media (max-width: 1024px) { .grid-4, .grid-3 { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 768px) { 
            .grid-4, .grid-3, .grid-2 { grid-template-columns: 1fr; }
            .chart-span { grid-column: span 1; }
        }

        /* Navbar Glass */
        .navbar { 
            background: rgba(3, 3, 5, 0.75); 
            backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
            border-bottom: 1px solid var(--border); 
            padding: 1.25rem 0; 
            position: sticky; top: 0; z-index: 100;
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
        }

        /* Bento Panels */
        .panel { 
            position: relative;
            background: linear-gradient(145deg, var(--bg-panel) 0%, rgba(10, 10, 12, 0.8) 100%);
            backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--border); 
            border-radius: 16px; 
            padding: 2.2rem 1.5rem 1.5rem 1.5rem; /* Extra top padding for Mac dots */
            transition: all 0.3s ease;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }
        .panel:hover { border-color: var(--border-highlight); background: var(--bg-panel-hover); transform: translateY(-2px); box-shadow: 0 12px 40px 0 rgba(0, 0, 0, 0.4); }
        
        /* --- MAC TERMINAL DOTS --- */
        .panel::before {
            content: '';
            position: absolute;
            top: 14px;
            left: 16px;
            width: 9px; height: 9px;
            border-radius: 50%;
            background: #ff5f56; /* Red */
            box-shadow: 16px 0 0 #ffbd2e, 32px 0 0 #27c93f; /* Yellow & Green */
            opacity: 0.3;
            transition: opacity 0.3s ease;
        }
        .panel:hover::before { opacity: 0.9; }

        .panel-title { 
            font-size: 0.75rem; font-weight: bold; text-transform: uppercase; 
            letter-spacing: 0.1em; color: var(--text-muted); margin-bottom: 0.5rem; 
        }
        .panel-val { font-size: 1.6rem; font-weight: bold; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
        .val-huge { font-size: 4.5rem; font-weight: bold; color: var(--brand); line-height: 1; text-shadow: 0 0 24px var(--brand-glow); }
        
        .panel-highlight { 
            border-color: rgba(255, 0, 60, 0.3); 
            box-shadow: inset 0 0 60px rgba(255, 0, 60, 0.05), 0 8px 32px 0 rgba(0, 0, 0, 0.3); 
        }

        /* Lists & Data */
        .list-container { display: flex; flex-direction: column; gap: 0.6rem; }
        .list-item {
            display: flex; justify-content: space-between; align-items: center;
            background: rgba(0, 0, 0, 0.4); padding: 0.85rem 1rem;
            border-radius: 12px; border: 1px solid var(--border); font-size: 0.85rem;
            transition: all 0.2s;
        }
        .list-item-hover:hover { border-color: var(--accent); background: rgba(0, 216, 255, 0.03); transform: translateX(4px); box-shadow: -4px 0 10px rgba(0, 216, 255, 0.05); }
        .rank { color: var(--text-muted); font-weight: bold; width: 1.75rem; display: inline-block; }
        
        .tag-red { background: rgba(255, 0, 60, 0.1); color: var(--brand); padding: 3px 10px; border-radius: 12px; font-weight: bold; font-size: 0.7rem; border: 1px solid rgba(255,0,60,0.2); }
        .tag-green { background: rgba(0, 255, 136, 0.05); color: var(--success); padding: 3px 10px; border-radius: 12px; font-weight: bold; font-size: 0.7rem; text-transform: uppercase; border: 1px solid rgba(0,255,136,0.3); box-shadow: 0 0 10px var(--success-glow); }

        .table { width: 100%; border-collapse: separate; border-spacing: 0 0.5rem; font-size: 0.85rem; }
        .table th { text-align: left; padding: 0 0.5rem 0.5rem 0.5rem; color: var(--text-muted); font-weight: normal; border-bottom: 1px solid var(--border); }
        .table td { padding: 0.85rem 1rem; background: rgba(0, 0, 0, 0.4); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border); }
        .table tr td:first-child { border-left: 1px solid var(--border); border-top-left-radius: 12px; border-bottom-left-radius: 12px; }
        .table tr td:last-child { border-right: 1px solid var(--border); border-top-right-radius: 12px; border-bottom-right-radius: 12px; }
        .table tr:hover td { background: rgba(255, 255, 255, 0.03); border-color: var(--border-highlight); color: var(--accent); }

        .scroll-y { max-height: 290px; overflow-y: auto; padding-right: 0.5rem; }
        .chart-wrapper { position: relative; height: 280px; width: 100%; margin-top: 10px; }

        /* --- ANIMATIONS --- */
        @keyframes pulse-green {
            0% { box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
            100% { box-shadow: 0 0 0 0 rgba(0, 255, 136, 0); }
        }
        @keyframes pulse-red {
            0% { box-shadow: 0 0 0 0 rgba(255, 0, 60, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(255, 0, 60, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 0, 60, 0); }
        }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; }
        .status-up { background-color: var(--success); animation: pulse-green 2s infinite; }
        .status-down { background-color: var(--brand); animation: pulse-red 2s infinite; }
        
        .syswarden-pulse {
            width: 6px; height: 6px; border-radius: 50%; background: var(--brand);
            animation: pulse-red 2s infinite; margin-left: 2px; margin-top: 4px;
        }
		
		/* --- 3. LIGHT THEME & SWITCHER OVERRIDES --- */
        /* Theme Switcher UI */
        .theme-toggle {
            background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border);
            border-radius: 20px; display: flex; align-items: center;
            padding: 4px; cursor: pointer; transition: all 0.3s; margin-right: 15px;
        }
        .theme-btn {
            background: transparent; border: none; color: var(--text-muted);
            width: 30px; height: 30px; border-radius: 50%; display: flex;
            align-items: center; justify-content: center; cursor: pointer;
            transition: all 0.3s; padding: 6px;
        }
        .theme-btn:hover { color: var(--text-main); }
        .theme-btn.active {
            background: var(--bg-panel-hover); color: var(--accent);
            box-shadow: 0 2px 8px rgba(0,0,0,0.3);
        }
        .theme-btn svg { width: 16px; height: 16px; fill: currentColor; }

        /* Light Theme Variables */
        html[data-theme="light"] {
            --bg-base: #f1f5f9;
            --bg-panel: rgba(255, 255, 255, 0.75);
            --bg-panel-hover: rgba(255, 255, 255, 0.95);
            --text-main: #0f172a;
            --text-muted: #475569;
            --border: rgba(0, 0, 0, 0.1);
            --border-highlight: rgba(0, 0, 0, 0.2);
            --brand: #e11d48;
            --brand-glow: rgba(225, 29, 72, 0.15);
            --success: #059669;
            --success-glow: rgba(5, 150, 105, 0.15);
            --accent: #0284c7;
        }

        /* Light Theme Specific Fixes (Glassmorphism Adaptation) */
        html[data-theme="light"] body {
            background-image: 
                linear-gradient(rgba(0, 0, 0, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 0, 0, 0.03) 1px, transparent 1px);
        }
        html[data-theme="light"] .panel-val { text-shadow: none; }
        html[data-theme="light"] .theme-toggle { background: rgba(0, 0, 0, 0.05); }
        html[data-theme="light"] .theme-btn.active { background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        html[data-theme="light"] .list-item, html[data-theme="light"] .table td { background: rgba(255, 255, 255, 0.5); }
        html[data-theme="light"] .navbar { background: rgba(241, 245, 249, 0.85); box-shadow: 0 10px 30px -10px rgba(0,0,0,0.1); }
        html[data-theme="light"] .panel { background: linear-gradient(145deg, var(--bg-panel) 0%, rgba(255, 255, 255, 0.9) 100%); box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.05); }
        html[data-theme="light"] .panel-highlight { box-shadow: inset 0 0 60px rgba(225, 29, 72, 0.05), 0 8px 32px 0 rgba(0, 0, 0, 0.05); }
        html[data-theme="light"] thead { background: rgba(248, 250, 252, 0.95) !important; }
    </style>
</head>
<body>

    <nav class="navbar">
        <div class="container flex-between">
            <div class="flex-align">
                <h1 style="font-size: 1.3rem; font-weight: bold; letter-spacing: -0.05em; display: flex; align-items: flex-start;">
                    SYSWARDEN&nbsp;<span class="text-brand">v1.86</span>
                    <div class="syswarden-pulse"></div>
                </h1>
            </div>
            <div class="flex-align">
			    <div class="theme-toggle" id="theme-switcher">
                    <button class="theme-btn" data-theme-val="light" title="Light Theme">
                        <svg viewBox="0 0 24 24"><path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.39.39-1.03 0-1.41L5.99 4.58zm12.37 12.37c-.39-.39-1.03-.39-1.41 0-.39.39-.39 1.03 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0 .39-.39.39-1.03 0-1.41l-1.06-1.06zm1.06-10.96c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41.39.39 1.03.39 1.41 0l1.06-1.06zM7.05 18.36c.39-.39.39-1.03 0-1.41-.39-.39-1.03-.39-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41.39.39 1.03.39 1.41 0l1.06-1.06z"/></svg>
                    </button>
                    <button class="theme-btn active" data-theme-val="system" title="System Theme">
                        <svg viewBox="0 0 24 24"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>
                    </button>
                    <button class="theme-btn" data-theme-val="dark" title="Dark Theme">
                        <svg viewBox="0 0 24 24"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/></svg>
                    </button>
                </div>
                <span class="text-xs uppercase tracking-widest font-bold" id="status-text" style="color: var(--text-muted);">Initializing...</span>
                <div class="status-dot status-down" id="status-indicator"></div>
            </div>
        </div>
    </nav>

    <main class="container" style="padding-top: 2.5rem; padding-bottom: 3rem;">
        
        <div class="grid grid-4 mb-8">
            <div class="panel">
                <p class="panel-title">Hostname</p>
                <p class="panel-val text-accent" id="sys-hostname">--</p>
            </div>
            <div class="panel">
                <p class="panel-title">Uptime</p>
                <p class="panel-val" id="sys-uptime">--</p>
            </div>
            <div class="panel">
                <p class="panel-title">Load Average</p>
                <p class="panel-val" id="sys-load">--</p>
            </div>
            <div class="panel">
                <p class="panel-title">RAM Usage</p>
                <p class="panel-val" id="sys-ram">--</p>
            </div>
        </div>

        <div class="grid grid-3 mb-8">
            <div class="panel">
                <h2 class="panel-title mb-4">Layer 3 Kernel Shield</h2>
                <div class="list-container">
                    <div class="flex-between">
                        <span class="text-muted">Global Blocklist</span>
                        <span class="font-bold text-accent" id="l3-global">0</span>
                    </div>
                    <div class="flex-between mt-4">
                        <span class="text-muted">GeoIP Blocks</span>
                        <span class="font-bold text-accent" id="l3-geoip">0</span>
                    </div>
                    <div class="flex-between mt-4">
                        <span class="text-muted">ASN Blocks</span>
                        <span class="font-bold text-accent" id="l3-asn">0</span>
                    </div>
                </div>
            </div>

            <div class="panel panel-highlight">
                <h2 class="panel-title text-brand mb-4">Layer 7 Fail2ban WAF</h2>
                <p class="text-sm text-muted mb-4">Total Active Bans (Real-time)</p>
                <p class="val-huge" id="l7-banned">0</p>
                <p class="text-sm text-muted mt-4"><span id="l7-jails" class="font-bold text-main">0</span> Jails Monitoring</p>
            </div>

            <div class="panel" style="display: flex; flex-direction: column; justify-content: space-between;">
                <div>
                    <h2 class="panel-title text-success mb-4">Safe Zone (Whitelist)</h2>
                    <p class="val-huge" style="color: var(--success);" id="wl-count">0</p>
                    <p class="text-sm text-muted mt-4">Protected IP Addresses</p>
                </div>
                <div style="border-top: 1px solid var(--border); padding-top: 1rem; margin-top: 1rem; text-align: right;">
                    <p class="text-xs text-muted uppercase">Last Sync: <span id="last-update" class="font-bold text-main">Never</span></p>
                </div>
            </div>
        </div>

        <div class="panel mb-8">
            <h2 class="panel-title text-brand mb-4">Threat Vectors & Repeat Offenders</h2>
            <div class="grid grid-2">
                <div>
                    <h3 class="text-xs font-bold text-muted uppercase mb-4">Most Triggered Jails</h3>
                    <ul id="top-jails-list" class="list-container">
                        <li class="text-xs text-muted italic">Awaiting telemetry...</li>
                    </ul>
                </div>
                <div>
                    <h3 class="text-xs font-bold text-muted uppercase mb-4">Top Attacking IPs (OSINT)</h3>
                    <ul id="top-ips-list" class="list-container">
                        <li class="text-xs text-muted italic">Awaiting telemetry...</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="grid grid-3 mb-8">
            <div class="panel chart-span">
                <h2 class="panel-title mb-4">L7 Threat Telemetry (Live)</h2>
                <div class="chart-wrapper">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>

            <div class="panel">
                <h2 class="panel-title mb-4">Active Jail Triggers</h2>
                <div class="scroll-y">
                    <ul id="jail-list" class="list-container">
                        <li class="text-sm text-muted italic">Awaiting telemetry data...</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="grid grid-2 mb-8">
            <div class="panel">
                <h2 class="panel-title mb-4">L7 Banned IP Registry</h2>
                <div class="scroll-y">
                     <table class="table">
                        <thead style="position: sticky; top: 0; background: rgba(18, 18, 22, 0.85); backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); z-index: 10;">
                            <tr>
                                <th style="padding-top: 0.5rem;">IP Address</th>
                                <th style="text-align: right; padding-top: 0.5rem;">Target Jail</th>
                            </tr>
                        </thead>
                        <tbody id="banned-ips-list"></tbody>
                     </table>
                </div>
            </div>

            <div class="panel">
                <h2 class="panel-title text-success mb-4">Global Whitelist Registry</h2>
                <div class="scroll-y">
                     <ul id="whitelist-ips-list" class="grid grid-2"></ul>
                </div>
            </div>
        </div>
    </main>

    <script>
        // --- GLOBAL VARIABLES (Evite l'erreur Temporal Dead Zone) ---
        let threatChart = null;

        // --- 0. THEME MANAGER ---
        const themeBtns = document.querySelectorAll('.theme-btn');
        const rootHtml = document.documentElement;

        // --- DEVSECOPS FIX: Failsafe pour le localStorage en exécution locale (file://) ---
        function getSavedTheme() {
            try { return localStorage.getItem('syswarden-theme') || 'system'; } 
            catch (e) { return 'system'; }
        }
        function saveTheme(theme) {
            try { localStorage.setItem('syswarden-theme', theme); } 
            catch (e) {}
        }
        // ---------------------------------------------------------------------------------

        function applyTheme(theme) {
            let actualTheme = theme;
            if (theme === 'system') {
                actualTheme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
            }
            rootHtml.setAttribute('data-theme', actualTheme);

            // Update button states
            themeBtns.forEach(btn => {
                btn.classList.remove('active');
                if (btn.getAttribute('data-theme-val') === theme) {
                    btn.classList.add('active');
                }
            });

            // Dynamically update Chart.js colors (Grids and Tooltips)
            if (typeof threatChart !== 'undefined' && threatChart !== null) {
                const isLight = actualTheme === 'light';
                threatChart.options.scales.x.grid.color = isLight ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.03)';
                threatChart.options.scales.y.grid.color = isLight ? 'rgba(0, 0, 0, 0.05)' : 'rgba(255, 255, 255, 0.05)';
                threatChart.options.plugins.tooltip.backgroundColor = isLight ? 'rgba(255, 255, 255, 0.95)' : 'rgba(10, 10, 15, 0.9)';
                threatChart.options.plugins.tooltip.titleColor = isLight ? '#0f172a' : '#fff';
                threatChart.options.plugins.tooltip.bodyColor = isLight ? '#0f172a' : '#fff';
                threatChart.options.plugins.tooltip.borderColor = isLight ? 'rgba(0, 0, 0, 0.1)' : 'rgba(255, 255, 255, 0.15)';
                threatChart.update();
            }
        }

        // Initialize theme safely
        applyTheme(getSavedTheme());

        // Click listeners for the buttons
        themeBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const selectedTheme = btn.getAttribute('data-theme-val');
                saveTheme(selectedTheme);
                applyTheme(selectedTheme);
            });
        });

        // Listen for OS/System theme changes in real-time
        window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
            if (getSavedTheme() === 'system') {
                applyTheme('system');
            }
        });
        
        // --- 1. CHART ENGINE (FAULT-TOLERANT & GLASSMORPHISM ADAPTED) ---
        const chartData = {
            labels: [],
            datasets: [{
                label: 'L7 Active Bans',
                data: [],
                borderColor: '#ff003c',
                backgroundColor: 'rgba(255, 0, 60, 0.1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true,
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: '#00d8ff',
                pointHoverBorderColor: '#fff',
                pointHoverBorderWidth: 2
            }]
        };
        
        try {
            const ctx = document.getElementById('threatChart').getContext('2d');
            
            // Subtle glowing gradient
            let gradient = ctx.createLinearGradient(0, 0, 0, 300);
            gradient.addColorStop(0, 'rgba(255, 0, 60, 0.35)');
            gradient.addColorStop(1, 'rgba(255, 0, 60, 0.02)');
            chartData.datasets[0].backgroundColor = gradient;

            threatChart = new Chart(ctx, {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    color: '#8b9bb4',
                    plugins: { 
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(10, 10, 15, 0.9)',
                            titleFont: { family: 'JetBrains Mono', size: 13 },
                            bodyFont: { family: 'JetBrains Mono', size: 13 },
                            borderColor: 'rgba(255, 255, 255, 0.15)',
                            borderWidth: 1,
                            padding: 12,
                            displayColors: false
                        }
                    },
                    scales: {
                        x: { 
                            display: false,
                            grid: { color: 'rgba(255, 255, 255, 0.03)' }
                        },
                        y: { 
                            beginAtZero: true, 
                            grid: { color: 'rgba(255, 255, 255, 0.05)', borderDash: [5, 5] },
                            border: { display: false },
                            ticks: { font: { family: 'JetBrains Mono' }, padding: 10 }
                        }
                    },
                    animation: { duration: 0 },
                    interaction: { mode: 'nearest', axis: 'x', intersect: false }
                }
            });
        } catch (error) {
            console.warn("Chart.js failed to load. The dashboard will continue running without the graph.", error);
        }

        // Force chart theme sync on load
        applyTheme(getSavedTheme());

        // --- 2. DATA FETCH ENGINE ---
        const MAX_DATA_POINTS = 30;

        async function fetchTelemetry() {
            try {
                const response = await fetch(`data.json?t=${new Date().getTime()}`);
                if (!response.ok) throw new Error('Network response was not ok');
                const data = await response.json();

                document.getElementById('sys-hostname').innerText = data.system.hostname;
                document.getElementById('sys-uptime').innerText = data.system.uptime;
                document.getElementById('sys-load').innerText = data.system.load_average;
                document.getElementById('sys-ram').innerText = `${data.system.ram_used_mb} MB / ${data.system.ram_total_mb} MB`;

                document.getElementById('l3-global').innerText = data.layer3.global_blocked.toLocaleString();
                document.getElementById('l3-geoip').innerText = data.layer3.geoip_blocked.toLocaleString();
                document.getElementById('l3-asn').innerText = data.layer3.asn_blocked.toLocaleString();

                document.getElementById('l7-banned').innerText = data.layer7.total_banned.toLocaleString();
                document.getElementById('l7-jails').innerText = data.layer7.active_jails;
                document.getElementById('wl-count').innerText = data.whitelist.active_ips;

                // --- DOM UPDATE: Top 10 Jails ---
                const topJailsEl = document.getElementById('top-jails-list');
                topJailsEl.innerHTML = '';
                if (data.layer7.jails_data && data.layer7.jails_data.length > 0) {
                    const sortedJails = [...data.layer7.jails_data].sort((a, b) => b.count - a.count).slice(0, 10);
                    sortedJails.forEach((jail, index) => {
                        const li = document.createElement('li');
                        li.className = 'list-item list-item-hover';
                        
                        const leftDiv = document.createElement('div');
                        leftDiv.className = 'flex-align';
                        const rankSpan = document.createElement('span');
                        rankSpan.className = 'rank';
                        rankSpan.textContent = `#${index + 1}`;
                        const nameSpan = document.createElement('span');
                        nameSpan.textContent = jail.name;
                        
                        const countSpan = document.createElement('span');
                        countSpan.className = 'font-bold text-brand text-xs';
                        countSpan.textContent = jail.count + ' bans';
                        
                        leftDiv.appendChild(rankSpan);
                        leftDiv.appendChild(nameSpan);
                        li.appendChild(leftDiv);
                        li.appendChild(countSpan);
                        topJailsEl.appendChild(li);
                    });
                } else {
                    topJailsEl.innerHTML = '<li class="text-xs text-muted italic">No active vectors.</li>';
                }

                // --- DOM UPDATE: Top 10 Attacking IPs ---
                const topIpsEl = document.getElementById('top-ips-list');
                topIpsEl.innerHTML = '';
                if (data.layer7.top_attackers && data.layer7.top_attackers.length > 0) {
                    data.layer7.top_attackers.forEach((attacker, index) => {
                        const li = document.createElement('li');
                        li.className = 'list-item list-item-hover';
                        
                        const leftDiv = document.createElement('div');
                        leftDiv.className = 'flex-align';
                        const rankSpan = document.createElement('span');
                        rankSpan.className = 'rank';
                        rankSpan.textContent = `#${index + 1}`;
                        
                        const ipLink = document.createElement('a');
                        ipLink.href = `https://www.abuseipdb.com/check/${attacker.ip}`;
                        ipLink.target = '_blank';
                        ipLink.rel = 'noopener noreferrer';
                        ipLink.className = 'font-bold';
                        ipLink.textContent = attacker.ip;
                        
                        const countSpan = document.createElement('span');
                        countSpan.className = 'font-bold text-muted text-xs';
                        countSpan.textContent = attacker.count + ' hits';
                        
                        leftDiv.appendChild(rankSpan);
                        leftDiv.appendChild(ipLink);
                        li.appendChild(leftDiv);
                        li.appendChild(countSpan);
                        topIpsEl.appendChild(li);
                    });
                } else {
                    topIpsEl.innerHTML = '<li class="text-xs text-muted italic">No attackers recorded yet.</li>';
                }

                // --- DOM UPDATE: Active Jails List ---
                const jailListEl = document.getElementById('jail-list');
                jailListEl.innerHTML = '';
                if (data.layer7.jails_data && data.layer7.jails_data.length > 0) {
                    data.layer7.jails_data.forEach(jail => {
                        const li = document.createElement('li');
                        li.className = 'list-item list-item-hover';
                        
                        const spanName = document.createElement('span');
                        spanName.textContent = jail.name;
                        
                        const spanCount = document.createElement('span');
                        spanCount.className = 'tag-red';
                        spanCount.textContent = jail.count;
                        
                        li.appendChild(spanName);
                        li.appendChild(spanCount);
                        jailListEl.appendChild(li);
                    });
                } else {
                    jailListEl.innerHTML = '<li class="text-sm text-muted italic">No active bans found. Server is quiet.</li>';
                }

                // --- DOM UPDATE: Banned IPs Registry Table ---
                const bannedIpsEl = document.getElementById('banned-ips-list');
                bannedIpsEl.innerHTML = '';
                if (data.layer7.banned_ips && data.layer7.banned_ips.length > 0) {
                    data.layer7.banned_ips.reverse().forEach(entry => {
                        const tr = document.createElement('tr');
                        
                        const tdIp = document.createElement('td');
                        const ipLink = document.createElement('a');
                        ipLink.href = `https://www.abuseipdb.com/check/${entry.ip}`;
                        ipLink.target = '_blank';
                        ipLink.rel = 'noopener noreferrer';
                        ipLink.className = 'font-bold text-xs';
                        ipLink.textContent = entry.ip;
                        tdIp.appendChild(ipLink);
                        
                        const tdJail = document.createElement('td');
                        tdJail.style.textAlign = 'right';
                        tdJail.className = 'text-xs text-muted font-bold uppercase';
                        tdJail.textContent = entry.jail;
                        
                        tr.appendChild(tdIp);
                        tr.appendChild(tdJail);
                        bannedIpsEl.appendChild(tr);
                    });
                } else {
                    bannedIpsEl.innerHTML = '<tr><td colspan="2" style="text-align: center; padding: 1.5rem 0;" class="text-xs text-muted italic">Registry is empty.</td></tr>';
                }

                // --- DOM UPDATE: Whitelist IPs Registry Grid ---
                const wlIpsEl = document.getElementById('whitelist-ips-list');
                wlIpsEl.innerHTML = '';
                if (data.whitelist.ips && data.whitelist.ips.length > 0) {
                    data.whitelist.ips.forEach(ip => {
                        const li = document.createElement('li');
                        li.className = 'list-item';
                        li.style.borderColor = 'rgba(0, 255, 136, 0.2)';
                        li.style.background = 'rgba(0, 255, 136, 0.05)';
                        
                        const spanIp = document.createElement('span');
                        spanIp.className = 'font-bold text-success text-xs';
                        spanIp.textContent = ip;
                        
                        const spanBadge = document.createElement('span');
                        spanBadge.className = 'tag-green';
                        spanBadge.textContent = 'SAFE';
                        
                        li.appendChild(spanIp);
                        li.appendChild(spanBadge);
                        wlIpsEl.appendChild(li);
                    });
                } else {
                    wlIpsEl.innerHTML = '<li class="text-xs text-muted italic" style="grid-column: span 2;">Registry is empty.</li>';
                }

                // Update Chart
                const now = new Date();
                const timeString = now.getHours() + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
                
                if (threatChart) {
                    chartData.labels.push(timeString);
                    chartData.datasets[0].data.push(data.layer7.total_banned);

                    if (chartData.labels.length > MAX_DATA_POINTS) {
                        chartData.labels.shift();
                        chartData.datasets[0].data.shift();
                    }
                    threatChart.update();
                }

                // Update Status UI (GREEN = UP)
                document.getElementById('last-update').innerText = timeString;
                const statusInd = document.getElementById('status-indicator');
                const statusTxt = document.getElementById('status-text');
                statusInd.className = 'status-dot status-up';
                statusTxt.innerText = 'SYSTEM ONLINE';
                statusTxt.style.color = 'var(--success)';

            } catch (error) {
                console.error("Telemetry Fetch Error:", error);
                document.getElementById('last-update').innerText = "Offline / Error";
                // Update Status UI (RED = DOWN)
                const statusInd = document.getElementById('status-indicator');
                const statusTxt = document.getElementById('status-text');
                statusInd.className = 'status-dot status-down';
                statusTxt.innerText = 'SYSTEM OFFLINE';
                statusTxt.style.color = 'var(--brand)';
            }
        }

        fetchTelemetry();
        setInterval(fetchTelemetry, 5000);
    </script>
</body>
</html>
EOF

    local SSL_DIR="/etc/syswarden/ssl"
    mkdir -p "$SSL_DIR"
    if [[ ! -f "$SSL_DIR/syswarden.crt" ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout "$SSL_DIR/syswarden.key" -out "$SSL_DIR/syswarden.crt" -subj "/CN=syswarden-dashboard" 2>/dev/null
        chmod 600 "$SSL_DIR/syswarden.key"
    fi

    # Slackware Nginx config injection
    local NGINX_CONF="/etc/nginx/conf.d/syswarden-ui.conf"
    mkdir -p /etc/nginx/conf.d

    local NGINX_ALLOW_RULES=""
    if [[ -s "$WHITELIST_FILE" ]]; then
        # DEVSECOPS FIX: Read securely and strip hidden carriage returns (\r) to prevent Nginx fatal syntax crashes
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
    listen 9999 ssl http2;
    server_name _;
    ssl_certificate $SSL_DIR/syswarden.crt;
    ssl_certificate_key $SSL_DIR/syswarden.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root $UI_DIR;
    index index.html;

$(echo -e "$NGINX_ALLOW_RULES")

    # --- Strict Security Headers (XSS, CSP, IDOR mitigation) ---
    # DEVSECOPS FIX: Removed Tailwind CDN & Google Fonts. Added local font-src.
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdnjs.cloudflare.com; font-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline';" always;
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

    # --- DEVSECOPS FIX: Dynamically patch native Slackware nginx.conf ---
    if [[ -f /etc/nginx/nginx.conf ]]; then
        if ! grep -q "include /etc/nginx/conf.d/\*.conf;" /etc/nginx/nginx.conf; then
            log "INFO" "Patching native /etc/nginx/nginx.conf to include syswarden dashboard..."
            sed -i 's/http {/http {\n    include \/etc\/nginx\/conf.d\/\*.conf;/g' /etc/nginx/nginx.conf || true
        fi
    fi

    # --- DEVSECOPS FIX: Safely reload or restart Nginx (Zero Downtime) ---
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
        # DevSecOps Fix: Map syslog months to ISO numbers and fetch current year
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
        nft delete table inet syswarden_table 2>/dev/null || true
        nft delete table inet syswarden_wg 2>/dev/null || true
    elif command -v iptables >/dev/null 2>&1; then
        # Remove specific iptables rules by recreating logic in delete mode or flush specific
        iptables-save | grep -v 'SysWarden' | iptables-restore 2>/dev/null || true
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

# --- DEVSECOPS FIX: Intercept 'alerts' mode for CLI Dashboard ---
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

if [[ "$MODE" != "update" ]] && [[ "$MODE" != "uninstall" ]]; then
    clear
    echo -e "${GREEN}#############################################################"
    echo -e "#     SysWarden Tool Installer (Slackware $VERSION)     #"
    echo -e "#############################################################${NC}"
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
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v1.86 - PRE-FLIGHT CHECKLIST                     ${NC}"
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

        echo -e "\n${BOLD}6. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] None (Geo/ASN Only)"

        echo -e "\n${BOLD}7. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
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
    select_list_type "$MODE"
    select_mirror "$MODE"
    download_list
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

    # --- DEVSECOPS FIX: Ensure all configuration defaults & whitelists are applied during update ---
    define_ssh_port "update"
    define_wireguard "update"
    define_os_hardening "update"
    define_geoblocking "update"
    define_asnblocking "update"
    select_list_type "update"
    select_mirror "update"

    auto_whitelist_admin
    process_auto_whitelist "update"
    # -----------------------------------------------------------------------------------------------

    download_list
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
