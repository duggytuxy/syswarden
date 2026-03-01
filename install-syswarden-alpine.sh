#!/bin/bash

# SysWarden for Alpine Linux - Advanced Firewall & Blocklist Orchestrator
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

# --- ALPINE LINUX SAFETY FIRST ---
if [ -z "$BASH_VERSION" ]; then
    echo "ERROR: This script requires Bash."
    echo "Please install it first by running: apk add bash"
    echo "Then re-run the script with: bash $0"
    exit 1
fi

set -euo pipefail
IFS=$'\n\t'

# --- SECURE PATH FOR ALPINE ---
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"
TMP_DIR=$(mktemp -d)
VERSION="v9.27"
SYSWARDEN_DIR="/etc/syswarden"
WHITELIST_FILE="$SYSWARDEN_DIR/whitelist.txt"
BLOCKLIST_FILE="$SYSWARDEN_DIR/blocklist.txt"
GEOIP_SET_NAME="syswarden_geoip"
GEOIP_FILE="$SYSWARDEN_DIR/geoip.txt"
ASN_SET_NAME="syswarden_asn"
ASN_FILE="$SYSWARDEN_DIR/asn.txt"
VPN_SET_NAME="syswarden_vpn"
VPN_FILE="$SYSWARDEN_DIR/vpn.txt"

# --- LIST URLS ---
declare -A URLS_STANDARD
URLS_STANDARD[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt"

declare -A URLS_CRITICAL
URLS_CRITICAL[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt"

# --- SHELLCHECK FIX (Nameref workaround) ---
: "${URLS_STANDARD[@]}"
: "${URLS_CRITICAL[@]}"
# -------------------------------------------

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp; timestamp=$(date "+%Y-%m-%d %H:%M:%S")
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
    
    if [ -f /etc/alpine-release ]; then
        OS="Alpine Linux"
        OS_ID="alpine"
    else
        log "ERROR" "This specific script is designed ONLY for Alpine Linux."
        exit 1
    fi

    # Logic to select the best firewall for Alpine
    if command -v nft >/dev/null 2>&1 || apk info -e nftables >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="ipset" # Fallback Iptables
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Installing required dependencies..."
    
    local deps="curl python3 py3-requests ipset fail2ban bash coreutils grep gawk sed procps logrotate ncurses whois rsyslog util-linux wireguard-tools libqrencode libqrencode-tools"
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        deps="$deps nftables"
    else
        deps="$deps iptables ip6tables"
    fi

    # --- ALPINE / POSIX FIX FOR IFS ---
    # Temporarily restore default IFS (space) so word splitting works for apk
    local OLD_IFS="$IFS"
    IFS=$' \t\n'
    
    # shellcheck disable=SC2086
    if ! apk add --no-cache $deps >/dev/null; then
        IFS="$OLD_IFS" # Restore strict IFS before exiting on error
        log "ERROR" "Failed to install dependencies via apk. Check your network or repositories."
        exit 1
    fi
    
    IFS="$OLD_IFS" # Restore strict IFS for the rest of the script
    # ----------------------------------

    if ! command -v rc-update >/dev/null; then
        log "ERROR" "OpenRC is missing. This script requires a standard Alpine setup."
        exit 1
    fi
	
	# Ensure standard syslog is active to capture Kernel Firewall Drops
    rc-update add rsyslog default >/dev/null 2>&1 || true
    rc-service rsyslog restart >/dev/null 2>&1 || true

    log "INFO" "All dependencies check complete."
}

define_ssh_port() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SSH_PORT:-}" ]]; then SSH_PORT=22; fi
        log "INFO" "Update Mode: Preserving SSH Port $SSH_PORT"
        return
    fi

    echo -e "\n${BLUE}=== Step: SSH Configuration ===${NC}"
    
    # --- DYNAMIC SSH PORT DETECTION ---
    local detected_port=22
    if command -v sshd >/dev/null; then
        local parsed_port
        parsed_port=$(sshd -T 2>/dev/null | grep -i '^port ' | awk '{print $2}')
        if [[ "$parsed_port" =~ ^[0-9]+$ ]] && [ "$parsed_port" -ge 1 ] && [ "$parsed_port" -le 65535 ]; then
            detected_port="$parsed_port"
        fi
    fi
    # ----------------------------------

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        SSH_PORT=${SYSWARDEN_SSH_PORT:-$detected_port}
        log "INFO" "Auto Mode: SSH Port configured via env var [${SSH_PORT}]"
    else
        read -p "Please enter your current SSH Port [Default: $detected_port]: " input_port
        SSH_PORT=${input_port:-$detected_port}
    fi
    # -----------------------------

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        log "WARN" "Invalid port detected. Defaulting to 22."
        SSH_PORT=22
    fi

    echo "SSH_PORT='$SSH_PORT'" >> "$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"
}

define_wireguard() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_WIREGUARD:-}" ]]; then USE_WIREGUARD="n"; fi
        log "INFO" "Update Mode: Preserving WireGuard setting ($USE_WIREGUARD)"
        return
    fi

    echo -e "\n${BLUE}=== Step: WireGuard Management VPN ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_wg=${SYSWARDEN_ENABLE_WG:-n}
        log "INFO" "Auto Mode: WireGuard choice loaded via env var [${input_wg}]"
    else
        echo -e "${YELLOW}Deploy an ultra-secure, invisible WireGuard VPN for administration?${NC}"
        read -p "Enable WireGuard Management VPN? (y/N): " input_wg
    fi
    # -----------------------------

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
        
        # PRE-CREATION: Ensure /etc/wireguard exists EARLY
        mkdir -p /etc/wireguard
        log "INFO" "WireGuard ENABLED (Port: $WG_PORT, Subnet: $WG_SUBNET)."
    else
        USE_WIREGUARD="n"
        log "INFO" "WireGuard DISABLED."
    fi
    
    echo "USE_WIREGUARD='$USE_WIREGUARD'" >> "$CONF_FILE"
    if [[ "$USE_WIREGUARD" == "y" ]]; then
        echo "WG_PORT='$WG_PORT'" >> "$CONF_FILE"
        echo "WG_SUBNET='$WG_SUBNET'" >> "$CONF_FILE"
    fi
}

define_docker_integration() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_DOCKER:-}" ]]; then USE_DOCKER="n"; fi
        log "INFO" "Update Mode: Preserving Docker integration setting ($USE_DOCKER)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Docker Integration ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_docker=${SYSWARDEN_USE_DOCKER:-n}
        log "INFO" "Auto Mode: Docker integration loaded via env var [${input_docker}]"
    else
        read -p "Do you use Docker on this server? (y/N): " input_docker
    fi
    # -----------------------------
    
    if [[ "$input_docker" =~ ^[Yy]$ ]]; then
        USE_DOCKER="y"
        log "INFO" "Docker integration ENABLED."
    else
        USE_DOCKER="n"
        log "INFO" "Docker integration DISABLED."
    fi
    echo "USE_DOCKER='$USE_DOCKER'" >> "$CONF_FILE"
}

define_geoblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${GEOBLOCK_COUNTRIES:-}" ]]; then GEOBLOCK_COUNTRIES="none"; fi
        log "INFO" "Update Mode: Preserving Geo-Blocking setting ($GEOBLOCK_COUNTRIES)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Geo-Blocking (High-Risk Countries) ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_geo=${SYSWARDEN_ENABLE_GEO:-n}
        log "INFO" "Auto Mode: Geo-Blocking choice loaded via env var [${input_geo}]"
    else
        echo "Do you want to block all inbound traffic from specific countries?"
        read -p "Enable Geo-Blocking? (y/N): " input_geo
    fi
    # -----------------------------

    if [[ "$input_geo" =~ ^[Yy]$ ]]; then
        if [[ "${1:-}" == "auto" ]]; then
            geo_codes=${SYSWARDEN_GEO_CODES:-"ru cn kp ir"}
            log "INFO" "Auto Mode: Geo-Codes loaded via env var [${geo_codes}]"
        else
            read -p "Enter country codes separated by space [Default: ru cn kp ir]: " geo_codes
        fi
        
        GEOBLOCK_COUNTRIES=${geo_codes:-ru cn kp ir}
        # Force lowercase for the URL formatting
        GEOBLOCK_COUNTRIES=$(echo "$GEOBLOCK_COUNTRIES" | tr '[:upper:]' '[:lower:]')
        log "INFO" "Geo-Blocking ENABLED for: $GEOBLOCK_COUNTRIES"
    else
        GEOBLOCK_COUNTRIES="none"
        log "INFO" "Geo-Blocking DISABLED."
    fi
    echo "GEOBLOCK_COUNTRIES='$GEOBLOCK_COUNTRIES'" >> "$CONF_FILE"
}

define_asnblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${BLOCK_ASNS:-}" ]]; then BLOCK_ASNS="none"; fi
        if [[ -z "${USE_SPAMHAUS_ASN:-}" ]]; then USE_SPAMHAUS_ASN="y"; fi
        log "INFO" "Update Mode: Preserving ASN-Blocking setting ($BLOCK_ASNS, Spamhaus: $USE_SPAMHAUS_ASN)"
        return
    fi

    echo -e "\n${BLUE}=== Step: ASN Blocking (Hosters/ISPs) ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_asn=${SYSWARDEN_ENABLE_ASN:-n}
        log "INFO" "Auto Mode: ASN-Blocking choice loaded via env var [${input_asn}]"
    else
        echo "Do you want to block entire Autonomous Systems (e.g., AS16276 for OVH)?"
        read -p "Enable ASN Blocking? (y/N): " input_asn
    fi
    # -----------------------------

    if [[ "$input_asn" =~ ^[Yy]$ ]]; then
        if [[ "${1:-}" == "auto" ]]; then
            asn_list=${SYSWARDEN_ASN_LIST:-""}
            use_spamhaus=${SYSWARDEN_USE_SPAMHAUS:-y}
            log "INFO" "Auto Mode: ASN List and Spamhaus preference loaded via env vars."
        else
            read -p "Enter custom ASN numbers separated by space (Leave empty for none): " asn_list
            echo -e "${YELLOW}Note: Fetching and resolving the Spamhaus ASN-DROP list can take more than 5 minutes.${NC}"
            read -p "Include Spamhaus ASN-DROP list (Cybercrime Hosters)? (Y/n): " use_spamhaus
        fi
        
        BLOCK_ASNS=${asn_list:-none}
        USE_SPAMHAUS_ASN=${use_spamhaus:-y} # Default to yes
        
        # Normalize Spamhaus choice
        if [[ "$USE_SPAMHAUS_ASN" =~ ^[Nn]$ ]]; then USE_SPAMHAUS_ASN="n"; else USE_SPAMHAUS_ASN="y"; fi
        
        if [[ "$BLOCK_ASNS" == "none" ]] && [[ "$USE_SPAMHAUS_ASN" == "n" ]]; then
            BLOCK_ASNS="none"
            log "WARN" "No custom ASNs provided and Spamhaus declined. ASN Blocking DISABLED."
        else
            if [[ "$BLOCK_ASNS" != "none" ]]; then
                BLOCK_ASNS=$(echo "$BLOCK_ASNS" | tr '[:lower:]' '[:upper:]')
            fi
            log "INFO" "ASN Blocking ENABLED. Custom: [$BLOCK_ASNS], Spamhaus: [$USE_SPAMHAUS_ASN]"
        fi
    else
        BLOCK_ASNS="none"
        USE_SPAMHAUS_ASN="n"
        log "INFO" "ASN Blocking DISABLED."
    fi
    echo "BLOCK_ASNS='$BLOCK_ASNS'" >> "$CONF_FILE"
    echo "USE_SPAMHAUS_ASN='$USE_SPAMHAUS_ASN'" >> "$CONF_FILE"
}

define_vpnblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${BLOCK_VPNS:-}" ]]; then BLOCK_VPNS="n"; fi
        log "INFO" "Update Mode: Preserving VPN-Blocking setting ($BLOCK_VPNS)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Commercial VPN & Datacenter Blocking ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_vpn=${SYSWARDEN_ENABLE_VPN:-n}
        log "INFO" "Auto Mode: VPN-Blocking choice loaded via env var [${input_vpn}]"
    else
        echo "Do you want to block Commercial VPNs and Datacenter IP ranges?"
        echo -e "${YELLOW}Note: This blocks NordVPN, ExpressVPN, and major cloud providers (AWS, DO, OVH, etc.)${NC}"
        read -p "Enable VPN Blocking? (y/N): " input_vpn
    fi

    if [[ "$input_vpn" =~ ^[Yy]$ ]]; then
        BLOCK_VPNS="y"
        log "INFO" "Commercial VPN Blocking ENABLED."
    else
        BLOCK_VPNS="n"
        log "INFO" "Commercial VPN Blocking DISABLED."
    fi
    echo "BLOCK_VPNS='$BLOCK_VPNS'" >> "$CONF_FILE"
}

auto_whitelist_admin() {
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    
    local admin_ip=""
    
    # 1. Standard SSH env variables
    if [[ -n "${SSH_CLIENT:-}" ]]; then admin_ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then admin_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    fi
    
    # 2. Sudo/Su fallback using 'who am i'
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        admin_ip=$(who am i 2>/dev/null | awk '{print $NF}' | tr -d '()')
    fi
    
    # 3. Process the IP
    if [[ "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$admin_ip" != "127.0.0.1" ]]; then
        if ! grep -q "^${admin_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
            log "INFO" "Auto-whitelisting current admin SSH session IP: $admin_ip"
            echo "$admin_ip" >> "$WHITELIST_FILE"
        fi
    else
        log "WARN" "Could not auto-detect admin SSH IP. (Expected if run from local console)"
    fi
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

select_list_type() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
	    # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Update Mode: Loaded configuration (Type: $LIST_TYPE)"
        return
    fi

    echo -e "\n${BLUE}=== Step 1: Select Blocklist Type ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        choice=${SYSWARDEN_LIST_CHOICE:-1}
        log "INFO" "Auto Mode: Blocklist choice loaded via env var [${choice}]"
    else
        echo "1) Standard List (~85,000 IPs) - Recommended for Web Servers"
        echo "2) Critical List (~100,000 IPs) - Recommended for High Security"
        echo "3) Custom List"
        read -p "Enter choice [1/2/3]: " choice
    fi
    # -----------------------------

    case "$choice" in
        1) LIST_TYPE="Standard";;
        2) LIST_TYPE="Critical";;
        3) 
           LIST_TYPE="Custom"
           if [[ "${1:-}" == "auto" ]]; then
               CUSTOM_URL=${SYSWARDEN_CUSTOM_URL:-""}
               log "INFO" "Auto Mode: Custom URL loaded via env var"
           else
               read -p "Enter the full URL: " CUSTOM_URL
           fi
           
           # Sanitize: Remove spaces, quotes, and dangerous shell characters
           CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d " '\"\;\\$\|\&\<\>\`")
           if [[ -z "$CUSTOM_URL" ]]; then
               log "WARN" "Custom URL is empty. Defaulting to Standard List."
               LIST_TYPE="Standard"
           fi
           ;;
        *) log "ERROR" "Invalid choice. Exiting."; exit 1;;
    esac
    
    echo "LIST_TYPE='$LIST_TYPE'" > "$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >> "$CONF_FILE"; fi
    log "INFO" "User selected: $LIST_TYPE Blocklist"
}

measure_latency() {
    local url="$1"
    local time_sec
    time_sec=$(curl -o /dev/null -s -w '%{time_connect}\n' --connect-timeout 2 "$url" || echo "error")
    
    if [[ "$time_sec" == "error" ]] || [[ -z "$time_sec" ]]; then
        echo "9999"
    else
        echo "$time_sec" | awk '{print int($1 * 1000)}' 2>/dev/null || echo "9999"
    fi
}

select_mirror() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
	    # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Update Mode: keeping mirror $SELECTED_URL"
        return
    fi

    if [[ "$LIST_TYPE" == "Custom" ]]; then
        SELECTED_URL="$CUSTOM_URL"
        echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
        return
    fi

    echo -e "\n${BLUE}=== Step 2: Selecting Fastest Mirror ===${NC}"
    log "INFO" "Benchmarking mirrors..."

    declare -n URL_MAP
    if [[ "$LIST_TYPE" == "Standard" ]]; then URL_MAP=URLS_STANDARD; else URL_MAP=URLS_CRITICAL; fi

    local fastest_time=10000
    local fastest_url=""
    local valid_mirror_found=false

    for name in "${!URL_MAP[@]}"; do
        url="${URL_MAP[$name]}"
        echo -n "Connecting to $name... "
        time=$(measure_latency "$url")
        
        if [[ "$time" -eq 9999 ]]; then
             echo "FAIL"
        else
             echo "${time} ms"
             if (( time < fastest_time )); then
                fastest_time=$time
                fastest_url=$url
                valid_mirror_found=true
             fi
        fi
    done

    if [[ "$valid_mirror_found" == "false" ]]; then
        SELECTED_URL="${URL_MAP[Codeberg]}"
    else
        SELECTED_URL="$fastest_url"
    fi

    echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
}

download_list() {
    echo -e "\n${BLUE}=== Step 3: Downloading Blocklist ===${NC}"
    log "INFO" "Fetching list from $SELECTED_URL..."
    
    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        tr -d '\r' < "$output_file" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' > "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        log "INFO" "Download success."
    else
        log "ERROR" "Failed to download blocklist."
        exit 1
    fi
}

download_geoip() {
    if [[ "${GEOBLOCK_COUNTRIES:-none}" == "none" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading Geo-Blocking Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : > "$TMP_DIR/geoip_raw.txt"

    for country in $(echo "$GEOBLOCK_COUNTRIES" | tr ' ' '\n'); do
        if [[ -z "$country" ]]; then continue; fi 
        
        echo -n "Fetching IP blocks for ${country^^}... "
        if curl -sS -L --retry 3 --connect-timeout 5 "https://www.ipdeny.com/ipblocks/data/countries/${country}.zone" >> "$TMP_DIR/geoip_raw.txt"; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            log "WARN" "Failed to download GeoIP data for $country."
        fi
    done

    if [[ -s "$TMP_DIR/geoip_raw.txt" ]]; then
        grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' "$TMP_DIR/geoip_raw.txt" | sort -u > "$GEOIP_FILE"
        log "INFO" "Geo-Blocking list updated successfully."
    else
        log "WARN" "Geo-Blocking list is empty. IPDeny might be unreachable."
        touch "$GEOIP_FILE"
    fi
}

download_asn() {
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading ASN Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : > "$TMP_DIR/asn_raw.txt"

    if [[ "${USE_SPAMHAUS_ASN:-y}" == "y" ]]; then
        echo -n "Fetching Spamhaus ASN-DROP list (Cybercrime Hosters)... "
        local spamhaus_url="https://www.spamhaus.org/drop/asndrop.json"
        
        local spamhaus_asns; spamhaus_asns=$(curl -sS -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --retry 2 --connect-timeout 5 "$spamhaus_url" 2>/dev/null | grep -Eo '"asn":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+' | sed 's/^/AS/' | tr '\n' ' ' || true)
        
        if [[ -n "$spamhaus_asns" ]]; then
            echo -e "${GREEN}OK${NC}"
            if [[ "$BLOCK_ASNS" == "none" ]] || [[ "$BLOCK_ASNS" == "auto" ]]; then
                BLOCK_ASNS="$spamhaus_asns"
            else
                BLOCK_ASNS="$BLOCK_ASNS $spamhaus_asns"
            fi
        else
            echo -e "${YELLOW}Failed/Skipped${NC}"
            log "WARN" "Could not fetch Spamhaus ASN-DROP. Proceeding with custom ASNs only."
        fi
    else
        log "INFO" "Spamhaus ASN-DROP integration skipped by user."
    fi

    # Temporarily restore IFS to allow space separation
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    
    local combined_asns; combined_asns=$(echo "$BLOCK_ASNS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

    for asn in $combined_asns; do
        if [[ -z "$asn" ]] || [[ "$asn" == "auto" ]] || [[ "$asn" == "none" ]]; then continue; fi
        
        if [[ ! "$asn" =~ ^AS[0-9]+$ ]]; then 
            local clean_num="${asn//[!0-9]/}"
            if [[ -z "$clean_num" ]]; then continue; fi
            asn="AS${clean_num}"
        fi
        
        echo -n "Fetching IP blocks for ${asn}... "
        
        local success=false
        local whois_out=""
        
        # ShellCheck fix: Unused variable '_'
        for _ in 1 2 3; do
            whois_out=$(whois -h whois.radb.net -- "-i origin $asn" 2>&1 || true)
            if [[ "$whois_out" == *"Connection reset by peer"* ]] || [[ "$whois_out" == *"Timeout"* ]] || [[ "$whois_out" == *"refused"* ]]; then
                sleep 2
                continue
            fi
            success=true
            break
        done

        if [ "$success" = true ]; then
            if echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >> "$TMP_DIR/asn_raw.txt"; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}Empty (IPv6-only/No routes)${NC}"
            fi
        else
            echo -e "${RED}FAIL (Blocked by RADB)${NC}"
            log "WARN" "Failed to fetch data for $asn (Network dropped)."
        fi
        sleep 0.5
    done
    
    # Restore security IFS
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
    print(net)' < "$TMP_DIR/asn_raw.txt" > "$ASN_FILE"
        
        log "INFO" "ASN Blocklist updated successfully."
    else
        log "WARN" "ASN Blocklist is empty."
        touch "$ASN_FILE"
    fi
}

download_vpn() {
    # Exit if user declined
    if [[ "${BLOCK_VPNS:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading VPN & Datacenter Lists ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : > "$TMP_DIR/vpn_raw.txt"

    # 1. X4B Net VPN & Datacenter List (Highly reliable, ~40k subnets)
    echo -n "Fetching X4B Commercial VPN/Datacenter list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt" >> "$TMP_DIR/vpn_raw.txt"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi

    # 2. EJRV VPN List (Complementary endpoints)
    echo -n "Fetching EJRV VPN list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://raw.githubusercontent.com/ejrv/VPNs/master/vpn-ipv4.txt" >> "$TMP_DIR/vpn_raw.txt"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi

    if [[ -s "$TMP_DIR/vpn_raw.txt" ]]; then
        # Use Python to mathematically collapse overlapping CIDRs and prevent kernel crash
        python3 -c '
import sys, ipaddress
nets = []
for line in sys.stdin:
    line = line.strip()
    if line and ":" not in line:
        try: nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError: pass
for net in ipaddress.collapse_addresses(nets):
    print(net)' < "$TMP_DIR/vpn_raw.txt" > "$VPN_FILE"
        
        log "INFO" "VPN Blocklist updated and mathematically optimized."
    else
        log "WARN" "VPN Blocklist is empty. Sources might be unreachable."
        touch "$VPN_FILE"
    fi
}

apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules ($FIREWALL_BACKEND) ===${NC}"
    
    # --- LOCAL PERSISTENCE INJECTION ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE"

    # 1. Inject local blocklist into the global list
    cat "$BLOCKLIST_FILE" >> "$FINAL_LIST"
    
    # 2. Clean duplicates to ensure firewall stability
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"

    # 3. Exclude local whitelisted IPs from the final blocklist
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" > "$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi
    # -----------------------------------
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        log "INFO" "Configuring Nftables Base Structure (Flat Syntax for Alpine compatibility)..."
        
        rc-update add nftables default >/dev/null 2>&1 || true
        rc-service nftables start >/dev/null 2>&1 || true

        cat <<EOF > "$TMP_DIR/syswarden.nft"
add table inet syswarden_table
flush table inet syswarden_table
add set inet syswarden_table $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "add set inet syswarden_table $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >> "$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "add set inet syswarden_table $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >> "$TMP_DIR/syswarden.nft"
        fi
        
        if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
            echo "add set inet syswarden_table $VPN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >> "$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >> "$TMP_DIR/syswarden.nft"
add chain inet syswarden_table input { type filter hook input priority filter - 10; policy accept; }
EOF

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "add rule inet syswarden_table input ct state established,related accept" >> "$TMP_DIR/syswarden.nft"
        fi
		
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "add rule inet syswarden_table input ip saddr $wl_ip accept" >> "$TMP_DIR/syswarden.nft"
            done < "$WHITELIST_FILE"
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "add rule inet syswarden_table input ip saddr @$GEOIP_SET_NAME log prefix \"[SysWarden-GEO] \" drop" >> "$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "add rule inet syswarden_table input ip saddr @$ASN_SET_NAME log prefix \"[SysWarden-ASN] \" drop" >> "$TMP_DIR/syswarden.nft"
        fi
        
        if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
            echo "add rule inet syswarden_table input ip saddr @$VPN_SET_NAME log prefix \"[SysWarden-VPN] \" drop" >> "$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >> "$TMP_DIR/syswarden.nft"
add rule inet syswarden_table input ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " drop
add rule inet syswarden_table input tcp dport { 23, 445, 1433, 3389, 5900 } log prefix "[SysWarden-BLOCK] " drop
EOF

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "add rule inet syswarden_table input iifname != \"wg0\" iifname != \"lo\" tcp dport ${SSH_PORT:-22} log prefix \"[SysWarden-SSH-DROP] \" drop" >> "$TMP_DIR/syswarden.nft"
        fi

        nft -f "$TMP_DIR/syswarden.nft"

        log "INFO" "Populating Nftables sets in chunks (Bypassing memory limits)..."
        if [[ -s "$FINAL_LIST" ]]; then
            cat "$FINAL_LIST" | xargs -n 5000 | while read -r chunk; do
                nft "add element inet syswarden_table $SET_NAME { $(echo "$chunk" | tr ' ' ',') }" 2>/dev/null || true
            done
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat "$GEOIP_FILE" | xargs -n 5000 | while read -r chunk; do
                nft "add element inet syswarden_table $GEOIP_SET_NAME { $(echo "$chunk" | tr ' ' ',') }" 2>/dev/null || true
            done
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat "$ASN_FILE" | xargs -n 5000 | while read -r chunk; do
                nft "add element inet syswarden_table $ASN_SET_NAME { $(echo "$chunk" | tr ' ' ',') }" 2>/dev/null || true
            done
        fi
        
        if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
            cat "$VPN_FILE" | xargs -n 5000 | while read -r chunk; do
                nft "add element inet syswarden_table $VPN_SET_NAME { $(echo "$chunk" | tr ' ' ',') }" 2>/dev/null || true
            done
        fi

        log "INFO" "Saving Nftables ruleset to /etc/nftables.nft for persistence..."
        nft list ruleset > /etc/nftables.nft

    else
		log "INFO" "Applying Iptables rules and loading IPSet lists..."
        rc-update add iptables default >/dev/null 2>&1 || true
        
        ipset create "${SET_NAME}_tmp" hash:net maxelem 200000 -exist
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore -!
        ipset create "$SET_NAME" hash:net maxelem 200000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"
        
        if ! iptables -C INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j DROP
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j LOG --log-prefix "[SysWarden-BLOCK] "
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "${ASN_SET_NAME}_tmp" hash:net maxelem 500000 -exist
            sed "s/^/add ${ASN_SET_NAME}_tmp /" "$ASN_FILE" | ipset restore -!
            ipset create "$ASN_SET_NAME" hash:net maxelem 500000 -exist
            ipset swap "${ASN_SET_NAME}_tmp" "$ASN_SET_NAME"
            ipset destroy "${ASN_SET_NAME}_tmp"
            
            if ! iptables -C INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
        fi
        
        if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
            ipset create "${VPN_SET_NAME}_tmp" hash:net maxelem 500000 -exist
            sed "s/^/add ${VPN_SET_NAME}_tmp /" "$VPN_FILE" | ipset restore -!
            ipset create "$VPN_SET_NAME" hash:net maxelem 500000 -exist
            ipset swap "${VPN_SET_NAME}_tmp" "$VPN_SET_NAME"
            ipset destroy "${VPN_SET_NAME}_tmp"
            
            if ! iptables -C INPUT -m set --match-set "$VPN_SET_NAME" src -j DROP 2>/dev/null; then
                iptables -I INPUT 1 -m set --match-set "$VPN_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$VPN_SET_NAME" src -j LOG --log-prefix "[SysWarden-VPN] "
            fi
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "${GEOIP_SET_NAME}_tmp" hash:net maxelem 500000 -exist
            sed "s/^/add ${GEOIP_SET_NAME}_tmp /" "$GEOIP_FILE" | ipset restore -!
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 500000 -exist
            ipset swap "${GEOIP_SET_NAME}_tmp" "$GEOIP_SET_NAME"
            ipset destroy "${GEOIP_SET_NAME}_tmp"
            
            if ! iptables -C INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
        fi
		
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
            while iptables -D INPUT -i wg0 -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
            
            iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j DROP
            iptables -I INPUT 1 -i wg0 -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT
            iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        fi

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                if ! iptables -C INPUT -s "$wl_ip" -j ACCEPT 2>/dev/null; then
                    iptables -I INPUT 1 -s "$wl_ip" -j ACCEPT
                fi
            done < "$WHITELIST_FILE"
        fi
        
        /etc/init.d/iptables save >/dev/null 2>&1 || true
    fi
    
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        log "INFO" "Applying Global Rules to Docker (DOCKER-USER chain)..."
        
        if ! ipset list "$SET_NAME" >/dev/null 2>&1; then
             ipset create "$SET_NAME" hash:net maxelem 200000 -exist
             sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!
        fi

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            if ! ipset list "$GEOIP_SET_NAME" >/dev/null 2>&1; then
                 ipset create "$GEOIP_SET_NAME" hash:net maxelem 500000 -exist
                 sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
            fi
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            if ! ipset list "$ASN_SET_NAME" >/dev/null 2>&1; then
                 ipset create "$ASN_SET_NAME" hash:net maxelem 500000 -exist
                 sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!
            fi
        fi
        
        if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
            if ! ipset list "$VPN_SET_NAME" >/dev/null 2>&1; then
                 ipset create "$VPN_SET_NAME" hash:net maxelem 500000 -exist
                 sed "s/^/add $VPN_SET_NAME /" "$VPN_FILE" | ipset restore -!
            fi
        fi

        if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$VPN_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$VPN_SET_NAME" src -j LOG --log-prefix "[SysWarden-VPN] " 2>/dev/null || true
            
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] "

            if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
            
            if [[ "${BLOCK_VPNS:-n}" == "y" ]] && [[ -s "$VPN_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$VPN_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$VPN_SET_NAME" src -j LOG --log-prefix "[SysWarden-VPN] "
            fi

            if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
            
            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Docker firewall rules applied successfully."
        else
            log "WARN" "DOCKER-USER chain not found. Docker might not be running yet."
        fi
    fi
}

configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Alpine Zero Trust Mode)..."
        
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 1. Alpine uses syslog or local files, NOT systemd.
        cat <<EOF > /etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
EOF

        # 2. Dynamic Action based on Firewall Backend
        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then f2b_action="nftables-multiport"; fi

        # --- FIX: DYNAMIC FAIL2BAN WHITELIST ---
        local f2b_ignoreip="127.0.0.1/8 ::1"
        if [[ -s "$WHITELIST_FILE" ]]; then
            # Extract IPs safely (ignore comments and empty lines) and format as space-separated
            local wl_ips
            wl_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            f2b_ignoreip="$f2b_ignoreip $wl_ips"
            log "INFO" "Fail2ban whitelist extended with: $wl_ips"
        fi
        # ---------------------------------------

        # 3. HEADER & SSH (Always Active - Backend MUST be auto for Alpine)
        cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
banaction = $f2b_action

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = $SSH_PORT
logpath = /var/log/messages
backend = auto
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST>.*\"(GET|POST|HEAD).*\" (400|401|403|404|444) .*$\nignoreregex =" > /etc/fail2ban/filter.d/nginx-scanner.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Nginx Protection ---
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
        if [[ -f "/var/log/apache2/error.log" ]]; then
            APACHE_LOG="/var/log/apache2/error.log"
            APACHE_ACCESS="/var/log/apache2/access.log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> .+\"(GET|POST|HEAD) .+\" (400|401|403|404) .+\$\nignoreregex =" > /etc/fail2ban/filter.d/apache-scanner.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Apache Protection ---
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
            log "INFO" "MongoDB logs detected. Enabling Mongo Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).* <HOST>(:[0-9]+)?.*\$\nignoreregex =" > /etc/fail2ban/filter.d/mongodb-guard.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- MongoDB Protection ---
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
        if [[ -f "/var/log/mysql/error.log" ]]; then MARIADB_LOG="/var/log/mysql/error.log";
        elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then MARIADB_LOG="/var/log/mariadb/mariadb.log"; fi

        if [[ -n "$MARIADB_LOG" ]]; then
            log "INFO" "MariaDB logs detected. Enabling MariaDB Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*[Aa]ccess denied for user .*@'<HOST>'.*\$\nignoreregex =" > /etc/fail2ban/filter.d/mariadb-auth.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- MariaDB Protection ---
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
        if [[ -f "/var/log/mail.log" ]]; then POSTFIX_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/messages" ]]; then POSTFIX_LOG="/var/log/messages"; fi

        if [[ -n "$POSTFIX_LOG" ]] && command -v postfix >/dev/null 2>&1; then
            log "INFO" "Postfix detected. Enabling SMTP Jails."
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Postfix SMTP Protection ---
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
            log "INFO" "VSFTPD logs detected. Enabling FTP Jail."
            cat <<EOF >> /etc/fail2ban/jail.local

# --- VSFTPD Protection ---
[vsftpd]
enabled = true
port    = ftp,ftp-data,ftps,20,21
logpath = /var/log/vsftpd.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi
        
        # 10. DYNAMIC DETECTION: WORDPRESS
        WP_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then WP_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> .* \"POST .*(wp-login\.php|xmlrpc\.php) HTTP.*\" 200\nignoreregex =" > /etc/fail2ban/filter.d/wordpress-auth.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- WordPress Protection ---
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
        
        # 11. DYNAMIC DETECTION: NEXTCLOUD
        NC_LOG=""
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then NC_LOG="$path"; break; fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Login failed: .* \(Remote IP: '<HOST>'\).*$\nignoreregex =" > /etc/fail2ban/filter.d/nextcloud.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Nextcloud Protection ---
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
        
        # 12. DYNAMIC DETECTION: ASTERISK
        ASTERISK_LOG=""
        if [[ -f "/var/log/asterisk/messages" ]]; then ASTERISK_LOG="/var/log/asterisk/messages"
        elif [[ -f "/var/log/asterisk/full" ]]; then ASTERISK_LOG="/var/log/asterisk/full"; fi

        if [[ -n "$ASTERISK_LOG" ]]; then
            log "INFO" "Asterisk logs detected. Enabling VoIP Jail."
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Asterisk VoIP Protection ---
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
            log "INFO" "Zabbix logs detected. Enabling Zabbix Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/zabbix-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*failed login of user .* from <HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/zabbix-auth.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Zabbix Protection ---
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
            log "INFO" "HAProxy logs detected. Enabling HAProxy Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/haproxy-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:\d+ .+(400|403|404|429) .+\$\nignoreregex =" > /etc/fail2ban/filter.d/haproxy-guard.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- HAProxy Protection ---
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
            if [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."
                if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                    echo -e "[Definition]\nfailregex = ^.*wireguard: .* Handshake for peer .* \\(<HOST>:[0-9]+\\) did not complete.*\$\nignoreregex =" > /etc/fail2ban/filter.d/wireguard.conf
                fi
                cat <<EOF >> /etc/fail2ban/jail.local

# --- WireGuard Protection ---
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
        PMA_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then PMA_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                     echo -e "[Definition]\nfailregex = ^<HOST> -.*\"POST .*phpmyadmin.* HTTP.*\" 200\nignoreregex =" > /etc/fail2ban/filter.d/phpmyadmin-custom.conf
                fi
                cat <<EOF >> /etc/fail2ban/jail.local

# --- phpMyAdmin Protection ---
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
            if [[ -f "$path" ]]; then LARAVEL_LOG="$path"; break; fi
        done
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/laravel-auth.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Laravel Protection ---
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
            log "INFO" "Grafana logs detected. Enabling Grafana Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/grafana-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/grafana-auth.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Grafana Protection ---
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
        if [[ -f "/var/log/mail.log" ]]; then SM_LOG="/var/log/mail.log";
        elif [[ -f "/var/log/messages" ]]; then SM_LOG="/var/log/messages"; fi

        if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
            log "INFO" "Sendmail detected. Enabling Sendmail Jails."
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Sendmail Protection ---
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
            log "INFO" "Squid Proxy logs detected. Enabling Squid Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/squid-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" > /etc/fail2ban/filter.d/squid-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Squid Proxy Protection ---
[squid-custom]
enabled = true
port    = 3128,8080
filter  = squid-custom
logpath = /var/log/squid/access.log
maxretry = 5
bantime  = 24h
EOF
        fi
        
        # --- DOCKER HERMETIC FAIL2BAN BLOCK ---
        if [[ "${USE_DOCKER:-n}" == "y" ]]; then
            log "INFO" "Creating Docker-specific Fail2ban banaction..."
            cat <<'EOF' > /etc/fail2ban/action.d/syswarden-docker.conf
[Definition]
actionstart = iptables -N f2b-<name>
              iptables -A f2b-<name> -j RETURN
              iptables -I DOCKER-USER -p <protocol> -m multiport --dports <port> -j f2b-<name>
actionstop = iptables -D DOCKER-USER -p <protocol> -m multiport --dports <port> -j f2b-<name>
             iptables -F f2b-<name>
             iptables -X f2b-<name>
actioncheck = iptables -n -L DOCKER-USER | grep -q 'f2b-<name>[ \t]'
actionban = iptables -I f2b-<name> 1 -s <ip> -j DROP
actionunban = iptables -D f2b-<name> -s <ip> -j DROP
EOF
            log "INFO" "Docker banaction 'syswarden-docker' created successfully."
        fi
        
        # 21. DYNAMIC DETECTION: DOVECOT (IMAP/POP3)
        DOVECOT_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then DOVECOT_LOG="/var/log/mail.log";
        elif [[ -f "/var/log/messages" ]]; then DOVECOT_LOG="/var/log/messages"; fi

        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/dovecot-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*\$\nignoreregex =" > /etc/fail2ban/filter.d/dovecot-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Dovecot Protection ---
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

        # 22. DYNAMIC DETECTION: PROXMOX VE
        if command -v pveversion >/dev/null 2>&1; then
            log "INFO" "Proxmox VE detected. Enabling PVE Jail."
            PVE_LOG="/var/log/messages"
            if [[ ! -f "/etc/fail2ban/filter.d/proxmox-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*pvedaemon\\[\\d+\\]: authentication failure; rhost=<HOST> user=.*\$\nignoreregex =" > /etc/fail2ban/filter.d/proxmox-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Proxmox Protection ---
[proxmox-custom]
enabled = true
port    = https,8006
filter  = proxmox-custom
logpath = $PVE_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 23. DYNAMIC DETECTION: OPENVPN
        OVPN_LOG=""
        if [[ -f "/var/log/openvpn/openvpn.log" ]]; then OVPN_LOG="/var/log/openvpn/openvpn.log";
        elif [[ -f "/var/log/openvpn.log" ]]; then OVPN_LOG="/var/log/openvpn.log";
        elif [[ -f "/var/log/messages" ]]; then OVPN_LOG="/var/log/messages"; fi

        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*\$\nignoreregex =" > /etc/fail2ban/filter.d/openvpn-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- OpenVPN Protection ---
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

        # 24. DYNAMIC DETECTION: GITEA / FORGEJO
        GITEA_LOG=""
        if [[ -f "/var/log/gitea/gitea.log" ]]; then GITEA_LOG="/var/log/gitea/gitea.log"
        elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then GITEA_LOG="/var/log/forgejo/forgejo.log"; fi

        if [[ -n "$GITEA_LOG" ]]; then
            log "INFO" "Gitea/Forgejo detected. Enabling Git Server Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Failed authentication attempt for .* from <HOST>:.*\$\nignoreregex =" > /etc/fail2ban/filter.d/gitea-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Gitea / Forgejo Protection ---
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
        
        # 25. DYNAMIC DETECTION: COCKPIT
        if [[ -d "/etc/cockpit" ]]; then
            log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."
            if [[ ! -f "/etc/fail2ban/filter.d/cockpit-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*cockpit-ws.*(?:authentication failed|invalid user).*from <HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/cockpit-custom.conf
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Cockpit Web Console Protection ---
[cockpit-custom]
enabled = true
port    = 9090
filter  = cockpit-custom
logpath = /var/log/messages
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi
        
        # 26. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth.log" ]]; then AUTH_LOG="/var/log/auth.log";
        elif [[ -f "/var/log/messages" ]]; then AUTH_LOG="/var/log/messages"; fi

        if [[ -n "$AUTH_LOG" ]]; then
            log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-privesc.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-privesc.conf
[Definition]
failregex = ^.*(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^.*(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^.* PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Privilege Escalation Protection (PAM/Su/Sudo) ---
[syswarden-privesc]
enabled = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port    = 0:65535
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi
        
        # 27. DYNAMIC DETECTION: CI/CD & DEVOPS INFRASTRUCTURE (JENKINS / GITLAB)
        if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
            log "INFO" "Jenkins CI/CD logs detected. Enabling Jenkins Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jenkins.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Jenkins CI/CD Protection ---
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
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi

        if [[ -n "$GITLAB_LOG" ]]; then
            log "INFO" "GitLab logs detected. Enabling GitLab Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- GitLab DevOps Protection ---
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
        
        # 28. DYNAMIC DETECTION: CRITICAL MIDDLEWARES (REDIS / RABBITMQ)
        REDIS_LOG=""
        if [[ -f "/var/log/redis/redis-server.log" ]]; then REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi

        if [[ -n "$REDIS_LOG" ]]; then
            log "INFO" "Redis logs detected. Enabling Redis Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-redis.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-redis.conf
[Definition]
failregex = ^.* <HOST>:[0-9]+ .* [Aa]uthentication failed.*\s*$
            ^.* Client <HOST>:[0-9]+ disconnected, .* [Aa]uthentication.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Redis In-Memory Data Store Protection ---
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
        if ls /var/log/rabbitmq/rabbit@*.log 1> /dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then 
            RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
        fi

        if [[ -n "$RABBIT_LOG" ]]; then
            log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-rabbitmq.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-rabbitmq.conf
[Definition]
failregex = ^.*HTTP access denied: .* from <HOST>.*\s*$
            ^.*AMQP connection <HOST>:[0-9]+ .* failed: .*authentication failure.*\s*$
            ^.*<HOST>:[0-9]+ .* (?:invalid credentials|authentication failed).*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- RabbitMQ Message Broker Protection ---
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
        
        # 29. DYNAMIC DETECTION: PORT SCANNERS (Alpine kernel logs)
        FIREWALL_LOG=""
        if [[ -f "/var/log/messages" ]]; then FIREWALL_LOG="/var/log/messages"; fi 

        if [[ -n "$FIREWALL_LOG" ]]; then
            log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-portscan.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-portscan.conf
[Definition]
failregex = ^.*(?:kernel: |\[[0-9. ]+\] ).*\[SysWarden-BLOCK\].*SRC=<HOST> .*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

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
        
        # 30. DYNAMIC DETECTION: SENSITIVE FILE INTEGRITY & AUDITD ANOMALIES
        AUDIT_LOG="/var/log/audit/audit.log"
        if command -v auditd >/dev/null 2>&1 && [[ -f "$AUDIT_LOG" ]]; then
            log "INFO" "Auditd logs detected. Enabling System Integrity Guard."
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-auditd.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi
            cat <<EOF >> /etc/fail2ban/jail.local

# --- System Integrity & Kernel Audit Protection ---
[syswarden-auditd]
enabled  = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi
        
        # 31. DYNAMIC DETECTION: RCE & REVERSE SHELL PAYLOADS
        RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "/var/log/apache2/access.log"; do
            if [[ -f "$log_file" ]]; then RCE_LOGS="$RCE_LOGS $log_file"; fi
        done
        RCE_LOGS=$(echo "$RCE_LOGS" | xargs)

        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."
            # Create Filter for Remote Code Execution and Reverse Shell signatures
            # Catches common payloads: bash interactive, netcat, wget/curl drops, and python/php one-liners
            # FIX: Using regex hex escape '\x25' instead of '%' to strictly bypass Python configparser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD|PUT) .*(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc\s+-e|nc\x2520-e|nc\s+-c|curl\s+http|curl\x2520http|wget\s+http|wget\x2520http|python\s+-c|php\s+-r|;\s*bash\s+-i|&\s*bash\s+-i).*" .*$
ignoreregex = 
EOF
            fi
			
            cat <<EOF >> /etc/fail2ban/jail.local

# --- Reverse Shell & RCE Injection Protection ---
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
		
		# 32. DYNAMIC DETECTION: MALICIOUS AI BOTS & SCRAPERS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

            # Create Filter for aggressive AI Scrapers, Crawlers, and LLM data miners
            # Matches HTTP requests containing known AI User-Agents regardless of the HTTP status code (\d{3})
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD) .*" \d{3} .* ".*(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai).*".*$
ignoreregex = 
EOF
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Malicious AI Bots & Scrapers Protection ---
[syswarden-aibots]
enabled  = true
port     = http,https
filter   = syswarden-aibots
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 hit = 48 hours ban at the kernel level
maxretry = 1
bantime  = 48h
EOF
        fi		
		
        # 33. DYNAMIC DETECTION: MALICIOUS SCANNERS & PENTEST TOOLS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Bad-Bot & Scanner Guard."

            # Create Filter for aggressive pentest tools, vulnerability scanners, and malicious crawlers
            # Matches HTTP requests containing known offensive User-Agents regardless of the HTTP status code (\d{3})
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) .*" \d{3} .* ".*(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf).*".*$
ignoreregex = 
EOF
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Malicious Scanners & Pentest Tools Protection ---
[syswarden-badbots]
enabled  = true
port     = http,https
filter   = syswarden-badbots
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 hit = 48 hours ban at the kernel level
maxretry = 1
bantime  = 48h
EOF
        fi
		
		# 34. DYNAMIC DETECTION: LAYER 7 DDOS (HTTP FLOOD)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Layer 7 Anti-DDoS Guard."

            # Create Filter for HTTP Floods
            # Matches absolutely ANY request (GET, POST, etc.) to count the raw volume per IP
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-httpflood.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) .*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Layer 7 DDoS & HTTP Flood Protection ---
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $RCE_LOGS
backend  = auto
# Policy: 150 requests within 2 seconds triggers an immediate drop
maxretry = 150
findtime = 2
bantime  = 24h
EOF
        fi

        # 35. DYNAMIC DETECTION: WEBSHELL UPLOADS (LFI / RFI)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling WebShell Upload Guard."

            # Create Filter for malicious file uploads
            # Targets specifically POST requests aimed at common upload folders, pushing executable extensions
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
failregex = ^<HOST> .* "POST .*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads).*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?.*)? HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Malicious WebShell Upload Protection ---
[syswarden-webshell]
enabled  = true
port     = http,https
filter   = syswarden-webshell
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to upload a shell = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 36. DYNAMIC DETECTION: SQL INJECTION (SQLi) & XSS PAYLOADS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling SQLi & XSS Payload Guard."

            # Create Filter for SQLi, XSS, and Path Traversal payloads in URIs
            # Catches: UNION SELECT, CONCAT, SLEEP, <script>, alert(), document.cookie, eval(), ../../
            # FIX: Used \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sqli-xss.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD|PUT) .*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F).*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- SQL Injection (SQLi) & XSS Protection ---
[syswarden-sqli-xss]
enabled  = true
port     = http,https
filter   = syswarden-sqli-xss
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 blatant SQLi/XSS payload = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # --- ALPINE FIX: Prevent Fail2ban crash due to missing log files ---
        touch /var/log/messages /var/log/fail2ban.log 2>/dev/null || true
        
        # Enable OpenRC service
        rc-update add fail2ban default >/dev/null 2>&1 || true
        rc-service fail2ban restart >/dev/null 2>&1 || true
    fi 
}

setup_abuse_reporting() {
    echo -e "\n${BLUE}=== Step 7: AbuseIPDB Reporting Setup ===${NC}"
    
    # --- ENTERPRISE COMPLIANCE KILL-SWITCH ---
    # Strictly prevents telemetry exfiltration regardless of other variables
    if [[ "${SYSWARDEN_ENTERPRISE_MODE:-n}" =~ ^[Yy]$ ]]; then
        log "WARN" "Enterprise Mode Active: Third-party telemetry (AbuseIPDB) is strictly DISABLED by corporate policy."
        return
    fi
    # -----------------------------------------

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_ABUSE:-n}
        log "INFO" "Auto Mode: AbuseIPDB choice loaded via env var [${response}]"
    else
        echo "Would you like to automatically report blocked IPs to AbuseIPDB?"
        read -p "Enable AbuseIPDB reporting? (y/N): " response
    fi
    # -----------------------------

    if [[ "$response" =~ ^[Yy]$ ]]; then
        if [[ "${1:-}" == "auto" ]]; then
            USER_API_KEY=${SYSWARDEN_ABUSE_API_KEY:-""}
        else
            read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
        fi
        
        # Sanitize API Key
        USER_API_KEY=$(echo "$USER_API_KEY" | tr -cd 'a-zA-Z0-9_-')

        if [[ -z "$USER_API_KEY" ]]; then
            log "ERROR" "No API Key provided. Skipping reporting setup."
            return
        fi

        if [[ "${1:-}" == "auto" ]]; then
            REPORT_F2B=${SYSWARDEN_REPORT_F2B:-y}
            REPORT_FW=${SYSWARDEN_REPORT_FW:-y}
        else
            echo ""
            read -p "Report Fail2ban Bans (SSH/Web brute-force)? [Y/n]: " REPORT_F2B
            REPORT_F2B=${REPORT_F2B:-y}

            echo ""
            read -p "Report Firewall Drops (Port Scans/Blacklist)? [Y/n]: " REPORT_FW
            REPORT_FW=${REPORT_FW:-y}
        fi

        if [[ "$REPORT_F2B" =~ ^[Nn]$ ]] && [[ "$REPORT_FW" =~ ^[Nn]$ ]]; then
            log "INFO" "Both reporting options declined. Skipping."
            return
        fi

        log "INFO" "Configuring Unified SysWarden Reporter for Alpine..."
        
        # Create cache directory securely
        mkdir -p /var/lib/syswarden
        
        cat <<'EOF' > /usr/local/bin/syswarden_reporter.py
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
import signal
import sys

# --- CONFIGURATION ---
API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900  # 15 minutes
ENABLE_F2B = PLACEHOLDER_F2B
ENABLE_FW = PLACEHOLDER_FW
CACHE_FILE = "/var/lib/syswarden/abuse_cache.json"

# --- DEFINITIONS ---
reported_cache = {}
cache_lock = threading.Lock()
tail_proc = None

# --- GRACEFUL SHUTDOWN (OPENRC STOP/RESTART FIX) ---
def cleanup_and_exit(signum, frame):
    global tail_proc
    print("[INFO] Signal received. Shutting down gracefully...", flush=True)
    if tail_proc is not None:
        try:
            tail_proc.terminate()
            tail_proc.wait(timeout=2)
        except Exception:
            pass
    sys.exit(0)

# Intercept OpenRC signals
signal.signal(signal.SIGTERM, cleanup_and_exit)
signal.signal(signal.SIGINT, cleanup_and_exit)

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
        print(f"[WARN] Failed to write cache: {e}", flush=True)

def clean_cache():
    current_time = time.time()
    with cache_lock:
        expired = [ip for ip, ts in reported_cache.items() if current_time - ts > REPORT_INTERVAL]
        for ip in expired:
            del reported_cache[ip]
    if expired:
        save_cache()

def send_report(ip, categories, comment):
    current_time = time.time()
    
    # --- Strict IP Validation ---
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[SKIP] Invalid IP detected by Regex: '{ip}'", flush=True)
        return

    # 1. Thread-safe cache check and update
    with cache_lock:
        if ip in reported_cache and (current_time - reported_cache[ip] < REPORT_INTERVAL):
            return 
        reported_cache[ip] = current_time
    save_cache()
    
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    full_comment = f"[{socket.gethostname()}] {comment}"
    params = {'ip': ip, 'categories': categories, 'comment': full_comment}

    try:
        response = requests.post(url, params=params, headers=headers)
        if response.status_code == 200:
            print(f"[SUCCESS] Reported {ip} -> Cats [{categories}]", flush=True)
            clean_cache()
        elif response.status_code == 429:
            print(f"[SKIP] IP {ip} already reported recently (HTTP 429).", flush=True)
            clean_cache()
        else:
            print(f"[API ERROR] HTTP {response.status_code} : {response.text}", flush=True)
            with cache_lock:
                if ip in reported_cache:
                    del reported_cache[ip]
            save_cache()
    except Exception as e:
        print(f"[FAIL] Error: {e}", flush=True)
        with cache_lock:
            if ip in reported_cache:
                del reported_cache[ip]
        save_cache()

def monitor_logs():
    global tail_proc
    print("🚀 Monitoring logs (dmesg + fail2ban)...", flush=True)
    load_cache() # Load JSON cache on startup
    
    # FIX: BusyBox dmesg does NOT support '--facility=kern'. 
    # We now spawn two separate native processes to avoid silent shell crashes.
    proc_fw = subprocess.Popen(['dmesg', '-w'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    proc_f2b = subprocess.Popen(['tail', '-F', '/var/log/fail2ban.log'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    
    tail_proc = proc_fw # Kept for the cleanup_and_exit reference
    
    p = select.poll()
    p.register(proc_fw.stdout, select.POLLIN)
    p.register(proc_f2b.stdout, select.POLLIN)
    
    fd_map = {
        proc_fw.stdout.fileno(): 'fw',
        proc_f2b.stdout.fileno(): 'f2b'
    }

    # v8.00 Logic: STRICT filter on [SysWarden-BLOCK] only.
    regex_fw = re.compile(r"\[SysWarden-BLOCK\].*?SRC=([\d\.]+).*?DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        for fd, event in p.poll(100):
            if event & select.POLLIN:
                source = fd_map.get(fd)
                
                if source == 'fw':
                    line = proc_fw.stdout.readline().decode('utf-8', errors='ignore')
                    if not line:
                        time.sleep(1) # Sécurité : Empêche le CPU à 100%
                        continue
                elif source == 'f2b':
                    line = proc_f2b.stdout.readline().decode('utf-8', errors='ignore')
                    if not line:
                        time.sleep(1) # Sécurité : Empêche le CPU à 100%
                        continue
                else:
                    continue

                # --- FIREWALL LOGIC ---
                if source == 'fw' and ENABLE_FW:
                    match_fw = regex_fw.search(line)
                    if match_fw:
                        ip = match_fw.group(1)
                        try:
                            port = int(match_fw.group(2))
                        except ValueError:
                            port = 0
                        
                        cats = ["14"]
                        attack_type = "Port Scan"

                        # Original v8.00 categorization logic
                        if port in [80, 443, 4443, 8080, 8443]: cats.extend(["20", "21"]); attack_type = "Web Attack"
                        elif port in [22, 2222, 22222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                        elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT Attack"
                        elif port == 88: cats.extend(["15", "20"]); attack_type = "Kerberos Attack"
                        elif port in [139, 445]: cats.extend(["15", "18"]); attack_type = "SMB/Possible Ransomware Attack"
                        elif port in [389, 636]: cats.extend(["15", "20"]); attack_type = "LDAP/LDAPS Attack"
                        elif port == 1433: cats.extend(["18", "15"]); attack_type = "MSSQL Attack"
                        elif port == 8006: cats.extend(["18", "21"]); attack_type = "Proxmox VE Brute-Force"
                        elif port == 3000: cats.extend(["15", "20"]); attack_type = "Possible Vulns Exploit"
                        elif port == 4444: cats.extend(["15", "20"]); attack_type = "Possible C2 Host"
                        elif port in [3389, 5900]: cats.extend(["18"]); attack_type = "RDP/VNC Attack"
                        elif port == 21: cats.extend(["5", "18"]); attack_type = "FTP Attack"
                        elif port in [25, 110, 143, 465, 587, 993, 995]: cats.extend(["18"]); attack_type = "Mail Service Attack"
                        elif port in [1080, 3128, 8118]: cats.extend(["9", "15"]); attack_type = "Open Proxy Probe"
                        elif port in [2375, 2376]: cats.extend(["15", "20"]); attack_type = "Docker API Attack"
                        elif port in [3306, 5432, 27017]: cats.extend(["15", "18"]); attack_type = "DB Attack (MySQL/PgSQL/Mongo)"
                        elif port in [5060, 5061]: cats.extend(["8", "18"]); attack_type = "SIP/VoIP Attack"
                        elif port in [6379, 9200, 11211]: cats.extend(["15", "20"]); attack_type = "NoSQL/Cache Attack"
                        elif port == 1194: cats.extend(["15", "18"]); attack_type = "OpenVPN Attack"
                        elif port in [51820, 51821]: cats.extend(["15", "18"]); attack_type = "WireGuard Attack"
                        elif port == 9090: cats.extend(["18", "21"]); attack_type = "Cockpit Web Console Attack"

                        threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type} Port {port})")).start()

                # --- FAIL2BAN LOGIC ---
                elif source == 'f2b' and ENABLE_F2B:
                    match_f2b = regex_f2b.search(line)
                    if match_f2b and "SysWarden-BLOCK" not in line:
                        jail = match_f2b.group(1)
                        ip = match_f2b.group(2)
                        
                        cats = ["18"] # General Abuse
                        if "ssh" in jail.lower(): cats.extend(["22"])
                        elif "nginx" in jail.lower() or "apache" in jail.lower() or "wordpress" in jail.lower(): cats.extend(["21"])
                        elif "postfix" in jail.lower() or "sendmail" in jail.lower(): cats.extend(["5", "11"])
                        elif "mariadb" in jail.lower() or "mongodb" in jail.lower(): cats.extend(["15"])

                        threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {jail})")).start()

if __name__ == "__main__":
    monitor_logs()
EOF

        # Replace placeholders based on user choices
        local PY_F2B="False"; if [[ "$REPORT_F2B" =~ ^[Yy]$ ]]; then PY_F2B="True"; fi
        local PY_FW="False"; if [[ "$REPORT_FW" =~ ^[Yy]$ ]]; then PY_FW="True"; fi

        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_F2B/$PY_F2B/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_FW/$PY_FW/" /usr/local/bin/syswarden_reporter.py
        
        chmod +x /usr/local/bin/syswarden_reporter.py

        log "INFO" "Creating OpenRC service for Reporter..."
        cat <<'EOF' > /etc/init.d/syswarden-reporter
#!/sbin/openrc-run

name="syswarden-reporter"
description="SysWarden Unified Reporter for AbuseIPDB"
command="/usr/local/bin/syswarden_reporter.py"
command_background=true
pidfile="/run/${name}.pid"
# Add these two lines to see what happens!
output_log="/var/log/syswarden-reporter.log"
error_log="/var/log/syswarden-reporter.log"

depend() {
    need net rsyslog
    after firewall
}
EOF
        chmod +x /etc/init.d/syswarden-reporter
        rc-update add syswarden-reporter default >/dev/null 2>&1
        rc-service syswarden-reporter restart >/dev/null 2>&1
        log "INFO" "AbuseIPDB Unified Reporter is ACTIVE."
        
    else
        log "INFO" "Skipping AbuseIPDB reporting setup."
    fi
}

detect_protected_services() {
    echo -e "\n${BLUE}=== Step 5: Service Integration Check ===${NC}"
    if command -v fail2ban-client >/dev/null && rc-service fail2ban status 2>/dev/null | grep -q "started"; then
        JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list://g')
        log "INFO" "Fail2ban is ACTIVE. Jails: ${JAILS}"
    else
        log "WARN" "Fail2ban not active."
    fi
}

setup_siem_logging() {
    echo -e "\n${BLUE}=== Step 6: SIEM Logging Status ===${NC}"
    log "INFO" "Logs are ready in /var/log/messages and /var/log/fail2ban.log"
}

setup_cron_autoupdate() {
    if [[ "${1:-}" != "update" ]]; then
        local script_path=$(realpath "$0")
        
        # Add to root's crontab natively for Alpine
        if ! grep -q "syswarden-update" /etc/crontabs/root 2>/dev/null; then
             echo "5 * * * * $script_path update >/dev/null 2>&1 # syswarden-update" >> /etc/crontabs/root
             rc-update add crond default >/dev/null 2>&1 || true
             rc-service crond restart >/dev/null 2>&1 || true
             log "INFO" "Automatic updates enabled via Crond."
        fi

        cat <<EOF > /etc/logrotate.d/syswarden
/var/log/messages
/var/log/syslog
$LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        /etc/init.d/syslog reload >/dev/null 2>&1 || true
    endscript
}
EOF
    fi
}

setup_wireguard() {
    if [[ "${USE_WIREGUARD:-n}" != "y" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring WireGuard VPN ===${NC}"
    
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        log "INFO" "WireGuard configuration already exists. Skipping key generation."
        return
    fi

    log "INFO" "Initializing WireGuard cryptographic engine..."
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    chmod 700 /etc/wireguard/clients

    log "INFO" "Enabling Kernel IPv4 Forwarding..."
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-syswarden-wireguard.conf
    sysctl -p /etc/sysctl.d/99-syswarden-wireguard.conf >/dev/null 2>&1 || true

    local SERVER_PRIV; SERVER_PRIV=$(wg genkey)
    local SERVER_PUB; SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    local CLIENT_PRIV; CLIENT_PRIV=$(wg genkey)
    local CLIENT_PUB; CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    local PRESHARED_KEY; PRESHARED_KEY=$(wg genpsk)

    local ACTIVE_IF; ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oEo 'dev [a-zA-Z0-9]+' | awk '{print $2}' | head -n 1)
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"
    
    local SERVER_IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null || \
                curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || \
                curl -4 -s --connect-timeout 3 icanhazip.com 2>/dev/null || \
                ip -4 addr show "$ACTIVE_IF" | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | head -n 1)
    
    local SUBNET_BASE; SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
    local SERVER_VPN_IP="${SUBNET_BASE}.1"
    local CLIENT_VPN_IP="${SUBNET_BASE}.2"

    local POSTUP=""
    local POSTDOWN=""
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        POSTUP="nft add table inet syswarden_wg; nft add chain inet syswarden_wg prerouting { type nat hook prerouting priority 0 \\; }; nft add chain inet syswarden_wg postrouting { type nat hook postrouting priority 100 \\; }; nft add rule inet syswarden_wg postrouting oifname \"$ACTIVE_IF\" masquerade"
        POSTDOWN="nft delete table inet syswarden_wg 2>/dev/null || true"
    else
        POSTUP="iptables -t nat -A POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT"
        POSTDOWN="iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT"
    fi

    log "INFO" "Deploying WireGuard Server Profile..."
    cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
Address = ${SERVER_VPN_IP}/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
PostUp = $POSTUP
PostDown = $POSTDOWN

[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF
    chmod 600 /etc/wireguard/wg0.conf

    log "INFO" "Generating Secure Client Profile..."
    cat <<EOF > /etc/wireguard/clients/admin-pc.conf
[Interface]
PrivateKey = $CLIENT_PRIV
Address = ${CLIENT_VPN_IP}/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 /etc/wireguard/clients/admin-pc.conf

    # --- OPENRC SPECIFIC SERVICE HANDLING ---
    log "INFO" "Starting WireGuard Tunnel Interface (wg0)..."
    if [[ ! -L "/etc/init.d/wg-quick.wg0" ]]; then
        ln -s /etc/init.d/wg-quick /etc/init.d/wg-quick.wg0
    fi
    rc-update add wg-quick.wg0 default >/dev/null 2>&1 || true
    rc-service wg-quick.wg0 restart >/dev/null 2>&1 || true
    
    log "INFO" "WireGuard VPN deployed successfully."
}

display_wireguard_qr() {
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -f "/etc/wireguard/clients/admin-pc.conf" ]]; then
        echo -e "\n${RED}========================================================================${NC}"
        echo -e "${YELLOW}           WIREGUARD MANAGEMENT VPN - SCAN TO CONNECT${NC}"
        echo -e "${RED}========================================================================${NC}\n"
        
        qrencode -t ansiutf8 < /etc/wireguard/clients/admin-pc.conf
        
        echo -e "\n${GREEN}[✔] Client Configuration File Saved At:${NC} /etc/wireguard/clients/admin-pc.conf"
        echo -e "${YELLOW}Keep this secure! Scan this code with the WireGuard App to connect.${NC}"
    fi
}

add_wireguard_client() {
    echo -e "\n${BLUE}=== SysWarden WireGuard Client Generator ===${NC}"

    local wg_conf="/etc/wireguard/wg0.conf"
    local admin_conf="/etc/wireguard/clients/admin-pc.conf"

    # 1. Verification
    if [[ ! -f "$wg_conf" ]] || [[ ! -f "$admin_conf" ]]; then
        log "ERROR" "WireGuard is not configured on this server. Run the main installer first."
        exit 1
    fi

    # 2. Ask for Client Name
    read -p "Enter a name for the new client (e.g., mobile, laptop-john): " client_name
    # Sanitize name
    client_name=$(echo "$client_name" | tr -cd 'a-zA-Z0-9_-')
    if [[ -z "$client_name" ]]; then
        log "ERROR" "Invalid client name."
        exit 1
    fi

    local client_conf="/etc/wireguard/clients/${client_name}.conf"
    if [[ -f "$client_conf" ]]; then
        log "ERROR" "Client '$client_name' already exists at $client_conf"
        exit 1
    fi

    log "INFO" "Generating keys for $client_name..."

    # 3. Cryptography
    local CLIENT_PRIV; CLIENT_PRIV=$(wg genkey)
    local CLIENT_PUB; CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    local PRESHARED_KEY; PRESHARED_KEY=$(wg genpsk)

    # 4. Extract Server Params
    local SERVER_PUB
    SERVER_PUB=$(grep "PublicKey" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')
    local ENDPOINT
    ENDPOINT=$(grep "Endpoint" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')

    # 5. IP Calculation (Find highest IP and increment)
    # Extract the base subnet (e.g., 10.66.66)
    local SUBNET_BASE
    SUBNET_BASE=$(grep "Address" "$wg_conf" | head -n 1 | awk -F'= ' '{print $2}' | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3}')
    
    # Find the highest 4th octet currently in use
    local LAST_OCTET
    LAST_OCTET=$(grep "AllowedIPs" "$wg_conf" | awk -F'= ' '{print $2}' | cut -d'/' -f1 | awk -F'.' '{print $4}' | sort -n | tail -n 1)
    
    local NEXT_OCTET=$((LAST_OCTET + 1))
    if [[ "$NEXT_OCTET" -ge 254 ]]; then
        log "ERROR" "Subnet exhausted. No more IPs available."
        exit 1
    fi
    local CLIENT_VPN_IP="${SUBNET_BASE}.${NEXT_OCTET}"

    # 6. Append to Server Config
    log "INFO" "Registering $client_name with IP $CLIENT_VPN_IP..."
    cat <<EOF >> "$wg_conf"

# Client: $client_name
[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF

    # 7. Create Client Config
    cat <<EOF > "$client_conf"
[Interface]
PrivateKey = $CLIENT_PRIV
Address = ${CLIENT_VPN_IP}/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PRESHARED_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    chmod 600 "$client_conf"

    # 8. Hot-Reload WireGuard Interface
    log "INFO" "Reloading WireGuard interface..."
    if command -v wg >/dev/null && wg show wg0 >/dev/null 2>&1; then
        # Hot reload without dropping connection
        wg syncconf wg0 <(wg-quick strip wg0)
    else
        # Fallback if interface is down
        if command -v systemctl >/dev/null; then systemctl restart wg-quick@wg0 2>/dev/null || true
        elif command -v rc-service >/dev/null; then rc-service wg-quick restart 2>/dev/null || true; fi
    fi

    # 9. Display Output
    echo -e "\n${RED}========================================================================${NC}"
    echo -e "${YELLOW}           WIREGUARD CLIENT: ${client_name^^}${NC}"
    echo -e "${RED}========================================================================${NC}\n"
    qrencode -t ansiutf8 < "$client_conf"
    echo -e "\n${GREEN}[✔] Client Configuration File Saved At:${NC} $client_conf"
}

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden (Alpine) ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation..."
	
	# --- WIREGUARD CLEANUP (OPENRC) ---
    if [[ -d "/etc/wireguard" ]] || [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        log "INFO" "Stopping and removing WireGuard VPN..."
        
        rc-service wg-quick.wg0 stop 2>/dev/null || true
        rc-update del wg-quick.wg0 default 2>/dev/null || true
        rm -f /etc/init.d/wg-quick.wg0
        rm -rf /etc/wireguard
        
        rm -f /etc/sysctl.d/99-syswarden-wireguard.conf
        sysctl -p 2>/dev/null || true
        
        # EMERGENCY SSH RESTORE FOR IPTABLES
        if command -v iptables >/dev/null; then
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
            /etc/init.d/iptables save >/dev/null 2>&1 || true
        fi
    fi
    # ----------------------------------

    if [[ -f "$CONF_FILE" ]]; then 
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # 1. Stop & Remove Reporter Service
    log "INFO" "Removing SysWarden Reporter..."
    rc-service syswarden-reporter stop 2>/dev/null || true
    rc-update del syswarden-reporter default 2>/dev/null || true
    rm -f /etc/init.d/syswarden-reporter /usr/local/bin/syswarden_reporter.py
    rm -rf /var/lib/syswarden

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    sed -i '/syswarden-update/d' /etc/crontabs/root 2>/dev/null || true
    rc-service crond restart 2>/dev/null || true
    rm -f "/etc/logrotate.d/syswarden"

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."
    
    # Nftables
    if command -v nft >/dev/null; then 
        nft delete table inet syswarden_table 2>/dev/null || true
        nft list ruleset > /etc/nftables.nft 2>/dev/null || true
    fi
    
    # Docker (DOCKER-USER chain)
    if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null || true
        /etc/init.d/iptables save >/dev/null 2>&1 || true
    fi
    
    # IPSet / Iptables (Legacy)
    if command -v ipset >/dev/null; then 
        ipset destroy "$SET_NAME" 2>/dev/null || true
        ipset destroy "$GEOIP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_SET_NAME" 2>/dev/null || true
        /etc/init.d/iptables save 2>/dev/null || true
    fi

    # 4. Revert Fail2ban Configuration
    if [[ -f /etc/fail2ban/jail.local.bak ]]; then
        log "INFO" "Restoring original Fail2ban configuration..."
        mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
        rc-service fail2ban restart 2>/dev/null || true
    elif [[ -f /etc/fail2ban/jail.local ]]; then
        log "INFO" "No backup found. Removing SysWarden jail.local..."
        rm -f /etc/fail2ban/jail.local
        rc-service fail2ban restart 2>/dev/null || true
    fi
    
    # Clean custom Fail2ban files
    rm -f /etc/fail2ban/fail2ban.local
    rm -f /etc/fail2ban/action.d/syswarden-docker.conf
    rm -f /etc/fail2ban/filter.d/syswarden-*.conf

    # 5. Remove Wazuh Agent (If installed)
    if apk info -e wazuh-agent >/dev/null 2>&1; then
        read -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            rc-service wazuh-agent stop 2>/dev/null || true
            rc-update del wazuh-agent default 2>/dev/null || true
            apk del wazuh-agent
            rm -rf /var/ossec
            log "INFO" "Wazuh Agent removed."
        else
            log "INFO" "Keeping Wazuh Agent installed."
        fi
    fi

    # 6. Remove Config Files & Logs
    rm -rf "$SYSWARDEN_DIR"
    rm -f "$CONF_FILE"
    rm -f "$LOG_FILE"
    
    log "INFO" "Cleanup complete. Environment restored."
    echo -e "${GREEN}Uninstallation complete.${NC}"
    exit 0
}

setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (Alpine) ===${NC}"
    
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_WAZUH:-n}
        log "INFO" "Auto Mode: Wazuh Agent choice loaded via env var [${response}]"
    else
        read -p "Install Wazuh Agent? (y/N): " response
    fi
    # -----------------------------
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping Wazuh Agent installation."
        return
    fi

    # 2. Gather Configuration Data
    if [[ "${1:-}" == "auto" ]]; then
        WAZUH_IP=${SYSWARDEN_WAZUH_IP:-""}
        W_PORT_COMM=${SYSWARDEN_WAZUH_COMM_PORT:-1514}
        W_PORT_ENROLL=${SYSWARDEN_WAZUH_ENROLL_PORT:-1515}
        log "INFO" "Auto Mode: Wazuh settings loaded via env vars."
    else
        read -p "Enter Wazuh Manager IP: " WAZUH_IP
        if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing IP. Skipping."; return; fi

        read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
        W_PORT_COMM=${W_PORT_COMM:-1514}

        read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
        W_PORT_ENROLL=${W_PORT_ENROLL:-1515}
    fi

    # Fail-Safe: Interdire l'installation si l'IP n'est pas fournie en mode auto
    if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing Wazuh IP. Skipping."; return; fi

    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on Alpine Firewall..."
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
         nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
         nft list ruleset > /etc/nftables.nft
         log "INFO" "Nftables rule added for Wazuh Manager."
    else
         if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
             iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT
             /etc/init.d/iptables save >/dev/null 2>&1 || true
         fi
    fi

    log "INFO" "Starting Wazuh Agent installation via Apk..."
    
    # Install directly from Wazuh repo for Alpine
    if apk add -q --allow-untrusted https://packages.wazuh.com/4.x/alpine/v3.14/main/x86_64/wazuh-agent-4.9.0-1.alpine.x86_64.apk; then
        
        # Inject Custom Settings into OSSEC Config
        if [[ -f /var/ossec/etc/ossec.conf ]]; then
            sed -i "s/<address>.*<\/address>/<address>$WAZUH_IP<\/address>/" /var/ossec/etc/ossec.conf
            sed -i "s/<port>1514<\/port>/<port>$W_PORT_COMM<\/port>/" /var/ossec/etc/ossec.conf
        fi

        rc-update add wazuh-agent default >/dev/null 2>&1
        rc-service wazuh-agent restart >/dev/null 2>&1
        
        echo "WAZUH_IP='$WAZUH_IP'" >> "$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >> "$CONF_FILE"
        log "INFO" "Wazuh Agent installed and started."
    else
        log "ERROR" "Failed to install Wazuh Agent package."
    fi
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            nft insert rule inet syswarden_table input ip saddr "$WL_IP" accept
            nft list ruleset > /etc/nftables.nft
            log "INFO" "Rule added to Nftables and saved."
            ;;
        *)
            iptables -I INPUT 1 -s "$WL_IP" -j ACCEPT
            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Rule added to IPTables."
            ;;
    esac
}

blocklist_ip() {
    echo -e "\n${RED}=== SysWarden Manual Blocklist Manager ===${NC}"
    read -p "Enter IP to Block: " BL_IP

    if [[ ! "$BL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    log "INFO" "Blocking IP: $BL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            nft insert rule inet syswarden_table input ip saddr "$BL_IP" drop
            nft list ruleset > /etc/nftables.nft
            log "INFO" "Drop rule added to Nftables and saved."
            ;;
        *)
            iptables -I INPUT 1 -s "$BL_IP" -j DROP
            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Drop rule added to IPTables."
            ;;
    esac
}

protect_docker_jail() {
    echo -e "\n${BLUE}=== SysWarden Docker Jail Protector ===${NC}"
    
    local jail_file="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_file" ]]; then
        log "ERROR" "Fail2ban configuration ($jail_file) not found."
        exit 1
    fi

    if command -v fail2ban-client >/dev/null && rc-service fail2ban status 2>/dev/null | grep -q "started"; then
        local active_jails; active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
        echo -e "Currently active Jails: ${YELLOW}${active_jails}${NC}"
    fi

    read -p "Enter the exact name of your custom Docker Jail (e.g. 'nginx-docker'): " jail_name
    jail_name=$(echo "$jail_name" | xargs | tr -cd 'a-zA-Z0-9_-')

    if [[ -z "$jail_name" ]]; then
        log "ERROR" "Jail name cannot be empty."
        exit 1
    fi

    if ! grep -q "^\[${jail_name}\]" "$jail_file"; then
        log "ERROR" "Jail [${jail_name}] not found in $jail_file. Please create it first."
        exit 1
    fi

    log "INFO" "Configuring jail [${jail_name}] to use Docker banaction..."

    local temp_file; temp_file=$(mktemp)
    local in_target_jail=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            if [[ "$line" == "[${jail_name}]" ]]; then
                in_target_jail=1
                echo "$line" >> "$temp_file"
                echo "banaction = syswarden-docker" >> "$temp_file"
                continue
            else
                in_target_jail=0
            fi
        fi

        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >> "$temp_file"
    done < "$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."
    rc-service fail2ban restart >/dev/null 2>&1 || true
    log "INFO" "Fail2ban service restarted."
}

check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Alpine) ===${NC}"
    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response
    
    # Fetch API response quietly (Timeout 5s to avoid hanging)
    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    # STRICT MATCH: Extract download URL specifically for the Alpine script
    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden-alpine\.sh"' | head -n 1 | cut -d'"' -f4)

    # ARCHITECTURE ISOLATION: If the latest release doesn't contain the Alpine script
    if [[ -z "$download_url" ]]; then
        echo -e "${GREEN}No specific update found for the Alpine version in the latest release. You are up to date!${NC}"
        return
    fi

    # Extract tag_name (e.g., "v9.22")
    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Alpine version ($latest_version) is available!${NC}"
        echo -e "To upgrade safely, please run the following commands:\n"
        echo -e "  wget -qO install-syswarden-alpine.sh \"$download_url\""
        echo -e "  chmod +x install-syswarden-alpine.sh"
        echo -e "  ./install-syswarden-alpine.sh\n"
        echo -e "Note: Running the updated script will cleanly overwrite old configurations if necessary."
    fi
}

show_alerts_dashboard() {
    # Trap Ctrl+C/Exit to restore cursor
    trap "tput cnorm; clear; exit 0" INT TERM
    tput civis # Hide cursor for cleaner UI

    while true; do
        clear
        local NOW; NOW=$(date "+%H:%M:%S")
        
        echo -e "${BLUE}====================================================================================================${NC}"
        echo -e "${BLUE}   SysWarden Live Attack Dashboard (Last Update: $NOW)        ${NC}"
        echo -e "${BLUE}====================================================================================================${NC}"
        # HEADER: 6 Columns
        printf "${YELLOW}%-19s | %-10s | %-16s | %-20s | %-12s | %-8s${NC}\n" "DATE / HOUR" "SOURCE" "IP ADDRESS" "RULES" "PORT" "DECISION"
        echo "----------------------------------------------------------------------------------------------------"

        # Regex corrigée pour capturer proprement la date Rsyslog (Format ISO avec T)
        local date_regex="^([A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+[0-9:]+|[0-9]{4}-[0-9]{2}-[0-9]{2}[T[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2})"

        # 1. FAIL2BAN ENTRIES
        if [[ -f "/var/log/fail2ban.log" ]]; then
             { grep " Ban " "/var/log/fail2ban.log" || true; } | tail -n 10 | while read -r line; do
                if [[ $line =~ \[([a-zA-Z0-9_-]+)\][[:space:]]+Ban[[:space:]]+([0-9.]+) ]]; then
                    jail="${BASH_REMATCH[1]}"
                    ip="${BASH_REMATCH[2]}"
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Fail2ban" "$ip" "$jail" "Dynamic" "BAN"
                fi
            done
        fi

        # 2. FIREWALL ENTRIES (Direct from Kernel Buffer)
        # Calculate boot time to translate kernel uptime to human-readable date
        local uptime_sec; uptime_sec=$(cut -d. -f1 /proc/uptime)
        local now_sec; now_sec=$(date +%s)
        local boot_sec=$((now_sec - uptime_sec))

        { dmesg | grep -E "\[SysWarden-BLOCK\]|\[SysWarden-GEO\]|\[SysWarden-ASN\]|\[SysWarden-VPN\]" | tail -n 20; } | while read -r line; do
            if [[ $line =~ SRC=([0-9.]+) ]]; then
                ip="${BASH_REMATCH[1]}"
                rule="Unknown"
                if [[ $line =~ (SysWarden-[A-Z]+) ]]; then rule="${BASH_REMATCH[1]}"; fi
                
                port="Global"
                if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                
                # Extract Kernel Timestamp and convert to YYYY-MM-DD HH:MM:SS format
                dtime="Kernel-TS"
                if [[ $line =~ ^\[[[:space:]]*([0-9]+)\.[0-9]+\] ]]; then
                    local kernel_sec="${BASH_REMATCH[1]}"
                    local event_sec=$((boot_sec + kernel_sec))
                    dtime=$(date -d "@$event_sec" "+%Y-%m-%d %H:%M:%S")
                fi
                
                printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
            fi
         done
                
        echo "----------------------------------------------------------------------------------------------------"
        echo -e "Press [ESC] to Quit."
        
        read -t 10 -n 1 -s -r key || true
        if [[ $key == $'\e' ]]; then
            break
        fi
    done
    tput cnorm # Restore cursor
    clear
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

MODE="${1:-install}"

# --- HEADLESS / UNATTENDED INSTALLATION PARSER ---
# Safely parses a provided .conf file to inject environment variables
if [[ -f "${1:-}" ]]; then
    echo -e "${GREEN}>>> Unattended configuration file detected: $1${NC}"
    while IFS='=' read -r key val; do
        # Ignore comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        
        # Clean up the key and value (remove whitespaces and quotes)
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | xargs | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
        
        # STRICT SECURITY: Only export variables starting with SYSWARDEN_
        if [[ "$key" =~ ^SYSWARDEN_[A-Z0-9_]+$ ]]; then
            export "$key"="$val"
        fi
    done < "$1"
    
    MODE="auto"
elif [[ "$MODE" == "--auto" ]]; then
    MODE="auto"
fi
# -------------------------------------------------

if [[ "$MODE" == "whitelist" ]]; then
    check_root
    detect_os_backend
    whitelist_ip
    exit 0
fi

if [[ "$MODE" == "blocklist" ]]; then
    check_root
    detect_os_backend
    blocklist_ip
    exit 0
fi

if [[ "$MODE" == "wireguard-client" ]]; then
    check_root
    add_wireguard_client
    exit 0
fi

if [[ "$MODE" == "protect-docker" ]]; then
    check_root
    protect_docker_jail
    exit 0
fi

if [[ "$MODE" == "alerts" ]]; then
    check_root
    show_alerts_dashboard
    exit 0
fi

if [[ "$MODE" == "upgrade" ]]; then
    check_root
    check_upgrade
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    check_root
    uninstall_syswarden
fi

if [[ "$MODE" != "update" ]]; then
    clear
    echo -e "${GREEN}#############################################################"
    echo -e "#     SysWarden Tool Installer (Alpine Linux Edition)       #"
    echo -e "#############################################################${NC}"
fi

check_root
detect_os_backend

# --- PREVENT ADMIN LOCK-OUT (EXECUTE BEFORE FAIL2BAN/FIREWALL) ---
auto_whitelist_admin
# -----------------------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    install_dependencies
    define_ssh_port "$MODE"
	define_wireguard "$MODE"
    define_docker_integration "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
	define_vpnblocking "$MODE"
    configure_fail2ban
fi

select_list_type "$MODE"
select_mirror "$MODE"
download_list
download_geoip
download_asn
download_vpn
apply_firewall_rules
detect_protected_services

if rc-service syswarden-reporter status 2>/dev/null | grep -q "started"; then
    rc-service syswarden-reporter restart >/dev/null 2>&1 || true
fi

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    setup_siem_logging
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"
    
    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> OS Detected: Alpine Linux (OpenRC)"
    echo -e " -> List loaded: $LIST_TYPE"
    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Interactive"
    fi
    echo -e " -> Protection: Active"
    
    display_wireguard_qr
fi