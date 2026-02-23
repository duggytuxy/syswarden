#!/bin/bash

# --- SAFETY FIRST ---
set -euo pipefail
IFS=$'\n\t'

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
VERSION="v9.00"
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
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        OS_ID=$ID
    else
        OS="Unknown"
        OS_ID="unknown"
    fi

    # Logic to select the best firewall for the OS
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        FIREWALL_BACKEND="ufw"
    elif [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]]; then
        FIREWALL_BACKEND="nftables"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_BACKEND="firewalld" # RHEL/Alma default
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="ipset" # Fallback
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Checking dependencies..."
    local missing_common=""

    if [[ -f /etc/debian_version ]]; then
        log "INFO" "Updating apt repositories..."
        apt-get update -qq
    fi

    if ! command -v curl >/dev/null; then missing_common="$missing_common curl"; fi
    if ! command -v python3 >/dev/null; then missing_common="$missing_common python3"; fi
	if ! command -v whois >/dev/null; then missing_common="$missing_common whois"; fi
    
    if [[ -n "$missing_common" ]]; then
        if [[ -f /etc/debian_version ]]; then apt-get install -y $missing_common; 
        elif [[ -f /etc/redhat-release ]]; then dnf install -y $missing_common; fi
    fi

    # Python Requests (Required for AbuseIPDB Reporter)
    # PEP 668 COMPLIANCE: We strictly use system packages (apt/dnf) to avoid 'externally-managed-environment' errors.
    if ! python3 -c "import requests" 2>/dev/null; then
        log "INFO" "Installing Python Requests library..."
        
        if [[ -f /etc/debian_version ]]; then
            # Debian/Ubuntu: MANDATORY usage of apt to avoid breaking system python
            apt-get install -y python3-requests
            
        elif [[ -f /etc/redhat-release ]]; then
            # RHEL/Alma: Prioritize RPM. Fallback to pip only if RPM fails (RHEL behavior is less strict than Debian yet)
            if ! dnf install -y python3-requests; then
                 log "WARN" "python3-requests RPM not found. Trying pip fallback..."
                 dnf install -y python3-pip
                 pip3 install requests
            fi
        fi

        # Verification post-install
        if ! python3 -c "import requests" 2>/dev/null; then
             log "ERROR" "Failed to install 'python3-requests'. AbuseIPDB reporting feature will be disabled."
        fi
    fi
	
	# --- CRON DEPENDENCY (For modern minimal OS like Fedora / RHEL 9+) ---
    if ! command -v crond >/dev/null && ! command -v cron >/dev/null; then
        log "WARN" "Installing package: cron daemon"
        if [[ -f /etc/debian_version ]]; then apt-get install -y cron
        elif [[ -f /etc/redhat-release ]]; then dnf install -y cronie; fi
    fi
    
    # Ensure it's enabled and started (moved outside the install check)
    if command -v systemctl >/dev/null; then
        systemctl enable --now crond 2>/dev/null || systemctl enable --now cron 2>/dev/null || true
    fi
    # --------------------------------------------------------------------

    if ! command -v ipset >/dev/null; then
        log "WARN" "Installing package: ipset"
        if [[ -f /etc/debian_version ]]; then apt-get install -y ipset
        elif [[ -f /etc/redhat-release ]]; then dnf install -y ipset; fi
    fi

    if ! command -v fail2ban-client >/dev/null; then
        log "WARN" "Installing package: fail2ban"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y fail2ban
        elif [[ -f /etc/redhat-release ]]; then
            log "INFO" "Enabling EPEL repository (Required for Fail2ban)..."
            dnf install -y epel-release || true
            dnf install -y fail2ban
        fi
    fi
	
	# --- ZTNA / SPA Dependencies ---
    if ! command -v fwknopd >/dev/null; then
        log "WARN" "Installing package: fwknop-server (ZTNA/SPA)"
        if [[ -f /etc/debian_version ]]; then 
            apt-get install -y fwknop-server fwknop-client
        elif [[ -f /etc/redhat-release ]]; then 
            dnf install -y fwknop
        fi
    fi
	
	# --- eBPF / L7 HIDS Dependencies ---
    if ! python3 -c "from bcc import BPF" 2>/dev/null; then
        log "WARN" "Installing package: BCC Tools & Kernel Headers (eBPF)"
        if [[ -f /etc/debian_version ]]; then 
            apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) || true
        elif [[ -f /etc/redhat-release ]]; then 
            dnf install -y bcc-tools python3-bcc kernel-devel-$(uname -r) || true
        fi
    fi

    if [[ "$FIREWALL_BACKEND" == "nftables" ]] && ! command -v nft >/dev/null; then
        log "WARN" "Installing package: nftables"
        if [[ -f /etc/debian_version ]]; then apt-get install -y nftables;
        elif [[ -f /etc/redhat-release ]]; then dnf install -y nftables; fi
    fi

    # --- RHEL/ROCKY/CENTOS 10 ZERO-REBOOT FIX ---
    # Moved to the VERY END of the function to ensure all DNF transactions are flushed to disk
    if [[ "$FIREWALL_BACKEND" != "nftables" ]] && [[ "$FIREWALL_BACKEND" != "ufw" ]]; then
        log "INFO" "Synchronizing Kernel modules..."
        /sbin/depmod -a 2>/dev/null || true
        /sbin/modprobe ip_set 2>/dev/null || true
        /sbin/modprobe ip_set_hash_net 2>/dev/null || true
        
        # Give Netlink sockets 2 seconds to bind
        sleep 2
        
        if command -v systemctl >/dev/null && systemctl is-active --quiet firewalld; then
            systemctl restart firewalld 2>/dev/null || true
        fi
    fi
    # --------------------------------------------

    log "INFO" "All dependencies check complete."
}

define_ssh_port() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SSH_PORT:-}" ]]; then SSH_PORT=22; fi
        log "INFO" "Update Mode: Preserving SSH Port $SSH_PORT"
        return
    fi

    echo -e "\n${BLUE}=== Step: SSH Configuration ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        SSH_PORT=${SYSWARDEN_SSH_PORT:-22}
        log "INFO" "Auto Mode: SSH Port configured via env var [${SSH_PORT}]"
    else
        read -p "Please enter your current SSH Port [Default: 22]: " input_port
        SSH_PORT=${input_port:-22}
    fi
    # -----------------------------

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        log "WARN" "Invalid port detected. Defaulting to 22."
        SSH_PORT=22
    fi

    echo "SSH_PORT='$SSH_PORT'" >> "$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"
}

define_ztna_spa() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_SPA:-}" ]]; then USE_SPA="n"; fi
        log "INFO" "Update Mode: Preserving ZTNA/SPA setting ($USE_SPA)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Zero Trust Network Access (SPA) ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_spa=${SYSWARDEN_ENABLE_SPA:-n}
        log "INFO" "Auto Mode: ZTNA/SPA choice loaded via env var [${input_spa}]"
    else
        echo -e "${YELLOW}Warning: This will cloak your SSH port completely. You will need the fwknop client to connect.${NC}"
        read -p "Enable Single Packet Authorization (SPA) for SSH? (y/N): " input_spa
    fi

    if [[ "$input_spa" =~ ^[Yy]$ ]]; then
        USE_SPA="y"
        log "INFO" "ZTNA/SPA ENABLED. SSH port will be cloaked."
    else
        USE_SPA="n"
        log "INFO" "ZTNA/SPA DISABLED."
    fi
    echo "USE_SPA='$USE_SPA'" >> "$CONF_FILE"
}

define_ebpf_hids() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_EBPF:-}" ]]; then USE_EBPF="n"; fi
        log "INFO" "Update Mode: Preserving eBPF HIDS setting ($USE_EBPF)"
        return
    fi

    echo -e "\n${BLUE}=== Step: L7 Process Monitoring (eBPF) ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_ebpf=${SYSWARDEN_ENABLE_EBPF:-n}
        log "INFO" "Auto Mode: eBPF HIDS choice loaded via env var [${input_ebpf}]"
    else
        echo -e "${YELLOW}Warning: This deploys an eBPF sensor to block RCE and Reverse Shells instantly.${NC}"
        read -p "Enable L7 eBPF Process Monitoring? (y/N): " input_ebpf
    fi

    if [[ "$input_ebpf" =~ ^[Yy]$ ]]; then
        USE_EBPF="y"
        log "INFO" "eBPF HIDS ENABLED. Web servers are now strictly monitored."
    else
        USE_EBPF="n"
        log "INFO" "eBPF HIDS DISABLED."
    fi
    echo "USE_EBPF='$USE_EBPF'" >> "$CONF_FILE"
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
        echo "4) No List (Geo-Blocking / Local rules only)"
        read -p "Enter choice [1/2/3/4]: " choice
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
           CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d " '\"\;\$\|\&\<\>\`")
           
           # Fail-Safe: If custom URL is empty/invalid, revert to standard to avoid leaving server unprotected
           if [[ -z "$CUSTOM_URL" ]]; then
               log "WARN" "Custom URL is empty. Defaulting to Standard List."
               LIST_TYPE="Standard"
           fi
           ;;
        4) LIST_TYPE="None";;
        *) 
           log "WARN" "Invalid choice detected. Defaulting to Standard List."
           LIST_TYPE="Standard"
           ;;
    esac
    
    echo "LIST_TYPE='$LIST_TYPE'" >> "$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >> "$CONF_FILE"; fi
    log "INFO" "User selected: $LIST_TYPE Blocklist"
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
        # Force lowercase for the URL
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
        # Rétrocompatibilité : si la variable Spamhaus n'existe pas dans le conf, on l'active par défaut
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
        USE_SPAMHAUS_ASN=${use_spamhaus:-y} # Default to yes if user just hits Enter
        
        # Normalize Spamhaus choice
        if [[ "$USE_SPAMHAUS_ASN" =~ ^[Nn]$ ]]; then
            USE_SPAMHAUS_ASN="n"
        else
            USE_SPAMHAUS_ASN="y"
        fi
        
        # Fail-Safe: If user typed nothing AND declined Spamhaus
        if [[ "$BLOCK_ASNS" == "none" ]] && [[ "$USE_SPAMHAUS_ASN" == "n" ]]; then
            BLOCK_ASNS="none"
            log "WARN" "No custom ASNs provided and Spamhaus declined. ASN Blocking DISABLED."
        else
            # Force uppercase on custom ASNs if they exist
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
	
	if [[ "$LIST_TYPE" == "None" ]]; then
        SELECTED_URL="none"
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
	
	if [[ "$SELECTED_URL" == "none" ]]; then
        log "INFO" "No global blocklist selected. Skipping download."
        touch "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        return
    fi
    
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
    
    # FIX: Create required directories before doing anything
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : > "$TMP_DIR/geoip_raw.txt"

    # FIX: Bypass strict IFS by transforming spaces into newlines for the loop
    for country in $(echo "$GEOBLOCK_COUNTRIES" | tr ' ' '\n'); do
        # Skip empty strings just in case
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
        # Ensure valid CIDR formats and remove duplicates
        grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' "$TMP_DIR/geoip_raw.txt" | sort -u > "$GEOIP_FILE"
        log "INFO" "Geo-Blocking list updated successfully."
    else
        log "WARN" "Geo-Blocking list is empty. IPDeny might be unreachable."
        touch "$GEOIP_FILE"
    fi
}

download_asn() {
    # On sort si l'utilisateur n'a rien mis en perso ET a dit non à Spamhaus
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading ASN Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : > "$TMP_DIR/asn_raw.txt"

    # --- SPAMHAUS ASN-DROP INTEGRATION (CONDITIONAL) ---
    if [[ "${USE_SPAMHAUS_ASN:-y}" == "y" ]]; then
        echo -n "Fetching Spamhaus ASN-DROP list (Cybercrime Hosters)... "
        local spamhaus_url="https://www.spamhaus.org/drop/asndrop.json"
        
        # Extract ASNs from JSON format securely using grep and sed
        local spamhaus_asns
        spamhaus_asns=$(curl -sS -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --retry 2 --connect-timeout 5 "$spamhaus_url" 2>/dev/null | grep -Eo '"asn":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+' | sed 's/^/AS/' | tr '\n' ' ' || true)
        
        if [[ -n "$spamhaus_asns" ]]; then
            echo -e "${GREEN}OK${NC}"
            # Clean merge: replace 'none' or 'auto' from older configs
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
    # -------------------------------------

    # --- FIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------
    
    local combined_asns
    combined_asns=$(echo "$BLOCK_ASNS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

    for asn in $combined_asns; do
        # Ignore empty strings or our keywords
        if [[ -z "$asn" ]] || [[ "$asn" == "auto" ]] || [[ "$asn" == "none" ]]; then continue; fi
        
        # Format the input properly
        if [[ ! "$asn" =~ ^AS[0-9]+$ ]]; then 
            local clean_num="${asn//[!0-9]/}"
            if [[ -z "$clean_num" ]]; then continue; fi # Failsafe
            asn="AS${clean_num}"
        fi
        
        echo -n "Fetching IP blocks for ${asn}... "
        
        # --- FIX: SMART RETRY (Distinguish Network Error vs Empty ASN) ---
        local success=false
        local whois_out=""
        
        for _ in 1 2 3; do
            # Capture total output (stdout + stderr)
            whois_out=$(whois -h whois.radb.net -- "-i origin $asn" 2>&1 || true)
            
            # If the RADB server drops the connection, pause and retry
            if [[ "$whois_out" == *"Connection reset by peer"* ]] || [[ "$whois_out" == *"Timeout"* ]] || [[ "$whois_out" == *"refused"* ]]; then
                sleep 2
                continue
            fi
            
            # If we reach this point, the query succeeded (even if the result is empty)
            success=true
            break
        done

        if [ "$success" = true ]; then
            # Now search for IPv4 CIDRs in the valid response
            if echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >> "$TMP_DIR/asn_raw.txt"; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}Empty (IPv6-only/No routes)${NC}"
            fi
        else
            echo -e "${RED}FAIL (Blocked by RADB)${NC}"
            log "WARN" "Failed to fetch data for $asn (Network dropped)."
        fi
        
        # Ultra-short pause to prevent getting rate-limited while staying fast
        sleep 0.5
        # ---------------------------------------------------------------
    done
    
    # Restore strict security IFS
    IFS="$OLD_IFS"

    if [[ -s "$TMP_DIR/asn_raw.txt" ]]; then
        # Use Python to mathematically collapse overlapping CIDRs and prevent Firewalld INVALID_ENTRY errors
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

apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules ($FIREWALL_BACKEND) ===${NC}"
    
    # --- LOCAL PERSISTENCE INJECTION ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE"

    # --- PREVENT ADMIN LOCK-OUT (AUTO-WHITELIST CURRENT SSH SESSION) ---
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        local ADMIN_IP
        ADMIN_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
        if [[ "$ADMIN_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if ! grep -q "^${ADMIN_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting current admin SSH session IP: $ADMIN_IP"
                echo "$ADMIN_IP" >> "$WHITELIST_FILE"
            fi
        fi
    fi
    # -------------------------------------------------------------------

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
        log "INFO" "Configuring Nftables Set..."
        
        # 1. Main Blocklist Elements (Conditional for Option 4 "No List")
        local main_elements=""
        if [[ -s "$FINAL_LIST" ]]; then
            main_elements="elements = { $(awk '{print $1 ","}' "$FINAL_LIST") }"
        fi
        
        # 2. GeoIP Blocklist Elements (Conditional)
        local geoip_block=""
        local geoip_rule=""
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            geoip_block="
    set $GEOIP_SET_NAME {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $(awk '{print $1 ","}' "$GEOIP_FILE") }
    }"
            geoip_rule="ip saddr @$GEOIP_SET_NAME log prefix \"[SysWarden-GEO] \" flags all drop"
        fi

        # 3. ASN Blocklist Elements (Conditional)
        local asn_block=""
        local asn_rule=""
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            asn_block="
    set $ASN_SET_NAME {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { $(awk '{print $1 ","}' "$ASN_FILE") }
    }"
            asn_rule="ip saddr @$ASN_SET_NAME log prefix \"[SysWarden-ASN] \" flags all drop"
        fi
		
		# 4. ZTNA / SPA Rule (Handled via iptables for fwknop compatibility)
        local ztna_rule=""

        # 4.5. Build Whitelist Set for Nftables
        local wl_elements=""
        if [[ -s "$WHITELIST_FILE" ]]; then
            wl_elements="elements = { $(awk '{print $1 ","}' "$WHITELIST_FILE") }"
        fi

        # 5. Build and Apply Nftables config (Respecting Priority)
        cat <<EOF > "$TMP_DIR/syswarden.nft"
table inet syswarden_table {
    set syswarden_whitelist {
        type ipv4_addr
        flags interval
        auto-merge
        $wl_elements
    }
    set $SET_NAME {
        type ipv4_addr
        flags interval
        auto-merge
        $main_elements
    }$geoip_block$asn_block
    chain input {
        type filter hook input priority filter - 10; policy accept;
        
        # PRIORITY 0: Critical Bypasses (Keep SSH alive & Admin Whitelist)
        ct state established,related accept
        ip saddr @syswarden_whitelist accept
        
        # PRIORITY 1: Geo-Blocking (Broadest scope)
        $geoip_rule
        
        # PRIORITY 2: ASN-Blocking (Mid-level scope)
        $asn_rule
        
        # PRIORITY 3: Standard Blocklist & Scanners
        ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " flags all drop
        tcp dport { 23, 445, 1433, 3389, 5900 } log prefix "[SysWarden-BLOCK] " flags all drop
        
        # PRIORITY 4: ZTNA / SPA Cloaking
        $ztna_rule
    }
}
EOF
        nft -f "$TMP_DIR/syswarden.nft"
		
		# --- ZTNA COMPATIBILITY FIX FOR NFTABLES ---
        if [[ "${USE_SPA:-n}" == "y" ]]; then
            log "INFO" "ZTNA: Cloaking SSH port via iptables-nft for fwknop compatibility..."
            
            # 1. Clean existing ZTNA rules to prevent duplicates
            while iptables -D INPUT -p tcp --dport "$SSH_PORT" -j DROP 2>/dev/null; do :; done
            while iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done

            # 2. Insert the Absolute Drop Rule (HARDCORE MODE)
            iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j DROP
            
            # 3. CRITICAL: Save the current SSH session so the script can finish!
            # We insert this ABOVE the drop rule (at position 1, pushing DROP to position 2)
            iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi

            # 4. Restart fwknopd to guarantee its dynamic hook is at the very top
            log "INFO" "ZTNA: Restarting SPA service to ensure correct iptables hook priority..."
            if command -v systemctl >/dev/null; then
                systemctl restart fwknop-server 2>/dev/null || systemctl restart fwknopd 2>/dev/null || true
            fi
        fi
        # -------------------------------------------

        # --- PERSISTENCE & SERVICE ENABLEMENT ---
        log "INFO" "Saving Nftables ruleset to /etc/nftables.conf for persistence..."
        nft list ruleset > /etc/nftables.conf
        if command -v systemctl >/dev/null; then
            systemctl enable --now nftables 2>/dev/null || true
        fi

    elif [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        # --- ZTNA COMPATIBILITY FIX ---
        if [[ "${USE_SPA:-n}" == "y" ]]; then
            log "INFO" "ZTNA: Switching Firewalld backend to iptables for fwknop compatibility..."
            sed -i 's/^FirewallBackend=nftables/FirewallBackend=iptables/' /etc/firewalld/firewalld.conf
            systemctl restart firewalld
        fi
        # ------------------------------

        if ! systemctl is-active --quiet firewalld; then systemctl enable --now firewalld; fi
        
        if [[ "${USE_SPA:-n}" == "y" ]]; then
            log "INFO" "ZTNA: Removing public SSH port access from Firewalld..."
            firewall-cmd --permanent --remove-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || true
            firewall-cmd --permanent --remove-service="ssh" >/dev/null 2>&1 || true
        elif [[ -n "${SSH_PORT:-}" ]]; then
            firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1 || true
        fi

        log "INFO" "Preparing Firewalld IPSets (Bypassing DBus limitations)..."
        
        # 1. Clean old rules quietly
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" >/dev/null 2>&1 || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" >/dev/null 2>&1 || true
        
        firewall-cmd --permanent --delete-ipset="$SET_NAME" >/dev/null 2>&1 || true
        firewall-cmd --permanent --delete-ipset="$GEOIP_SET_NAME" >/dev/null 2>&1 || true
        firewall-cmd --permanent --delete-ipset="$ASN_SET_NAME" >/dev/null 2>&1 || true

        # 2. Create ALL empty XMLs first
        mkdir -p /etc/firewalld/ipsets
        cat <<EOF > "/etc/firewalld/ipsets/${SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="200000"/>
</ipset>
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat <<EOF > "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="500000"/>
</ipset>
EOF
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat <<EOF > "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="500000"/>
</ipset>
EOF
        fi

        # 3. Fast reload to register empty sets
        firewall-cmd --reload >/dev/null 2>&1 || true

        # 4. Add all Rich Rules
        firewall-cmd --permanent --add-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" >/dev/null 2>&1 || true
        
        for port in 23 445 1433 3389 5900; do
            firewall-cmd --permanent --add-rich-rule="rule port port=\"$port\" protocol=\"tcp\" log prefix=\"[SysWarden-BLOCK] \" level=\"info\" drop" >/dev/null 2>&1 || true
        done

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        # 5. Populate XMLs directly with data
        log "INFO" "Injecting massive IP lists into kernel..."
        sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${SET_NAME}.xml"
        sed 's/.*/  <entry>&<\/entry>/' "$FINAL_LIST" >> "/etc/firewalld/ipsets/${SET_NAME}.xml"
        echo "</ipset>" >> "/etc/firewalld/ipsets/${SET_NAME}.xml"

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$GEOIP_FILE" >> "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            echo "</ipset>" >> "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$ASN_FILE" >> "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            echo "</ipset>" >> "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
        fi
        
        log "INFO" "Loading rules into kernel (This may take up to 30s)..."
        firewall-cmd --reload >/dev/null 2>&1 || true
        log "INFO" "Firewalld rules applied."
        
    elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        log "INFO" "Configuring UFW with IPSet..."
        
        # 1. Create IPSet (UFW uses iptables underneath)
        ipset create "$SET_NAME" hash:net maxelem 200000 -exist
        sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!

        # 2. Inject Rule into /etc/ufw/before.rules
        UFW_RULES="/etc/ufw/before.rules"
        
        # Remove old rules if present to avoid duplicates
        sed -i "/$SET_NAME/d" "$UFW_RULES"

        # Insert new rules after "# End required lines" marker
        if grep -q "# End required lines" "$UFW_RULES"; then
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j DROP" "$UFW_RULES"
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix '[SysWarden-BLOCK] '" "$UFW_RULES"
        else
            log "WARN" "Standard UFW marker not found. Appending to end of file."
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix '[SysWarden-BLOCK] '" >> "$UFW_RULES"
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j DROP" >> "$UFW_RULES"
        fi

        # --- GEOIP INJECTION ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            log "INFO" "Configuring UFW GeoIP Set..."
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 500000 -exist
            sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
            
            sed -i "/$GEOIP_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix '[SysWarden-GEO] '" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix '[SysWarden-GEO] '" >> "$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" >> "$UFW_RULES"
            fi
        fi

        # --- ASN INJECTION ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            log "INFO" "Configuring UFW ASN Set..."
            ipset create "$ASN_SET_NAME" hash:net maxelem 500000 -exist
            sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!
            
            sed -i "/$ASN_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix '[SysWarden-ASN] '" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix '[SysWarden-ASN] '" >> "$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" >> "$UFW_RULES"
            fi
        fi

        # --- ZTNA / SPA INJECTION ---
            if [[ "${USE_SPA:-n}" == "y" ]]; then
                while iptables -D INPUT -p tcp --dport "$SSH_PORT" -j DROP 2>/dev/null; do :; done
                while iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
                
                iptables -I INPUT 1 -p tcp --dport "$SSH_PORT" -j DROP
                iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                
                # CRITICAL: Restart fwknopd to ensure it hooks above this drop rule
                if command -v systemctl >/dev/null; then
                    systemctl restart fwknop-server 2>/dev/null || systemctl restart fwknopd 2>/dev/null || true
                fi
            fi

        ufw reload
        log "INFO" "UFW rules applied."

    else
        # Fallback IPSET / IPTABLES
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
			
			# --- ZTNA / SPA INJECTION ---
            if [[ "${USE_SPA:-n}" == "y" ]]; then
                if ! iptables -C INPUT -p tcp --dport "$SSH_PORT" -j DROP 2>/dev/null; then
                    iptables -A INPUT -p tcp --dport "$SSH_PORT" -j DROP
                fi
            fi
            
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi

        # --- ASN INJECTION (Priority 2) ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "${ASN_SET_NAME}_tmp" hash:net maxelem 500000 -exist
            sed "s/^/add ${ASN_SET_NAME}_tmp /" "$ASN_FILE" | ipset restore -!
            ipset create "$ASN_SET_NAME" hash:net maxelem 500000 -exist
            ipset swap "${ASN_SET_NAME}_tmp" "$ASN_SET_NAME"
            ipset destroy "${ASN_SET_NAME}_tmp"
            
            if ! iptables -C INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Pushed down by GeoIP later if exists)
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
        fi

        # --- GEOIP INJECTION (Priority 1) ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "${GEOIP_SET_NAME}_tmp" hash:net maxelem 500000 -exist
            # The -! flag is crucial to prevent ipset from crashing if two countries share the same CIDR
            sed "s/^/add ${GEOIP_SET_NAME}_tmp /" "$GEOIP_FILE" | ipset restore -!
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 500000 -exist
            ipset swap "${GEOIP_SET_NAME}_tmp" "$GEOIP_SET_NAME"
            ipset destroy "${GEOIP_SET_NAME}_tmp"
            
            if ! iptables -C INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Top priority, enforced before ASN and standard list)
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
        fi
        
        # Save IPtables persistence for legacy OS
        if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
    fi
    
    # --- DOCKER HERMETIC FIREWALL BLOCK ---
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        log "INFO" "Applying Global Rules to Docker (DOCKER-USER chain)..."
        
        # 1. Standard Blocklist
        if ! ipset list "$SET_NAME" >/dev/null 2>&1; then
             ipset create "$SET_NAME" hash:net maxelem 200000 -exist
             sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!
        fi

        # 2. Geo-Blocking Set
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            if ! ipset list "$GEOIP_SET_NAME" >/dev/null 2>&1; then
                 ipset create "$GEOIP_SET_NAME" hash:net maxelem 500000 -exist
                 sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
            fi
        fi

        # 3. ASN-Blocking Set
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            if ! ipset list "$ASN_SET_NAME" >/dev/null 2>&1; then
                 ipset create "$ASN_SET_NAME" hash:net maxelem 500000 -exist
                 sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!
            fi
        fi

        if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            # Clean old rules
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null || true
            
            # Apply Standard Blocklist (Priority 3)
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] "

            # Apply ASN-Blocklist (Priority 2)
            if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi

            # Apply Geo-Blocklist (Priority 1)
            if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I DOCKER-USER 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
            
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save 2>/dev/null || true; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save 2>/dev/null || true; fi
            log "INFO" "Docker firewall rules applied successfully."
        else
            log "WARN" "DOCKER-USER chain not found. Docker might not be running yet."
        fi
    fi
	
    # --- UNIVERSAL IPSET PERSISTENCE (UFW / IPTABLES / DOCKER) ---
    if command -v ipset >/dev/null && [[ "$FIREWALL_BACKEND" != "firewalld" ]]; then
        log "INFO" "Configuring universal IPSet persistence for boot survival..."
        mkdir -p /etc/syswarden
        ipset save > /etc/syswarden/ipsets.save 2>/dev/null || true

        cat <<'EOF' > /etc/systemd/system/syswarden-ipset.service
[Unit]
Description=SysWarden IPSet Restorer
DefaultDependencies=no
Before=network-pre.target ufw.service netfilter-persistent.service docker.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c "if [ -s /etc/syswarden/ipsets.save ]; then /sbin/ipset restore -! < /etc/syswarden/ipsets.save; fi"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        if command -v systemctl >/dev/null; then
            systemctl daemon-reload
            systemctl enable syswarden-ipset.service 2>/dev/null || true
        fi
    fi
}

configure_fail2ban() {
    # [UNIVERSAL MODE] Configures services ONLY if they exist to prevent crashes
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."
		
		# --- Add backup Fai2ban jail ---
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi
        # -------------------------------------------------------

        # 1. Syslog requirement
        cat <<EOF > /etc/fail2ban/fail2ban.local
[Definition]
logtarget = SYSLOG
EOF

        # 2. Backup
        if [[ -f /etc/fail2ban/jail.local ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 3. HEADER & SSH (Always Active)
        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then f2b_action="firewallcmd-ipset";
        elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then f2b_action="nftables-multiport";
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then f2b_action="ufw"; fi

        cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = systemd
# Default Action dynamically set based on OS backend
banaction = $f2b_action

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = $SSH_PORT
logpath = %(sshd_log)s
backend = systemd
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
            # Create Filter for 404/403 scanners
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

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
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
            APACHE_LOG="/var/log/apache2/error.log" # Debian/Ubuntu
            APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/error_log" ]]; then
            APACHE_LOG="/var/log/httpd/error_log"   # RHEL/CentOS
            APACHE_ACCESS="/var/log/httpd/access_log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."
            
            # Create Filter for 404/403 scanners (Apache specific)
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

[apache-badbots]
enabled = true
port = http,https
logpath = $APACHE_ACCESS
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

            # Create strict Filter for Auth failures & Unauthorized commands (Injection probing)
            # Catches: "Authentication failed", "SASL authentication failed", "unauthorized", "not authorized"
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
        if [[ -f "/var/log/mysql/error.log" ]]; then
            MARIADB_LOG="/var/log/mysql/error.log" # Debian/Ubuntu default
        elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then
            MARIADB_LOG="/var/log/mariadb/mariadb.log" # RHEL/Alma default
        fi

        if [[ -n "$MARIADB_LOG" ]]; then
            log "INFO" "MariaDB logs detected. Enabling MariaDB Jail."

            # Create Filter for Authentication Failures (Access Denied brute-force)
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
        if [[ -f "/var/log/mail.log" ]]; then
            POSTFIX_LOG="/var/log/mail.log" # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then
            POSTFIX_LOG="/var/log/maillog" # RHEL/Alma
        fi

        if [[ -n "$POSTFIX_LOG" ]]; then
            log "INFO" "Postfix logs detected. Enabling SMTP Jails."

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
		
		# 10. DYNAMIC DETECTION: WORDPRESS (WP-LOGIN)
        # Reuses web logs detected in steps 4 & 5
        WP_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then WP_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."

            # Create specific filter for WP Login & XMLRPC
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
        # Check common paths for Nextcloud log file
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then NC_LOG="$path"; break; fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."

            # Create Filter (Supports both JSON and Legacy text logs)
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
		
		# 12. DYNAMIC DETECTION: ASTERISK (VOIP)
        ASTERISK_LOG=""
        if [[ -f "/var/log/asterisk/messages" ]]; then
            ASTERISK_LOG="/var/log/asterisk/messages"
        elif [[ -f "/var/log/asterisk/full" ]]; then
            ASTERISK_LOG="/var/log/asterisk/full"
        fi

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
            log "INFO" "Zabbix Server logs detected. Enabling Zabbix Jail."

            # Create Filter for Zabbix Server Login Failures
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

            # Create Filter for HTTP Errors (403 Forbidden, 404 Scan, 429 RateLimit)
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
            if [[ -f "/var/log/kern.log" ]]; then WG_LOG="/var/log/kern.log"; # Debian/Ubuntu
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi # RHEL

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."

                # Create Filter for Handshake Failures (Requires Kernel Logging)
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
        # Reuses web logs detected in steps 4 & 5
        PMA_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then PMA_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        # Check if phpMyAdmin is installed (common paths)
        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/etc/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."

                # Create Filter for POST requests to PMA (Bruteforce usually returns 200 OK)
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
        # Check standard Laravel log paths
        for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
            if [[ -f "$path" ]]; then LARAVEL_LOG="$path"; break; fi
        done

        # Fallback: search in /var/www (max depth 4)
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."

            # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
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

            # Create Filter for Grafana Auth Failures
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
        if [[ -f "/var/log/mail.log" ]]; then SM_LOG="/var/log/mail.log"; # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then SM_LOG="/var/log/maillog"; fi # RHEL/Alma

        # Check if Sendmail is installed to avoid conflict with Postfix
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

            # Create Filter for Proxy Abuse (TCP_DENIED / 403 / 407)
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
            
            # Create a custom action that routes bans directly to the DOCKER-USER chain
            # This allows users to protect containers without breaking host SSH routing.
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
            # Note: The user can now append 'banaction = syswarden-docker' to any custom 
            # Docker container jail in their jail.local to protect exposed container ports.
        fi
		
		# 21. DYNAMIC DETECTION: DOVECOT (IMAP/POP3)
        DOVECOT_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then DOVECOT_LOG="/var/log/mail.log";
        elif [[ -f "/var/log/maillog" ]]; then DOVECOT_LOG="/var/log/maillog"; fi

        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."

            # Filter for Dovecot Auth Failures (catches standard rip=IP format)
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
            
            PVE_LOG="/var/log/daemon.log"
            if [[ ! -f "$PVE_LOG" ]]; then PVE_LOG="/var/log/syslog"; fi

            # Filter for Proxmox Web GUI Auth Failures
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
        elif [[ -f "/var/log/syslog" ]]; then OVPN_LOG="/var/log/syslog"; fi

        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."

            # Filter for OpenVPN TLS Handshake & Verification Errors
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

            # Filter for Git Web UI Auth Failures
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
		
		# 25. DYNAMIC DETECTION: COCKPIT (WEB CONSOLE)
        if systemctl is-active --quiet cockpit.socket 2>/dev/null || [[ -d "/etc/cockpit" ]]; then
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
logpath = /var/log/secure
backend = systemd
maxretry = 3
bantime  = 24h
EOF
        fi
		
		# 26. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth.log" ]]; then AUTH_LOG="/var/log/auth.log"; # Debian/Ubuntu
        elif [[ -f "/var/log/secure" ]]; then AUTH_LOG="/var/log/secure"; fi # RHEL/Alma

        if [[ -n "$AUTH_LOG" ]]; then
            log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."

            # Create Filter for PAM, su, and sudo failures where rhost (Remote Host) is logged
            # This detects internal lateral movement and brute-force attempts on PAM-aware services
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
port    = all
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi
		
		# 27. DYNAMIC DETECTION: CI/CD & DEVOPS INFRASTRUCTURE (JENKINS / GITLAB)
        
        # --- JENKINS ---
        if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
            log "INFO" "Jenkins CI/CD logs detected. Enabling Jenkins Guard."

            # Create Filter for Jenkins Authentication Failures
            # Catches standard Jenkins login failures and invalid API token attempts
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

        # --- GITLAB ---
        GITLAB_LOG=""
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi

        if [[ -n "$GITLAB_LOG" ]]; then
            log "INFO" "GitLab logs detected. Enabling GitLab Guard."

            # Create Filter for GitLab Authentication Failures
            # Catches web UI login failures and API authentication errors
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
        
        # --- REDIS ---
        REDIS_LOG=""
        if [[ -f "/var/log/redis/redis-server.log" ]]; then REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi

        if [[ -n "$REDIS_LOG" ]]; then
            log "INFO" "Redis logs detected. Enabling Redis Guard."

            # Create Filter for Redis Authentication Failures
            # Covers both legacy 'requirepass' failures and modern Redis 6.0+ ACL failures
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

        # --- RABBITMQ ---
        RABBIT_LOG=""
        # RabbitMQ appends the node name to the log file (e.g., rabbit@hostname.log)
        if ls /var/log/rabbitmq/rabbit@*.log 1> /dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then 
            RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
        fi

        if [[ -n "$RABBIT_LOG" ]]; then
            log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."

            # Create Filter for RabbitMQ Authentication Failures
            # Catches AMQP protocol brute-force and HTTP Management API login failures
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
		
		# 29. DYNAMIC DETECTION: PORT SCANNERS & LATERAL MOVEMENT (NMAP / MASSCAN)
        
        FIREWALL_LOG=""
        # Determine the correct kernel logging path based on the OS
        if [[ -f "/var/log/kern.log" ]]; then FIREWALL_LOG="/var/log/kern.log"; # Debian/Ubuntu
        elif [[ -f "/var/log/messages" ]]; then FIREWALL_LOG="/var/log/messages"; # RHEL/Alma
        elif [[ -f "/var/log/syslog" ]]; then FIREWALL_LOG="/var/log/syslog"; fi # Legacy fallback

        if [[ -n "$FIREWALL_LOG" ]]; then
            log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."

            # Create Filter for SysWarden Firewall Drops
            # Parses the kernel logs to extract the Source IP (SRC) of the scanner
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
port     = all
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

            # Create Filter for Auditd anomalies (Unauthorized access, failed auth, bad commands)
            # Looks for kernel-level audit records containing a remote address (addr=IP) 
            # and a failure result (res=failed or res=0), or binary crash anomalies.
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
port     = all
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi
		
		# 31. DYNAMIC DETECTION: RCE & REVERSE SHELL PAYLOADS
        RCE_LOGS=""
        # Dynamically aggregate all available web access logs (Nginx, Apache Debian, Apache RHEL)
        for log_file in "/var/log/nginx/access.log" "/var/log/apache2/access.log" "/var/log/httpd/access_log"; do
            if [[ -f "$log_file" ]]; then
                # Space-separated list of log files for Fail2ban
                RCE_LOGS="$RCE_LOGS $log_file"
            fi
        done
        
        # Trim leading/trailing whitespace safely
        RCE_LOGS=$(echo "$RCE_LOGS" | xargs)

        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."

            # Create Filter for Remote Code Execution and Reverse Shell signatures
            # Catches common payloads: bash interactive, netcat, wget/curl drops, and python/php one-liners
            # Includes URL-encoded equivalents (%2F = /, %20 = space) to catch obfuscated attacks
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
                cat <<'EOF' > /etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
failregex = ^<HOST> .* "(?:GET|POST|HEAD|PUT) .*(?:/bin/bash|%2Fbin%2Fbash|/bin/sh|%2Fbin%2Fsh|nc\s+-e|nc%20-e|nc\s+-c|curl\s+http|curl%20http|wget\s+http|wget%20http|python\s+-c|php\s+-r|;\s*bash\s+-i|&\s*bash\s+-i).*" .*$
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
# Zero-Tolerance policy for RCE payloads
maxretry = 1
bantime  = 24h
EOF
        fi

        log "INFO" "Starting Fail2ban service..."
        if command -v systemctl >/dev/null; then
            systemctl enable --now fail2ban >/dev/null 2>&1 || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
        fi
    fi 
}

setup_abuse_reporting() {
    echo -e "\n${BLUE}=== Step 7: AbuseIPDB Reporting Setup ===${NC}"
    
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
        
        # Sanitize: Allow only alphanumeric characters, dashes, and underscores
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

        log "INFO" "Configuring Unified SysWarden Reporter..."
        
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

# --- CONFIGURATION ---
API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900  # 15 minutes
ENABLE_F2B = PLACEHOLDER_F2B
ENABLE_FW = PLACEHOLDER_FW
CACHE_FILE = "/var/lib/syswarden/abuse_cache.json"

# --- DEFINITIONS ---
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
            print(f"[SKIP] IP {ip} already reported to AbuseIPDB recently (HTTP 429).", flush=True)
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
    print("🚀 Monitoring logs (Unified SysWarden Reporter)...", flush=True)
    load_cache() # Load JSON cache on startup
    
    # Secure journalctl to force raw output
    f = subprocess.Popen(['journalctl', '-f', '-n', '0', '-o', 'cat'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
                    
                    cats = ["14"]
                    attack_type = "Port Scan"

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
                    continue

            # --- FAIL2BAN LOGIC ---
            if ENABLE_F2B:
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

        log "INFO" "Creating systemd service for Reporter..."
        cat <<EOF > /etc/systemd/system/syswarden-reporter.service
[Unit]
Description=SysWarden Unified Reporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syswarden_reporter.py
Restart=always

# --- SECURITY & LEAST PRIVILEGE ---
DynamicUser=yes
SupplementaryGroups=systemd-journal adm
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# Ensure script can write its cache file securely via DynamicUser
StateDirectory=syswarden
# ----------------------------------

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now syswarden-reporter
        log "INFO" "AbuseIPDB Unified Reporter is ACTIVE."
        
    else
        log "INFO" "Skipping AbuseIPDB reporting setup."
    fi
}

detect_protected_services() {
    echo -e "\n${BLUE}=== Step 5: Service Integration Check ===${NC}"
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list://g')
        log "INFO" "Fail2ban is ACTIVE. Jails: ${JAILS}"
    else
        log "WARN" "Fail2ban not active."
    fi
}

setup_ztna_spa() {
    if [[ "${USE_SPA:-n}" != "y" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring ZTNA / fwknop ===${NC}"
    log "INFO" "Generating SPA cryptographic keys..."

    # Generate secure Base64 keys
    local KEY_BASE64; KEY_BASE64=$(head -c 32 /dev/urandom | base64 -w 0)
    local HMAC_BASE64; HMAC_BASE64=$(head -c 64 /dev/urandom | base64 -w 0)
    
    # Auto-detect the primary network interface facing the internet
    local ACTIVE_IF; ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n 1)
    if [[ -z "$ACTIVE_IF" ]]; then
        ACTIVE_IF="eth0"
        log "WARN" "Could not auto-detect interface. Defaulting to $ACTIVE_IF"
    fi

    # Write fwknop access configuration
    mkdir -p /etc/fwknop
    cat <<EOF > /etc/fwknop/access.conf
SOURCE ANY
KEY_BASE64 $KEY_BASE64
HMAC_KEY_BASE64 $HMAC_BASE64
FW_ACCESS_TIMEOUT 30
EOF

    # Write fwknop server configuration (fwknopd auto-detects iptables)
    cat <<EOF > /etc/fwknop/fwknopd.conf
PCAP_INTF                   $ACTIVE_IF;
EOF
    chmod 600 /etc/fwknop/access.conf /etc/fwknop/fwknopd.conf

    # Enable and restart service (Handles both Debian and RHEL service names)
    if command -v systemctl >/dev/null; then
        systemctl enable fwknop-server 2>/dev/null || systemctl enable fwknopd 2>/dev/null || true
        systemctl restart fwknop-server 2>/dev/null || systemctl restart fwknopd 2>/dev/null || true
    fi

    log "INFO" "SPA configured successfully on interface $ACTIVE_IF."

    # Extract Public IP for the client command
    local SERVER_IP; SERVER_IP=$(curl -4 -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")

    echo -e "\n${RED}!!! CRITICAL: SAVE THESE INSTRUCTIONS NOW !!!${NC}"
    echo -e "Your SSH port ($SSH_PORT) is now INVISIBLE. To connect, you must run this on your client machine:\n"
    echo -e "${YELLOW}fwknop -n $(hostname) -A tcp/$SSH_PORT -a \$(curl -s ifconfig.me) --key-base64-hmac $HMAC_BASE64 --use-hmac --key-base64 $KEY_BASE64 -D $SERVER_IP${NC}\n"
    echo -e "${RED}!!! DO NOT LOSE THIS COMMAND. THE SCREEN WILL CONTINUE IN 10 SECONDS !!!${NC}"
    
    sleep 10
}

setup_ebpf_hids() {
    if [[ "${USE_EBPF:-n}" != "y" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring L7 eBPF Agent ===${NC}"
    log "INFO" "Generating SysWarden eBPF Python Agent..."

    # Create the eBPF Python Daemon (Using single quotes for cat to protect python syntax)
    cat <<'EOF' > /usr/local/bin/syswarden_ebpf.py
#!/usr/bin/python3
from bcc import BPF
import time
import subprocess
import sys
import os
import ctypes
import signal
import syslog

# --- eBPF C KERNEL PROGRAM ---
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char fname[128];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // KERNEL FILTER: Only trace web servers & PHP to save CPU cycles
    if (data.comm[0] != 'n' && data.comm[0] != 'a' && data.comm[0] != 'h' && data.comm[0] != 'p')
        return 0;

    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), filename);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

/* --- RING 0 SELF-DEFENSE MODULE --- */
    
    // Array to store the PID of our own Python daemon
    BPF_ARRAY(protected_pid_map, u32, 1);
    
    // Hook the 'kill' system call entry point natively
    TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
        u32 key = 0;
        u32 *my_pid_ptr = protected_pid_map.lookup(&key);
        
        // 1. If defense is not armed (map is empty or zeroed), let the syscall pass
        if (!my_pid_ptr || *my_pid_ptr == 0) return 0;
        
        // 2. Is the signal targeting our daemon's PID?
        if (args->pid == *my_pid_ptr) {
            
            // 3. SECURE BYPASS: Allow systemd (PID 1) to manage the service.
            // This is CRITICAL to prevent Kernel Panic during server reboots.
            u64 pid_tgid = bpf_get_current_pid_tgid();
            u32 sender_pid = pid_tgid >> 32;
            if (sender_pid == 1) return 0;
            
            // 4. MAGIC DISARM SIGNAL: Signal 62 acts as the kill-switch.
            // If the admin sends 'kill -62 <pid>', we disarm the shield globally.
            if (args->sig == 62) {
                u32 disarm = 0;
                protected_pid_map.update(&key, &disarm);
                bpf_trace_printk("[SysWarden] Shield DISARMED via Magic Signal (62).\\n");
                return 0; // Allow the magic signal to pass without killing the sender
            }
            
            // 5. PREEMPTIVE STRIKE: For any other signal (9, 15) from a non-systemd process.
            bpf_send_signal(9);
            bpf_trace_printk("[SysWarden] Unauthorized kill attempt blocked. Attacker destroyed.\\n");
        }
        return 0;
    }
"""

try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile eBPF code: {e}")
    sys.exit(1)

# --- ARM THE SELF-DEFENSE MODULE ---
# Inject the daemon's current PID into the eBPF kernel map
try:
    current_pid = os.getpid()
    b["protected_pid_map"][0] = ctypes.c_uint32(current_pid)
    print(f"[+] eBPF Self-Defense armed for PID: {current_pid}")
except Exception as e:
    print(f"[-] Warning: Failed to arm self-defense module: {e}")
# -----------------------------------	
	
# --- USERSPACE LOGIC ---
WEB_SERVERS = [b"nginx", b"apache2", b"httpd", b"php-fpm", b"php-cgi"]
# Zero-Trust payloads for a web server process
FORBIDDEN_BINS = [b"sh", b"bash", b"dash", b"nc", b"ncat", b"wget", b"curl", b"socat", b"python", b"python3", b"perl"]

def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.comm in WEB_SERVERS:
        fname = event.fname.split(b'/')[-1]
        
        if fname in FORBIDDEN_BINS:
            # 1. KILL INSTANTLY (SIGKILL)
            try:
                os.kill(event.pid, signal.SIGKILL)
                action = "BLOCKED (SIGKILL)"
            except ProcessLookupError:
                action = "DETECTED (Already exited)"
            
            # 2. LOG TO SYSTEM
            msg = f"[SysWarden-eBPF] {action} | L7 RCE Attempt: '{event.comm.decode()}' executed '{event.fname.decode()}' (UID: {event.uid}, PID: {event.pid})"
            syslog.syslog(syslog.LOG_WARNING, msg)
            
            # 3. LOG TO DASHBOARD
            with open("/var/log/syswarden-ebpf.log", "a") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")

b["events"].open_perf_buffer(print_event)
syslog.syslog(syslog.LOG_INFO, "SysWarden eBPF L7 Process Monitoring Started.")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
EOF
    chmod +x /usr/local/bin/syswarden_ebpf.py
    touch /var/log/syswarden-ebpf.log

    # Create Systemd Service
    cat <<EOF > /etc/systemd/system/syswarden-ebpf.service
[Unit]
Description=SysWarden L7 eBPF Process Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syswarden_ebpf.py
Restart=always
# Needs root for eBPF bpf() syscalls
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now syswarden-ebpf 2>/dev/null || true
    log "INFO" "eBPF L7 Service deployed and started."
}

setup_siem_logging() {
    echo -e "\n${BLUE}=== Step 6: SIEM Logging Status ===${NC}"
    log "INFO" "Logs are ready in journalctl and /var/log/."
}

setup_cron_autoupdate() {
    if [[ "${1:-}" != "update" ]]; then
        local script_path; script_path=$(realpath "$0")
        local cron_file="/etc/cron.d/syswarden-update"
        local random_min=$((RANDOM % 60))
        echo "$random_min * * * * root $script_path update >/dev/null 2>&1" > "$cron_file"
        chmod 644 "$cron_file"
        log "INFO" "Automatic updates enabled."

        cat <<EOF > /etc/logrotate.d/syswarden
/var/log/kern.log
/var/log/syslog
/var/log/messages
$LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
    fi
}

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation..."

    # Load config to retrieve variables (Wazuh IP, etc.)
    if [[ -f "$CONF_FILE" ]]; then 
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # 1. Stop & Remove Reporter & eBPF Services
    log "INFO" "Removing SysWarden Services (Reporter, eBPF)..."
    
    # Reporter
    systemctl disable --now syswarden-reporter 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-reporter.service /usr/local/bin/syswarden_reporter.py
    
    # eBPF HIDS
    # --- DISARM RING 0 DEFENSE BEFORE UNINSTALL ---
    local EBPF_PID
    EBPF_PID=$(systemctl show -p MainPID syswarden-ebpf 2>/dev/null | cut -d= -f2)
    
    if [[ -n "$EBPF_PID" && "$EBPF_PID" -gt 0 ]]; then
        log "INFO" "Transmitting Magic Signal (62) to disarm eBPF Ring 0 defense..."
        # We send signal 62. The kernel clears the BPF map, dropping the shield.
        kill -62 "$EBPF_PID" 2>/dev/null || true
        sleep 1
    fi
    # ----------------------------------------------

    log "INFO" "Stopping and disabling SysWarden eBPF service..."
    systemctl stop syswarden-ebpf 2>/dev/null || true
    systemctl disable syswarden-ebpf 2>/dev/null || true
    
    rm -f /etc/systemd/system/syswarden-ebpf.service /usr/local/bin/syswarden_ebpf.py
    rm -f /var/log/syswarden-ebpf.log
	
	# ZTNA / SPA (fwknop)
    if [[ "${USE_SPA:-n}" == "y" ]]; then
        log "INFO" "Stopping ZTNA/SPA service..."
        systemctl disable --now fwknop-server 2>/dev/null || true
        systemctl disable --now fwknopd 2>/dev/null || true
        rm -rf /etc/fwknop
    fi
    
    systemctl daemon-reload
	
	log "INFO" "Removing IPSet Restorer Service..."
    systemctl disable syswarden-ipset 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-ipset.service /etc/syswarden/ipsets.save
    systemctl daemon-reload

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    rm -f "/etc/cron.d/syswarden-update"
    rm -f "/etc/logrotate.d/syswarden"

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."
    
    # Nftables
    if command -v nft >/dev/null; then 
        nft delete table inet syswarden_table 2>/dev/null || true
    fi
    
    # UFW
    if [[ -f "/etc/ufw/before.rules" ]]; then
        sed -i "/$SET_NAME/d" /etc/ufw/before.rules
        sed -i "/$GEOIP_SET_NAME/d" /etc/ufw/before.rules
        sed -i "/$ASN_SET_NAME/d" /etc/ufw/before.rules
        
        # Restore SSH if SPA was used
        if [[ "${USE_SPA:-n}" == "y" ]]; then
            ufw delete deny "${SSH_PORT:-22}/tcp" 2>/dev/null || true
        fi
        
        if command -v ufw >/dev/null; then ufw reload; fi
    fi
    
    # Firewalld
    if command -v firewall-cmd >/dev/null; then
        # Remove Blocklist Rules
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$ASN_SET_NAME" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$GEOIP_SET_NAME" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$SET_NAME" 2>/dev/null || true
        
        # Remove Wazuh Whitelist Rules (if they exist)
        if [[ -n "${WAZUH_IP:-}" ]]; then
             firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1514' protocol='tcp' accept" 2>/dev/null || true
             firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1515' protocol='tcp' accept" 2>/dev/null || true
        fi
        
        # Restore SSH if SPA was used
        if [[ "${USE_SPA:-n}" == "y" ]]; then
            log "INFO" "Restoring SSH port in Firewalld..."
            firewall-cmd --permanent --add-port="${SSH_PORT:-22}/tcp" 2>/dev/null || true
        fi
        
        firewall-cmd --reload 2>/dev/null || true
    fi
    
    # Docker (DOCKER-USER chain)
    if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null || true
        
        if command -v netfilter-persistent >/dev/null; then netfilter-persistent save 2>/dev/null || true; 
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save 2>/dev/null || true; fi
    fi
    
    # IPSet / Iptables (Legacy)
    if command -v ipset >/dev/null; then 
        ipset destroy "$SET_NAME" 2>/dev/null || true
        ipset destroy "$GEOIP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_SET_NAME" 2>/dev/null || true
    fi
    
    # Restore SSH if SPA was used under raw Iptables
    if [[ "${USE_SPA:-n}" == "y" ]] && command -v iptables >/dev/null; then
        iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null || true
        if command -v netfilter-persistent >/dev/null; then netfilter-persistent save 2>/dev/null || true; 
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save 2>/dev/null || true; fi
    fi

    # 4. Revert Fail2ban Configuration
    if [[ -f /etc/fail2ban/jail.local.bak ]]; then
        log "INFO" "Restoring original Fail2ban configuration..."
        mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
        systemctl restart fail2ban
    elif [[ -f /etc/fail2ban/jail.local ]]; then
        # If no backup exists, jail.local didn't exist before (Clean install).
        # We delete it to revert to the default OS state.
        log "INFO" "No backup found (was a clean install). Removing SysWarden jail.local..."
        rm /etc/fail2ban/jail.local
        systemctl restart fail2ban
    else
        log "WARN" "No Fail2ban configuration found to revert."
    fi
    
    # Remove custom Docker banaction
    rm -f /etc/fail2ban/action.d/syswarden-docker.conf

    # 5. Remove Wazuh Agent (Optional but cleaner)
    if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q wazuh-agent; then
        read -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            systemctl disable --now wazuh-agent 2>/dev/null || true
            
            if [[ -f /etc/debian_version ]]; then
                apt-get remove --purge -y wazuh-agent
                rm -f /etc/apt/sources.list.d/wazuh.list
                rm -f /usr/share/keyrings/wazuh.gpg
                apt-get update -qq
            elif [[ -f /etc/redhat-release ]]; then
                dnf remove -y wazuh-agent
                rm -f /etc/yum.repos.d/wazuh.repo
            fi
            log "INFO" "Wazuh Agent removed."
        else
            log "INFO" "Keeping Wazuh Agent installed."
        fi
    fi

    # 6. Remove Config File
    rm -f "$CONF_FILE"
    
    # 7. Remove All logs
    rm -f "$LOG_FILE"
    
    log "INFO" "Cleanup complete. Logs at $LOG_FILE are kept for reference."
    echo -e "${GREEN}Uninstallation complete.${NC}"
    exit 0
}

setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (Custom) ===${NC}"
    
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_WAZUH:-n}
        log "INFO" "Auto Mode: Wazuh Agent choice loaded via env var [${response}]"
    else
        # 1. Ask for confirmation
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
        W_NAME=${SYSWARDEN_WAZUH_NAME:-$(hostname)}
        W_GROUP=${SYSWARDEN_WAZUH_GROUP:-default}
        W_PORT_COMM=${SYSWARDEN_WAZUH_COMM_PORT:-1514}
        W_PORT_ENROLL=${SYSWARDEN_WAZUH_ENROLL_PORT:-1515}
        log "INFO" "Auto Mode: Wazuh settings loaded via env vars."
    else
        # IP Serveur
        read -p "Enter Wazuh Manager IP: " WAZUH_IP
        if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing IP. Skipping."; return; fi

        # Hostname (Agent Name)
        read -p "Agent Name [Press Enter for '$(hostname)']: " W_NAME
        W_NAME=${W_NAME:-$(hostname)}

        # Group
        read -p "Agent Group [Press Enter for 'default']: " W_GROUP
        W_GROUP=${W_GROUP:-default}

        # Agent Port (Communication)
        read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
        W_PORT_COMM=${W_PORT_COMM:-1514}

        # Enrollment Port (Registration)
        read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
        W_PORT_ENROLL=${W_PORT_ENROLL:-1515}
    fi
    
    # Fail-Safe: Interdire l'installation si l'IP n'est pas fournie en mode auto
    if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing Wazuh IP. Skipping."; return; fi

    # Protocol (Default TCP)
    W_PROTO="TCP"

    # 3. Whitelist Wazuh Manager (Universal Firewall)
    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on ports $W_PORT_COMM & $W_PORT_ENROLL..."
    
    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
         # RHEL / Alma / Rocky
         # Rules for Custom Ports
         firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_COMM' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
         firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_ENROLL' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
         firewall-cmd --reload

    elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
         # Debian / Ubuntu (Modern)
         # We accept all traffic from Manager IP (Highest Priority) to ensure connectivity & Active Response
         nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
         log "INFO" "Nftables rule added for Wazuh Manager (Full Trust)."
		 
		 # ### PERSISTENCE FIX ###
         # Save current RAM ruleset to disk so it survives reboot
         log "INFO" "Saving Nftables ruleset to /etc/nftables.conf for persistence..."
         nft list ruleset > /etc/nftables.conf
         # Enable service just in case
         systemctl enable nftables >/dev/null 2>&1 || true

    else
         # Fallback Iptables / IPSet
         if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
             iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT
             
             if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
             elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
         fi
    fi

    log "INFO" "Starting Wazuh Agent installation..."

    # 4. OS-Specific Installation Logic with EXPORTS
    # These variables are automatically read by the Wazuh package installer
    export WAZUH_MANAGER="$WAZUH_IP"
    export WAZUH_AGENT_NAME="$W_NAME"
    export WAZUH_AGENT_GROUP="$W_GROUP"
    export WAZUH_MANAGER_PORT="$W_PORT_COMM"       # Custom Agent Port
    export WAZUH_REGISTRATION_PORT="$W_PORT_ENROLL" # Custom Enrollment Port
    export WAZUH_PROTOCOL="$W_PROTO"

    if [[ -f /etc/debian_version ]]; then
        # --- DEBIAN / UBUNTU ---
        log "INFO" "Detected Debian/Ubuntu system."
        apt-get install -y gnupg apt-transport-https
        
        if curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import; then
            chmod 644 /usr/share/keyrings/wazuh.gpg
        else
            log "ERROR" "Failed to import GPG key."
            return
        fi
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
        
        apt-get update -qq
        apt-get install -y wazuh-agent

    elif [[ -f /etc/redhat-release ]]; then
        # --- RHEL / ALMA / ROCKY ---
        log "INFO" "Detected RHEL/Alma/Rocky system."
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF
        dnf install -y wazuh-agent
    else
        log "ERROR" "Unsupported OS."
        return
    fi

    # 5. Enable and Persistence
    if systemctl list-unit-files | grep -q wazuh-agent; then
        systemctl daemon-reload
        systemctl enable --now wazuh-agent
        
        # Save config for uninstall reference
        echo "WAZUH_IP='$WAZUH_IP'" >> "$CONF_FILE"
        echo "WAZUH_AGENT_NAME='$W_NAME'" >> "$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >> "$CONF_FILE"
        echo "WAZUH_ENROLL_PORT='$W_PORT_ENROLL'" >> "$CONF_FILE"
        
        log "INFO" "Wazuh Agent '$W_NAME' installed (Group: $W_GROUP, Ports: $W_PORT_COMM/$W_PORT_ENROLL)."
    else
        log "ERROR" "Wazuh Agent installation seemed to fail."
    fi
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    # Simple IP validation
    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi
	
	# --- LOCAL PERSISTENCE ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    if ! grep -q "^${WL_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$WL_IP" >> "$WHITELIST_FILE"
    fi
    # -------------------------

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            # Insert Rule at position 1 (Pre-Filter)
            nft insert rule inet syswarden_table input ip saddr "$WL_IP" accept
            # Persistence
            nft list ruleset > /etc/nftables.conf
            log "INFO" "Rule added to Nftables and saved."
            ;;
        
        "firewalld")
            # Add Rich Rule with ACCEPT action
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WL_IP' accept"
            firewall-cmd --reload
            log "INFO" "Rule added to Firewalld."
            ;;
        
        "ufw")
            # 1. Add UFW Allow Rule (High priority on user chain)
            ufw insert 1 allow from "$WL_IP"
            # 2. Remove from Blacklist IPSet immediately (in case it was blocked there)
            ipset del "$SET_NAME" "$WL_IP" 2>/dev/null || true
            ufw reload
            log "INFO" "Rule added to UFW (and removed from current blocklist)."
            ;;
        
        *)
            # Fallback IPSet / Iptables
            iptables -I INPUT 1 -s "$WL_IP" -j ACCEPT
            # Persistence
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
            log "INFO" "Rule added to IPTables."
            ;;
    esac
}

blocklist_ip() {
    echo -e "\n${RED}=== SysWarden Manual Blocklist Manager ===${NC}"
    read -p "Enter IP to Block: " BL_IP

    # Validation simple de l'IP
    if [[ ! "$BL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi
	
	# --- LOCAL PERSISTENCE ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$BLOCKLIST_FILE"
    if ! grep -q "^${BL_IP}$" "$BLOCKLIST_FILE" 2>/dev/null; then
        echo "$BL_IP" >> "$BLOCKLIST_FILE"
    fi
    # -------------------------

    log "INFO" "Blocking IP: $BL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            # Insert Rule at position 1 (Immediate Drop)
            nft insert rule inet syswarden_table input ip saddr "$BL_IP" drop
            # Persistence
            nft list ruleset > /etc/nftables.conf
            log "INFO" "Drop rule added to Nftables and saved."
            ;;
        
        "firewalld")
            # Add Rich Rule with DROP action
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$BL_IP' drop"
            firewall-cmd --reload
            log "INFO" "Drop rule added to Firewalld."
            ;;
        
        "ufw")
            # Add UFW Deny Rule (High priority)
            ufw insert 1 deny from "$BL_IP"
            ufw reload
            log "INFO" "Deny rule added to UFW."
            ;;
        
        *)
            # Fallback IPSet / Iptables
            iptables -I INPUT 1 -s "$BL_IP" -j DROP
            # Persistence
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
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

    # Display active jails to help the user
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        local active_jails; active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
        echo -e "Currently active Jails: ${YELLOW}${active_jails}${NC}"
    fi

    read -p "Enter the exact name of your custom Docker Jail (e.g. 'nginx-docker'): " jail_name
    
    # Trim whitespace and sanitize: allow only alphanumeric, dashes, and underscores
    jail_name=$(echo "$jail_name" | xargs | tr -cd 'a-zA-Z0-9_-')

    if [[ -z "$jail_name" ]]; then
        log "ERROR" "Jail name cannot be empty."
        exit 1
    fi

    # Check if the jail block exists in the configuration file
    if ! grep -q "^\[${jail_name}\]" "$jail_file"; then
        log "ERROR" "Jail [${jail_name}] not found in $jail_file. Please create it first."
        exit 1
    fi

    log "INFO" "Configuring jail [${jail_name}] to use Docker banaction..."

    # Safely inject or update banaction exclusively within the specified jail block
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

        # If inside the target block, skip any pre-existing 'banaction' line to avoid duplicates
        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >> "$temp_file"
    done < "$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."
    
    if command -v systemctl >/dev/null; then
        systemctl restart fail2ban
        log "INFO" "Fail2ban service restarted to apply changes."
    fi
}

check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker ===${NC}"
    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response
    
    # Fetch API response quietly (Timeout 5s to avoid hanging)
    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    # Extract tag_name (e.g., "v3.00") using standard POSIX grep/cut (no external dependencies needed)
    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)
    
    if [[ -z "$latest_version" ]]; then
        log "ERROR" "Could not parse latest version from GitHub."
        exit 1
    fi

    # Extract download URL for the .sh script from the release assets
    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*\.sh"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new version ($latest_version) is available!${NC}"
        echo -e "To upgrade safely, please run the following commands:\n"
        
        # If the API returned a direct .sh link, provide the wget shortcut
        if [[ -n "$download_url" ]]; then
            echo -e "  wget -qO install-syswarden.sh \"$download_url\""
            echo -e "  chmod +x install-syswarden.sh"
            echo -e "  ./install-syswarden.sh\n"
        else
            # Fallback to the main releases page if no .sh asset is directly found
            echo -e "  Please download the new release manually from:"
            echo -e "  https://github.com/duggytuxy/syswarden/releases/latest\n"
        fi
        
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
        # HEADER: 6 Columns (DATE / HOUR aligned to max 19 characters)
        printf "${YELLOW}%-19s | %-10s | %-16s | %-20s | %-12s | %-8s${NC}\n" "DATE / HOUR" "SOURCE" "IP ADDRESS" "RULES" "PORT" "DECISION"
        echo "----------------------------------------------------------------------------------------------------"

        # Regex to cleanly extract the date: "Feb 14 10:05:10" OR "2026-02-14 10:05:10"
        local date_regex="^([A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+[0-9:]+|[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9:]+)"

        # 1. FAIL2BAN ENTRIES (Via Journalctl)
        if command -v journalctl >/dev/null; then
            journalctl -u fail2ban -n 100 --no-pager 2>/dev/null | { grep " Ban " || true; } | tail -n 10 | while read -r line; do
                if [[ $line =~ \[([a-zA-Z0-9_-]+)\][[:space:]]+Ban[[:space:]]+([0-9.]+) ]]; then
                    jail="${BASH_REMATCH[1]}"
                    ip="${BASH_REMATCH[2]}"
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Fail2ban" "$ip" "$jail" "Dynamic" "BAN"
                fi
            done
        elif [[ -f "/var/log/fail2ban.log" ]]; then
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

        # 2. FIREWALL ENTRIES (Via Journalctl)
        # Increased journalctl to -n 500 to ensure enough lines are found
        if command -v journalctl >/dev/null; then
            journalctl -k -n 500 --no-pager 2>/dev/null | { grep -E "SysWarden-(BLOCK|GEO|ASN)" || true; } | tail -n 20 | while read -r line; do
                if [[ $line =~ SRC=([0-9.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    rule="Unknown"
                    if [[ $line =~ (SysWarden-[A-Z]+) ]]; then rule="${BASH_REMATCH[1]}"; fi
                    port="Global"
                    if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
                fi
            done
        elif [[ -f "/var/log/kern.log" ]]; then
             { grep -E "SysWarden-(BLOCK|GEO|ASN)" "/var/log/kern.log" || true; } | tail -n 20 | while read -r line; do
                if [[ $line =~ SRC=([0-9.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    rule="Unknown"
                    if [[ $line =~ (SysWarden-[A-Z]+) ]]; then rule="${BASH_REMATCH[1]}"; fi
                    port="Global"
                    if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
                fi
             done
        fi
		
		# 3. eBPF L7 ENTRIES
        if [[ -f "/var/log/syswarden-ebpf.log" ]]; then
             tail -n 10 "/var/log/syswarden-ebpf.log" | while read -r line; do
                if [[ $line =~ ^([0-9-]+\ [0-9:]+).*L7\ RCE\ Attempt:\ \'([a-zA-Z0-9_-]+)\'.*\'([^\']+)\' ]]; then
                    dtime="${BASH_REMATCH[1]}"
                    parent="${BASH_REMATCH[2]}"
                    payload="${BASH_REMATCH[3]}"
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "eBPF L7" "Local Process" "RCE: $parent" "$payload" "KILL"
                fi
            done
        fi
        
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
# --- AUTOMATION / CI-CD SUPPORT ---
# Permet de capturer ./install.sh --auto et de le normaliser
if [[ "$MODE" == "--auto" ]]; then
    MODE="auto"
fi
# ----------------------------------

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
    # We don't strictly need root just to check the API, but consistency is kept
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
    echo -e "#     SysWarden Tool Installer (Universal v9.00)     #"
    echo -e "#############################################################${NC}"
fi

check_root
detect_os_backend

# --- SECURITY: ENFORCE STRICT PERMISSIONS ---
touch "$CONF_FILE" "$LOG_FILE" 2>/dev/null || true
chmod 600 "$CONF_FILE" 2>/dev/null || true
chmod 640 "$LOG_FILE" 2>/dev/null || true
# ------------------------------------------

if [[ "$MODE" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
fi

if [[ "$MODE" != "update" ]]; then
    : > "$CONF_FILE"
    install_dependencies
    
    # --- CRITICAL ARCHITECTURE FIX ---
    # Re-detect backend! DNF might have just installed Firewalld or Nftables (via fail2ban)
    detect_os_backend
    # ---------------------------------
    
    define_ssh_port "$MODE"
	define_ztna_spa "$MODE"
	define_ebpf_hids "$MODE"
    define_docker_integration "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
    configure_fail2ban
fi

select_list_type "$MODE"
select_mirror "$MODE"
download_list
download_geoip
download_asn
apply_firewall_rules
detect_protected_services

if command -v systemctl >/dev/null && systemctl is-active --quiet syswarden-reporter; then
    systemctl restart syswarden-reporter
fi

if [[ "$MODE" != "update" ]]; then
    setup_ztna_spa "$MODE"
	setup_ebpf_hids "$MODE"
	setup_siem_logging
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"
    
    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> List loaded: $LIST_TYPE"
    
    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Universal (Interactive)"
    fi
    
    echo -e " -> Protection: Active"
fi