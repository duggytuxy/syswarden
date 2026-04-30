#!/bin/bash

# SysWarden - An ultra-lightweight Host-based Security Orchestrator for Linux.
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
NC='\033[0m' # No Color

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"

# --- SECURITY FIX: SECURE TMP DIR (CWE-377: Insecure Temporary File) ---
# Ensure absolute privacy for the temporary directory to prevent unauthorized access
TMP_DIR=$(mktemp -d -t syswarden-install-XXXXXX)
chmod 0700 "$TMP_DIR"
# ------------------------------------

VERSION="v0.27.4"
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

    # --- HOTFIX: PREVENT BACKEND AMNESIA ---
    if [[ -f "$CONF_FILE" ]] && grep -q "FIREWALL_BACKEND=" "$CONF_FILE"; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Loaded saved Firewall Backend: $FIREWALL_BACKEND"
        return
    fi
    # ---------------------------------------

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

    # Save detection for future cron jobs
    echo "FIREWALL_BACKEND='$FIREWALL_BACKEND'" >>"$CONF_FILE"
}

install_dependencies() {
    log "INFO" "Checking dependencies..."
    local missing_common=()

    # ==============================================================================
    # --- HOTFIX: STATE TRACKER (Avoid God Mode Uninstall) ---
    # Record pre-existing critical services so we don't purge them on uninstall.
    # MUST BE EXECUTED BEFORE ANY APT/DNF COMMANDS!
    # ==============================================================================
    if [[ ! -f "$CONF_FILE" ]]; then
        touch "$CONF_FILE"
        chmod 600 "$CONF_FILE"
    fi
    # Detect if ANY web server is already present to prevent uninstall disasters
    if ! command -v nginx >/dev/null 2>&1 && ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        echo "NGINX_INSTALLED_BY_SYSWARDEN='y'" >>"$CONF_FILE"
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "FAIL2BAN_INSTALLED_BY_SYSWARDEN='y'" >>"$CONF_FILE"
    fi
    # ==============================================================================

    if [[ -f /etc/debian_version ]]; then
        log "INFO" "Updating apt repositories..."
        apt-get update -qq
    fi

    if ! command -v curl >/dev/null; then missing_common+=("curl"); fi
    # --- HOTFIX: WGET DEPENDENCY (Required for UI Fonts & Upgrades) ---
    if ! command -v wget >/dev/null; then missing_common+=("wget"); fi
    # ------------------------------------------------------------------
    if ! command -v python3 >/dev/null; then missing_common+=("python3"); fi
    if ! command -v whois >/dev/null; then missing_common+=("whois"); fi
    # --- FIX: Added 'jq' dependency required for telemetry JSON generation ---
    if ! command -v jq >/dev/null; then missing_common+=("jq"); fi
    # -----------------------------------------------------------------------

    # --- HOTFIX: WEB SERVER & OPENSSL AS CORE DEPENDENCIES ---
    # We install Nginx only if absolutely no supported web server is found
    if ! command -v nginx >/dev/null 2>&1 && ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        missing_common+=("nginx")
    fi
    if ! command -v openssl >/dev/null; then missing_common+=("openssl"); fi
    # -----------------------------------------------------------

    # Check if array is not empty
    if [[ ${#missing_common[@]} -gt 0 ]]; then

        # --- HOTFIX: GHOST CONFIGURATION PREVENTION ---
        # Debian/Ubuntu automatically starts Nginx post-installation.
        # If a previous SysWarden configuration exists but the SSL certs were wiped,
        # dpkg will crash. We aggressively clean legacy configs before installing.
        if [[ -f /etc/debian_version ]] && [[ " ${missing_common[*]} " =~ " nginx " ]]; then
            log "INFO" "Cleaning up potential legacy Nginx configurations before install..."
            rm -f /etc/nginx/conf.d/syswarden-ui.conf
            rm -f /etc/nginx/sites-available/syswarden-ui.conf
            rm -f /etc/nginx/sites-enabled/syswarden-ui.conf
        fi
        # -----------------------------------------------------

        if [[ -f /etc/debian_version ]]; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y "${missing_common[@]}"
        elif [[ -f /etc/redhat-release ]]; then
            dnf install -y "${missing_common[@]}"
        fi
    fi

    # --- HOTFIX: PREEMPTIVE WEB LOG CREATION ---
    # We guarantee the existence of Web logs immediately after package installation.
    # This ensures Fail2ban naturally detects them and activates Layer 7 Web Jails natively.
    if command -v apache2 >/dev/null 2>&1 || [[ -d /etc/apache2 ]]; then
        mkdir -p /var/log/apache2
        touch /var/log/apache2/access.log /var/log/apache2/error.log
        chmod 640 /var/log/apache2/*.log 2>/dev/null || true
    elif command -v httpd >/dev/null 2>&1 || [[ -d /etc/httpd ]]; then
        mkdir -p /var/log/httpd
        touch /var/log/httpd/access_log /var/log/httpd/error_log
        chmod 640 /var/log/httpd/*_log 2>/dev/null || true
    else
        mkdir -p /var/log/nginx
        touch /var/log/nginx/access.log /var/log/nginx/error.log
        chmod 640 /var/log/nginx/*.log 2>/dev/null || true
    fi
    # ----------------------------------------------------

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
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y cron
        elif [[ -f /etc/redhat-release ]]; then dnf install -y cronie; fi
    fi

    # Ensure it's enabled and started (moved outside the install check)
    if command -v systemctl >/dev/null; then
        systemctl enable --now crond 2>/dev/null || systemctl enable --now cron 2>/dev/null || true
    fi
    # --------------------------------------------------------------------

    # --- RSYSLOG DEPENDENCY (For modern OS like Debian 12+ / Ubuntu 24.04+) ---
    # Required to generate /var/log/auth.log and /var/log/kern.log for Fail2ban
    if ! command -v rsyslogd >/dev/null && [ ! -f /usr/sbin/rsyslogd ]; then
        log "WARN" "Installing package: rsyslog"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y rsyslog
        elif [[ -f /etc/redhat-release ]]; then dnf install -y rsyslog; fi
    fi

    if command -v systemctl >/dev/null; then
        systemctl enable --now rsyslog 2>/dev/null || true
        touch /var/log/auth.log /var/log/kern.log /var/log/secure /var/log/messages 2>/dev/null || true

        # --- SECURITY FIX: UNIVERSAL KERNEL LOGGING & LOG INJECTION PREVENTION (CWE-117: Improper Output Neutralization for Logs) ---
        # Force rsyslog to write all Netfilter drops and Auth logs to DEDICATED files.
        # This prevents unprivileged users from spoofing firewall drops (F3, F4, F5).
        if [[ -f /etc/rsyslog.conf ]]; then
            # 1. Isolate Kernel Firewall logs
            sed -i '/^kern\./d' /etc/rsyslog.conf
            echo "kern.* /var/log/kern-firewall.log" >>/etc/rsyslog.conf
            touch /var/log/kern-firewall.log && chmod 600 /var/log/kern-firewall.log

            # 2. Isolate Auth/PAM logs (su, sudo, sshd)
            sed -i '/^authpriv\./d' /etc/rsyslog.conf
            sed -i '/^auth\./d' /etc/rsyslog.conf
            echo "auth,authpriv.* /var/log/auth-syswarden.log" >>/etc/rsyslog.conf
            touch /var/log/auth-syswarden.log && chmod 600 /var/log/auth-syswarden.log
        fi
        # -------------------------------------------------------------------------

        systemctl restart rsyslog 2>/dev/null || true
    fi

    # --- WIREGUARD & QR-CODE DEPENDENCIES ---
    if ! command -v wg >/dev/null || ! command -v qrencode >/dev/null; then
        log "WARN" "Installing package: WireGuard & Qrencode"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y wireguard qrencode
        elif [[ -f /etc/redhat-release ]]; then
            log "INFO" "Enabling EPEL repository (Required for Qrencode)..."
            dnf install -y epel-release || true
            dnf install -y wireguard-tools qrencode
        fi
    fi
    # ----------------------------------------

    if ! command -v ipset >/dev/null; then
        log "WARN" "Installing package: ipset"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y ipset
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

    if [[ "$FIREWALL_BACKEND" == "nftables" ]] && ! command -v nft >/dev/null; then
        log "WARN" "Installing package: nftables"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y nftables
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

    # --- SECURITY FIX: DISABLE TCP FORWARDING (ANTI-PIVOTING) (CWE-284: Improper Access Control) ---
    # Prevents attackers from using compromised low-privilege accounts to bypass the firewall
    if [[ -f /etc/ssh/sshd_config ]]; then
        log "INFO" "Ensuring SSH TCP Forwarding is strictly DISABLED..."
        sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
        sed -i 's/^[[:space:]]*AllowTcpForwarding[[:space:]]*yes/AllowTcpForwarding no/' /etc/ssh/sshd_config
        if command -v systemctl >/dev/null; then
            systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        fi
    fi
    # ------------------------------------------------------------

    echo "SSH_PORT='$SSH_PORT'" >>"$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"
}

# --- FIREWALL ENGINE OPTIMIZATION (RHEL/ALMA/FEDORA) ---
define_firewall_engine() {
    local mode="$1"

    # Do not execute during standard upgrades
    if [[ "$mode" == "update" ]]; then return; fi

    # --- BUG FIX: ALMALINUX DEAD-SERVICE PARADOX ---
    # Cloud images often ship Firewalld installed but disabled.
    # We trigger the swap logic if the binary exists, regardless of systemd state.
    if command -v firewall-cmd >/dev/null 2>&1; then

        # --- AUTOMATED MODE (CI/CD & Cloud-init) ---
        if [[ "$mode" == "auto" ]]; then
            local backend_choice="${SYSWARDEN_FIREWALL_BACKEND:-keep}"

            if [[ "$backend_choice" == "nftables" ]]; then
                log "INFO" "Auto-Deploy: Bypassing Firewalld for pure Nftables..."
                systemctl disable --now firewalld >/dev/null 2>&1 || true

                # --- FIX: Dynamic Nftables installation ---
                if ! command -v nft >/dev/null; then
                    if command -v dnf >/dev/null; then
                        dnf install -y nftables >/dev/null 2>&1 || true
                    elif command -v yum >/dev/null; then yum install -y nftables >/dev/null 2>&1 || true; fi
                fi
                # ------------------------------------------

                systemctl enable --now nftables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="nftables"
            elif [[ "$backend_choice" == "iptables" ]]; then
                log "INFO" "Auto-Deploy: Bypassing Firewalld for classic Iptables..."
                systemctl disable --now firewalld >/dev/null 2>&1 || true
                if command -v dnf >/dev/null; then
                    dnf install -y iptables-services >/dev/null 2>&1 || true
                elif command -v yum >/dev/null; then
                    yum install -y iptables-services >/dev/null 2>&1 || true
                fi
                systemctl enable --now iptables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="iptables"
            else
                log "INFO" "Auto-Deploy: Keeping Firewalld active."
            fi
            return
        fi

        # --- INTERACTIVE MODE ---
        echo -e "\n${BLUE}=== Step: Firewall Engine Optimization ===${NC}"
        echo -e "${YELLOW}WARNING: Firewalld is currently installed on your system.${NC}"
        echo -e "Because Firewalld uses D-Bus, injecting massive Threat Intelligence blocklists"
        echo -e "(100k+ IPs) can cause severe CPU bottlenecks and extremely slow reload times."
        echo -e "For production servers, we highly recommend bypassing Firewalld and using"
        echo -e "pure Nftables or classic Iptables directly in the kernel."

        local swap_fw
        read -p "Do you want SysWarden to replace Firewalld natively? (y/N): " swap_fw
        if [[ "$swap_fw" =~ ^[Yy]$ ]]; then
            echo -e "\nChoose your target Kernel backend:"
            echo -e "  1) Nftables (Modern, Recommended, Hardware Offload support)"
            echo -e "  2) Iptables (Classic SysAdmin choice, via iptables-services)"

            local fw_choice
            while true; do
                read -p "Select backend [1-2]: " fw_choice
                if [[ "$fw_choice" =~ ^[1-2]$ ]]; then break; fi
            done

            log "INFO" "Stopping and safely disabling Firewalld..."
            systemctl disable --now firewalld >/dev/null 2>&1 || true

            if [[ "$fw_choice" == "2" ]]; then
                log "INFO" "Installing and enabling classic Iptables persistence..."
                if command -v dnf >/dev/null; then
                    dnf install -y iptables-services >/dev/null 2>&1 || true
                elif command -v yum >/dev/null; then yum install -y iptables-services >/dev/null 2>&1 || true; fi
                systemctl enable --now iptables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="iptables"
                sed -i '/^FIREWALL_BACKEND=/d' "$CONF_FILE" 2>/dev/null || true
                echo "FIREWALL_BACKEND='iptables'" >>"$CONF_FILE"
                log "INFO" "Engine swapped: IPtables Active. Firewalld bypassed."
            else
                log "INFO" "Enabling pure Nftables persistence..."

                # --- FIX: Dynamic Nftables installation ---
                if ! command -v nft >/dev/null; then
                    if command -v dnf >/dev/null; then
                        dnf install -y nftables >/dev/null 2>&1 || true
                    elif command -v yum >/dev/null; then yum install -y nftables >/dev/null 2>&1 || true; fi
                fi
                # ------------------------------------------

                systemctl enable --now nftables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="nftables"
                sed -i '/^FIREWALL_BACKEND=/d' "$CONF_FILE" 2>/dev/null || true
                echo "FIREWALL_BACKEND='nftables'" >>"$CONF_FILE"
                log "INFO" "Engine swapped: Nftables Active. Firewalld bypassed."
            fi
        else
            echo -e "${YELLOW}Keeping Firewalld. Note: Firewall reload operations will take longer.${NC}"
            log "INFO" "User opted to keep Firewalld despite performance warnings."
        fi
    fi
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

        if [[ "$input_wg" =~ ^[Yy]$ ]]; then
            WG_PORT=${SYSWARDEN_WG_PORT:-51820}
            WG_SUBNET=${SYSWARDEN_WG_SUBNET:-"10.66.66.0/24"}

            # --- SECURITY FIX: Strict Input Validation for Auto Mode (CWE-20: Improper Input Validation) ---
            if ! [[ "$WG_PORT" =~ ^[0-9]+$ ]] || [ "$WG_PORT" -lt 1 ] || [ "$WG_PORT" -gt 65535 ]; then
                log "WARN" "Auto Mode: Invalid WG_PORT format. Defaulting to 51820."
                WG_PORT=51820
            fi

            if ! [[ "$WG_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
                log "WARN" "Auto Mode: Invalid WG_SUBNET CIDR format. Defaulting to 10.66.66.0/24."
                WG_SUBNET="10.66.66.0/24"
            fi
            # -----------------------------------------------------------
        fi
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
            # --- SECURITY FIX: STRICT WG PORT & SUBNET VALIDATION (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter WireGuard Port [Default: 51820]: " input_wg_port
                WG_PORT=${input_wg_port:-51820}
                if [[ "$WG_PORT" =~ ^[0-9]+$ ]] && [ "$WG_PORT" -ge 1 ] && [ "$WG_PORT" -le 65535 ]; then break; else echo -e "${RED}Invalid Port. Must be 1-65535.${NC}"; fi
            done

            while true; do
                read -p "Enter VPN Subnet (CIDR) [Default: 10.66.66.0/24]: " input_wg_subnet
                WG_SUBNET=${input_wg_subnet:-"10.66.66.0/24"}
                # Strict Regex for IPv4 CIDR notation
                if [[ "$WG_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then break; else echo -e "${RED}Invalid CIDR format (e.g. 10.66.66.0/24).${NC}"; fi
            done
            # --------------------------------------------------------
        fi

        # PRE-CREATION: Ensure /etc/wireguard exists EARLY so Fail2ban detects it globally
        mkdir -p /etc/wireguard
        log "INFO" "WireGuard ENABLED (Port: $WG_PORT, Subnet: $WG_SUBNET)."
    else
        USE_WIREGUARD="n"
        log "INFO" "WireGuard DISABLED."
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
    echo "USE_DOCKER='$USE_DOCKER'" >>"$CONF_FILE"
}

define_os_hardening() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${APPLY_OS_HARDENING:-}" ]]; then APPLY_OS_HARDENING="n"; fi
        log "INFO" "Update Mode: Preserving OS Hardening setting ($APPLY_OS_HARDENING)"
        return
    fi

    echo -e "\n${BLUE}=== Step: OS Security & Hardening ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_hard=${SYSWARDEN_HARDENING:-n}
        log "INFO" "Auto Mode: OS Hardening choice loaded via env var [${input_hard}]"
    else
        echo -e "${YELLOW}WARNING: Strict OS hardening will restrict CRON to root and remove non-root users from sudo/wheel groups.${NC}"
        read -p "Apply strict OS Hardening? (Recommended for NEW servers only) [y/N]: " input_hard
    fi

    if [[ "$input_hard" =~ ^[Yy]$ ]]; then
        APPLY_OS_HARDENING="y"
        log "INFO" "OS Hardening ENABLED. Sudo/Cron will be strictly restricted."
    else
        APPLY_OS_HARDENING="n"
        log "INFO" "OS Hardening DISABLED. Preserving existing system permissions."
    fi
    echo "APPLY_OS_HARDENING='$APPLY_OS_HARDENING'" >>"$CONF_FILE"
}

apply_os_hardening() {
    if [[ "${APPLY_OS_HARDENING:-n}" != "y" ]]; then
        return
    fi

    log "INFO" "Applying strict OS hardening (Crontab, Sudo/Wheel, Profiles)..."

    # 1. Lock down Crontab (Only root can schedule tasks)
    echo "root" >/etc/cron.allow
    chmod 600 /etc/cron.allow
    rm -f /etc/cron.deny 2>/dev/null || true

    # 2. Backup and Purge non-root users from privileged groups (sudo/wheel/adm)
    mkdir -p "$SYSWARDEN_DIR"
    local current_admin="${SUDO_USER:-}"

    for grp in sudo wheel adm; do
        if grep -q "^${grp}:" /etc/group 2>/dev/null; then
            # Backup current members
            local members
            members=$(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group)
            if [[ -n "$members" && "$members" != "root" ]]; then
                echo "${grp}:${members}" >>"$SYSWARDEN_DIR/group_backup.txt"
            fi

            # Purge non-root users
            for user in $(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group | tr ',' ' ' 2>/dev/null); do
                if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                    # --- SAFEGUARD: Never purge the executing admin ---
                    if [[ -n "$current_admin" ]] && [[ "$user" == "$current_admin" ]]; then
                        log "INFO" "SAFEGUARD: Preserving current admin '$user' in '$grp' group."
                        continue
                    fi
                    gpasswd -d "$user" "$grp" >/dev/null 2>&1 || true
                    log "INFO" "Removed user '$user' from '$grp' group."
                fi
            done
        fi
    done

    # 3. Lock down profiles for standard users (Prevents SSH Login backdoors)
    for user_dir in /home/*; do
        if [[ -d "$user_dir" ]]; then
            local user_name
            user_name=$(basename "$user_dir")
            # Preserve current admin's profile to avoid breaking their active SSH session
            if [[ -n "$current_admin" ]] && [[ "$user_name" == "$current_admin" ]]; then
                continue
            fi
            for profile_file in "$user_dir/.profile" "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                if [[ -f "$profile_file" ]]; then
                    chattr -i "$profile_file" 2>/dev/null || true
                    chown "$user_name:$user_name" "$profile_file"
                    chmod 644 "$profile_file"
                    chattr +i "$profile_file" 2>/dev/null || true
                fi
            done
        fi
    done
}

auto_whitelist_admin() {
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    local admin_ip=""

    # 1. Standard SSH env variables
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        admin_ip=$(echo "$SSH_CLIENT" | awk '{print $1}' || true)
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        admin_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}' || true)
    fi

    # --- SECURITY FIX: BULLETPROOF KERNEL SOCKET DETECTION (CWE-345: Insufficient Verification of Data Authenticity) ---
    # Query active SSH sockets directly instead of relying on easily wiped SSH variables.
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local current_tty
        current_tty=$(tty 2>/dev/null | sed 's#/dev/##' || true)

        if [[ -n "$current_tty" && "$current_tty" != "not a tty" ]]; then
            admin_ip=$(who 2>/dev/null | grep "$current_tty" | awk '{print $5}' | tr -d '()' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    # Ultimate fallback via SSHD sockets if no TTY is detected (e.g. CI/CD Pipeline)
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if command -v ss >/dev/null; then
            admin_ip=$(ss -tnp 2>/dev/null | grep -i 'estab' | grep -i 'sshd' | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    # Process the IP
    if [[ "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$admin_ip" != "127.0.0.1" ]]; then
        # --- FIX: DO NOT AUTO-WHITELIST THE VPN SUBNET ---
        # If the admin is connected via WireGuard, we skip the absolute whitelist
        # because the VPN subnet is already allowed natively (Priority -50).
        local is_vpn_ip=0
        if [[ -n "${WG_SUBNET:-}" ]]; then
            local subnet_base
            subnet_base=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
            if [[ "$admin_ip" == "${subnet_base}."* ]]; then
                is_vpn_ip=1
            fi
        fi

        if [[ $is_vpn_ip -eq 1 ]]; then
            log "INFO" "Admin connected via VPN ($admin_ip). Skipping absolute whitelist."
        else
            if ! grep -q "^${admin_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting current admin SSH session IP: $admin_ip"
                echo "$admin_ip" >>"$WHITELIST_FILE"
            fi
        fi
    else
        log "WARN" "CRITICAL: Could not auto-detect admin SSH IP. You risk being locked out!"
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

        # --- SECURITY FIX: STRICT IPV4 VALIDATION (CWE-20: Improper Input Validation) ---
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

# ==============================================================================
# Function: auto_whitelist_infra
# Purpose: Automatically detects and whitelists critical infrastructure IPs
#          (DNS, Default Gateway, DHCP, Cloud Metadata) to prevent server lockout.
# ==============================================================================
auto_whitelist_infra() {
    # 1. State Machine: Handle silent background updates (No Prompts)
    if [[ "${1:-}" == "update" ]] || [[ "${1:-}" == "cron-update" ]]; then
        # Ensure config is loaded to read the user's initial choice
        if [[ -f "$CONF_FILE" ]] && ! grep -q "WHITELIST_INFRA=" <<<"$(set)"; then
            # shellcheck source=/dev/null
            source "$CONF_FILE" 2>/dev/null || true
        fi

        if [[ "${WHITELIST_INFRA:-y}" == "n" ]]; then
            return
        fi
    else
        # 2. Interactive & Auto Mode (Initial Installation)
        echo -e "\n${BLUE}=== Step: Critical Infrastructure Whitelist ===${NC}"

        # --- CI/CD AUTO MODE CHECK ---
        if [[ "${1:-}" == "auto" ]]; then
            input_infra=${SYSWARDEN_WHITELIST_INFRA:-y}
            log "INFO" "Auto Mode: Infra Whitelist choice loaded via env var [${input_infra}]"
        else
            echo -e "${YELLOW}To prevent server lockouts, SysWarden can automatically detect and whitelist"
            echo -e "your DNS, DHCP, Default Gateway, and Cloud Metadata IPs.${NC}"
            read -p "Enable Critical Infrastructure Whitelisting? (Y/n): " input_infra
        fi

        # Normalize and Save to configuration
        if [[ "$input_infra" =~ ^[Nn]$ ]]; then
            WHITELIST_INFRA="n"
            echo "WHITELIST_INFRA='n'" >>"$CONF_FILE"
            log "WARN" "Auto-whitelisting of critical infrastructure is DISABLED."
            return
        else
            WHITELIST_INFRA="y"
            echo "WHITELIST_INFRA='y'" >>"$CONF_FILE"
        fi
    fi

    log "INFO" "Scanning and whitelisting critical infrastructure IPs (DNS, Gateway, Cloud Metadata)..."

    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    local infra_ips=""

    # 1. Extract DNS Resolvers
    if [[ -f /etc/resolv.conf ]]; then
        local dns_ips
        dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        infra_ips="$infra_ips $dns_ips"
    fi

    # 2. Extract Default Gateway(s)
    if command -v ip >/dev/null; then
        local gw_ips
        gw_ips=$(ip -4 route show default 2>/dev/null | grep -Eo 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' || true)
        infra_ips="$infra_ips $gw_ips"
    fi

    # 3. Add Cloud Metadata IP (Universal AWS, GCP, Azure, OVH, Scaleway)
    infra_ips="$infra_ips 169.254.169.254"

    # 4. Extract DHCP Server IP (from common dhclient lease files)
    if [[ -f /var/lib/dhcp/dhclient.leases ]]; then
        local dhcp_ips
        dhcp_ips=$(grep -E 'dhcp-server-identifier' /var/lib/dhcp/dhclient.leases 2>/dev/null | awk '{print $3}' | tr -d ';' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        infra_ips="$infra_ips $dhcp_ips"
    fi

    # 5. Extract Host's own public/local IPs (Prevents self-routing drops in extreme cases)
    if command -v ip >/dev/null; then
        local host_ips
        host_ips=$(ip -4 addr show | grep -oEo 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | grep -v '^127\.' || true)
        infra_ips="$infra_ips $host_ips"
    fi

    # --- HOTFIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global strict IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------

    # Filter, validate, and inject into the master whitelist
    for ip in $infra_ips; do
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if ! grep -q "^${ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting critical Infra IP: $ip"
                echo "$ip" >>"$WHITELIST_FILE"
            fi
        fi
    done

    # Restore strict security IFS
    IFS="$OLD_IFS"
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

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
        # Preemptive cleanup of spaces/newlines to prevent switch-case bypass
        choice=$(echo "${SYSWARDEN_LIST_CHOICE:-1}" | tr -d '[:space:]')
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
        1) LIST_TYPE="Standard" ;;
        2) LIST_TYPE="Critical" ;;
        3)
            LIST_TYPE="Custom"
            if [[ "${1:-}" == "auto" ]]; then
                CUSTOM_URL=${SYSWARDEN_CUSTOM_URL:-""}

                # --- SECURITY FIX: Strict URL Validation & Anti-Poisoning (CWE-20: Improper Input Validation) ---
                # Strip newlines (\r\n) and dangerous escape characters
                CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d "\r\n '\"\;\$\|\&\<\>\`")

                # Strict Regex: Must have a valid domain or IP, and no exotic characters (Anti-SSRF)
                if [[ -n "$CUSTOM_URL" && ! "$CUSTOM_URL" =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]+)?(/.*)?$ ]]; then
                    log "ERROR" "Auto Mode: Invalid CUSTOM_URL. Bad format or invalid characters. Defaulting to Standard List."
                    LIST_TYPE="Standard"
                    CUSTOM_URL=""
                fi
                # ---------------------------------------------------------
                log "INFO" "Auto Mode: Custom URL loaded via env var"
            else
                # --- SECURITY FIX: STRICT URL VALIDATION (INTERACTIVE) (CWE-20: Improper Input Validation) ---
                while true; do
                    read -p "Enter the full URL (must be raw .txt format): " CUSTOM_URL

                    # Absolute sanitization
                    CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d "\r\n '\"\;\$\|\&\<\>\`")

                    if [[ -z "$CUSTOM_URL" ]]; then
                        log "WARN" "URL cannot be empty."
                    elif [[ ! "$CUSTOM_URL" =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]+)?(/.*)?$ ]]; then
                        echo -e "${RED}ERROR: Invalid URL format. Must start with http:// or https:// and contain a valid domain/IP.${NC}"
                    else
                        break
                    fi
                done
                # -------------------------------------------
            fi

            # Fail-Safe
            if [[ -z "$CUSTOM_URL" ]]; then
                log "WARN" "Custom URL is empty. Defaulting to Standard List."
                LIST_TYPE="Standard"
            fi
            ;;
        4) LIST_TYPE="None" ;;
        *)
            log "WARN" "Invalid choice detected. Defaulting to Standard List."
            LIST_TYPE="Standard"
            ;;
    esac

    echo "LIST_TYPE='$LIST_TYPE'" >>"$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then
        echo "CUSTOM_URL='$CUSTOM_URL'" >>"$CONF_FILE"
    fi
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
        # --- SECURITY FIX: STRICT INPUT SANITIZATION (CWE-20: Improper Input Validation) ---
        # Strip all characters except letters and spaces to prevent command injection
        # or malformed URLs during the curl fetch phase.
        GEOBLOCK_COUNTRIES=$(echo "$GEOBLOCK_COUNTRIES" | tr -cd 'a-zA-Z ' | tr '[:upper:]' '[:lower:]')
        log "INFO" "Geo-Blocking ENABLED for: $GEOBLOCK_COUNTRIES"
    else
        GEOBLOCK_COUNTRIES="none"
        log "INFO" "Geo-Blocking DISABLED."
    fi
    echo "GEOBLOCK_COUNTRIES='$GEOBLOCK_COUNTRIES'" >>"$CONF_FILE"
}

define_asnblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${BLOCK_ASNS:-}" ]]; then BLOCK_ASNS="none"; fi
        # Backward compatibility: if Spamhaus variable doesn't exist in config, enable by default
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
            # --- SECURITY FIX: STRICT INPUT SANITIZATION (CWE-20: Improper Input Validation) ---
            # Allow only alphanumeric characters and spaces to prevent whois command injection.
            if [[ "$BLOCK_ASNS" != "none" ]]; then
                BLOCK_ASNS=$(echo "$BLOCK_ASNS" | tr -cd 'a-zA-Z0-9 ' | tr '[:lower:]' '[:upper:]')
            fi
            log "INFO" "ASN Blocking ENABLED. Custom: [$BLOCK_ASNS], Spamhaus: [$USE_SPAMHAUS_ASN]"
        fi
    else
        BLOCK_ASNS="none"
        USE_SPAMHAUS_ASN="n"
        log "INFO" "ASN Blocking DISABLED."
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

        # --- SECURITY FIX: Strict IPV4 Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ "$HA_ENABLED" =~ ^[Yy]$ ]] && ! [[ "$HA_PEER_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            log "ERROR" "Auto Mode: Invalid HA_PEER_IP IPv4 format. Disabling HA Cluster."
            HA_ENABLED="n"
            HA_PEER_IP=""
        fi
        # ----------------------------------------------------------
        log "INFO" "Auto Mode: HA choice loaded via env var."
    else
        echo "SysWarden can automatically replicate its threat intelligence state to a standby node."
        read -p "Enable HA Cluster Sync? (y/N): " input_ha

        if [[ "$input_ha" =~ ^[Yy]$ ]]; then
            HA_ENABLED="y"
            # --- SECURITY FIX: STRICT IPV4 VALIDATION LOOP (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter Standby Node IP (Must be accessible via SSH keys): " HA_PEER_IP
                if [[ "$HA_PEER_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                    break
                else
                    echo -e "${RED}ERROR: Invalid IPv4 address format. Please try again.${NC}"
                fi
            done
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
# SysWarden HA State Synchronization
# Runs securely via Cron to replicate states to the standby node

PEER="$HA_PEER_IP"
SSH_PORT="${SSH_PORT:-22}"

# 1. Sync custom lists
rsync -a -e "ssh -p \$SSH_PORT -o StrictHostKeyChecking=no" /etc/syswarden/whitelist.txt /etc/syswarden/blocklist.txt root@\$PEER:/etc/syswarden/ 2>/dev/null

# 2. Trigger remote reload securely
ssh -p \$SSH_PORT -o StrictHostKeyChecking=no root@\$PEER "/usr/local/bin/syswarden-telemetry.sh >/dev/null 2>&1" 2>/dev/null
EOF
        chmod +x "$SYNC_SCRIPT"

        # Inject into Crontab (Syncs every 30 mins)
        if ! crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
            (
                crontab -l 2>/dev/null || true
                echo "*/30 * * * * $SYNC_SCRIPT >/dev/null 2>&1"
            ) | crontab -
        fi
        log "INFO" "HA Cluster Sync ENABLED. Target: $HA_PEER_IP"
    else
        log "INFO" "HA Cluster Sync DISABLED."
    fi
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
        echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
        return
    fi

    if [[ "$LIST_TYPE" == "None" ]]; then
        SELECTED_URL="none"
        echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
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
            if ((time < fastest_time)); then
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

    echo "SELECTED_URL='$SELECTED_URL'" >>"$CONF_FILE"
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
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION (CWE-20: Improper Input Validation) ---
        # Validates exact octet ranges (0-255) and subnet masks (0-32) to prevent firewall crash (F13)
        tr -d '\r' <"$output_file" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >"$TMP_DIR/clean_list.txt"
        # -----------------------------------------------------
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        log "INFO" "Download success."
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

        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION (CWE-20: Improper Input Validation) ---
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
    if [[ "${GEOBLOCK_COUNTRIES:-none}" == "none" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading Geo-Blocking Data ===${NC}"

    # FIX: Create required directories before doing anything
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : >"$TMP_DIR/geoip_raw.txt"

    # FIX: Bypass strict IFS by transforming spaces into newlines for the loop
    for country in $(echo "$GEOBLOCK_COUNTRIES" | tr ' ' '\n'); do
        # Skip empty strings just in case
        if [[ -z "$country" ]]; then continue; fi

        echo -n "Fetching IP blocks for ${country^^}... "
        if curl -sS -L --retry 3 --connect-timeout 5 "https://www.ipdeny.com/ipblocks/data/countries/${country}.zone" >>"$TMP_DIR/geoip_raw.txt"; then
            echo -e "${GREEN}OK${NC}"
        else
            echo -e "${RED}FAIL${NC}"
            log "WARN" "Failed to download GeoIP data for $country."
        fi
    done

    if [[ -s "$TMP_DIR/geoip_raw.txt" ]]; then
        # Ensure valid CIDR formats and remove duplicates
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION (CWE-20: Improper Input Validation) ---
        awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' "$TMP_DIR/geoip_raw.txt" | sort -u >"$GEOIP_FILE"
        # -----------------------------------------------------
        log "INFO" "Geo-Blocking list updated successfully."
    else
        log "WARN" "Geo-Blocking list is empty. IPDeny might be unreachable."
        touch "$GEOIP_FILE"
    fi
}

download_asn() {
    # Exit if user provided no custom ASNs AND declined Spamhaus
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading ASN Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : >"$TMP_DIR/asn_raw.txt"

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
            if echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >>"$TMP_DIR/asn_raw.txt"; then
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
    print(net)' <"$TMP_DIR/asn_raw.txt" >"$ASN_FILE"

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

    # 1. Inject local blocklist into the global list
    cat "$BLOCKLIST_FILE" >>"$FINAL_LIST"

    # 2. Clean duplicates to ensure firewall stability
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"

    # 3. Exclude local whitelisted IPs from the final blocklist
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" >"$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi

    # --- FIX: TELEMETRY PERSISTENCE ---
    # Save the massive compiled list to disk so the telemetry engine can count it instantly
    # without running heavy queries against the kernel every minute.
    cp "$FINAL_LIST" "$SYSWARDEN_DIR/active_global_blocklist.txt"
    # -----------------------------------

    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        log "INFO" "Configuring Nftables via Atomic Transaction (Zero-Downtime)..."

        # --- L2 HARDWARE ACCELERATION (eBPF/XDP Alternative) ---
        # Dynamically detect the physical network interface facing the internet
        local ACTIVE_IF
        ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

        # 1. Start building the atomic configuration file
        cat <<EOF >"$TMP_DIR/syswarden.nft"
# Flush tables atomically
table inet syswarden_table
delete table inet syswarden_table
table netdev syswarden_hw_drop
delete table netdev syswarden_hw_drop

# ==============================================================
# TIER 1: HARDWARE LEVEL DROP (Layer 2 Ingress)
# Destroys packets at the NIC driver level before CPU allocates 
# memory for Conntrack. Zero-DDoS impact.
# ==============================================================
table netdev syswarden_hw_drop {
    set $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "    set $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "    set $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    chain ingress_frontline {
        type filter hook ingress device "$ACTIVE_IF" priority -500; policy accept;
        
        # Absolute whitelist bypass at NIC level
EOF

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "        ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
            done <"$WHITELIST_FILE"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        # Hardware Drops with SIEM Logging (Rate-Limited to prevent CPU/IO exhaustion)
        ip saddr @$SET_NAME limit rate 2/second log prefix "[SysWarden-BLOCK] "
        ip saddr @$SET_NAME drop
EOF
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "        ip saddr @$GEOIP_SET_NAME limit rate 2/second log prefix \"[SysWarden-GEO] \"" >>"$TMP_DIR/syswarden.nft"
            echo "        ip saddr @$GEOIP_SET_NAME drop" >>"$TMP_DIR/syswarden.nft"
        fi
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "        ip saddr @$ASN_SET_NAME limit rate 2/second log prefix \"[SysWarden-ASN] \"" >>"$TMP_DIR/syswarden.nft"
            echo "        ip saddr @$ASN_SET_NAME drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }
}

# ==============================================================
# TIER 2: OS KERNEL FILTERING (Layer 3/4)
# Manages complex stateful routing (WireGuard, Catch-All)
# ==============================================================
table inet syswarden_table {
    # 3. FRONTLINE CHAIN (Executes BEFORE Fail2ban at priority -10)
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
            echo "        iifname { \"wg0\", \"lo\" } accept comment \"SysWarden: Global Trust for VPN\"" >>"$TMP_DIR/syswarden.nft"
            echo "        tcp dport ${SSH_PORT:-22} log prefix \"[SysWarden-SSH-DROP] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
    }

    # 4. BACKEND CHAIN (Executes AFTER Fail2ban at priority 10)
    # Serves as the Zero-Trust Catch-All, allowing legitimate traffic first.
    chain input_backend {
        type filter hook input priority filter + 10; policy drop;
        ct state established,related accept
        iifname "lo" accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
EOF

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            echo "        tcp dport { ${SSH_PORT:-22}, 9999, $ACTIVE_PORTS } accept" >>"$TMP_DIR/syswarden.nft"
        else
            echo "        tcp dport { ${SSH_PORT:-22}, 9999 } accept" >>"$TMP_DIR/syswarden.nft"
        fi

        # --- HOTFIX: WG BACKEND SURVIVAL ---
        # WG traffic explicitly allowed in Frontline must ALSO be allowed in the Zero-Trust Backend
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept" >>"$TMP_DIR/syswarden.nft"
        fi
        # ------------------------------------------

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        # The Catch-All Drop: Any packet surviving Frontline and Fail2ban hits this.
        limit rate 2/second log prefix "[SysWarden-BLOCK] [Catch-All] "
        drop
    }
}
EOF

        # 4. APPEND ELEMENTS IN CHUNKS (Anti-OOM Killer)
        log "INFO" "Populating Nftables sets atomically in chunks (Bypassing memory limits)..."

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

        log "INFO" "Applying Atomic Nftables Transaction to the Kernel..."
        nft -f "$TMP_DIR/syswarden.nft"
        # --------------------------------------------

        # --- FIX: KERNEL FORWARDING & OS-LEVEL BYPASS FOR WIREGUARD ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            log "INFO" "Applying WireGuard routing bypass to native OS tables..."
            if nft list table inet filter >/dev/null 2>&1; then
                # 1. Open UDP port and allow wg0 interface in OS default input chain
                if nft list chain inet filter input >/dev/null 2>&1; then
                    # HOTFIX: grep >/dev/null prevents SIGPIPE pipefail crashes that cause ghost duplicates
                    if ! nft list chain inet filter input 2>/dev/null | grep -E "udp[[:space:]]+dport[[:space:]]+${WG_PORT:-51820}[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter input udp dport "${WG_PORT:-51820}" accept 2>/dev/null || true
                    fi
                    if ! nft list chain inet filter input 2>/dev/null | grep -E "iifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter input iifname "wg0" accept 2>/dev/null || true
                    fi
                fi
                # 2. Allow IP Forwarding for the VPN tunnel (Idempotent)
                if nft list chain inet filter forward >/dev/null 2>&1; then
                    if ! nft list chain inet filter forward 2>/dev/null | grep -E "iifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter forward iifname "wg0" accept 2>/dev/null || true
                    fi
                    if ! nft list chain inet filter forward 2>/dev/null | grep -E "oifname[[:space:]]+[\"']?wg0[\"']?[[:space:]]+accept" >/dev/null; then
                        nft insert rule inet filter forward oifname "wg0" accept 2>/dev/null || true
                    fi
                fi

                # --- HOTFIX: SAFE OS PERSISTENCE (NO RAM DUMP) ---
                # We prevent dumping the active 'inet filter' table to avoid duplicating
                # the sysadmin's custom rules or breaking their native file structure.
                # The include directive handled later in this script is sufficient.
                # ----------------------------------------------------------
            fi
        fi
        # --------------------------------------------------------------

        # --- MODULAR PERSISTENCE (ZERO-TOUCH) ---
        log "INFO" "Saving SysWarden Nftables tables to isolated config..."
        mkdir -p /etc/syswarden
        # FIX: Export BOTH tables (Tier 1 Hardware Drop + Tier 2 Stateful)
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft
        nft list table netdev syswarden_hw_drop >>/etc/syswarden/syswarden.nft 2>/dev/null || true

        local MAIN_NFT_CONF="/etc/nftables.conf"
        if [[ -f "$MAIN_NFT_CONF" ]]; then
            # Inject include directive securely if not already present
            if ! grep -q 'include "/etc/syswarden/syswarden.nft"' "$MAIN_NFT_CONF"; then
                log "INFO" "Injecting include directive into $MAIN_NFT_CONF..."
                echo -e '\n# Added by SysWarden' >>"$MAIN_NFT_CONF"
                echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
            fi
        else
            # Create a basic standard configuration if the file doesn't exist at all
            log "WARN" "$MAIN_NFT_CONF not found. Creating basic layout."
            echo '#!/usr/sbin/nft -f' >"$MAIN_NFT_CONF"
            echo 'flush ruleset' >>"$MAIN_NFT_CONF"
            echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
            chmod 755 "$MAIN_NFT_CONF"
        fi

        if command -v systemctl >/dev/null; then
            systemctl enable --now nftables 2>/dev/null || true
        fi

    elif [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        # Ensure firewalld is active and running
        if ! systemctl is-active --quiet firewalld; then systemctl enable --now firewalld; fi

        # --- WIREGUARD SSH CLOAKING & NATIVE NAT (FIXED FOR ALMA 10) ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            log "INFO" "WireGuard: Configuring Native Firewalld Routing and Strict SSH Cloaking..."

            # 1. Native NAT for VPN Internet Access (Alma/RHEL/Fedora)
            firewall-cmd --permanent --add-masquerade >/dev/null 2>&1 || true
            firewall-cmd --permanent --zone=trusted --add-interface=wg0 >/dev/null 2>&1 || true

            # 2. Universal SSH Port Purge (Cleans lingering SSH rules from ALL zones)
            for zone in $(firewall-cmd --get-zones 2>/dev/null || echo "public"); do
                # --- FIX ALMA/RHEL: AGGRESSIVE PHANTOM SERVICE PURGE ---
                firewall-cmd --zone="$zone" --remove-service="ssh" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-service="ssh" >/dev/null 2>&1 || true

                firewall-cmd --zone="$zone" --remove-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

                # Cleanup old priority rules to prevent conflicts
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-50' family='ipv4' source address='${WG_SUBNET}' port port='${SSH_PORT:-22}' protocol='tcp' accept" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-50' family='ipv4' source address='${WG_SUBNET}' port port='9999' protocol='tcp' accept" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-10' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
                firewall-cmd --permanent --zone="$zone" --remove-rich-rule="rule priority='-10' family='ipv4' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
            done

            # 3. Allow WireGuard UDP port for tunnel establishment
            firewall-cmd --permanent --add-port="${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true

            # --- STRICT ZERO TRUST HIERARCHY (v0.27.4) - DEBIAN PARITY) ---

            # Priority -1000: Highest priority. Allow SSH & Dashboard strictly from VPN.
            firewall-cmd --permanent --add-rich-rule="rule priority='-1000' family='ipv4' source address='${WG_SUBNET}' port port='${SSH_PORT:-22}' protocol='tcp' accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-rich-rule="rule priority='-1000' family='ipv4' source address='${WG_SUBNET}' port port='9999' protocol='tcp' accept" >/dev/null 2>&1 || true

            # Priority -900: BULLETPROOF DROP. Executes BEFORE the Admin Whitelist (-100).
            # This mimics Debian: SSH is strictly dropped globally before any IP whitelists are evaluated.
            firewall-cmd --permanent --add-rich-rule="rule priority='-900' port port='${SSH_PORT:-22}' protocol='tcp' drop" >/dev/null 2>&1 || true
            # -----------------------------------

            # 4. VERIFICATION (Purple Team Check)
            if ! firewall-cmd --permanent --zone=trusted --list-interfaces | grep -q "wg0"; then
                log "WARN" "WARNING: wg0 interface not found in permanent trusted zone."
            fi

            # Note: We intentionally DO NOT reload here. We wait for the whitelist injection
            # at the end of the Firewalld section to guarantee an atomic, safe reload that keeps the admin session alive.
        fi
        # ------------------------------

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
        cat <<EOF >"/etc/firewalld/ipsets/${SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat <<EOF >"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat <<EOF >"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
<?xml version="1.0" encoding="utf-8"?>
<ipset type="hash:net">
  <option name="family" value="inet"/>
  <option name="maxelem" value="1000000"/>
</ipset>
EOF
        fi

        # 3. Fast reload to register empty sets
        firewall-cmd --reload >/dev/null 2>&1 || true

        # --- FIX: STRICT WHITELIST SYNCHRONIZATION (ANTI-GHOST RULES) ---
        log "INFO" "Synchronizing Whitelist with Firewalld memory..."

        # 1. Hunt and destroy ALL existing priority rules in permanent memory
        while IFS= read -r rule; do
            if [[ "$rule" == *"priority=\"-100\""* ]] || [[ "$rule" == *"priority=\"-32000\""* ]]; then
                firewall-cmd --permanent --remove-rich-rule="$rule" >/dev/null 2>&1 || true
            fi
        done < <(firewall-cmd --permanent --list-rich-rules 2>/dev/null || true)

        # 2. Re-inject ONLY the IPs that are currently in the text file
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                # Clean up any old unprioritized legacy rule if it exists
                firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$wl_ip' accept" >/dev/null 2>&1 || true

                # Inject the new prioritized rule (-32000 guarantees absolute top execution)
                firewall-cmd --permanent --add-rich-rule="rule priority='-32000' family='ipv4' source address='$wl_ip' accept" >/dev/null 2>&1 || true
            done <"$WHITELIST_FILE"
        fi
        # ----------------------------------------------------------------

        # 4. Add all Rich Rules
        firewall-cmd --permanent --add-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" >/dev/null 2>&1 || true

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            firewall-cmd --permanent --add-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" >/dev/null 2>&1 || true
        fi

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        # Firewalld uses Zones. We dynamically force the target of the active default zone to DROP.
        # This acts as our Catch-All (Priority Guillotine).
        local ACTIVE_ZONE
        ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")

        firewall-cmd --permanent --zone="$ACTIVE_ZONE" --set-target=DROP >/dev/null 2>&1 || true

        # Explicitly allow discovered services to override the DROP target
        firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            for port in $(echo "$ACTIVE_PORTS" | tr ',' ' '); do
                # HOTFIX: Use dynamic ACTIVE_ZONE instead of hardcoded public
                firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-port="${port}/tcp" >/dev/null 2>&1 || true
            done
        fi

        # Ensure Firewalld DenyLogs are active so Fail2ban can catch the drops
        firewall-cmd --set-log-denied=all >/dev/null 2>&1 || true

        # 5. Populate XMLs directly with data
        log "INFO" "Injecting massive IP lists into kernel..."
        sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${SET_NAME}.xml"
        sed 's/.*/  <entry>&<\/entry>/' "$FINAL_LIST" >>"/etc/firewalld/ipsets/${SET_NAME}.xml"
        echo "</ipset>" >>"/etc/firewalld/ipsets/${SET_NAME}.xml"

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$GEOIP_FILE" >>"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
            echo "</ipset>" >>"/etc/firewalld/ipsets/${GEOIP_SET_NAME}.xml"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            sed -i '/<\/ipset>/d' "/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            sed 's/.*/  <entry>&<\/entry>/' "$ASN_FILE" >>"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
            echo "</ipset>" >>"/etc/firewalld/ipsets/${ASN_SET_NAME}.xml"
        fi

        log "INFO" "Loading rules into kernel (This may take up to 30s)..."
        firewall-cmd --reload >/dev/null 2>&1 || true
        log "INFO" "Firewalld rules applied."

    elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        log "INFO" "Configuring UFW with IPSet..."

        # 1. Create IPSet (UFW uses iptables underneath)
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!

        # 2. Inject Rule into /etc/ufw/before.rules
        UFW_RULES="/etc/ufw/before.rules"

        # Remove old rules if present to avoid duplicates
        sed -i "/$SET_NAME/d" "$UFW_RULES"

        # Insert new rules after "# End required lines" marker
        if grep -q "# End required lines" "$UFW_RULES"; then
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j DROP" "$UFW_RULES"
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix \"[SysWarden-BLOCK] \"" "$UFW_RULES"
        else
            log "WARN" "Standard UFW marker not found. Appending to end of file."
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix \"[SysWarden-BLOCK] \"" >>"$UFW_RULES"
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j DROP" >>"$UFW_RULES"
        fi

        # --- GEOIP INJECTION ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            log "INFO" "Configuring UFW GeoIP Set..."
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!

            sed -i "/$GEOIP_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix \"[SysWarden-GEO] \"" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j LOG --log-prefix \"[SysWarden-GEO] \"" >>"$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $GEOIP_SET_NAME src -j DROP" >>"$UFW_RULES"
            fi
        fi

        # --- ASN INJECTION ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            log "INFO" "Configuring UFW ASN Set..."
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $ASN_SET_NAME /" "$ASN_FILE" | ipset restore -!

            sed -i "/$ASN_SET_NAME/d" "$UFW_RULES"
            if grep -q "# End required lines" "$UFW_RULES"; then
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" "$UFW_RULES"
                sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix \"[SysWarden-ASN] \"" "$UFW_RULES"
            else
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j LOG --log-prefix \"[SysWarden-ASN] \"" >>"$UFW_RULES"
                echo "-A ufw-before-input -m set --match-set $ASN_SET_NAME src -j DROP" >>"$UFW_RULES"
            fi
        fi

        # --- STRICT WIREGUARD SSH CLOAKING & GLOBAL TRUST ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            # Priority 4: Deny public SSH access
            ufw insert 1 deny "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true

            # Priority 3: Allow SSH strictly from the WG Subnet
            ufw insert 1 allow from "${WG_SUBNET}" to any port "${SSH_PORT:-22}" proto tcp >/dev/null 2>&1 || true

            # Priority 2: HOTFIX - Global Trust for WireGuard Interface (Fixes Ping & UI)
            ufw insert 1 allow in on wg0 >/dev/null 2>&1 || true

            # Priority 1: Allow UDP port for WireGuard Tunnel
            ufw insert 1 allow "${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true
        fi

        # --- FIX DEVSECOPS: WHITELIST MUST BE ON TOP ---
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                ufw insert 1 allow from "$wl_ip" >/dev/null 2>&1 || true
            done <"$WHITELIST_FILE"
        fi

        # --- ZERO TRUST: DYNAMIC ALLOW & CATCH-ALL DROP ---
        # 1. Allow discovered ports
        ufw allow "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            for port in $(echo "$ACTIVE_PORTS" | tr ',' ' '); do
                ufw allow "${port}/tcp" >/dev/null 2>&1 || true
            done
        fi

        # 2. Change UFW Default Policy to Deny (Catch-All)
        ufw default deny incoming >/dev/null 2>&1 || true
        # Enable UFW logging so Fail2ban can read the drops
        ufw logging on >/dev/null 2>&1 || true

        ufw reload
        log "INFO" "UFW rules applied."

    else
        # Fallback IPSET / IPTABLES
        ipset create "${SET_NAME}_tmp" hash:net maxelem 1000000 -exist
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore -!
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"

        # --- FIX: IDEMPOTENCY ON RAW TABLE ---
        if ! iptables -t raw -C PREROUTING -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi

        # --- ASN INJECTION (Priority 2) ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "${ASN_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            sed "s/^/add ${ASN_SET_NAME}_tmp /" "$ASN_FILE" | ipset restore -!
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${ASN_SET_NAME}_tmp" "$ASN_SET_NAME"
            ipset destroy "${ASN_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Pushed down by GeoIP later if exists)
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
        fi

        # --- GEOIP INJECTION (Priority 1) ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "${GEOIP_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            # The -! flag is crucial to prevent ipset from crashing if two countries share the same CIDR
            sed "s/^/add ${GEOIP_SET_NAME}_tmp /" "$GEOIP_FILE" | ipset restore -!
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${GEOIP_SET_NAME}_tmp" "$GEOIP_SET_NAME"
            ipset destroy "${GEOIP_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Top priority, enforced before ASN and standard list)
                iptables -t raw -I PREROUTING 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -t raw -I PREROUTING 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
            fi
        fi

        # --- STRICT WIREGUARD SSH CLOAKING & GLOBAL TRUST ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            # Clean existing WG rules first to prevent duplicates
            while iptables -D INPUT -p udp --dport "${WG_PORT:-51820}" -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
            while iptables -D INPUT -i wg0 -j ACCEPT 2>/dev/null; do :; done
            while iptables -D INPUT -i lo -j ACCEPT 2>/dev/null; do :; done

            # Insert top-priority rules (inserted in reverse order so they stack correctly)
            iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j DROP
            iptables -I INPUT 1 -i wg0 -j ACCEPT
            iptables -I INPUT 1 -i lo -j ACCEPT
            iptables -I INPUT 1 -p udp --dport "${WG_PORT:-51820}" -j ACCEPT
        fi

        # ==========================================================
        # >>> ZERO TRUST INJECTION (DYNAMIC ALLOW & CATCH-ALL)
        # ==========================================================

        # --- HOTFIX: IDEMPOTENCY FOR IPTABLES (ANTI-CRON DUPLICATION) ---
        # 1. Allow discovered ports explicitly
        while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT 2>/dev/null; do :; done
        iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            while iptables -D INPUT -p tcp -m multiport --dports "$ACTIVE_PORTS" -j ACCEPT 2>/dev/null; do :; done
            iptables -I INPUT 1 -p tcp -m multiport --dports "$ACTIVE_PORTS" -j ACCEPT
        fi
        # -----------------------------------------------------------------------

        # 2. The Catch-All Drop (Appended to the VERY END of the INPUT chain)
        # Clean old catch-all if it exists
        while iptables -D INPUT -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] " 2>/dev/null; do :; done

        iptables -A INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] "
        iptables -A INPUT -j DROP

        # ==========================================================

        # --- FIX DEVSECOPS: STRICT WHITELIST EVALUATION ---
        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                if ! iptables -C INPUT -s "$wl_ip" -j ACCEPT 2>/dev/null; then
                    iptables -I INPUT 1 -s "$wl_ip" -j ACCEPT
                fi
            done <"$WHITELIST_FILE"
        fi

        # --- ESSENTIAL CONNECTION TRACKING (ALWAYS ACTIVE AT TOP) ---
        while iptables -D INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done
        iptables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

        # Save IPtables persistence for legacy OS
        if command -v netfilter-persistent >/dev/null; then
            netfilter-persistent save
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
    fi

    # --- DOCKER HERMETIC FIREWALL BLOCK ---
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        log "INFO" "Applying Global Rules to Docker (DOCKER-USER chain)..."

        # 1. Standard Blocklist
        if ! ipset list "$SET_NAME" >/dev/null 2>&1; then
            ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
            sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!
        fi

        # 2. Geo-Blocking Set
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            if ! ipset list "$GEOIP_SET_NAME" >/dev/null 2>&1; then
                ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
                sed "s/^/add $GEOIP_SET_NAME /" "$GEOIP_FILE" | ipset restore -!
            fi
        fi

        # 3. ASN-Blocking Set
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            if ! ipset list "$ASN_SET_NAME" >/dev/null 2>&1; then
                ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
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

            # ==============================================================================
            # --- HOTFIX: STATEFUL DOCKER BYPASS (Priority 0 - Absolute Top) ---
            # Ensures outbound traffic (like S3 uploads) never times out on the way back.
            # Executed LAST so it becomes Rule #1 in the DOCKER-USER chain.
            # ==============================================================================
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
            iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
            # ==============================================================================

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
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
        ipset save >/etc/syswarden/ipsets.save 2>/dev/null || true

        cat <<'EOF' >/etc/systemd/system/syswarden-ipset.service
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

discover_active_services() {
    log "INFO" "Scanning User-Space for actively listening TCP services..."
    local detected_ports=""

    # We use 'ss' (modern iproute2) to find all active listening TCP ports
    # Bypassing IPv6 (for now) and local-only (127.0.0.1) binds
    if command -v ss >/dev/null; then
        # Awk parses the 4th column (Local Address:Port) and extracts just the port number
        detected_ports=$(ss -tlnH 2>/dev/null | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    elif command -v netstat >/dev/null; then
        # Fallback for older systems using netstat
        detected_ports=$(netstat -tln 2>/dev/null | grep '^tcp' | grep -v '127.0.0.1' | grep -v '::1' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -nu)
    fi

    # --- HOTFIX: TELNET HONEYPOT FAIL-SAFE ---
    # telnetd is often managed by inetd/systemd.socket and might not show up as a standard listening daemon.
    # If the binary exists, we forcefully open port 23 so the Fail2ban honeypot can trap payloads.
    if command -v telnetd >/dev/null 2>&1 || command -v in.telnetd >/dev/null 2>&1; then
        detected_ports=$(printf "%s\n23" "$detected_ports" | grep -v '^$' | sort -nu)
        log "INFO" "Telnet Honeypot binary detected. Force-whitelisting port 23."
    fi
    # ------------------------------------------------

    # Format the ports into a comma-separated list for easy firewall injection
    if [[ -n "$detected_ports" ]]; then
        ACTIVE_PORTS=$(echo "$detected_ports" | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
        log "INFO" "Whitelisted active services (TCP): [$ACTIVE_PORTS]"
    else
        log "WARN" "No active external services found. Server will be locked down."
        ACTIVE_PORTS="none"
    fi
}

configure_fail2ban() {
    # [UNIVERSAL MODE] Configures services ONLY if they exist to prevent crashes
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS (SCORCHED EARTH) (CWE-1188: Insecure Default Initialization) ---
        # OS package managers silently inject .conf, .local, or symlinks
        # (like defaults-debian.conf) that spawn Ghost Jails like mysqld-auth.
        # We destroy and recreate the directory to guarantee absolute Zero Trust.
        if [[ -d /etc/fail2ban/jail.d ]]; then
            rm -rf /etc/fail2ban/jail.d
        fi

        # Recreate a strictly pristine directory
        mkdir -p /etc/fail2ban/jail.d
        chmod 755 /etc/fail2ban/jail.d

        log "INFO" "Purged fail2ban/jail.d/ directory entirely to enforce absolute Zero Trust."
        # ----------------------------------------------------------------------

        # --- Add backup Fai2ban jail ---
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi
        # -------------------------------------------------------

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
# DEVSECOPS FIX: Prevent SQLite database bloat and memory exhaustion.
# Synchronized to 8 days (691200s) to perfectly match the 1-week findtime of the 'recidive' jail.
dbpurgeage = 691200
EOF

        # 2. Backup
        if [[ -f /etc/fail2ban/jail.local ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 3. HEADER & SSH (Always Active)
        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
            f2b_action="firewallcmd-ipset"
        elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            f2b_action="nftables-multiport"
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then f2b_action="ufw"; fi

        # --- HOTFIX: SYSTEMD BACKEND OPTIMIZATION ---
        local OS_BACKEND="auto"
        if command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-journald 2>/dev/null; then
            OS_BACKEND="systemd"
            log "INFO" "Systemd-journald detected. OS-native jails will be optimized for maximum performance."
        fi
        # ---------------------------------------------------

        # --- HOTFIX: LONG-TERM RECIDIVE FILTER ---
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Replaced greedy '^.*' with absolute strict timestamp and class anchoring.
# This mathematically prevents ReDoS and reduces CPU cycles by 90% during massive horizontal movement tracking.
failregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Ban|Found)\s+<HOST>\s*$
ignoreregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Restore )?(?:Unban|unban)\s+<HOST>\s*$
EOF
        fi
        # ------------------------------------------------

        # --- FIX: DYNAMIC FAIL2BAN INFRASTRUCTURE WHITELIST (ANTI SELF-DOS) ---
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"

        # 1. Dynamically extract Public IP of the server
        local public_ip
        public_ip=$(ip -4 addr show | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | grep -v '127.0.0.1' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi

        # 2. Dynamically extract active direct subnets (Lab & VPC Network protection)
        local local_subnets
        local_subnets=$(ip -4 route | grep -v default | awk '{print $1}' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi

        # 3. Dynamically extract active DNS resolvers
        local dns_ips
        if [[ -f /etc/resolv.conf ]]; then
            dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi

        # 4. Add Custom Whitelist entries
        if [[ -s "$WHITELIST_FILE" ]]; then
            local wl_ips
            wl_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            f2b_ignoreip="$f2b_ignoreip $wl_ips"
        fi

        log "INFO" "Fail2ban infrastructure whitelist enforced: $f2b_ignoreip"
        # ----------------------------------------------------------------------

        cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
banaction = $f2b_action

# --- Persistent Attacker Protection (Recidive) ---
[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $f2b_action
# Policy: 3 bans across ANY jail within 1 week triggers a 1-month absolute drop
maxretry = 3
findtime = 1w
bantime  = 4w

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-22}
logpath = %(sshd_log)s
backend = $OS_BACKEND
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
            # Create Filter for 404/403 scanners
            # RED TEAM FIX: Replaced greedy '.*' with strictly bounded '[^"]*?' to prevent URI-based ReDoS.
            # Expanded HTTP methods to catch evasion techniques.
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/nginx-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405|444)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
            APACHE_LOG="/var/log/apache2/error.log" # Debian/Ubuntu
            APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/error_log" ]]; then
            APACHE_LOG="/var/log/httpd/error_log" # RHEL/CentOS
            APACHE_ACCESS="/var/log/httpd/access_log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."

            # Create Filter for 404/403 scanners (Apache specific)
            # RED TEAM FIX: ReDoS prevention and HTTP method expansion.
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/apache-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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

            # Create strict Filter for Auth failures & Unauthorized commands (Injection probing)
            # RED TEAM FIX: Replaced '^.*' with non-greedy '^.*?' to stop deep engine traversal.
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/mongodb-guard.conf
[Definition]
failregex = ^.*? (?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).*? (?:<HOST>|remote:\s*<HOST>:\d+)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
            # RED TEAM FIX: Non-greedy start and structured matching to prevent log spoofing.
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/mariadb-auth.conf
[Definition]
failregex = ^.*? \[?(?:Note|Warning|ERROR)\]? [Aa]ccess denied for user .*?@'<HOST>'(?: \(using password: (?:YES|NO)\))?
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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

            cat <<EOF >>/etc/fail2ban/jail.local

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

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -n "$APACHE_ACCESS" ]]; then
            WP_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."

            # Create specific filter for WP Login & XMLRPC
            # RED TEAM FIX: Prevent query string evasion and ReDoS by bounding quotes.
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/wordpress-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:wp-login\.php|xmlrpc\.php)[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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

        # 10.5. DYNAMIC DETECTION: DRUPAL CMS
        DRUPAL_LOG=""
        # Check for standard web access logs across OS distributions
        if [[ -n "${APACHE_ACCESS:-}" ]]; then
            DRUPAL_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then DRUPAL_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$DRUPAL_LOG" ]]; then
            log "INFO" "Web logs detected. Enabling Drupal Guard."

            # Create Filter for Drupal Authentication Failures
            # RED TEAM FIX: Prevent query string evasion and ReDoS.
            if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/user/login|\?q=user/login)[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Drupal CMS Protection ---
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
        # Check common paths for Nextcloud log file
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then
                NC_LOG="$path"
                break
            fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."

            # Create Filter (Supports both JSON and Legacy text logs)
            # RED TEAM FIX: Switched to Heredoc and non-greedy start to prevent log parsing lag
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
failregex = ^.*?Login failed: .*? \(Remote IP: '<HOST>'\).*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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

            cat <<EOF >>/etc/fail2ban/jail.local

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
                cat <<'EOF' >/etc/fail2ban/filter.d/zabbix-auth.conf
[Definition]
failregex = ^.*?failed login of user .*? from <HOST>.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                cat <<'EOF' >/etc/fail2ban/filter.d/haproxy-guard.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? (?:400|403|404|429) .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
            if [[ -f "/var/log/kern-firewall.log" ]]; then
                WG_LOG="/var/log/kern-firewall.log"
            elif [[ -f "/var/log/kern.log" ]]; then
                WG_LOG="/var/log/kern.log"
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."

                # Create Filter for Handshake Failures (Requires Kernel Logging)
                if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                    cat <<'EOF' >/etc/fail2ban/filter.d/wireguard.conf
[Definition]
failregex = ^.*?wireguard: .*? Handshake for peer .*? \(<HOST>:\d+\) did not complete.*$
ignoreregex = 
EOF
                fi

                cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -n "$APACHE_ACCESS" ]]; then
            PMA_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        # Check if phpMyAdmin is installed (common paths)
        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/etc/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."

                # Create Filter for POST requests to PMA
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                    cat <<'EOF' >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?phpmyadmin[^"]*? HTTP[^"]*?" 200
ignoreregex = 
EOF
                fi

                cat <<EOF >>/etc/fail2ban/jail.local

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
            if [[ -f "$path" ]]; then
                LARAVEL_LOG="$path"
                break
            fi
        done

        # Fallback: search in /var/www (max depth 4)
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."

            # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
            if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/laravel-auth.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/grafana-auth.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -f "/var/log/mail.log" ]]; then
            SM_LOG="/var/log/mail.log"                                       # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then SM_LOG="/var/log/maillog"; fi # RHEL/Alma

        # Check if Sendmail is installed to avoid conflict with Postfix
        if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
            log "INFO" "Sendmail detected. Enabling Sendmail Jails."

            cat <<EOF >>/etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" >/etc/fail2ban/filter.d/squid-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
            cat <<'EOF' >/etc/fail2ban/action.d/syswarden-docker.conf
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
        if [[ -f "/var/log/mail.log" ]]; then
            DOVECOT_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/maillog" ]]; then DOVECOT_LOG="/var/log/maillog"; fi

        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."

            # Filter for Dovecot Auth Failures (catches standard rip=IP format)
            if [[ ! -f "/etc/fail2ban/filter.d/dovecot-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*\$\nignoreregex =" >/etc/fail2ban/filter.d/dovecot-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^.*pvedaemon\\[\\d+\\]: authentication failure; rhost=<HOST> user=.*\$\nignoreregex =" >/etc/fail2ban/filter.d/proxmox-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn/openvpn.log"
        elif [[ -f "/var/log/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn.log"
        elif [[ -f "/var/log/syslog" ]]; then OVPN_LOG="/var/log/syslog"; fi

        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."

            # Filter for OpenVPN TLS Handshake & Verification Errors
            if [[ ! -f "/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*\$\nignoreregex =" >/etc/fail2ban/filter.d/openvpn-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -f "/var/log/gitea/gitea.log" ]]; then
            GITEA_LOG="/var/log/gitea/gitea.log"
        elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then GITEA_LOG="/var/log/forgejo/forgejo.log"; fi

        if [[ -n "$GITEA_LOG" ]]; then
            log "INFO" "Gitea/Forgejo detected. Enabling Git Server Jail."

            # Filter for Git Web UI Auth Failures
            if [[ ! -f "/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/gitea-custom.conf
[Definition]
failregex = ^.*?Failed authentication attempt for .*? from <HOST>:.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                cat <<'EOF' >/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
failregex = ^.*?cockpit-ws.*?(?:authentication failed|invalid user).*?from <HOST>.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Cockpit Web Console Protection ---
[cockpit-custom]
enabled = true
port    = 9090
filter  = cockpit-custom
logpath = /var/log/secure
backend = $OS_BACKEND
maxretry = 3
bantime  = 24h
EOF
        fi

        # 26. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth-syswarden.log" ]]; then
            AUTH_LOG="/var/log/auth-syswarden.log"
        elif [[ -f "/var/log/auth.log" ]]; then
            AUTH_LOG="/var/log/auth.log"
        elif [[ -f "/var/log/secure" ]]; then AUTH_LOG="/var/log/secure"; fi

        if [[ -n "$AUTH_LOG" ]]; then
            log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."

            # Create Filter for PAM, su, and sudo failures where rhost (Remote Host) is logged
            # This detects internal lateral movement and brute-force attempts on PAM-aware services
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-privesc.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-privesc.conf
[INCLUDES]
before = common.conf

[Definition]
# [DEVSECOPS FIX] Replaced blind '^.*' with strict '^%(__prefix_line)s' to prevent 
# syslog evaluation lag on massive authentication brute-force attacks.
failregex = ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^%(__prefix_line)s PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Privilege Escalation Protection (PAM/Su/Sudo) ---
[syswarden-privesc]
enabled = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port    = 0:65535
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = $OS_BACKEND
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
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
            GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi

        if [[ -n "$GITLAB_LOG" ]]; then
            log "INFO" "GitLab logs detected. Enabling GitLab Guard."

            # Create Filter for GitLab Authentication Failures
            # Catches web UI login failures and API authentication errors
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
        if [[ -f "/var/log/redis/redis-server.log" ]]; then
            REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi

        if [[ -n "$REDIS_LOG" ]]; then
            log "INFO" "Redis logs detected. Enabling Redis Guard."

            # Create Filter for Redis Authentication Failures
            # Covers both legacy 'requirepass' failures and modern Redis 6.0+ ACL failures
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
        if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then
            RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
        fi

        if [[ -n "$RABBIT_LOG" ]]; then
            log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."

            # Create Filter for RabbitMQ Authentication Failures
            # Catches AMQP protocol brute-force and HTTP Management API login failures
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
        if [[ -f "/var/log/kern-firewall.log" ]]; then
            FIREWALL_LOG="/var/log/kern-firewall.log"
        elif [[ -f "/var/log/kern.log" ]]; then
            FIREWALL_LOG="/var/log/kern.log"
        elif [[ -f "/var/log/messages" ]]; then
            FIREWALL_LOG="/var/log/messages"
        elif [[ -f "/var/log/syslog" ]]; then FIREWALL_LOG="/var/log/syslog"; fi

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
backend  = $OS_BACKEND
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
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- System Integrity & Kernel Audit Protection ---
[syswarden-auditd]
enabled  = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = $OS_BACKEND
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
            # FIX: Using regex hex escape '\x25' instead of '%' to strictly bypass Python configparser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
# DEVSECOPS NOTES:
# 1. Replaced '.*' with '[^"]*?' inside the HTTP request string to prevent ReDoS (Catastrophic Backtracking).
# 2. Expanded HTTP methods (DELETE, PATCH, OPTIONS can be used to bypass WAFs).
# 3. Clustered space bypasses: whitespace, URL-encoded space (\x2520), tab (\x2509), and plus sign (+).
# 4. Added command execution chaining (; | ` $) followed by critical binaries.
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc(?:\s+|\x2520|\x2509|\+)+(?:-e|-c)|(?:curl|wget)(?:\s+|\x2520|\x2509|\+)+(?:-q|-s|-O|http)|python(?:\s+|\x2520|\x2509|\+)+-c|php(?:\s+|\x2520|\x2509|\+)+-r|(?:\x253B|;|\x257C|\||`|\x2560|\$|\x2524)(?:\s+|\x2520|\x2509|\+)*(?:bash|sh|nc|curl|wget|chmod)).*?" .*$

ignoreregex = 
EOF
            fi

            # Ensure the jail configuration is appended securely
            # Relying on Fail2ban's default banaction to seamlessly support iptables, nftables, ufw, and firewalld
            cat <<EOF >>/etc/fail2ban/jail.local

# --- Reverse Shell & RCE Injection Protection ---
[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy for RCE payloads
maxretry = 1
findtime = 3600
bantime  = 24h
EOF
        fi

        # 32. DYNAMIC DETECTION: MALICIOUS AI BOTS & SCRAPERS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

            # Create Filter for aggressive AI Scrapers, Crawlers, and LLM data miners
            # RED TEAM FIX: Strictly bound the URI and User-Agent parsing fields to prevent ReDoS payloads in User-Agent strings.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|OPTIONS) [^"]*?" \d{3} [^"]*? "[^"]*?(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai)[^"]*?"
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
            # RED TEAM FIX: Same strict bounds for offensive User-Agents.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) [^"]*?" \d{3} [^"]*? "[^"]*?(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf)[^"]*?"
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
# [DEVSECOPS FIX] Micro-Regex: We only parse up to the timestamp bracket and stop.
# This saves ~85% CPU cycles during a volumetric Layer 7 DDoS attack.
failregex = ^<HOST> \S+ \S+ \[
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

        # 35. DYNAMIC DETECTION: WEBSHELL UPLOADS (LFI / RFI)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling WebShell Upload Guard."

            # Create Filter for malicious file uploads
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads)[^"]*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?[^"]*)? HTTP/[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
# [DEVSECOPS FIX] Replaced '.*' with '[^"]*' inside the HTTP request string to strictly bound
# the evaluation and mathematically prevent ReDoS (Catastrophic Backtracking) on massive payloads.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|PATCH|DELETE) [^"]*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F)[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

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

        # 37. DYNAMIC DETECTION: STEALTH SECRETS & CONFIG HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Stealth Secrets Hunter Guard."

            # Create Filter for sensitive file and config directory bruteforcing
            # Catches: .env, .git, .aws, id_rsa, .sql, .bak, docker-compose, etc.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-secretshunter.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-secretshunter.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/\.env[^ ]*|/\.git/?.*|/\.aws/?.*|/\.ssh/?.*|/id_rsa[^ ]*|/id_ed25519[^ ]*|/[^ ]*\.(?:sql|bak|swp|db|sqlite3?)(?:\.gz|\.zip)?|/docker-compose\.ya?ml|/wp-config\.php\.(?:bak|save|old|txt|zip)) HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Stealth Secrets & Config Hunting Protection ---
[syswarden-secretshunter]
enabled  = true
port     = http,https
filter   = syswarden-secretshunter
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to access a sensitive config file = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 38. DYNAMIC DETECTION: SSRF & CLOUD METADATA EXFILTRATION
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling SSRF & Cloud Metadata Guard."

            # Create Filter for Server-Side Request Forgery targeting Cloud instances
            # Catches: 169.254.169.254 (AWS/GCP/Azure/Linode metadata IP) and common metadata endpoints
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:169\.254\.169\.254|latest/meta-data|metadata\.google\.internal|/v1/user-data|/metadata/v1).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- SSRF & Cloud Metadata Exfiltration Protection ---
[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 39. DYNAMIC DETECTION: JNDI, LOG4J & SSTI PAYLOADS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling JNDI & SSTI Guard."

            # Create Filter for Log4Shell (JNDI) and Server-Side Template Injection (SSTI)
            # Catches: ${jndi:ldap...}, URL-encoded equivalents, and Spring4Shell payloads in URLs AND User-Agents
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

# --- JNDI, Log4Shell & SSTI Injection Protection ---
[syswarden-jndi-ssti]
enabled  = true
port     = http,https
filter   = syswarden-jndi-ssti
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 40. DYNAMIC DETECTION: API MAPPING & SWAGGER HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling API Mapper Guard."

            # Create Filter for API Blueprint Hunting (Swagger, OpenAPI, GraphiQL)
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) [^"]*(?:/swagger-ui[^ "]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ "]*|/graphiql|/graphql/schema) HTTP/[^"]*" (403|404)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- API Mapping & Swagger Hunting Protection ---
[syswarden-apimapper]
enabled  = true
port     = http,https
filter   = syswarden-apimapper
logpath  = $RCE_LOGS
backend  = auto
# Policy: 2 attempts to find hidden API documentation = 48 hours ban
maxretry = 2
bantime  = 48h
EOF
        fi

        # 40.5. DYNAMIC DETECTION: BEHAVIORAL IDOR ENUMERATION & API BRUTE-FORCING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Behavioral IDOR Guard."

            # Create Filter for IDOR (Insecure Direct Object Reference) Enumeration
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-idor-enum.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-idor-enum.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH) [^"]*(?:/api/v[0-9]+/|/users?/|/profile/|/invoices?/|/downloads?/|/docs?/|/id/|/view\?id=)[a-zA-Z0-9_-]+/?(?:[^"]*)? HTTP/[^"]*" (401|403|404)
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

        # 41. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

            # Create Filter for Advanced Local File Inclusion and PHP Wrapper abuse
            # Catches: php://, file://, expect://, /etc/passwd, /etc/shadow, and null byte (%00) injections
            # Note: We use \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
# [DEVSECOPS FIX] Non-greedy bounds applied. Stops parsing exactly at the HTTP quote.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT) [^"]*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb))[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Advanced LFI & Wrapper Abuse Protection ---
[syswarden-lfi-advanced]
enabled  = true
port     = http,https
filter   = syswarden-lfi-advanced
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 42. DYNAMIC DETECTION: VAULTWARDEN (BITWARDEN COMPATIBLE PASSWORD MANAGER)
        VW_LOG=""
        # Search for standard Vaultwarden log paths (Native or Docker mounted)
        for path in "/var/log/vaultwarden/vaultwarden.log" "/vw-data/vaultwarden.log" "/opt/vaultwarden/vaultwarden.log"; do
            if [[ -f "$path" ]]; then
                VW_LOG="$path"
                break
            fi
        done

        if [[ -n "$VW_LOG" ]]; then
            log "INFO" "Vaultwarden logs detected. Enabling Vaultwarden Guard."

            # Create Filter for Vaultwarden Master Password brute-forcing
            # Note: Vaultwarden MUST be configured with LOG_IP_ADDRESSES=true or EXTENDED_LOGGING=true
            # Catches standard Rust backend identity warnings
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

# --- Vaultwarden / Bitwarden Password Manager Protection ---
[syswarden-vaultwarden]
enabled  = true
port     = http,https,80,443,8080
filter   = syswarden-vaultwarden
logpath  = $VW_LOG
backend  = auto
# Zero-Tolerance for the password vault: 3 failed attempts = 24h ban
maxretry = 3
bantime  = 24h
EOF
        fi

        # 43. DYNAMIC DETECTION: IAM & SSO (AUTHELIA / AUTHENTIK)
        SSO_LOG=""
        # Check standard output logs for major open-source SSO providers
        for path in "/var/log/authelia/authelia.log" "/var/log/authentik/authentik.log" "/opt/authelia/authelia.log" "/opt/authentik/authentik.log"; do
            if [[ -f "$path" ]]; then
                SSO_LOG="$path"
                break
            fi
        done

        if [[ -n "$SSO_LOG" ]]; then
            log "INFO" "SSO (Authelia/Authentik) logs detected. Enabling IAM Guard."

            # Create Filter for Identity and Access Management credential stuffing
            # Supports both Authelia (logfmt/JSON) and Authentik (JSON) log formats
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sso.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sso.conf
[Definition]
failregex = ^.*(?:level=error|level=\"error\").*msg=\"Authentication failed\".*remote_ip=\"<HOST>\".*$
            ^.*(?:\"event\":\"Failed login\"|event=\'Failed login\').*(?:\"client_ip\":\"<HOST>\"|\"remote_ip\":\"<HOST>\").*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Authelia / Authentik SSO Protection ---
[syswarden-sso]
enabled  = true
port     = http,https
filter   = syswarden-sso
logpath  = $SSO_LOG
backend  = auto
# Strict policy to prevent SSO compromise
maxretry = 3
bantime  = 24h
EOF
        fi

        # 44. DYNAMIC DETECTION: BEHAVIORAL SILENT SCANNERS (DIRBUSTER/GOBUSTER)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Behavioral Scanner Guard."

            # Create Filter for high-frequency 400/401/403/404/405/444 errors
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-silent-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-silent-scanner.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PROPFIND) [^"]*" (?:400|401|403|404|405|444)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Behavioral Silent Scanner Protection (DirBuster/Gobuster) ---
[syswarden-silent-scanner]
enabled  = true
port     = http,https
filter   = syswarden-silent-scanner
logpath  = $RCE_LOGS
backend  = auto
# Policy: 20 anomalous HTTP errors within 10 seconds triggers an immediate drop
maxretry = 20
findtime = 10
bantime  = 48h
EOF
        fi

        # 45. DYNAMIC DETECTION: OPEN PROXY PROBING & EXOTIC HTTP METHOD ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Open Proxy & Exotic Method Guard."

            # Create Filter for Open Proxy Probing and Tunneling attempts
            # RED TEAM FIX: Non-greedy bounds to prevent ReDoS on massive CONNECT requests.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) [^"]*?" \d{3}
            ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//[^"]*?" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Open Proxy Abuse & Malicious Tunneling Protection ---
[syswarden-proxy-abuse]
enabled  = true
port     = http,https
filter   = syswarden-proxy-abuse
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to use the server as a proxy = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 46. DYNAMIC DETECTION: TELNET HONEYPOT & IOT BOTNETS (MIRAI/GAFGYT)
        TELNET_LOG=""
        # Dynamically aggregate auth and system logs where login/telnetd events are recorded
        for log_file in "/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/auth-syswarden.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$TELNET_LOG" ]]; then
                    TELNET_LOG="$log_file"
                else
                    # HOTFIX: Strict ConfigParser multiline format (newline + 10 spaces)
                    TELNET_LOG+=$'\n          '"$log_file"
                fi
            fi
        done

        # Check if Port 23 is actively listening or if telnetd is installed
        if [[ -n "$TELNET_LOG" ]] && { command -v telnetd >/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -qE ':(23)\b'; }; then
            log "INFO" "Telnet service detected on Port 23. Enabling IoT Botnet Guard."

            # Create Filter for Telnet Brute-force and IoT Botnet probing
            # Catches:
            # 1. Raw tcpwrapper/xinetd telnetd connections (excessive probing)
            # 2. FAILED LOGIN from standard OS /bin/login (which telnetd pipes to)
            # 3. PAM authentication failures strictly tied to the 'login' service
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

# --- Telnet Honeypot & IoT Botnet Protection (Mirai/Gafgyt) ---
[syswarden-telnet]
enabled  = true
port     = 23,telnet
filter   = syswarden-telnet
logpath  = $TELNET_LOG
backend  = auto
# Purple Team Policy: Allow 3 attempts to capture the attacker's payload/credentials in logs for Threat Intel, then drop.
maxretry = 3
findtime = 10m
bantime  = 48h
EOF
        fi

        # 47. DYNAMIC DETECTION: GENERIC BRUTE-FORCE & PASSWORD SPRAYING (HTML/PHP LOGINS)
        # Relies on $RCE_LOGS aggregated earlier in the script
        if [[ -n "${RCE_LOGS:-}" ]]; then
            log "INFO" "Web access logs detected. Enabling Generic Brute-Force & Password Spraying Guard."

            # Create Filter for generic login endpoints
            # RED TEAM FIX: Removed inner greedy match to prevent regex engine exhaustion on fake auth endpoints.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-generic-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-generic-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login|/sign-in|/signin|/log-in|/auth|/authenticate|/admin/login|/user/login|/member/login)[^"]*?(?:\.php|\.html|\.htm|\.jsp|\.aspx)?[^"]*?" (?:200|401|403)
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

        # 48. DYNAMIC DETECTION: ODOO ERP
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
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-odoo.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-odoo.conf
[Definition]
failregex = ^.*? \d+ INFO \S+ odoo\.addons\.base\.models\.res_users: Login failed for db:.*? login:.*? from <HOST>.*$
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

        # 49. DYNAMIC DETECTION: PRESTASHOP E-COMMERCE
        if [[ -n "$RCE_LOGS" ]]; then
            # PrestaShop often runs on the main web server logs
            # We check if it's potentially a web hosting server
            log "INFO" "Web access logs detected. Enabling PrestaShop Guard."

            # Create Filter for PrestaShop Backoffice Brute-Force
            # RED TEAM FIX: Bounded the URI parsing to strictly prevent query string ReDoS.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-prestashop.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-prestashop.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?index\.php\?[^"]*?controller=AdminLogin[^"]*?" 200
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

        # 50. DYNAMIC DETECTION: ATLASSIAN JIRA & CONFLUENCE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Atlassian Guard."

            # Create Filter for Jira and Confluence Auth Failures
            # RED TEAM FIX: Strict non-greedy bounds inside the HTTP method quotes.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-atlassian.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-atlassian.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login\.jsp|/dologin\.action|/rest/auth/\d+/session)[^"]*?" (?:401|403|200)
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

        # 51. DYNAMIC DETECTION: DOLIBARR ERP & CRM
        if [[ -n "$RCE_LOGS" ]]; then
            # We check if Dolibarr might be present (optional check to avoid overlapping generic index.php rules,
            # but relying on RCE_LOGS is standard for Syswarden web guards).
            log "INFO" "Web access logs detected. Enabling Dolibarr ERP Guard."

            # Create Filter for Dolibarr Authentication Failures
            # RED TEAM FIX: Strict non-greedy bounds inside the HTTP method quotes.
            # Rationale: Dolibarr Web UI returns HTTP 200 on failed logins (form reload).
            # The REST API returns 401/403. We catch both vectors strictly on POST requests.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-dolibarr.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-dolibarr.conf
[Definition]
# [DEVSECOPS FIX] Bounded the URI parsing to strictly prevent query string ReDoS.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/htdocs/index\.php|/index\.php|/api/index\.php/login)[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Dolibarr ERP & CRM Protection ---
[syswarden-dolibarr]
enabled  = true
port     = http,https
filter   = syswarden-dolibarr
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # --- HOTFIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
            chown root:root /var/log/fail2ban.log 2>/dev/null || true
        fi
        # ------------------------------------------------------

        log "INFO" "Starting Fail2ban service..."
        if command -v systemctl >/dev/null; then
            systemctl enable --now fail2ban >/dev/null 2>&1 || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
        else
            fail2ban-client reload >/dev/null 2>&1 || true
        fi

        # --- HOTFIX: ALMALINUX/RHEL SOCKET RACE CONDITION ---
        # Wait dynamically for the Python daemon to compile the jails and bind the socket.
        # This prevents 'Failed to access socket' errors in the subsequent Steps.
        log "INFO" "Waiting for Fail2ban socket to initialize (Polling)..."
        for _ in {1..10}; do
            if fail2ban-client ping >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        # ----------------------------------------------------
    fi
}

setup_wireguard() {
    if [[ "${USE_WIREGUARD:-n}" != "y" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring WireGuard VPN ===${NC}"

    # 1. IDEMPOTENCY CHECK: Never overwrite existing keys!
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        log "INFO" "WireGuard configuration already exists. Skipping key generation to prevent VPN lockout."
        return
    fi

    log "INFO" "Initializing WireGuard cryptographic engine..."

    # 2. STRICT DIRECTORY SANDBOXING
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    chmod 700 /etc/wireguard/clients

    # 3. KERNEL ROUTING (IP FORWARDING)
    # Required for the VPN tunnel to access the internet and internal services
    log "INFO" "Enabling Kernel IPv4 Forwarding..."
    echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/99-syswarden-wireguard.conf
    sysctl -p /etc/sysctl.d/99-syswarden-wireguard.conf >/dev/null 2>&1 || true

    # 4. SECURE IN-MEMORY KEY GENERATION
    # Using local variables prevents keys from leaking into stdout or logs
    local SERVER_PRIV
    SERVER_PRIV=$(wg genkey)
    local SERVER_PUB
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    local CLIENT_PRIV
    CLIENT_PRIV=$(wg genkey)
    local CLIENT_PUB
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    local PRESHARED_KEY
    PRESHARED_KEY=$(wg genpsk)

    # 5. DYNAMIC NETWORK CALCULATIONS
    local ACTIVE_IF
    ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n 1)
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

    local SERVER_IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
        curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null ||
        curl -4 -s --connect-timeout 3 icanhazip.com 2>/dev/null ||
        ip -4 addr show "$ACTIVE_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

    # Safely extract base network (e.g., 10.66.66.0/24 -> 10.66.66)
    local SUBNET_BASE
    SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
    local SERVER_VPN_IP="${SUBNET_BASE}.1"
    local CLIENT_VPN_IP="${SUBNET_BASE}.2"

    # 6. DYNAMIC FIREWALL NAT (MASQUERADE)
    # Adapts WireGuard PostUp/PostDown hooks to the active firewall engine
    local POSTUP=""
    local POSTDOWN=""

    case "$FIREWALL_BACKEND" in
        "nftables")
            # NATIVE DEBIAN/UBUNTU
            # HOTFIX: We use single quotes around nft commands to avoid \' escaping issues in wg-quick.
            # We also explicitly inject FORWARD rules to allow internet access through the VPN.
            POSTUP="nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname \"$ACTIVE_IF\" masquerade'; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname \"wg0\" accept'; nft 'insert rule inet filter forward oifname \"wg0\" accept'"
            POSTDOWN="nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname \"wg0\" accept 2>/dev/null || true; nft delete rule inet filter forward oifname \"wg0\" accept 2>/dev/null || true"
            ;;
        "firewalld")
            # --- FIX ALMA/RHEL 10: NATIVE FIREWALLD ROUTING ---
            # No iptables/nft hacks. Firewalld handles NAT natively via its trusted zone.
            POSTUP=""
            POSTDOWN=""
            ;;
        *)
            # Fallback for UFW / Alpine Legacy
            POSTUP="iptables -t nat -I POSTROUTING 1 -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT"
            POSTDOWN="iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true"
            ;;
    esac

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS (CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition) ---
    # Enclosing file creation in a umask 077 subshell to ensure native 600 permissions
    (
        umask 077

        # 7. WRITE SERVER CONFIGURATION (wg0.conf)
        log "INFO" "Deploying WireGuard Server Profile..."
        cat <<EOF >/etc/wireguard/wg0.conf
# SysWarden WireGuard Server Configuration
[Interface]
Address = ${SERVER_VPN_IP}/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
PostUp = $POSTUP
PostDown = $POSTDOWN

[Peer]
# Admin Workstation Client
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF

        # 8. WRITE CLIENT CONFIGURATION (admin-pc.conf)
        log "INFO" "Generating Secure Client Profile..."
        cat <<EOF >/etc/wireguard/clients/admin-pc.conf
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
    )
    # -----------------------------------------------------------
    chmod 600 /etc/wireguard/clients/admin-pc.conf

    # 9. SERVICE ORCHESTRATION
    log "INFO" "Starting WireGuard Tunnel Interface (wg0)..."
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || true
    fi

    log "INFO" "WireGuard VPN deployed successfully."

    # --- FIX: Restore default OS umask to prevent strict permission leaks to other functions ---
    umask 022
}

display_wireguard_qr() {
    # This runs at the VERY END to display the QR code cleanly without interrupting logs
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -f "/etc/wireguard/clients/admin-pc.conf" ]]; then
        echo -e "\n${RED}========================================================================${NC}"
        echo -e "${YELLOW}           WIREGUARD MANAGEMENT VPN - SCAN TO CONNECT${NC}"
        echo -e "${RED}========================================================================${NC}\n"

        # Generates a high-contrast ANSI UTF-8 QR Code directly in the terminal
        qrencode -t ansiutf8 </etc/wireguard/clients/admin-pc.conf

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

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS (CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition) ---
    # We use a subshell with a strict umask (077). This mathematically guarantees
    # that the configuration files are created with 600 permissions natively.
    (
        umask 077

        # 3. Cryptography
        CLIENT_PRIV=$(wg genkey)
        CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
        PRESHARED_KEY=$(wg genpsk)

        # 4. Extract Server Params
        SERVER_PUB=$(grep "PublicKey" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')
        ENDPOINT=$(grep "Endpoint" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')

        # 5. IP Calculation (Find highest IP and increment)
        SUBNET_BASE=$(grep "Address" "$wg_conf" | head -n 1 | awk -F'= ' '{print $2}' | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3}')
        LAST_OCTET=$(grep "AllowedIPs" "$wg_conf" | awk -F'= ' '{print $2}' | cut -d'/' -f1 | awk -F'.' '{print $4}' | sort -n | tail -n 1)

        NEXT_OCTET=$((LAST_OCTET + 1))
        if [[ "$NEXT_OCTET" -ge 254 ]]; then
            log "ERROR" "Subnet exhausted. No more IPs available."
            exit 1
        fi
        CLIENT_VPN_IP="${SUBNET_BASE}.${NEXT_OCTET}"

        # 6. Append to Server Config
        log "INFO" "Registering $client_name with IP $CLIENT_VPN_IP..."
        echo -e "\n# Client: $client_name\n[Peer]\nPublicKey = $CLIENT_PUB\nPresharedKey = $PRESHARED_KEY\nAllowedIPs = ${CLIENT_VPN_IP}/32" >>"$wg_conf"

        # 7. Create Client Config
        cat <<EOF >"$client_conf"
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
    )
    # -----------------------------------------------------------
    chmod 600 "$client_conf"

    # 8. Hot-Reload WireGuard Interface
    log "INFO" "Reloading WireGuard interface..."
    if command -v wg >/dev/null && wg show wg0 >/dev/null 2>&1; then
        # Hot reload without dropping connection
        wg syncconf wg0 <(wg-quick strip wg0)
    else
        # Fallback if interface is down
        if command -v systemctl >/dev/null; then
            systemctl restart wg-quick@wg0 2>/dev/null || true
        elif command -v rc-service >/dev/null; then rc-service wg-quick restart 2>/dev/null || true; fi
    fi

    # 9. Display Output
    echo -e "\n${RED}========================================================================${NC}"
    echo -e "${YELLOW}           WIREGUARD CLIENT: ${client_name^^}${NC}"
    echo -e "${RED}========================================================================${NC}\n"
    qrencode -t ansiutf8 <"$client_conf"
    echo -e "\n${GREEN}[✔] Client Configuration File Saved At:${NC} $client_conf"
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

        # --- HOTFIX: Strict Validation with CI/CD Auto-Mode support ---
        if [[ "${1:-}" == "auto" ]]; then
            USER_API_KEY=${SYSWARDEN_ABUSE_API_KEY:-""}
            if [[ -n "$USER_API_KEY" && ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                log "ERROR" "Auto Mode: Invalid SYSWARDEN_ABUSE_API_KEY format. Must be exactly 80 lowercase letters/numbers. Skipping reporting setup."
                return
            fi
        else
            while true; do
                read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
                if [[ -z "$USER_API_KEY" ]]; then
                    break
                elif [[ ! "$USER_API_KEY" =~ ^[a-z0-9]{80}$ ]]; then
                    echo -e "${RED}ERROR: Invalid API Key format. It must contain exactly 80 lowercase letters and numbers.${NC}"
                else
                    echo -e "${GREEN}[✔] API Key syntax validated.${NC}"
                    break
                fi
            done
        fi
        # ---------------------------------------------------------------------

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
    
    # --- BUG FIX: MULTIPLEXING FLAT FILES VS JOURNALCTL ---
    logs_to_tail = []
    for log_path in ['/var/log/kern-firewall.log', '/var/log/kern.log', '/var/log/syslog', '/var/log/messages', '/var/log/fail2ban.log']:
        if os.path.exists(log_path):
            logs_to_tail.append(log_path)
            
    # DEVSECOPS FIX: We route stderr to STDOUT so permission errors are caught by journalctl instead of being swallowed.
    if logs_to_tail:
        f = subprocess.Popen(['tail', '-F', '-n', '0', '-q'] + logs_to_tail, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        # Fallback if no physical logs exist
        f = subprocess.Popen(['journalctl', '-f', '-n', '0', '-o', 'cat'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    p = select.poll()
    p.register(f.stdout)

    # v0.27.4 Logic: Universal Firewall Netfilter Regex (Matches Standard, Docker, GeoIP and ASN)
    regex_fw = re.compile(r"\[SysWarden-(BLOCK|DOCKER|GEO|ASN)\].*?SRC=([\d\.]+)")
    regex_dpt = re.compile(r"DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            
            # DEVSECOPS FIX: CPU Time-Bomb Prevention. 
            # If tail dies or hits EOF, it returns an empty string. We must break out.
            if not line:
                print("[FATAL] Log process died or reached EOF. Exiting to allow Systemd to restart the service.", flush=True)
                break

            # --- FIREWALL LOGIC ---
            if ENABLE_FW:
                match_fw = regex_fw.search(line)
                if match_fw:
                    fw_type = match_fw.group(1) # Extract BLOCK, DOCKER, GEO or ASN
                    ip = match_fw.group(2)
                    
                    # Dynamic port extraction (Fallback to Port 0 for ICMP/IGMP)
                    match_port = regex_dpt.search(line)
                    port = int(match_port.group(1)) if match_port else 0
                    
                    # Base: Scanning for open ports and vulnerable services (Cat 14)
                    cats = ["14"]
                    attack_type = "Port Scan / Probing"

                    # Dynamic AbuseIPDB comment customization based on L2/L3 source
                    if fw_type == "GEO":
                        attack_type = "Traffic from Blocked Country (GeoIP)"
                    elif fw_type == "ASN":
                        attack_type = "Traffic from Malicious Hoster (ASN)"
                    elif port in [80, 443, 4443, 8080, 8443]: cats.extend(["15", "21"]); attack_type = "Web Attack"
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

        # Replace placeholders based on user choices
        local PY_F2B="False"
        if [[ "$REPORT_F2B" =~ ^[Yy]$ ]]; then PY_F2B="True"; fi
        local PY_FW="False"
        if [[ "$REPORT_FW" =~ ^[Yy]$ ]]; then PY_FW="True"; fi

        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_F2B/$PY_F2B/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_FW/$PY_FW/" /usr/local/bin/syswarden_reporter.py

        # --- SECURITY FIX: SECURE ABUSEIPDB API KEY (CWE-732: Incorrect Permission Assignment for Critical Resource) ---
        # The python script contains the API key in plain text.
        # We enforce absolute root ownership so no non-privileged user can view the code.
        chown root:root /usr/local/bin/syswarden_reporter.py
        chmod 700 /usr/local/bin/syswarden_reporter.py
        # ----------------------------------------------

        log "INFO" "Creating systemd service for Reporter..."
        cat <<EOF >/etc/systemd/system/syswarden-reporter.service
[Unit]
Description=SysWarden Unified Reporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syswarden_reporter.py
Restart=always

# --- SECURITY & LEAST PRIVILEGE ---
# DEVSECOPS FIX: Removed DynamicUser=yes. The telemetry script MUST have the right 
# to read /var/log/kern-firewall.log which is strictly locked to root (600) to prevent log spoofing.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# Ensure script can write its cache file securely 
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

setup_siem_logging() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SIEM_ENABLED:-}" ]]; then SIEM_ENABLED="n"; fi
        log "INFO" "Update Mode: Preserving SIEM Log Forwarding setting ($SIEM_ENABLED)"
        return
    fi

    echo -e "\n${BLUE}=== Step: SIEM Log Forwarding (ISO 27001/NIS2) ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        SIEM_ENABLED=${SYSWARDEN_SIEM_ENABLED:-n}
        SIEM_IP=${SYSWARDEN_SIEM_IP:-""}
        SIEM_PORT=${SYSWARDEN_SIEM_PORT:-514}
        SIEM_PROTO=${SYSWARDEN_SIEM_PROTO:-udp}

        # --- SECURITY FIX: Strict Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ "$SIEM_ENABLED" =~ ^[Yy]$ ]]; then
            if ! [[ "$SIEM_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then
                log "ERROR" "Auto Mode: Invalid SIEM_IP hostname/IP format. Disabling SIEM."
                SIEM_ENABLED="n"
            fi
            if ! [[ "$SIEM_PORT" =~ ^[0-9]+$ ]] || [ "$SIEM_PORT" -lt 1 ] || [ "$SIEM_PORT" -gt 65535 ]; then
                log "WARN" "Auto Mode: Invalid SIEM_PORT. Defaulting to 514."
                SIEM_PORT=514
            fi
            SIEM_PROTO=$(echo "$SIEM_PROTO" | tr '[:upper:]' '[:lower:]')
            if [[ "$SIEM_PROTO" != "tcp" && "$SIEM_PROTO" != "udp" ]]; then
                log "WARN" "Auto Mode: Invalid SIEM_PROTO. Defaulting to udp."
                SIEM_PROTO="udp"
            fi
        fi
        # -----------------------------------------------------
        log "INFO" "Auto Mode: SIEM config loaded via env vars."
    else
        echo "Forward EXCLUSIVELY Fail2ban L7 attack logs to an external SIEM?"
        read -p "Enable SIEM Forwarding? (y/N): " response_siem
        if [[ "$response_siem" =~ ^[Yy]$ ]]; then
            SIEM_ENABLED="y"

            # --- SECURITY FIX: STRICT INPUT VALIDATION LOOPS (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter SIEM IP/Hostname: " SIEM_IP
                # Basic Hostname/IP validation (alphanumeric, dots, hyphens)
                if [[ "$SIEM_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then break; else echo -e "${RED}Invalid IP/Hostname format.${NC}"; fi
            done

            while true; do
                read -p "Enter SIEM Port [Default: 514]: " SIEM_PORT
                SIEM_PORT=${SIEM_PORT:-514}
                if [[ "$SIEM_PORT" =~ ^[0-9]+$ ]] && [ "$SIEM_PORT" -ge 1 ] && [ "$SIEM_PORT" -le 65535 ]; then break; else echo -e "${RED}Invalid Port. Must be between 1 and 65535.${NC}"; fi
            done

            while true; do
                read -p "Enter SIEM Protocol (tcp/udp) [Default: udp]: " SIEM_PROTO
                SIEM_PROTO=${SIEM_PROTO:-udp}
                SIEM_PROTO=$(echo "$SIEM_PROTO" | tr '[:upper:]' '[:lower:]')
                if [[ "$SIEM_PROTO" == "tcp" || "$SIEM_PROTO" == "udp" ]]; then break; else echo -e "${RED}Must be tcp or udp.${NC}"; fi
            done
        else
            SIEM_ENABLED="n"
        fi
    fi

    echo "SIEM_ENABLED='$SIEM_ENABLED'" >>"$CONF_FILE"
    if [[ "$SIEM_ENABLED" == "y" ]] && [[ -n "$SIEM_IP" ]]; then
        echo "SIEM_IP='$SIEM_IP'" >>"$CONF_FILE"
        echo "SIEM_PORT='$SIEM_PORT'" >>"$CONF_FILE"
        echo "SIEM_PROTO='$SIEM_PROTO'" >>"$CONF_FILE"

        log "INFO" "Configuring Rsyslog to forward ONLY Fail2ban logs to SIEM..."

        cat <<EOF >/etc/rsyslog.d/99-syswarden-siem.conf
# SysWarden SIEM Forwarder - Exclusive Fail2ban Routing
module(load="imfile")

input(type="imfile"
      File="/var/log/fail2ban.log"
      Tag="fail2ban"
      Severity="warning"
      Facility="local7")

if \$programname == 'fail2ban' then {
    action(type="omfwd" target="$SIEM_IP" port="$SIEM_PORT" protocol="$SIEM_PROTO")
    stop
}
EOF
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart rsyslog 2>/dev/null || true
        else
            service rsyslog restart 2>/dev/null || true
        fi
        log "INFO" "SIEM Log Forwarding is ACTIVE. (Target: $SIEM_IP:$SIEM_PORT/$SIEM_PROTO)"
    else
        log "INFO" "SIEM Log Forwarding DISABLED."
        rm -f /etc/rsyslog.d/99-syswarden-siem.conf
        if command -v systemctl >/dev/null 2>&1; then systemctl restart rsyslog 2>/dev/null || true; fi
    fi
}

setup_cron_autoupdate() {
    # No manuel cron update function
    if [[ "${1:-}" != "update" ]] && [[ "${1:-}" != "cron-update" ]]; then
        local script_path
        script_path=$(realpath "$0")
        local cron_file="/etc/cron.d/syswarden-update"
        local random_min=$((RANDOM % 60))

        # FIX DEVSECOPS
        echo "$random_min * * * * root $script_path cron-update >/dev/null 2>&1" >"$cron_file"
        chmod 644 "$cron_file"

        log "INFO" "Automatic updates enabled."

        cat <<EOF >/etc/logrotate.d/syswarden
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

# ==============================================================================
# Function: uninstall_syswarden
# Purpose: Safely and completely removes SysWarden and all its components.
#          Restores the system to its pre-installation state (Scorched Earth).
# Arguments: None
# Returns: 0 on successful removal, exits 1 on critical failure.
# ==============================================================================
uninstall_syswarden() {
    # --- DEFENSE IN DEPTH: Absolute Privilege Check ---
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "CRITICAL: uninstall_syswarden() must be executed as root."
        exit 1
    fi

    echo -e "\n${RED}=== Uninstalling SysWarden ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation (Scorched Earth)..."

    # --- LOCAL VARIABLE DECLARATIONS (Strict Scope Enforcement) ---
    local os_log
    local filter
    local rule
    local handle
    local user_dir
    local profile_file
    local rm_wazuh="N"
    local active_jails
    local user
    local grp
    local members

    # Load config to retrieve variables
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # --- DEVSECOPS FIX: GRACEFUL TO SCORCHED EARTH TERMINATION ---
    # We first send SIGTERM (-15) to allow daemons to cleanly close file descriptors and SQLite transactions.
    log "INFO" "Sending SIGTERM to gracefully shutdown background processes..."
    pkill -15 -f "^/bin/bash.*syswarden-telemetry" 2>/dev/null || true
    pkill -15 -f "syswarden_reporter.py" 2>/dev/null || true
    pkill -15 -f "syswarden-ui-server.py" 2>/dev/null || true
    pkill -15 -f "syswarden-ui-sync" 2>/dev/null || true

    # Wait for I/O buffers to flush natively
    sleep 2

    # Hunt down any surviving orphans (Absolute SIGKILL)
    log "INFO" "Executing Scorched Earth (SIGKILL) on surviving orphans..."
    pkill -9 -f "^/bin/bash.*syswarden-telemetry" 2>/dev/null || true
    pkill -9 -f "syswarden_reporter.py" 2>/dev/null || true
    pkill -9 -f "syswarden-ui-server.py" 2>/dev/null || true
    pkill -9 -f "syswarden-ui-sync" 2>/dev/null || true
    # -------------------------------------------------------------

    # 1. Stop & Remove Reporter Service
    log "INFO" "Removing SysWarden Reporter..."
    systemctl disable --now syswarden-reporter 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-reporter.service /usr/local/bin/syswarden_reporter.py

    log "INFO" "Removing IPSet Restorer Service..."
    systemctl disable --now syswarden-ipset 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-ipset.service /etc/syswarden/ipsets.save

    log "INFO" "Removing UI Dashboard Service & Audit Tools..."
    systemctl disable --now syswarden-ui 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-ui.service /usr/local/bin/syswarden-telemetry.sh /usr/local/bin/syswarden-ui-server.py /usr/local/bin/syswarden-ui-sync.sh
    rm -rf /etc/syswarden/ui
    rm -f /var/log/syswarden-audit.log

    # --- HA CLUSTER ENGINE PURGE ---
    log "INFO" "Removing HA Cluster Sync Engine..."
    rm -f /usr/local/bin/syswarden-sync.sh
    if crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
        crontab -l 2>/dev/null | grep -v "syswarden-sync" | crontab -
    fi
    # --------------------------------------------

    # --- HOTFIX: SCORCHED EARTH TELEMETRY PURGE ---
    # Destroys any hidden databases or dashboard memory files
    rm -rf /var/log/syswarden 2>/dev/null || true
    rm -rf /opt/syswarden 2>/dev/null || true
    # -----------------------------------------------------

    systemctl daemon-reload

    # --- HOTFIX: SURGICAL WIREGUARD CLEANUP ---
    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        log "INFO" "Stopping and removing SysWarden WireGuard VPN..."
        if command -v systemctl >/dev/null; then
            systemctl disable --now wg-quick@wg0 >/dev/null 2>&1 || true
        fi

        # Only remove SysWarden configs, protect user's custom WireGuard tunnels
        rm -f /etc/wireguard/wg0.conf
        rm -rf /etc/wireguard/clients
        if [[ -d /etc/wireguard ]] && [[ -z "$(ls -A /etc/wireguard 2>/dev/null)" ]]; then
            rmdir /etc/wireguard 2>/dev/null || true
        fi

        rm -f /etc/sysctl.d/99-syswarden-wireguard.conf
        sysctl --system >/dev/null 2>&1 || true

        # Clean firewall & RESTORE PUBLIC SSH
        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
            firewall-cmd --permanent --remove-port="${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true
            firewall-cmd --permanent --remove-rich-rule="rule priority='-1000' family='ipv4' source address='${WG_SUBNET}' port port='${SSH_PORT:-22}' protocol='tcp' accept" >/dev/null 2>&1 || true
            firewall-cmd --permanent --add-port="${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
            firewall-cmd --reload >/dev/null 2>&1 || true
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
            ufw delete allow "${WG_PORT:-51820}/udp" >/dev/null 2>&1 || true
            ufw delete allow from "${WG_SUBNET}" to any port "${SSH_PORT:-22}" proto tcp >/dev/null 2>&1 || true
            ufw delete deny "${SSH_PORT:-22}/tcp" >/dev/null 2>&1 || true
            ufw reload >/dev/null 2>&1 || true
        elif command -v iptables >/dev/null; then
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
        fi
    fi
    # -------------------------------------------------

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    rm -f "/etc/cron.d/syswarden-update"
    rm -f "/etc/logrotate.d/syswarden"
    # Edge case cleanup for crontabs
    if [[ -f /etc/crontabs/root ]]; then sed -i '/syswarden/d' /etc/crontabs/root 2>/dev/null || true; fi

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."

    if command -v nft >/dev/null; then
        # --- NETDEV TABLE PURGE (L2 HARDWARE DROP) ---
        nft delete table netdev syswarden_hw_drop 2>/dev/null || true
        # -------------------------------------------------------------
        nft delete table inet syswarden_table 2>/dev/null || true
        # HOTFIX: Purge WG NAT table left by PostUp
        nft delete table inet syswarden_wg 2>/dev/null || true
        rm -f /etc/syswarden/syswarden.nft

        # --- DEVSECOPS FIX: BULLETPROOF NFTABLES GHOST RULE PURGE ---
        for rule in 'tcp dport 9999 accept' 'udp dport 51820 accept' 'iifname "wg0" accept' 'oifname "wg0" accept'; do
            # Clean INPUT chain
            while nft -a list chain inet filter input 2>/dev/null | grep -q "$rule"; do
                handle=$(nft -a list chain inet filter input 2>/dev/null | grep "$rule" | grep -oE 'handle [0-9]+' | awk '{print $2}' | head -n 1)
                if [[ -n "$handle" ]]; then
                    nft delete rule inet filter input handle "$handle" 2>/dev/null || true
                else
                    log "WARN" "SAFEGUARD: Could not extract handle in INPUT chain. Breaking loop."
                    break
                fi
            done
            # Clean FORWARD chain
            while nft -a list chain inet filter forward 2>/dev/null | grep -q "$rule"; do
                handle=$(nft -a list chain inet filter forward 2>/dev/null | grep "$rule" | grep -oE 'handle [0-9]+' | awk '{print $2}' | head -n 1)
                if [[ -n "$handle" ]]; then
                    nft delete rule inet filter forward handle "$handle" 2>/dev/null || true
                else
                    log "WARN" "SAFEGUARD: Could not extract handle in FORWARD chain. Breaking loop."
                    break
                fi
            done
        done
        # -------------------------------------------------------------

        if [[ -f "/etc/nftables.conf" ]]; then
            sed -i '\|include "/etc/syswarden/syswarden.nft"|d' /etc/nftables.conf
            sed -i '/# Added by SysWarden/d' /etc/nftables.conf

            # HOTFIX: Persist the cleaned table!
            if grep -q "flush ruleset" /etc/nftables.conf; then
                echo '#!/usr/sbin/nft -f' >/etc/nftables.conf
                echo 'flush ruleset' >>/etc/nftables.conf
                nft list table inet filter >>/etc/nftables.conf 2>/dev/null || true
            fi
        fi
    fi

    if [[ -f "/etc/ufw/before.rules" ]]; then
        sed -i "/$SET_NAME/d" /etc/ufw/before.rules
        sed -i "/$GEOIP_SET_NAME/d" /etc/ufw/before.rules
        sed -i "/$ASN_SET_NAME/d" /etc/ufw/before.rules
        if command -v ufw >/dev/null; then ufw reload; fi
    fi

    if command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$GEOIP_SET_NAME' log prefix='[SysWarden-GEO] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$ASN_SET_NAME' log prefix='[SysWarden-ASN] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$ASN_SET_NAME" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$GEOIP_SET_NAME" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$SET_NAME" 2>/dev/null || true
        if [[ -n "${WAZUH_IP:-}" ]]; then
            firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1514' protocol='tcp' accept" 2>/dev/null || true
            firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1515' protocol='tcp' accept" 2>/dev/null || true
        fi
        firewall-cmd --reload 2>/dev/null || true
    fi

    if command -v iptables >/dev/null; then
        # Docker (DOCKER-USER chain)
        if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            while iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null; do :; done
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
        fi

        # IPtables Standard (Purge of IPsets and RAW table)
        while iptables -t raw -D PREROUTING -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] " 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null; do :; done

        while iptables -D INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done

        # --- HOTFIX: IPTABLES-NFT GHOST RULE PURGE ---
        log "INFO" "Purging translated iptables-nft ghost rules..."
        while iptables -D INPUT -p tcp --dport 9999 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -p udp --dport "${WG_PORT:-51820}" -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -i wg0 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null; do :; done
        while iptables -D INPUT -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -j LOG --log-prefix "[SysWarden-BLOCK] [Catch-All] " 2>/dev/null; do :; done
        # ----------------------------------------------------
    fi

    # IPSet Cleanup
    if command -v ipset >/dev/null; then
        ipset destroy "$SET_NAME" 2>/dev/null || true
        ipset destroy "$GEOIP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_SET_NAME" 2>/dev/null || true
    fi

    # Save final iptables state AFTER clearing our stuff
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then
        service iptables save 2>/dev/null || true
    fi

    # --- HOTFIX: DOCKER NETWORK RESURRECTION ---
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
        log "INFO" "Restarting Docker daemon to rebuild NAT & Masquerade routing..."
        systemctl restart docker
        sleep 3
    fi
    # --------------------------------------------------

    # 4. Revert Fail2ban Configuration (State Aware)

    # --- HOTFIX: SCORCHED EARTH FAIL2BAN & TELEMETRY PURGE ---
    log "INFO" "Executing Scorched Earth purge on Fail2ban memory and logs..."

    # 1. Stop services first to release file locks
    systemctl stop fail2ban syswarden-ui syswarden-reporter 2>/dev/null || true

    # 2. Destroy the SQLite database (The CPU/History Killer)
    rm -f /var/lib/fail2ban/fail2ban.sqlite3

    # 3. Truncate historical logs (This clears the "Hits" and "Top IPs" columns)
    if [[ -f /var/log/fail2ban.log ]]; then
        : >/var/log/fail2ban.log
    fi
    rm -f /var/log/fail2ban.log.*

    # =====================================================================
    # --- HOTFIX: SCORCHED EARTH OS LOG SCRUBBING (ANTI-GHOST) ---
    for os_log in "/var/log/messages" "/var/log/syslog" "/var/log/daemon.log"; do
        if [[ -f "$os_log" ]]; then
            sed -i '/\] Ban /d' "$os_log" 2>/dev/null || true
            sed -i '/\] Restore Ban /d' "$os_log" 2>/dev/null || true
        fi
    done

    # Flush the Systemd Journal
    if command -v journalctl >/dev/null 2>&1; then
        journalctl --flush >/dev/null 2>&1 || true
        journalctl --rotate >/dev/null 2>&1 || true
        journalctl --vacuum-time=1s >/dev/null 2>&1 || true
    fi
    # =====================================================================

    # 4. Wipe UI data and telemetry registry
    rm -rf /etc/syswarden/ui/data.json
    rm -rf /var/log/syswarden/* 2>/dev/null || true
    # ----------------------------------------------------------------

    # --- Clean up all SysWarden Fail2ban filters ---
    for filter in nginx-scanner mariadb-auth mongodb-guard syswarden-privesc syswarden-portscan \
        syswarden-revshell syswarden-aibots syswarden-badbots syswarden-httpflood syswarden-webshell \
        syswarden-sqli-xss syswarden-secretshunter syswarden-ssrf syswarden-jndi-ssti syswarden-apimapper \
        syswarden-lfi-advanced syswarden-vaultwarden syswarden-sso syswarden-silent-scanner syswarden-recidive syswarden-generic-auth \
        syswarden-proxy-abuse syswarden-jenkins syswarden-gitlab syswarden-redis syswarden-rabbitmq \
        syswarden-idor-enum syswarden-odoo syswarden-prestashop syswarden-atlassian \
        wordpress-auth drupal-auth nextcloud openvpn-custom gitea-custom cockpit-custom proxmox-custom \
        haproxy-guard phpmyadmin-custom squid-custom dovecot-custom laravel-auth grafana-auth zabbix-auth wireguard; do
        rm -f "/etc/fail2ban/filter.d/${filter}.conf"
    done
    rm -f /etc/fail2ban/action.d/syswarden-docker.conf
    rm -f /etc/fail2ban/jail.local
    rm -f /etc/fail2ban/fail2ban.local

    if [[ "${FAIL2BAN_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Fail2ban (installed by SysWarden)..."
        if [[ -f /etc/debian_version ]]; then apt-get purge -y fail2ban 2>/dev/null || true; else dnf remove -y fail2ban 2>/dev/null || true; fi
    else
        log "INFO" "Restoring default Fail2ban configuration..."
        if [[ -f /etc/fail2ban/jail.local.bak ]]; then
            mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
        else
            cat >/etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = auto
[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = systemd
EOF
        fi
        systemctl restart fail2ban 2>/dev/null || true
    fi

    # 5. Remove UI Dashboard (State Aware for Apache & Nginx)
    # --- HOTFIX: CLEAN UNINSTALL ---
    log "INFO" "Removing Web Server UI configurations..."

    # Apache Cleanup
    rm -f /etc/apache2/sites-available/syswarden-ui.conf
    rm -f /etc/apache2/sites-enabled/syswarden-ui.conf
    rm -f /etc/httpd/conf.d/syswarden-ui.conf

    if systemctl is-active --quiet apache2; then
        systemctl reload apache2 >/dev/null 2>&1 || true
    elif systemctl is-active --quiet httpd; then
        systemctl reload httpd >/dev/null 2>&1 || true
    fi

    # Nginx Cleanup
    rm -f /etc/nginx/conf.d/syswarden-ui.conf
    rm -f /etc/nginx/sites-available/syswarden-ui.conf
    rm -f /etc/nginx/sites-enabled/syswarden-ui.conf

    if systemctl is-active --quiet nginx; then
        systemctl reload nginx >/dev/null 2>&1 || true
    fi

    if [[ "${NGINX_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Nginx (installed by SysWarden)..."
        systemctl stop nginx 2>/dev/null || true
        if [[ -f /etc/debian_version ]]; then
            apt-get purge -y nginx 2>/dev/null || true
        else
            dnf remove -y nginx 2>/dev/null || true
        fi
    fi
    # -----------------------------------------------------

    # 6. Remove Wazuh Agent (With Auto-Mode CI/CD Protection)
    if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q wazuh-agent; then
        # CI/CD SAFEGUARD: Don't hang on read prompt if running unattended
        if [[ "${MODE:-}" == "auto" ]]; then
            log "INFO" "Auto Mode: Skipping Wazuh Agent uninstallation to prevent accidental SIEM disconnection."
            rm_wazuh="N"
        else
            read -r -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        fi

        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            systemctl disable --now wazuh-agent 2>/dev/null || true
            if [[ -f /etc/debian_version ]]; then
                apt-get remove --purge -y wazuh-agent
                rm -f /etc/apt/sources.list.d/wazuh.list /usr/share/keyrings/wazuh.gpg
                apt-get update -qq
            elif [[ -f /etc/redhat-release ]]; then
                dnf remove -y wazuh-agent
                rm -f /etc/yum.repos.d/wazuh.repo
            fi
        fi
    fi

    # --- 7. OS & SECURITY REVERT ---
    log "INFO" "Reverting OS Hardening & Log Routing..."

    # SIEM Forwarding Purge
    rm -f /etc/rsyslog.d/99-syswarden-siem.conf 2>/dev/null || true

    if [[ -f /etc/rsyslog.conf ]]; then
        sed -i '/kern-firewall\.log/d' /etc/rsyslog.conf
        sed -i '/auth-syswarden\.log/d' /etc/rsyslog.conf
        if command -v systemctl >/dev/null; then systemctl restart rsyslog 2>/dev/null || true; fi
    fi

    # Isolated Logs Purge
    rm -f /var/log/kern-firewall.log 2>/dev/null || true
    rm -f /var/log/auth-syswarden.log 2>/dev/null || true

    if command -v chattr >/dev/null; then
        for user_dir in /home/*; do
            if [[ -d "$user_dir" ]]; then
                for profile_file in "$user_dir/.profile" "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                    if [[ -f "$profile_file" ]]; then chattr -i "$profile_file" 2>/dev/null || true; fi
                done
            fi
        done
    fi

    if [[ -f /etc/ssh/sshd_config ]]; then
        sed -i 's/^[[:space:]]*AllowTcpForwarding[[:space:]]*no/#AllowTcpForwarding yes/' /etc/ssh/sshd_config
        if command -v systemctl >/dev/null; then systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true; fi
    fi

    if [[ -f /etc/cron.allow ]] && [[ "$(cat /etc/cron.allow)" == "root" ]]; then rm -f /etc/cron.allow; fi

    # HOTFIX: RESTORE GROUPS
    if [[ -f "$SYSWARDEN_DIR/group_backup.txt" ]]; then
        while IFS=':' read -r grp members; do
            for user in $(echo "$members" | tr ',' ' '); do
                if [[ -n "$user" ]] && id "$user" >/dev/null 2>&1; then usermod -aG "$grp" "$user" 2>/dev/null || true; fi
            done
        done <"$SYSWARDEN_DIR/group_backup.txt"
    fi

    # --- HOTFIX: ABSOLUTE FILE SYSTEM SCORCHED EARTH ---
    rm -rf "$SYSWARDEN_DIR" # This automatically removes /etc/syswarden/ssl (Self-signed certs)
    rm -f "$LOG_FILE"
    rm -f /etc/syswarden.conf
    rm -f /usr/local/bin/syswarden*
    # ----------------------------------------------------------

    log "INFO" "Cleanup complete."
    echo -e "${GREEN}Uninstallation complete (Scorched Earth).${NC}"
    echo -e "${YELLOW}[i] A reboot is recommended to ensure all network routes are completely flushed.${NC}"
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

        # --- SECURITY FIX: Strict Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ -n "$WAZUH_IP" && ! "$WAZUH_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && ! "$WAZUH_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            log "ERROR" "Auto Mode: Invalid WAZUH_IP format. Skipping Wazuh installation."
            return
        fi
        if ! [[ "$W_PORT_COMM" =~ ^[0-9]+$ ]] || [ "$W_PORT_COMM" -lt 1 ] || [ "$W_PORT_COMM" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_COMM. Defaulting to 1514."
            W_PORT_COMM=1514
        fi
        if ! [[ "$W_PORT_ENROLL" =~ ^[0-9]+$ ]] || [ "$W_PORT_ENROLL" -lt 1 ] || [ "$W_PORT_ENROLL" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_ENROLL. Defaulting to 1515."
            W_PORT_ENROLL=1515
        fi
        # -----------------------------------------------------
        log "INFO" "Auto Mode: Wazuh settings loaded via env vars."
    else
        # IP Serveur
        read -p "Enter Wazuh Manager IP: " WAZUH_IP
        if [[ -z "$WAZUH_IP" ]]; then
            log "ERROR" "Missing IP. Skipping."
            return
        fi

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

    # --- SECURITY FIX: SANITIZE WAZUH STRINGS (CWE-20: Improper Input Validation) ---
    # Strip dangerous characters that could break the agent's OS environment exports
    W_NAME=$(echo "$W_NAME" | tr -cd 'a-zA-Z0-9.-')
    W_GROUP=$(echo "$W_GROUP" | tr -cd 'a-zA-Z0-9_-')

    # Fail-Safe
    if [[ -z "$WAZUH_IP" ]]; then
        log "ERROR" "Missing Wazuh IP. Skipping."
        return
    fi

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

        # ### MODULAR PERSISTENCE FIX ###
        log "INFO" "Saving SysWarden Nftables table to isolated config..."
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft
        # Enable service just in case
        systemctl enable nftables >/dev/null 2>&1 || true

    else
        # Fallback Iptables / IPSet
        if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi
    fi

    log "INFO" "Starting Wazuh Agent installation..."

    # 4. OS-Specific Installation Logic with EXPORTS
    # These variables are automatically read by the Wazuh package installer
    export WAZUH_MANAGER="$WAZUH_IP"
    export WAZUH_AGENT_NAME="$W_NAME"
    export WAZUH_AGENT_GROUP="$W_GROUP"
    export WAZUH_MANAGER_PORT="$W_PORT_COMM"        # Custom Agent Port
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
        cat >/etc/yum.repos.d/wazuh.repo <<EOF
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
        echo "WAZUH_IP='$WAZUH_IP'" >>"$CONF_FILE"
        echo "WAZUH_AGENT_NAME='$W_NAME'" >>"$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >>"$CONF_FILE"
        echo "WAZUH_ENROLL_PORT='$W_PORT_ENROLL'" >>"$CONF_FILE"

        log "INFO" "Wazuh Agent '$W_NAME' installed (Group: $W_GROUP, Ports: $W_PORT_COMM/$W_PORT_ENROLL)."
    else
        log "ERROR" "Wazuh Agent installation seemed to fail."
    fi
}

# ==============================================================================
# SYSWARDEN v0.27.4 - TELEMETRY BACKEND
# ==============================================================================
function setup_telemetry_backend() {
    log "INFO" "Installation of the advanced telemetry engine (Backend)..."

    local BIN_PATH="/usr/local/bin/syswarden-telemetry.sh"
    local UI_DIR="/etc/syswarden/ui"

    # 1. Writing the Telemetry Bash script
    cat <<'EOF' >"$BIN_PATH"
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# --- SECURITY FIX: ZOMBIE PROCESS PREVENTION (CWE-400: Uncontrolled Resource Consumption) ---
trap 'wait' EXIT

# --- HOTFIX: ABSOLUTE MUTEX LOCK (ANTI-OVERLAP) ---
LOCK_DIR="/var/run/syswarden"
mkdir -p "$LOCK_DIR"
chmod 700 "$LOCK_DIR"

exec 9>"$LOCK_DIR/telemetry.lock"
if ! flock -n 9; then
    exit 0
fi
# ---------------------------------------------------------

# --- Configuration Paths ---
SYSWARDEN_DIR="/etc/syswarden"
UI_DIR="/etc/syswarden/ui"
TMP_FILE="$UI_DIR/data.json.tmp"
DATA_FILE="$UI_DIR/data.json"

mkdir -p "$UI_DIR"

# --- HOTFIX: UNIVERSAL PACKAGE MANAGER ---
if ! command -v jq >/dev/null; then
    if [[ -f /etc/debian_version ]]; then apt-get install -y jq >/dev/null 2>&1 || true
    elif [[ -f /etc/redhat-release ]]; then dnf install -y jq >/dev/null 2>&1 || true; fi
fi

# --- System Metrics Gathering ---
SYS_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SYS_HOSTNAME=$(hostname)
SYS_UPTIME=$(awk '{d=int($1/86400); h=int(($1%86400)/3600); m=int(($1%3600)/60); if(d>0) printf "%dd %dh %dm", d, h, m; else printf "%dh %dm", h, m}' /proc/uptime 2>/dev/null || echo "Unknown")
SYS_LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}' || echo "0, 0, 0")

SYS_RAM_USED=$(free -m 2>/dev/null | awk '/^Mem:/{print $3}')
SYS_RAM_USED=${SYS_RAM_USED:-0}
SYS_RAM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
SYS_RAM_TOTAL=${SYS_RAM_TOTAL:-0}
# --- System Storage Gathering (Root) ---
SYS_DISK_USED=$(df -m / 2>/dev/null | awk 'NR==2 {print $3}' || echo 0)
SYS_DISK_TOTAL=$(df -m / 2>/dev/null | awk 'NR==2 {print $2}' || echo 1)

# NEW: Hardware and OS specifications
SYS_CORES=$(nproc 2>/dev/null || echo "1")
SYS_ARCH=$(uname -m 2>/dev/null || echo "Unknown")
SYS_OS=$(grep -P '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Linux")
SYS_CPU=$(grep -m 1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed -e 's/^[[:space:]]*//' || echo "Unknown")

# --- Layer 3 Metrics ---
L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

# --- System Services Tracking (Universal Pgrep) ---
SRV_F2B=$(pgrep -f fail2ban-server >/dev/null && echo "active" || echo "offline")
SRV_CRON=$(pgrep -f "cron|crond" >/dev/null && echo "active" || echo "offline")

# --- Mutually Exclusive Web Server Tracking (XOR) ---
if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
    WEB_NAME="apache (worker)"
    WEB_PATH="/usr/sbin/httpd"
    [[ -f /usr/sbin/apache2 ]] && WEB_PATH="/usr/sbin/apache2"
    WEB_STATUS=$(pgrep -f "apache2|httpd" >/dev/null && echo "active" || echo "offline")
else
    WEB_NAME="nginx (worker)"
    WEB_PATH="/usr/sbin/nginx"
    WEB_STATUS=$(pgrep -f "nginx" >/dev/null && echo "active" || echo "offline")
fi

# AbuseIPDB Reporter Tracking (3 States)
if [[ -f "/usr/local/bin/syswarden_reporter.py" ]]; then
    if pgrep -f "syswarden_reporter" >/dev/null; then
        SRV_REP="active"
    else
        SRV_REP="offline"
    fi
else
    SRV_REP="skipped"
fi

# --- DEVSECOPS: Advanced Dynamic Firewall Backend Detection ---
FW_NAME="Unknown Firewall"
FW_PATH="unknown"
FW_STATUS="offline"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
    FW_NAME="ufw (Uncomplicated Firewall)"
    FW_PATH=$(command -v ufw)
    FW_STATUS="active"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qw "running"; then
    FW_NAME="firewalld"
    FW_PATH=$(command -v firewalld || command -v firewall-cmd)
    FW_STATUS="active"
elif command -v nft >/dev/null 2>&1 && { nft list ruleset 2>/dev/null | grep -qE "(table|chain)" || systemctl is-active --quiet nftables 2>/dev/null || rc-service nftables status 2>/dev/null | grep -q "started"; }; then
    FW_NAME="netfilter/nftables"
    FW_PATH=$(command -v nft)
    FW_STATUS="active"
elif command -v iptables >/dev/null 2>&1 && { iptables -nL 2>/dev/null | grep -q "Chain" || systemctl is-active --quiet iptables 2>/dev/null || rc-service iptables status 2>/dev/null | grep -q "started"; }; then
    FW_NAME="iptables"
    FW_PATH=$(command -v iptables)
    FW_STATUS="active"
fi

SERVICES_JSON=$(jq -n \
  --arg f2b "$SRV_F2B" --arg crn "$SRV_CRON" --arg web_name "$WEB_NAME" --arg web_path "$WEB_PATH" --arg web_status "$WEB_STATUS" --arg rep "$SRV_REP" \
  --arg fw_name "$FW_NAME" --arg fw_path "$FW_PATH" --arg fw_status "$FW_STATUS" \
  '[
    {"name":"fail2ban-server","path":"/usr/bin/fail2ban-server","status":$f2b},
    {"name":$fw_name,"path":$fw_path,"status":$fw_status},
    {"name":$web_name,"path":$web_path,"status":$web_status},
    {"name":"cron/crond","path":"/usr/sbin/cron","status":$crn},
    {"name":"syswarden-reporter","path":"/usr/local/bin/syswarden_reporter.py","status":$rep},
    {"name":"syswarden-telemetry","path":"/usr/local/bin/syswarden-telemetry.sh","status":"active"}
  ]')

# --- Network Ports Gathering (ss) ---
PORTS_JSON="[]"
if command -v ss >/dev/null; then
    # DEVSECOPS FIX: Bulletproof awk parsing. Finds the exact IP:Port column regardless of OS shifting (Recv-Q/Send-Q).
    while IFS=" " read -r proto state local_addr; do
        [[ -z "$proto" || -z "$state" || -z "$local_addr" ]] && continue
        
        # Standardize protocol nomenclature
        proto=$(echo "$proto" | tr 'a-z' 'A-Z')
        [[ "$proto" == "TCPV6" ]] && proto="TCP (v6)"
        [[ "$proto" == "UDPV6" ]] && proto="UDP (v6)"
        
        # Fallback if 'ss' omits the State column and shifts an integer (Recv-Q) into the State variable
        if [[ "$state" =~ ^[0-9]+$ ]]; then
            state="ACTIVE"
        fi
        
        # Parse Local IP and Port dynamically (Strict matching via last colon)
        port="${local_addr##*:}"
        ip="${local_addr%:*}"
        
        # Strip IPv6 brackets and kernel interface bindings (e.g. ::1%lo)
        ip="${ip//\[/}"
        ip="${ip//\]/}"
        ip="${ip%%%*}"
        
        # We exclusively track globally exposed ports (0.0.0.0 or ::) for the security dashboard
        if [[ "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
            ip="0.0.0.0 (Any)"
            
            # Inject securely into the JSON Array
            PORTS_JSON=$(echo "$PORTS_JSON" | jq --arg ip "$ip" --arg s "$state" --arg po "$port" --arg pt "$proto" '. + [{"ip": $ip, "state": $s, "port": $po, "protocol": $pt}]')
        fi
    done <<< "$(ss -tulpn 2>/dev/null | awk 'NR>1 {addr=""; for(i=3;i<=NF;i++){if($i~/:/ && $i!~/users:/){addr=$i; break}}; if(addr!="") print $1, $2, addr}' || true)"
fi

# --- Layer 7 Metrics & IP Registry (SECURE JSON ARRAYS) ---
L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"
BANNED_IPS_JSON="[]"

# --- Risk Radar Vectors ---
R_EXP=0; R_BF=0; R_REC=0; R_DOS=0; R_ABU=0

if command -v fail2ban-client >/dev/null && timeout 2 fail2ban-client ping >/dev/null 2>&1; then
    JAIL_LIST=$(timeout 2 fail2ban-client status 2>/dev/null | awk -F'Jail list:[ \t]*' '/Jail list:/ {print $2}' | tr -d ' ' | tr ',' '\n' || true)
    
    for JAIL in $JAIL_LIST; do
        [[ -z "$JAIL" ]] && continue
        L7_ACTIVE_JAILS=$((L7_ACTIVE_JAILS + 1))
        
        STATUS_OUT=$(timeout 3 fail2ban-client status "$JAIL" 2>/dev/null || echo "")
        
        if [[ -n "$STATUS_OUT" ]]; then
            BANNED_COUNT=$(echo "$STATUS_OUT" | grep -i 'Currently banned:' | head -n 1 | grep -oE '[0-9]+' || echo "0")
            BANNED_COUNT=${BANNED_COUNT:-0}
            L7_TOTAL_BANNED=$((L7_TOTAL_BANNED + BANNED_COUNT))
            
            if [[ "$BANNED_COUNT" -gt 0 ]]; then
                # --- THREAT INTEL: MITRE ATT&CK MAPPING ---
                MITRE_ID="T1499" # Default
                MITRE_NAME="Endpoint DoS"
                
                case "${JAIL,,}" in
                    *webshell*) MITRE_ID="T1505.003"; MITRE_NAME="Server Software Component: Web Shell" ;;
                    *revshell*|*rce*) MITRE_ID="T1059"; MITRE_NAME="Command and Scripting Interpreter" ;;
                    *sqli*|*xss*|*lfi*|*ssti*|*jndi*|*haproxy*) MITRE_ID="T1190"; MITRE_NAME="Exploit Public-Facing Application" ;;
                    *privesc*|*auditd*) MITRE_ID="T1068"; MITRE_NAME="Exploitation for Privilege Escalation" ;;
                    *secretshunter*|*hunter*|*ssrf*|*idor*) MITRE_ID="T1552"; MITRE_NAME="Unsecured Credentials / Cloud Discovery" ;;
                    *proxy-abuse*|*squid*) MITRE_ID="T1090"; MITRE_NAME="Connection Proxy" ;;
                    *portscan*) MITRE_ID="T1046"; MITRE_NAME="Network Service Discovery" ;;
                    *scanner*|*bot*|*mapper*|*enum*) MITRE_ID="T1595"; MITRE_NAME="Active Scanning" ;;
                    *flood*|*dos*) MITRE_ID="T1498.001"; MITRE_NAME="Direct Network Flood" ;;
                    *wireguard*|*openvpn*) MITRE_ID="T1136"; MITRE_NAME="External Remote Services" ;;
                    *ssh*|*auth*|*telnet*|*ftp*|*mail*|*postfix*|*dovecot*|*mysql*|*mariadb*|*redis*|*rabbitmq*|*zabbix*|*grafana*|*vaultwarden*|*sso*|*odoo*|*prestashop*|*atlassian*|*jenkins*|*gitlab*|*proxmox*|*cockpit*|*nextcloud*) MITRE_ID="T1110"; MITRE_NAME="Brute Force / Password Guessing" ;;
                    *recidive*) MITRE_ID="T1133"; MITRE_NAME="External Remote Services / Repeat Offender" ;;
                esac
                MITRE_PAYLOAD="${MITRE_ID}: ${MITRE_NAME}"

                JAILS_JSON=$(echo "$JAILS_JSON" | jq --arg n "$JAIL" --argjson c "$BANNED_COUNT" --arg ttp "$MITRE_PAYLOAD" '. + [{"name": $n, "count": $c, "mitre": $ttp}]')
                
                # --- RISK RADAR CALCULATION ---
                if [[ "$JAIL" =~ (sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi) ]]; then R_EXP=$((R_EXP + BANNED_COUNT))
                elif [[ "$JAIL" =~ (ssh|auth|privesc|prestashop) ]]; then R_BF=$((R_BF + BANNED_COUNT))
                elif [[ "$JAIL" =~ (scan|bot|mapper|enum|hunter) ]]; then R_REC=$((R_REC + BANNED_COUNT))
                elif [[ "$JAIL" =~ (flood) ]]; then R_DOS=$((R_DOS + BANNED_COUNT))
                else R_ABU=$((R_ABU + BANNED_COUNT)); fi
                
                BANNED_IPS=$(echo "$STATUS_OUT" | grep -i 'Banned IP list:' | head -n 1 | sed 's/.*Banned IP list://I' | tr -d ',' | tr -s ' \t' '\n' | grep -vE '^\s*$' | tail -n 50 || true)
                for IP in $BANNED_IPS; do
                    if [[ -n "$IP" ]]; then
                        L7_PAYLOAD=""
                        if [[ "$JAIL" =~ (recidive) ]]; then
                            L7_PAYLOAD="Repeat Offender (Recidive Module)"
                        else
                            L7_PAYLOAD=$(timeout 1 grep -h -F "$IP" /var/log/kern-firewall.log /var/log/kern.log /var/log/messages /var/log/syslog /var/log/nginx/access.log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log /var/log/auth-syswarden.log /var/log/secure /var/log/auth.log /var/log/maillog /var/log/mail.log /var/log/daemon.log /var/log/audit/audit.log 2>/dev/null | grep -vE '(syswarden_reporter|fail2ban-server)' | tail -n 1 || true)
                        fi
                        
                        L7_PAYLOAD=$(echo "$L7_PAYLOAD" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)
                        
                        # --- DEVSECOPS FIX: SILENT DROP OF ORPHANED IPS ---
                        # If no logs exist (log rotated or flushed), we do NOT inject the IP into the JSON registry.
                        # This prevents UI pollution and maintains a high Signal-to-Noise Ratio.
                        if [[ -n "$L7_PAYLOAD" ]]; then
                            BANNED_IPS_JSON=$(echo "$BANNED_IPS_JSON" | jq --arg ip "$IP" --arg j "$JAIL" --arg p "$L7_PAYLOAD" --arg ttp "$MITRE_PAYLOAD" '. + [{"ip": $ip, "jail": $j, "payload": $p, "mitre": $ttp}]')
                        fi
                    fi
                done
            fi
        fi
    done
fi

# --- DEVSECOPS: Top 10 Historical Attacking IPs (Aggregated & Bulletproof) ---
TOP_ATTACKERS_JSON="[]"
TOP_STATS=""

# FIX BUG: Suppress "Restore Ban" matches to prevent double counting on updates/reloads
TOP_STATS=$( { 
    cat /var/log/fail2ban.log 2>/dev/null || true
} | grep -E "\] Ban " | sed -E 's/.*\[([^]]+)\].*Ban ([0-9.]+)/\2 \1/' | sort | uniq -c | sort -nr | head -n 10 || true )

if [[ -n "$TOP_STATS" ]]; then
    while IFS=" " read -r count ip jail; do
        if [[ -n "$ip" && -n "$count" ]]; then
            PORT="Unknown"
            
            EXACT_PORT=$(timeout 2 grep -h -F "$ip" /var/log/kern-firewall.log /var/log/kern.log /var/log/syslog /var/log/messages 2>/dev/null | grep -oE 'DPT=[0-9]+' | cut -d= -f2 | sort | uniq -c | sort -nr | awk 'NR==1 {print $2}' || true)
            
            if [[ -n "$EXACT_PORT" ]]; then
                PORT="$EXACT_PORT"
            else
                case "${jail,,}" in
                    *ssh*) PORT="22" ;;
                    *http*|*web*|*nginx*|*apache*|*prestashop*|*sqli*|*xss*|*lfi*) PORT="80/443" ;;
                    *ftp*) PORT="21" ;;
                    *mail*|*postfix*|*exim*|*dovecot*) PORT="25/143" ;;
                    *mysql*|*mariadb*) PORT="3306" ;;
                    *recidive*) PORT="Multiple" ;;
                    *scan*|*portscan*|*syswarden*) PORT="Network" ;;
                    *) PORT="Unknown" ;;
                esac
            fi
            
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --arg p "$PORT" --argjson c "$count" '. + [{"ip": $ip, "port": $p, "count": $c}]')
        fi
    done <<< "$TOP_STATS"
fi

# --- Whitelist Registry Extraction ---
WHITELIST_COUNT=0
WL_JSON="[]"

if [[ -f "$SYSWARDEN_DIR/whitelist.txt" ]]; then
    WHITELIST_COUNT=$(grep -cvE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    WL_IPS=$(grep -vE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    for IP in $WL_IPS; do
        if [[ -n "$IP" ]]; then
            WL_JSON=$(echo "$WL_JSON" | jq --arg ip "$IP" '. + [$ip]')
        fi
    done
fi

# --- Generate Atomic JSON Payload ---
RADAR_JSON=$(jq -n --argjson e "$R_EXP" --argjson b "$R_BF" --argjson r "$R_REC" --argjson d "$R_DOS" --argjson a "$R_ABU" '[$e, $b, $r, $d, $a]')

jq -n \
  --arg ts "$SYS_TIMESTAMP" \
  --arg host "$SYS_HOSTNAME" \
  --arg up "$SYS_UPTIME" \
  --arg load "$SYS_LOAD" \
  --argjson ru "$SYS_RAM_USED" \
  --argjson rt "$SYS_RAM_TOTAL" \
  --argjson du "$SYS_DISK_USED" \
  --argjson dt "$SYS_DISK_TOTAL" \
  --arg cores "$SYS_CORES" \
  --arg arch "$SYS_ARCH" \
  --arg os "$SYS_OS" \
  --arg cpu "$SYS_CPU" \
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
  --argjson srv "$SERVICES_JSON" \
  --argjson pts "$PORTS_JSON" \
  --argjson rad "$RADAR_JSON" \
'{
  timestamp: $ts,
  system: { hostname: $host, uptime: $up, load_average: $load, ram_used_mb: $ru, ram_total_mb: $rt, disk_used_mb: $du, disk_total_mb: $dt, services: $srv, cores: $cores, arch: $arch, os: $os, cpu_model: $cpu, ports: $pts },
  layer3: { global_blocked: $lg, geoip_blocked: $lgeo, asn_blocked: $lasn },
  layer7: { total_banned: $ltb, active_jails: $laj, jails_data: $jj, banned_ips: $bip, top_attackers: $top, risk_radar: $rad },
  whitelist: { active_ips: $wlc, ips: $wlip }
}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$DATA_FILE"
chown www-data:www-data "$DATA_FILE" 2>/dev/null || chown nginx:nginx "$DATA_FILE" 2>/dev/null || true
chmod 640 "$DATA_FILE"
EOF

    # 2. Make executable
    chmod +x "$BIN_PATH"

    # 3. Injection into CRON tasks
    if ! crontab -l 2>/dev/null | grep "$BIN_PATH" >/dev/null; then
        (
            crontab -l 2>/dev/null || true
            echo "* * * * * $BIN_PATH >/dev/null 2>&1"
        ) | crontab -
    fi

    # 4. First immediate run
    if ! "$BIN_PATH"; then
        log "WARN" "Initial telemetry run failed, but script will continue."
    fi
}

# ==============================================================================
# SYSWARDEN v0.27.4 - NGINX / APACHESECURE DASHBOARD (ENTERPRISE SAAS UI / SPA / CSP)
# ==============================================================================
function generate_dashboard() {
    log "INFO" "Generating the Enterprise SaaS Nginx Dashboard (SPA/CSP)..."

    local UI_DIR="/etc/syswarden/ui"
    mkdir -p "$UI_DIR"

    chmod 750 /etc/syswarden
    chmod 750 "$UI_DIR"

    if id "www-data" >/dev/null 2>&1; then
        chown root:www-data /etc/syswarden "$UI_DIR"
    elif id "apache" >/dev/null 2>&1; then
        chown root:apache /etc/syswarden "$UI_DIR"
    elif id "nginx" >/dev/null 2>&1; then
        chown root:nginx /etc/syswarden "$UI_DIR"
    fi

    # 1. Generating the HTML file (Single Page Layout)
    cat <<'EOF' >"$UI_DIR/index.html"
<!DOCTYPE html>
<html lang="en" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>SysWarden | Dashboard</title>
    
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700;900&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
    
    <style>
        :root[data-bs-theme="light"] {
            --sw-bg: #ffffff;
            --sw-nav-bg: #ffffff;
            --sw-card-bg: #ffffff;
            --sw-border: #e5e7eb;
            --sw-text: #1f2937;
            --sw-text-muted: #6b7280;
            --sw-brand-icon: #2563eb;
        }
        :root[data-bs-theme="dark"] {
            --sw-bg: #000000;
            --sw-nav-bg: #09090b;
            --sw-card-bg: #09090b;
            --sw-border: rgba(255, 255, 255, 0.12);
            --sw-text: #ffffff;
            --sw-text-muted: #a1a1aa;
            --sw-brand-icon: #3b82f6;
        }

        body { 
            font-family: 'Roboto', sans-serif;
            background-color: var(--sw-bg); color: var(--sw-text);
            transition: background-color 0.3s ease, color 0.3s ease;
            -webkit-font-smoothing: antialiased;
        }
        .font-mono { font-weight: 500; }

        .main-wrapper { flex-grow: 1; overflow-y: auto; overflow-x: hidden; scroll-behavior: smooth; height: calc(100vh - 65px); }

        .top-navbar {
            height: 65px; min-height: 65px;
            background-color: var(--sw-nav-bg); border-bottom: 1px solid var(--sw-border);
            display: flex; align-items: center; justify-content: space-between; padding: 0 1.5rem;
        }
        .theme-toggle-btn { background: transparent; border: none; color: var(--sw-text); cursor: pointer; display: flex; align-items: center; justify-content: center; width: 36px; height: 36px; border-radius: 50%; transition: background 0.2s; }
        .theme-toggle-btn:hover { background: var(--sw-border); }

        .card { background-color: var(--sw-card-bg); border: 1px solid var(--sw-border); border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .card-header { border-bottom: 1px solid var(--sw-border); font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase; font-size: 0.80rem; color: var(--sw-text-muted); }
        
        .card-l3 { border-left: 4px solid var(--sw-brand-icon) !important; }
        .card-l7 { border-left: 4px solid #ef4444 !important; }
        .card-wl { border-left: 4px solid #10b981 !important; }

        .stat-value { font-size: clamp(1.2rem, 1.6vw, 1.6rem); font-weight: 800; line-height: 1.1; letter-spacing: -0.5px; }
        .stat-label { font-size: 0.80rem; text-transform: uppercase; letter-spacing: 1px; color: var(--sw-text-muted); font-weight: 700; }
        .table-container { max-height: 350px; overflow-y: auto; }

        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: var(--sw-border); border-radius: 10px; }
        ::-webkit-scrollbar-corner { background: transparent; }
        
        .table { --bs-table-bg: transparent !important; margin-bottom: 0 !important; }
        .table > :not(caption) > * > * { background-color: transparent !important; border-color: var(--sw-border) !important; }
        .ip-font { font-size: 85% !important; }
    </style>
</head>
<body class="d-flex flex-column" style="height: 100vh; margin: 0;">

    <nav class="top-navbar">
        <div class="d-flex align-items-center gap-3">
            <svg style="color: var(--sw-brand-icon);" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            <h5 class="mb-0 fw-bold d-none d-md-block text-uppercase" style="letter-spacing: 0.5px; font-size: 1.1rem; color: var(--sw-text);">SYSWARDEN v0.27.4</h5>
        </div>
        
        <div class="d-flex align-items-center gap-3 gap-md-4">
            <div class="d-none d-md-flex align-items-center gap-4 border-end pe-4" style="border-color: var(--sw-border) !important;">
                <a href="https://github.com/duggytuxy/syswarden" target="_blank" rel="noopener noreferrer" class="text-decoration-none small font-mono d-flex align-items-center gap-2" style="color: var(--sw-text);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
                    Stars <span id="gh-stars" class="fw-bold">--</span>
                </a>
                <a href="https://github.com/duggytuxy/syswarden/releases/latest" target="_blank" rel="noopener noreferrer" class="text-decoration-none small font-mono d-flex align-items-center gap-2" style="color: var(--sw-text);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                    Release <span id="gh-release" class="text-primary fw-bold">--</span>
                </a>
            </div>

            <div class="d-flex align-items-center gap-2 px-3 py-1 rounded-pill" style="background: var(--sw-bg); border: 1px solid var(--sw-border);">
                <div id="status-spinner" class="spinner-grow spinner-grow-sm text-success" style="width: 8px; height: 8px;" role="status"></div>
                <span id="sys-hostname" class="text-truncate fw-bold small" style="max-width: 150px;">Node</span>
                <span id="sys-ip" class="text-muted font-mono small d-none d-lg-block"></span>
            </div>
            
            <button class="theme-toggle-btn" id="theme-toggle-btn" title="Toggle Theme">
                <svg id="icon-sun" class="d-none" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
                <svg id="icon-moon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            </button>
        </div>
    </nav>

    <main class="main-wrapper">
        <div class="container-fluid px-xl-5 px-4 py-4">
            
            <div class="card mb-4">
                <div class="card-body py-3 px-4 d-flex flex-column gap-2 justify-content-center" style="min-height: 70px;">
                    <div class="d-flex flex-wrap gap-4 align-items-center border-bottom pb-2" style="border-color: var(--sw-border) !important;">
                        <div class="font-mono small"><span class="text-muted">Cores:</span> <span id="hw-cores" class="ms-1">--</span></div>
                        <div class="font-mono small"><span class="text-muted">Arch:</span> <span id="hw-arch" class="ms-1">--</span></div>
                        <div class="font-mono small"><span class="text-muted">OS:</span> <span id="hw-os" class="ms-1">--</span></div>
                        <div class="font-mono small d-flex align-items-center"><span class="text-muted me-1">CPU:</span> <span class="text-truncate" style="max-width: 250px;" id="hw-cpu" title="CPU Model">--</span></div>
                        <div class="font-mono small"><span class="text-muted">Last update:</span> <span id="hw-update" class="ms-1">--</span></div>
                    </div>
                    <div class="d-flex flex-wrap gap-4 align-items-center border-bottom pb-2 pt-1" style="border-color: var(--sw-border) !important;">
                        <div class="font-mono small"><span class="text-muted">Uptime:</span> <span id="sys-uptime" class="ms-1 text-primary">--</span></div>
                        <div class="font-mono small"><span class="text-muted">Load Avg (1,5,15m):</span> <span id="sys-load" class="ms-1">--</span></div>
                        <div class="font-mono small"><span class="text-muted">RAM:</span> <span id="sys-ram" class="ms-1">-- MB</span></div>
                        <div class="font-mono small"><span class="text-muted">Storage (Root):</span> <span id="sys-disk" class="ms-1">-- GB</span></div>
                    </div>
                    <div class="d-flex flex-wrap gap-3 align-items-center border-bottom pb-2 pt-1 font-mono small" id="sys-services-list" style="border-color: var(--sw-border) !important;">
                        </div>
                    <div class="d-flex flex-wrap gap-3 align-items-center pt-1 font-mono small" id="sys-ports-list">
                        </div>
                </div>
            </div>
            
            <div class="row g-4 mb-4">
                <div class="col-xxl-4 col-lg-6">
                    <div class="card card-l3 h-100">
                        <div class="card-body p-4">
                            <div class="stat-label mb-3">L3 Kernel Blocks (Global)</div>
                            <div class="stat-value text-primary font-mono mb-3" id="l3-global">0</div>
                            <div class="d-flex justify-content-between border-top pt-3 font-mono small text-muted" style="border-color: var(--sw-border) !important;">
                                <span>GeoIP: <strong class="text-body" id="l3-geoip">0</strong></span>
                                <span>ASN: <strong class="text-body" id="l3-asn">0</strong></span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xxl-4 col-lg-6">
                    <div class="card card-l7 h-100">
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
                    <div class="card card-wl h-100">
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

            <div class="row g-4 mb-4">
                <div class="col-xl-4">
                    <div class="card h-100">
                        <div class="card-header bg-transparent pt-4 pb-0 px-4 d-flex align-items-center gap-2">Global Risk Vectors</div>
                        <div class="card-body p-4 d-flex align-items-center justify-content-center">
                            <div style="position: relative; height: 280px; width: 100%;">
                                <canvas id="riskChart"></canvas>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-8">
                    <div class="card h-100">
                        <div class="card-header bg-transparent pt-4 pb-3 px-4 border-bottom-0">Top Attackers (OSINT History)</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 310px;">
                                <table class="table table-sm mb-0 small">
                                    <thead style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2; border: none;">
                                        <tr>
                                            <th class="text-muted small fw-normal pb-2 ps-4">IP ADDRESS</th>
                                            <th class="text-muted small fw-normal pb-2">PORT</th>
                                            <th class="text-end text-muted small fw-normal pb-2 pe-4">HITS</th>
                                        </tr>
                                    </thead>
                                    <tbody id="top-ips-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row g-4 mb-4">
                <div class="col-xl-4">
                    <div class="card h-100">
                        <div class="card-header bg-transparent pt-4 pb-3 px-4 border-bottom-0">Jails Load Distribution</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 450px;">
                                <table class="table table-sm mb-0 small">
                                    <thead style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2; border: none;">
                                        <tr>
                                            <th class="text-muted small fw-normal pb-2 ps-4">TARGET JAIL</th>
                                            <th class="text-muted small fw-normal pb-2">MITRE ATT&CK</th>
                                            <th class="text-end text-muted small fw-normal pb-2 pe-4">LOAD</th>
                                        </tr>
                                    </thead>
                                    <tbody id="top-jails-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-xl-8">
                    <div class="card h-100">
                        <div class="card-header bg-transparent pt-4 pb-3 px-4 border-bottom-0">L7 Banned IP Registry (Live Jail Allocations)</div>
                        <div class="card-body p-0">
                            <div class="table-responsive table-container" style="max-height: 450px;">
                                <table class="table table-sm mb-0 small">
                                    <thead style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2; border: none;">
                                        <tr>
                                            <th class="text-muted small fw-normal pb-2 ps-4" style="min-width: 150px;">IP ADDRESS</th>
                                            <th class="text-muted small fw-normal pb-2" style="min-width: 150px;">TARGET JAIL</th>
                                            <th class="text-muted small fw-normal pb-2 ps-3" style="min-width: 200px;">MITRE ATT&CK</th>
                                            <th class="text-muted small fw-normal pb-2 ps-4 pe-4" style="min-width: 250px;">TRIGGER PAYLOAD</th>
                                        </tr>
                                    </thead>
                                    <tbody id="banned-ips-list"></tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row g-4 mb-4">
                <div class="col-12">
                    <div class="card h-100">
                        <div class="card-header bg-transparent pt-4 pb-0 px-4 d-flex align-items-center gap-2">
                            Filtration Efficiency (Signal vs Noise)
                        </div>
                        <div class="card-body p-4">
                            <div class="row align-items-center">
                                <div class="col-md-6 mb-4 mb-md-0" style="border-right: 1px solid var(--sw-border);">
                                    <div class="d-flex justify-content-between small font-mono fw-bold mb-2">
                                        <span class="text-muted">Automated Noise Blocked (L2/L3 Blocklists)</span>
                                        <span id="noise-pct" class="text-success">--%</span>
                                    </div>
                                    <div class="progress" style="height: 10px; background-color: var(--sw-border);">
                                        <div id="noise-bar" class="progress-bar bg-success" role="progressbar" style="width: 0%; transition: width 0.5s ease;"></div>
                                    </div>
                                </div>
                                <div class="col-md-6 ps-md-4">
                                    <div class="d-flex justify-content-between small font-mono fw-bold mb-2">
                                        <span class="text-muted">Actionable Signals (L7 Fail2ban)</span>
                                        <span id="signal-pct" class="text-danger">--%</span>
                                    </div>
                                    <div class="progress" style="height: 10px; background-color: var(--sw-border);">
                                        <div id="signal-bar" class="progress-bar bg-danger" role="progressbar" style="width: 0%; transition: width 0.5s ease;"></div>
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
    <script>
    let riskChart = null;

    document.addEventListener('DOMContentLoaded', () => {
        
        // --- THEME ENGINE (ICONS) ---
        const themeBtn = document.getElementById('theme-toggle-btn');
        const iconSun = document.getElementById('icon-sun');
        const iconMoon = document.getElementById('icon-moon');
        
        const applyThemeState = (isDark) => {
            document.documentElement.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');
            if(isDark) {
                iconMoon.classList.add('d-none');
                iconSun.classList.remove('d-none');
            } else {
                iconSun.classList.add('d-none');
                iconMoon.classList.remove('d-none');
            }
            updateChartTheme(isDark ? 'dark' : 'light');
        };

        const toggleTheme = () => {
            const currentTheme = document.documentElement.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('syswarden-theme', newTheme);
            applyThemeState(newTheme === 'dark');
        };

        themeBtn.addEventListener('click', toggleTheme);

        const savedTheme = localStorage.getItem('syswarden-theme');
        if (savedTheme) {
            applyThemeState(savedTheme === 'dark');
        } else {
            applyThemeState(window.matchMedia('(prefers-color-scheme: dark)').matches);
        }

        // --- CHART.JS INITIALIZATION (DOUGHNUT ONLY) ---
        try {
            const ctxRadar = document.getElementById('riskChart').getContext('2d');
            riskChart = new Chart(ctxRadar, {
                type: 'doughnut',
                data: {
                    labels: ['Exploits', 'Brute-Force', 'Recon', 'DDoS', 'Abuse/Spam'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ef4444', // Red
                            '#eab308', // Yellow
                            '#3b82f6', // Blue
                            'var(--sw-chart-ddos)', // Black/Grey depending on theme
                            '#f97316'  // Orange
                        ],
                        borderWidth: 2,
                        borderColor: 'var(--sw-card-bg)'
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, cutout: '65%',
                    plugins: { 
                        legend: { position: 'bottom', labels: { padding: 20, font: { family: 'Roboto', size: 12, weight: '500' } } },
                        tooltip: { padding: 10, cornerRadius: 8, bodyFont: { family: 'monospace', size: 13, weight: 'bold' } }
                    }
                }
            });
        } catch (e) { console.warn("Chart.js init failed:", e); }

        updateChartTheme(document.documentElement.getAttribute('data-bs-theme'));

        function updateChartTheme(theme) {
            if(riskChart) {
                const isDark = theme === 'dark';
                riskChart.data.datasets[0].borderColor = isDark ? '#09090b' : '#ffffff';
                riskChart.options.plugins.legend.labels.color = isDark ? '#a1a1aa' : '#6b7280';
                riskChart.update();
            }
        }
        
        // --- UI HELPER: MATCH JAIL TO DOUGHNUT CHART COLORS ---
        function getJailBadgeStyle(jailName) {
            const j = jailName.toLowerCase();
            const baseStyle = 'font-size: 0.70rem; ';
            
            if (j.match(/(sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi|prestashop|atlassian|wordpress|drupal|nginx|apache)/)) 
                return baseStyle + 'background-color: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3);';
            if (j.match(/(portscan|scan|bot|mapper|enum|hunter|proxy)/)) 
                return baseStyle + 'background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3);';
            if (j.match(/(recidive|postfix|dovecot|exim|mail)/)) 
                return baseStyle + 'background-color: rgba(249, 115, 22, 0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3);';
            if (j.match(/(flood|limit|ddos)/)) 
                return baseStyle + 'background-color: rgba(107, 114, 128, 0.15); color: var(--sw-text); border: 1px solid var(--sw-border);';
            return baseStyle + 'background-color: rgba(234, 179, 8, 0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3);';
        }

        // --- DATA INGESTION ENGINE ---
        async function fetchTelemetry() {
            try {
                const response = await fetch(`data.json?t=${new Date().getTime()}`);
                if (!response.ok) throw new Error('HTTP request failed');
                const data = await response.json();

                // Status Spinner -> Online
                const spinner = document.getElementById('status-spinner');
                if (spinner) {
                    spinner.classList.remove('text-danger');
                    spinner.classList.add('text-success');
                }

                // System Metrics
                document.getElementById('sys-hostname').innerText = data.system.hostname;
                if(data.system.ip) {
                    document.getElementById('sys-ip').innerText = data.system.ip;
                }
                document.getElementById('sys-uptime').innerText = data.system.uptime;
                
                // Hardware Header
                if (document.getElementById('hw-cores')) {
                    document.getElementById('hw-cores').innerText = data.system.cores || '--';
                    document.getElementById('hw-arch').innerText = data.system.arch || '--';
                    document.getElementById('hw-os').innerText = data.system.os || '--';
                    document.getElementById('hw-cpu').innerText = data.system.cpu_model || '--';
                    
                    const fetchTime = new Date();
                    document.getElementById('hw-update').innerText = fetchTime.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute:'2-digit', second:'2-digit' });
                }
                
                const ramUsed = parseInt(data.system.ram_used_mb) || 0;
                const ramTotal = parseInt(data.system.ram_total_mb) || 1;
                document.getElementById('sys-ram').innerText = `${ramUsed.toLocaleString()} / ${ramTotal.toLocaleString()} MB`;
                
                const diskUsed = (parseInt(data.system.disk_used_mb) / 1024).toFixed(1);
                const diskTotal = (parseInt(data.system.disk_total_mb) / 1024).toFixed(1);
                document.getElementById('sys-disk').innerText = `${diskUsed} / ${diskTotal} GB`;

                const sysLoadEl = document.getElementById('sys-load');
                sysLoadEl.innerText = data.system.load_average;
                const load1m = parseFloat(data.system.load_average.split(',')[0]);
                sysLoadEl.classList.remove('text-success', 'text-warning', 'text-danger');
                sysLoadEl.classList.add(load1m <= 0.35 ? 'text-success' : load1m <= 0.70 ? 'text-warning' : 'text-danger');

                // Flat Services Listing (Horizontal inline rendering)
                const srvEl = document.getElementById('sys-services-list');
                if(data.system.services && srvEl) {
                    srvEl.innerHTML = data.system.services.map(srv => {
                        const shortName = srv.name.split(' ')[0];
                        // Handle 3 states: active (green), skipped (yellow), offline (red)
                        const statusClass = srv.status === 'active' ? 'text-success' : (srv.status === 'skipped' ? 'text-warning opacity-75' : 'text-danger');
                        return `<span class="text-muted">${shortName}:</span> <span class="${statusClass}">${srv.status.toUpperCase()}</span>`;
                    }).join(' <span class="text-muted opacity-50 px-2">|</span> ');
                }

                // NEW: Flat Network Ports Listing (Horizontal inline rendering)
                const portsEl = document.getElementById('sys-ports-list');
                if(data.system.ports && portsEl) {
                    if (data.system.ports.length > 0) {
                        portsEl.innerHTML = data.system.ports.map(p => {
                            // Extract just the port number
                            const safePort = (p.port && p.port.trim() !== '' && p.port !== '*') ? p.port : 'N/A';
                            return `<span class="text-muted">${p.protocol || 'TCP'}:</span> <span style="color: var(--sw-brand-icon); font-weight: 700;">${safePort}</span>`;
                        }).join(' <span class="text-muted opacity-50 px-2">|</span> ');
                    } else {
                        portsEl.innerHTML = '<span class="text-muted fst-italic">No external ports exposed. Architecture is fully locked down.</span>';
                    }
                }

                // Layer 3 & 7 Metrics
                document.getElementById('l3-global').innerText = parseInt(data.layer3.global_blocked).toLocaleString();
                document.getElementById('l3-geoip').innerText = parseInt(data.layer3.geoip_blocked).toLocaleString();
                document.getElementById('l3-asn').innerText = parseInt(data.layer3.asn_blocked).toLocaleString();
                document.getElementById('l7-banned').innerText = parseInt(data.layer7.total_banned).toLocaleString();
                document.getElementById('l7-jails').innerText = data.layer7.active_jails;
                document.getElementById('wl-count').innerText = data.whitelist.active_ips;

                // Signal vs Noise Calculation
                const l3Blocked = parseInt(data.layer3.global_blocked) || 0;
                const l7Banned = parseInt(data.layer7.total_banned) || 0;
                const totalThreats = l3Blocked + l7Banned;
                
                let noisePercent = 0;
                let signalPercent = 0;
                
                if (totalThreats > 0) {
                    noisePercent = ((l3Blocked / totalThreats) * 100).toFixed(2);
                    signalPercent = ((l7Banned / totalThreats) * 100).toFixed(2);
                }

                document.getElementById('noise-pct').innerText = `${noisePercent}%`;
                document.getElementById('noise-bar').style.width = `${noisePercent}%`;

                document.getElementById('signal-pct').innerText = `${signalPercent}%`;
                document.getElementById('signal-bar').style.width = `${signalPercent}%`;
                
                // Inject Doughnut Data
                if(riskChart && data.layer7.risk_radar) {
                    riskChart.data.datasets[0].data = data.layer7.risk_radar;
                    riskChart.update();
                }

                // Renderers (Threat Intel Tables)
                document.getElementById('whitelist-ips-list').innerHTML = data.whitelist.ips.map(ip => `<li class="mb-1 opacity-75">${ip}</li>`).join('');

                const topIpsEl = document.getElementById('top-ips-list');
                if(data.layer7.top_attackers.length > 0) {
                    topIpsEl.innerHTML = data.layer7.top_attackers.map(attacker => `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><a href="https://www.abuseipdb.com/check/${attacker.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none ip-font" style="color: var(--sw-text);">${attacker.ip}</a></td>
                            <td class="align-middle py-3 font-mono">
                                <span class="badge rounded-pill" style="background-color: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); font-size: 0.70rem;">
                                    ${attacker.port || 'N/A'}
                                </span>
                            </td>
                            <td class="text-end align-middle py-3 pe-4 font-mono text-body-secondary">${attacker.count.toLocaleString()}</td>
                        </tr>`).join('');
                } else { topIpsEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted small py-4">No attackers recorded.</td></tr>`; }

                const jailsEl = document.getElementById('top-jails-list');
                if(data.layer7.jails_data.length > 0) {
                    jailsEl.innerHTML = [...data.layer7.jails_data].sort((a, b) => b.count - a.count).map(jail => {
                        const mitreId = jail.mitre ? jail.mitre.split(':')[0] : 'T1499';
                        const mitreLabel = jail.mitre || 'Unknown';
                        
                        return `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><span class="badge rounded-pill" style="${getJailBadgeStyle(jail.name)}">${jail.name}</span></td>
                            <td class="align-middle py-3 font-mono">
                                <a href="https://attack.mitre.org/techniques/${mitreId}/" target="_blank" rel="noopener noreferrer" class="text-decoration-none badge rounded-pill" style="${getJailBadgeStyle(jail.name)} font-size: 0.70rem;">
                                    ${mitreLabel}
                                </a>
                            </td>
                            <td class="text-end align-middle py-3 pe-4 font-mono text-body-secondary">${jail.count}</td>
                        </tr>`;
                    }).join('');
                } else { jailsEl.innerHTML = `<tr><td colspan="3" class="text-center text-muted small py-4">No active jails loaded.</td></tr>`; }

                const bannedEl = document.getElementById('banned-ips-list');
                if(data.layer7.banned_ips.length > 0) {
                    bannedEl.innerHTML = [...data.layer7.banned_ips].reverse().map(entry => {
                        const mitreId = entry.mitre ? entry.mitre.split(':')[0] : 'T1499';
                        const mitreLabel = entry.mitre || 'Unknown';
                        
                        // Removed the Timestamp column entirely as requested
                        return `
                        <tr>
                            <td class="align-middle py-3 ps-4 font-mono"><a href="https://www.abuseipdb.com/check/${entry.ip}" target="_blank" rel="noopener noreferrer" class="text-decoration-none ip-font" style="color: var(--sw-text);">${entry.ip}</a></td>
                            <td class="align-middle py-3 font-mono"><span class="badge rounded-pill" style="${getJailBadgeStyle(entry.jail)}">${entry.jail}</span></td>
                            <td class="align-middle py-3 ps-3 font-mono">
                                <a href="https://attack.mitre.org/techniques/${mitreId}/" target="_blank" rel="noopener noreferrer" class="text-decoration-none badge rounded-pill" style="${getJailBadgeStyle(entry.jail)} font-size: 0.70rem;">
                                    ${mitreLabel}
                                </a>
                            </td>
                            <td class="align-middle py-3 ps-4 pe-4 font-mono text-muted small text-nowrap" style="font-size: 0.75rem;">${entry.payload || 'N/A'}</td>
                        </tr>`
                    }).join('');
                } else { 
                    bannedEl.innerHTML = `<tr><td colspan="4" class="text-center text-muted small py-5">Registry is empty. Architecture is secure.</td></tr>`; 
                }

            } catch (error) {
                console.error("Telemetry Sync Error:", error);
                
                const spinner = document.getElementById('status-spinner');
                if (spinner) {
                    spinner.classList.remove('text-success');
                    spinner.classList.add('text-danger');
                }
            }
        }
        
        async function fetchGitHubData() {
            try {
                const repoRes = await fetch('https://api.github.com/repos/duggytuxy/syswarden');
                if (repoRes.ok) {
                    const repoData = await repoRes.json();
                    document.getElementById('gh-stars').innerText = repoData.stargazers_count;
                }
                
                const relRes = await fetch('https://api.github.com/repos/duggytuxy/syswarden/releases/latest');
                if (relRes.ok) {
                    const relData = await relRes.json();
                    document.getElementById('gh-release').innerText = relData.tag_name;
                }
            } catch (error) {
                console.warn("GitHub API Fetch Error:", error);
                document.getElementById('gh-stars').innerText = "N/A";
                document.getElementById('gh-release').innerText = "N/A";
            }
        }
        
        fetchGitHubData();

        fetchTelemetry();
        setInterval(fetchTelemetry, 5000);
    });
    </script>
</body>
</html>
EOF

    # --- 3. DYNAMIC ACCESS CONTROL (IP Whitelisting) ---
    local NGINX_ALLOW_RULES=""
    local APACHE_ALLOW_RULES=""

    if [[ -s "$WHITELIST_FILE" ]]; then
        while IFS= read -r wl_ip; do
            [[ -z "$wl_ip" ]] || [[ "$wl_ip" =~ ^# ]] && continue
            NGINX_ALLOW_RULES+="        allow $wl_ip;\n"
            APACHE_ALLOW_RULES+="        Require ip $wl_ip\n"
        done <"$WHITELIST_FILE"
    fi

    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        NGINX_ALLOW_RULES+="        allow ${WG_SUBNET};\n"
        APACHE_ALLOW_RULES+="        Require ip ${WG_SUBNET}\n"
    fi

    NGINX_ALLOW_RULES+="        allow 127.0.0.1;\n"
    NGINX_ALLOW_RULES+="        deny all;"
    APACHE_ALLOW_RULES+="        Require ip 127.0.0.1\n"
    # Apache uses 'Require all denied' implicitly via <RequireAny> block exclusion.

    # --- 4. CRYPTOGRAPHY (Self-Signed TLS) ---
    local SSL_DIR="/etc/syswarden/ssl"
    mkdir -p "$SSL_DIR"
    if [[ ! -f "$SSL_DIR/syswarden.crt" ]]; then
        log "INFO" "Generating Self-Signed RSA 4096 TLS Certificate..."
        openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
            -keyout "$SSL_DIR/syswarden.key" \
            -out "$SSL_DIR/syswarden.crt" \
            -subj "/C=BE/ST=Brussels/L=Brussels/O=SysWarden/CN=syswarden-dashboard" 2>/dev/null
        chmod 600 "$SSL_DIR/syswarden.key"
    fi

    # --- 5. WEB SERVER VHOST CONFIGURATION (Apache or Nginx) ---
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        log "INFO" "Apache detected. Configuring Apache VHost for port 9999..."
        local APACHE_CONF_DIR="/etc/apache2/sites-available"
        local APACHE_ENABLE_DIR="/etc/apache2/sites-enabled"
        local APACHE_DAEMON="apache2"

        if command -v httpd >/dev/null 2>&1 || [[ -d "/etc/httpd" ]]; then
            APACHE_CONF_DIR="/etc/httpd/conf.d"
            APACHE_ENABLE_DIR="/etc/httpd/conf.d"
            APACHE_DAEMON="httpd"
        fi

        mkdir -p "$APACHE_CONF_DIR"
        cat <<EOF >"$APACHE_CONF_DIR/syswarden-ui.conf"
Listen 9999
<VirtualHost *:9999>
    DocumentRoot "$UI_DIR"
    SSLEngine on
    SSLCertificateFile "$SSL_DIR/syswarden.crt"
    SSLCertificateKeyFile "$SSL_DIR/syswarden.key"

    <Directory "$UI_DIR">
        Options -Indexes +FollowSymLinks
        AllowOverride None
        <RequireAny>
$(echo -e "$APACHE_ALLOW_RULES")
        </RequireAny>
    </Directory>

    # Strict Security Headers
    Header always set Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://api.github.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</VirtualHost>
EOF

        if [[ "$APACHE_DAEMON" == "apache2" ]]; then
            # Debian/Ubuntu specific enabling
            a2enmod ssl headers >/dev/null 2>&1 || true
            ln -sf "$APACHE_CONF_DIR/syswarden-ui.conf" "$APACHE_ENABLE_DIR/syswarden-ui.conf" 2>/dev/null || true
        fi
    else
        log "INFO" "Configuring Nginx VHost for port 9999..."
        local NGINX_CONF_DIR="/etc/nginx/conf.d"
        if [[ -d "/etc/nginx/sites-available" ]]; then
            NGINX_CONF_DIR="/etc/nginx/sites-available"
        fi

        # HTTP/2 directive handling for backward compatibility (Nginx >= 1.25.1)
        local NGINX_HTTP2_DIRECTIVE="listen 9999 ssl http2;"
        if nginx -v 2>&1 | grep -qE "nginx/1\.(2[5-9]|[3-9][0-9])"; then
            NGINX_HTTP2_DIRECTIVE="listen 9999 ssl;
    http2 on;"
        fi

        cat <<EOF >"$NGINX_CONF_DIR/syswarden-ui.conf"
server {
    $NGINX_HTTP2_DIRECTIVE
    server_name _;

    ssl_certificate $SSL_DIR/syswarden.crt;
    ssl_certificate_key $SSL_DIR/syswarden.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root $UI_DIR;
    index index.html;

    include mime.types;

    # --- Security Access Control ---
$(echo -e "$NGINX_ALLOW_RULES")

    # --- Strict Security Headers ---
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://api.github.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    server_tokens off;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~ /\. {
        deny all;
    }
}
EOF

        if [[ -d "/etc/nginx/sites-enabled" ]]; then
            ln -sf "$NGINX_CONF_DIR/syswarden-ui.conf" "/etc/nginx/sites-enabled/syswarden-ui.conf"
            rm -f /etc/nginx/sites-enabled/default
        fi
    fi

    # --- 6. EXPOSE DASHBOARD PORT NATIVELY ---
    log "INFO" "Opening Port 9999 in OS Firewall to enable Dashboard routing..."
    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        local DASH_ZONE
        DASH_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
        firewall-cmd --permanent --zone="$DASH_ZONE" --add-port=9999/tcp >/dev/null 2>&1 || true
        firewall-cmd --zone="$DASH_ZONE" --add-port=9999/tcp >/dev/null 2>&1 || true
    elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        ufw allow 9999/tcp >/dev/null 2>&1 || true
    elif [[ "$FIREWALL_BACKEND" == "iptables" ]]; then
        if ! iptables -C INPUT -p tcp --dport 9999 -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -p tcp --dport 9999 -j ACCEPT
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi
        fi
    elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        if nft list chain inet filter input >/dev/null 2>&1; then
            if ! nft list chain inet filter input 2>/dev/null | grep "tcp dport 9999 accept" >/dev/null; then
                nft insert rule inet filter input tcp dport 9999 accept 2>/dev/null || true
            fi
            if ! grep -q 'include "/etc/syswarden/syswarden.nft"' /etc/nftables.conf 2>/dev/null; then
                echo -e '\n# Added by SysWarden' >>/etc/nftables.conf
                echo 'include "/etc/syswarden/syswarden.nft"' >>/etc/nftables.conf
            fi
        fi
    fi

    # --- 7. DAEMON ORCHESTRATION ---
    if systemctl is-active --quiet syswarden-ui; then
        systemctl stop syswarden-ui >/dev/null 2>&1 || true
        systemctl disable syswarden-ui >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/syswarden-ui.service /usr/local/bin/syswarden-ui-server.py
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        local APACHE_SVC="apache2"
        if command -v httpd >/dev/null 2>&1; then APACHE_SVC="httpd"; fi

        systemctl enable "$APACHE_SVC" >/dev/null 2>&1 || true
        if systemctl is-active --quiet "$APACHE_SVC"; then
            systemctl reload "$APACHE_SVC" >/dev/null 2>&1 || true
        else
            systemctl restart "$APACHE_SVC" >/dev/null 2>&1 || true
        fi
    else
        systemctl enable nginx >/dev/null 2>&1 || true
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx >/dev/null 2>&1 || true
        else
            systemctl restart nginx >/dev/null 2>&1 || true
        fi
    fi

    local SERVER_IP
    SERVER_IP=$(curl -sL4 https://ifconfig.me 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") print $(i+1)}' | head -n 1 || echo "<YOUR_IP>")

    log "INFO" "Dashboard UI secured by Web Server at https://${SERVER_IP}:9999"
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    # Simple IP validation
    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    # --- LOCAL PERSISTENCE (SINGLE SOURCE OF TRUTH) ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    if ! grep -q "^${WL_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$WL_IP" >>"$WHITELIST_FILE"
        log "INFO" "IP $WL_IP securely saved to $WHITELIST_FILE."
    else
        log "INFO" "IP $WL_IP is already in the whitelist file."
    fi
    # --------------------------------------------------

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    # --- FIX: SAFE DYNAMIC WHITELISTING (STATE MACHINE) ---
    log "INFO" "Rebuilding firewall framework to safely integrate the new IP..."

    # 1. Force loading config to ensure core variables (SSH_PORT, USE_WIREGUARD) are in RAM
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # 2. Universally remove the IP from the active blocklist in memory to prevent conflicts
    if command -v ipset >/dev/null; then
        ipset del "$SET_NAME" "$WL_IP" 2>/dev/null || true
    fi
    if command -v nft >/dev/null; then
        # Bypasses the active drop rule temporarily before reload
        nft delete element netdev syswarden_hw_drop "$SET_NAME" '{' "$WL_IP" '}' 2>/dev/null || true
    fi

    # 3. Trigger the orchestrator to rebuild rules with the strict hierarchy
    apply_firewall_rules

    log "SUCCESS" "IP $WL_IP safely whitelisted. Strict firewall hierarchy preserved."
    # ------------------------------------------------------
}

blocklist_ip() {
    echo -e "\n${RED}=== SysWarden Manual Blocklist Manager ===${NC}"
    read -p "Enter IP to Block: " BL_IP

    # Simple IP validation
    if [[ ! "$BL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    # --- LOCAL PERSISTENCE (SINGLE SOURCE OF TRUTH) ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$BLOCKLIST_FILE"
    if ! grep -q "^${BL_IP}$" "$BLOCKLIST_FILE" 2>/dev/null; then
        echo "$BL_IP" >>"$BLOCKLIST_FILE"
        log "INFO" "IP $BL_IP securely saved to $BLOCKLIST_FILE."
    else
        log "INFO" "IP $BL_IP is already in the blocklist file."
    fi
    # --------------------------------------------------

    log "INFO" "Blocking IP: $BL_IP on backend: $FIREWALL_BACKEND"

    # --- FIX: SAFE DYNAMIC BLOCKLISTING (STATE MACHINE) ---
    log "INFO" "Rebuilding firewall framework to safely integrate the new IP..."

    # 1. Force loading config to ensure core variables (SSH_PORT, USE_WIREGUARD) are in RAM
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # 2. Trigger the orchestrator to rebuild rules and load the IP into active sets
    apply_firewall_rules

    log "SUCCESS" "IP $BL_IP safely blocklisted. Strict firewall hierarchy preserved."
    # ------------------------------------------------------
}

protect_docker_jail() {
    echo -e "\n${BLUE}=== SysWarden Docker Jail Protector ===${NC}"

    # --- HOTFIX: DEPENDENCY & STATE VERIFICATION ---
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    if [[ "${USE_DOCKER:-n}" != "y" ]]; then
        log "ERROR" "Docker integration is disabled in SysWarden. Run the installer to enable it."
        exit 1
    fi

    local action_file="/etc/fail2ban/action.d/syswarden-docker.conf"
    if [[ ! -f "$action_file" ]]; then
        log "ERROR" "Docker banaction ($action_file) is missing. Cannot protect Docker jails."
        exit 1
    fi
    # ------------------------------------------------------

    local jail_file="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_file" ]]; then
        log "ERROR" "Fail2ban configuration ($jail_file) not found."
        exit 1
    fi

    # Display active jails to help the user
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        local active_jails
        active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
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
    local temp_file
    temp_file=$(mktemp)
    local in_target_jail=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            if [[ "$line" == "[${jail_name}]" ]]; then
                in_target_jail=1
                echo "$line" >>"$temp_file"
                echo "banaction = syswarden-docker" >>"$temp_file"
                continue
            else
                in_target_jail=0
            fi
        fi

        # If inside the target block, skip any pre-existing 'banaction' line to avoid duplicates
        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >>"$temp_file"
    done <"$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."

    if command -v systemctl >/dev/null; then
        systemctl restart fail2ban
        log "INFO" "Fail2ban service restarted to apply changes."

        # --- HOTFIX: STATEFUL DOCKER BYPASS RE-ENFORCEMENT ---
        # Fail2ban restarts will inject new chains at the top of DOCKER-USER.
        # We MUST ensure the ESTABLISHED, RELATED rule remains at Absolute Priority 0.
        if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
            iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
            log "INFO" "Stateful Docker bypass successfully re-enforced at Priority 0."

            # Persist state so the new order survives reboots
            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then
                service iptables save 2>/dev/null || true
            fi
        fi
        # ------------------------------------------------------------
    fi
}

check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Universal) ===${NC}"

    # --- DEVSECOPS FIX: CAPTURE ABSOLUTE PATH EARLY ---
    # We must resolve $0 before any 'cd' commands alter the current working directory,
    # otherwise realpath resolves relative to the temp folder, causing a cp self-collision.
    local current_script
    current_script=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "${PWD}/${0#./}")

    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response

    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden\.sh"' | head -n 1 | cut -d'"' -f4)

    local hash_url
    hash_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden\.sh\.sha256"' | head -n 1 | cut -d'"' -f4)

    if [[ -z "$download_url" ]]; then
        echo -e "${GREEN}No specific update found for the Universal version in the latest release. You are up to date!${NC}"
        return
    fi

    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Universal version ($latest_version) is available!${NC}"

        # --- DEVSECOPS: INTERACTIVE CONFIRMATION ---
        read -p "Do you want to proceed with the automated in-place upgrade now? (y/N): " proceed_upgrade
        if [[ ! "$proceed_upgrade" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrade aborted by user. System remains on $VERSION.${NC}"
            return
        fi

        # --- SECURITY FIX: MITM PROTECTION & SECURE UPDATE (CWE-494: Download of Code Without Integrity Check) ---
        echo -e "${YELLOW}Downloading and verifying update securely...${NC}"

        # --- HOTFIX: SAME-FILE COLLISION PREVENTION ---
        # Create an isolated sub-directory for the update payload to guarantee
        # it never collides with the script's current execution path.
        local UPGRADE_DIR="$TMP_DIR/syswarden_upgrade_payload"
        mkdir -p "$UPGRADE_DIR"

        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden.sh" "$download_url"
        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden.sh.sha256" "$hash_url"

        cd "$UPGRADE_DIR" || exit 1

        if ! sha256sum -c install-syswarden.sh.sha256 --status; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The downloaded script failed cryptographic validation!${NC}"
            echo -e "${RED}Possible causes: Man-In-The-Middle (MITM) attack, DNS poisoning, or incomplete download.${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        echo -e "${GREEN}Checksum validated successfully. Preparing in-place upgrade...${NC}"

        # --- PRE-UPGRADE: SURGICAL PROCESS TERMINATION ---
        # We must kill background telemetry and UI processes to avoid zombie orphans
        # or file locking issues during the transition to the new script version.
        log "INFO" "Terminating existing SysWarden background processes safely..."
        pkill -9 -f syswarden-telemetry 2>/dev/null || true
        pkill -9 -f syswarden_reporter 2>/dev/null || true

        if command -v systemctl >/dev/null; then
            systemctl stop syswarden-ui 2>/dev/null || true
            systemctl stop syswarden-reporter 2>/dev/null || true
        fi

        # --- IN-PLACE SCRIPT REPLACEMENT ---
        log "INFO" "Replacing current orchestrator at $current_script..."

        # We explicitly copy instead of move in case the OS locks the executing file
        cp -f "$UPGRADE_DIR/install-syswarden.sh" "$current_script"
        chmod 700 "$current_script"

        # Configuration sanity check
        if [[ ! -f "$CONF_FILE" ]]; then
            log "WARN" "Configuration file $CONF_FILE missing! The upgrade will behave as a fresh install."
        else
            log "INFO" "Configuration file $CONF_FILE found. User settings will be strictly preserved."
        fi

        echo -e "${GREEN}In-place upgrade sequence initiated. Handing over to the new version...${NC}"

        # --- EXECUTE NEW VERSION (PROCESS HANDOFF) ---
        exec bash "$current_script" update
    fi
}

show_alerts_dashboard() {
    # Trap Ctrl+C/Exit to restore cursor safely
    trap 'tput cnorm; echo -e "\n${GREEN}Exiting Dashboard...${NC}"; exit 0' INT TERM
    tput civis # Hide cursor for cleaner UI

    echo -e "\n${BLUE}=========================================================================================${NC}"
    echo -e "${GREEN}                        SYSWARDEN CLI DASHBOARD (Live Alerts)                            ${NC}"
    echo -e "${BLUE}=========================================================================================${NC}"
    echo -e "${YELLOW}[i] Tailing live Threat Intelligence Logs... (Press Ctrl+C to stop)${NC}\n"

    # --- TABLE HEADER ---
    printf "\033[1m\033[36m%-19s | %-16s | %-10s | %-15s | %s\033[0m\n" "TIMESTAMP" "MODULE" "ACTION" "SOURCE IP" "TARGET (PORT/JAIL)"
    echo -e "${BLUE}--------------------+------------------+------------+-----------------+--------------------${NC}"

    # HOTFIX: Mawk (Debian/Ubuntu) Input Buffering Bypass via Function Wrapper
    # Avoids IFS strict-mode word-splitting issues while injecting the '-W interactive' flag.
    syswarden_awk() {
        if awk -W version 2>&1 | grep -qi "mawk"; then
            awk -W interactive "$@"
        else
            awk "$@"
        fi
    }

    # Multiplex Systemd Journal and Flat files safely without creating orphan processes
    (
        P1=""
        if command -v journalctl >/dev/null 2>&1; then
            journalctl -k -f --no-pager 2>/dev/null &
            P1=$!
        fi

        P2=""
        local LOGS=()
        # HOTFIX: Integration of all possible log targets across Debian, Alpine, and Slackware
        [[ -f /var/log/kern-firewall.log ]] && LOGS+=(/var/log/kern-firewall.log)
        [[ -f /var/log/auth-syswarden.log ]] && LOGS+=(/var/log/auth-syswarden.log)
        [[ -f /var/log/fail2ban.log ]] && LOGS+=(/var/log/fail2ban.log)
        [[ -f /var/log/kern.log ]] && LOGS+=(/var/log/kern.log)
        [[ -f /var/log/syslog ]] && LOGS+=(/var/log/syslog)
        [[ -f /var/log/messages ]] && LOGS+=(/var/log/messages)

        if [[ ${#LOGS[@]} -gt 0 ]]; then
            tail -F -q "${LOGS[@]}" 2>/dev/null &
            P2=$!
        fi

        trap '[[ -n "$P1" ]] && kill $P1 2>/dev/null; [[ -n "$P2" ]] && kill $P2 2>/dev/null' EXIT
        wait
    ) | syswarden_awk '
    BEGIN {
        # Map syslog months to ISO numbers and fetch current year
        m["Jan"]="01"; m["Feb"]="02"; m["Mar"]="03"; m["Apr"]="04"; m["May"]="05"; m["Jun"]="06";
        m["Jul"]="07"; m["Aug"]="08"; m["Sep"]="09"; m["Oct"]="10"; m["Nov"]="11"; m["Dec"]="12";
        "date +%Y" | getline current_year; close("date +%Y")
    }
    {
        # --- 1. FIREWALL ALERTS PROCESSING ---
        if ($0 ~ /SysWarden-BLOCK|SysWarden-GEO|SysWarden-ASN|Catch-All/) {
            
            # Universal Date Parsing (Supports ISO-8601 from Debian 13 and Legacy Syslog)
            if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T/) {
                date = substr($1, 1, 10) " " substr($1, 12, 8)
            } else if ($1 in m) {
                date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
            } else {
                date = $1 " " $2 " " $3
            }
            
            module = "SysWarden-CATCH"
            if (match($0, /\[SysWarden-[A-Za-z]+\]/)) {
                module = substr($0, RSTART+1, RLENGTH-2)
            }
            
            src = "N/A"
            # IPv4 Strict Matching
            if (match($0, /SRC=[0-9.]+/)) {
                src = substr($0, RSTART+4, RLENGTH-4)
            }
            
            # --- HOTFIX: Dynamic Target Info (Port vs Protocol for ICMP/IGMP) ---
            target_info = "PORT: N/A"
            if (match($0, /DPT=[0-9]+/)) {
                # Extract port if present (TCP/UDP)
                target_info = "PORT: " substr($0, RSTART+4, RLENGTH-4)
            } else if (match($0, /PROTO=[A-Za-z0-9]+/)) {
                # Fallback to protocol if no port provided (e.g. ICMP)
                target_info = "PROTO: " substr($0, RSTART+6, RLENGTH-6)
            }
            
            printf "\033[1;30m%-19s\033[0m | \033[1;34m%-16s\033[0m | \033[1;31m%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36m%s\033[0m\n", date, module, "BLOCKED", src, target_info
            
            # HOTFIX: Universal stdout flush (Works on Debian mawk, Alpine busybox, RHEL gawk)
            system("")
            next
        }
        
        # --- 2. FAIL2BAN ALERTS PROCESSING ---
        if (($0 ~ /Ban / || $0 ~ /Found /) && $0 !~ /Restore/) {
            date = $1 " " $2
            sub(/,.*/, "", date)
            
            jail = "Unknown"
            if (match($0, /\[[-_A-Za-z0-9]+\] (Found|Ban)/)) {
                str = substr($0, RSTART, RLENGTH)
                if (match(str, /\[[-_A-Za-z0-9]+\]/)) {
                    jail = substr(str, RSTART+1, RLENGTH-2)
                }
            }
            
            act = ($0 ~ /Ban /) ? "BANNED" : "DETECTED"
            act_color = ($0 ~ /Ban /) ? "\033[1;31m" : "\033[1;35m"
            
            ip = "Unknown"
            # IPv4 Strict Matching
            if (match($0, /(Found|Ban) [0-9.]+/)) {
                ip = substr($0, RSTART, RLENGTH)
                sub(/(Found|Ban) /, "", ip)
            }
            
            printf "\033[1;30m%-19s\033[0m | \033[1;35m%-16s\033[0m | %s%-10s\033[0m | \033[1;33m%-15s\033[0m | \033[1;36mJAIL: %s\033[0m\n", date, "FAIL2BAN WAF", act_color, act, ip, jail
            
            # HOTFIX: Universal stdout flush
            system("")
        }
    }' || true

    tput cnorm # Restore cursor
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

MODE="${1:-install}"

# --- HEADLESS / UNATTENDED INSTALLATION PARSER ---
# Safely parses a provided .conf file to inject environment variables
if [[ -f "${1:-}" ]]; then
    echo -e "${GREEN}>>> Unattended configuration file detected: $1${NC}"

    # --- SECURITY FIX: SECURE AUTO-CONF FILE (CWE-732: Incorrect Permission Assignment for Critical Resource) ---
    # Restrict permissions immediately so local non-root users cannot read
    # the secrets inside (e.g., API keys, custom network configurations)
    chmod 600 "$1"
    # -------------------------------------------

    while IFS='=' read -r key val; do
        # Ignore comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue

        # Clean up the key and value (remove whitespaces and quotes)
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | xargs | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")

        # STRICT SECURITY: Only export variables starting with SYSWARDEN_
        # Prevents arbitrary code execution or PATH manipulation
        if [[ "$key" =~ ^SYSWARDEN_[A-Z0-9_]+$ ]]; then
            export "$key"="$val"
        fi
    done <"$1"

    # Force auto mode to bypass all interactive prompts
    MODE="auto"
elif [[ "$MODE" == "--auto" ]]; then
    # Legacy CI/CD support
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

if [[ "$MODE" == "fail2ban-jails" ]]; then
    check_root
    detect_os_backend

    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${GREEN}SysWarden - Fail2ban Jails Auto-Discovery & Reload${NC}"
    echo -e "${BLUE}======================================================================${NC}"

    # 1. Load existing configuration to retrieve custom settings (e.g., SSH_PORT)
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Configuration loaded successfully."
    else
        log "ERROR" "Configuration file ($CONF_FILE) not found. Please install SysWarden first."
        exit 1
    fi

    # 2. Trigger the existing Fail2ban configuration function (Auto-Discovery)
    log "INFO" "Scanning system for active services (Nginx, Apache, MongoDB, etc.)..."
    configure_fail2ban

    # --- HOTFIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
    # Ensure the log file exists before restarting, in case of logrotate or fresh env.
    if [[ ! -f /var/log/fail2ban.log ]]; then
        touch /var/log/fail2ban.log
        chmod 640 /var/log/fail2ban.log
        chown root:root /var/log/fail2ban.log 2>/dev/null || true
    fi
    # ------------------------------------------------------

    # 3. Reload the Fail2ban service natively based on the OS Init System
    log "INFO" "Restarting Fail2ban to apply new jails..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart fail2ban 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service fail2ban restart 2>/dev/null || true
    else
        fail2ban-client reload 2>/dev/null || true
    fi

    # --- HOTFIX: Calm Down boy ---
    sleep 5

    # 4. Show the final status to the administrator
    echo -e "\n${GREEN}[+] Fail2ban jails successfully updated! Active jails:${NC}"
    fail2ban-client status
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
    detect_os_backend
    uninstall_syswarden
fi

if [[ "$MODE" == "cron-update" ]]; then
    log "INFO" "Starting silent CRON update (Threat Intelligence only)..."
    check_root
    detect_os_backend

    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    else
        log "ERROR" "Config file missing. Aborting cron update."
        exit 1
    fi

    # 1. Download fresh lists
    select_list_type "update"
    select_mirror "update"
    download_list
    download_osint
    download_geoip
    download_asn

    # 2. Inject silently into Kernel (Zero-Downtime)
    discover_active_services
    apply_firewall_rules

    log "INFO" "CRON Update Complete. Firewall rules refreshed securely."
    # Vital exit 0
    exit 0
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
    echo -e "${GREEN}               Host-based Security Orchestrator for Linux. | v0.27.4                  ${NC}"
    echo -e "${BLUE}===================================================================================${NC}\n"
fi

check_root
detect_os_backend

# --- PREVENT ADMIN LOCK-OUT (EXECUTE BEFORE FAIL2BAN/FIREWALL) ---
auto_whitelist_admin
process_auto_whitelist "$MODE"
auto_whitelist_infra "$MODE"
# -----------------------------------------------------------------

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
    : >"$CONF_FILE"
    install_dependencies

    # --- CRITICAL ARCHITECTURE FIX ---
    # Re-detect backend! DNF might have just installed Firewalld or Nftables (via fail2ban)
    detect_os_backend
    # ---------------------------------

    # --- DEVSECOPS: PRE-FLIGHT CHECKLIST (Interactive Mode Only) ---
    if [[ "$MODE" != "auto" ]]; then
        BOLD='\033[1m'
        CYAN='\033[0;36m'
        clear
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v0.27.4 - PRE-FLIGHT CHECKLIST                     ${NC}"
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "Before proceeding with the deployment, please ensure you have the following"
        echo -e "information ready. If you lack any required data, press [Ctrl+C] to abort,"
        echo -e "gather the info, and restart the script.\n"

        echo -e "${BOLD}1. SSH CONFIGURATION${NC}"
        echo -e "   You will need to confirm the custom SSH port used to connect to this server."

        echo -e "\n${BOLD}2. FIREWALL ENGINE OPTIMIZATION${NC} ${YELLOW}(RHEL/Alma/Fedora only)${NC}"
        echo -e "   Decide whether to bypass Firewalld in favor of pure Nftables or Iptables"
        echo -e "   for extreme performance when loading massive Threat Intelligence blocklists."

        echo -e "\n${BOLD}3. WIREGUARD VPN${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Decide if you need a stealth admin VPN. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}4. DOCKER INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires Layer 3 routing adjustments for containers. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}5. OS HARDENING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Strict restrictions for privileged groups (Sudo/Wheel) & Cron. Recommended for NEW servers only."

        echo -e "\n${BOLD}6. GEOIP BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   ISO country codes to drop instantly (e.g., RU,CN,KP)."
        echo -e "   Reference: ${CYAN}https://www.ipdeny.com/ipblocks/${NC}"

        echo -e "\n${BOLD}7. ASN BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Target Autonomous System Numbers to drop (e.g., AS1234, AS5678)."
        echo -e "   Reference: ${CYAN}https://www.spamhaus.org/drop/asndrop.json${NC}"

        echo -e "\n${BOLD}8. HA CLUSTER SYNC${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Standby Node IP for automatic threat intelligence replication."

        echo -e "\n${BOLD}9. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] Disabled"

        echo -e "\n${BOLD}10. SIEM LOG FORWARDING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   External SIEM IP, Port (Default: 6514), and Protocol for central log auditing."
        echo -e "   Required for strict ISO 27001 / NIS2 compliance."

        echo -e "\n${BOLD}11. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."
        echo -e "   Get one at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"

        echo -e "\n${BOLD}12. WAZUH SIEM AGENT${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Required: Manager IP, Enrollment Port (1515), Listen Port (1514)."
        echo -e "   If unsure about your SIEM architecture, consult your Security Admin."

        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        read -p "$(echo -e "${YELLOW}Press [ENTER] to begin the configuration, or [Ctrl+C] to abort... ${NC}")"
        echo ""
        log "INFO" "Pre-Flight Checklist acknowledged. Starting interactive configuration..."
    fi
    # ---------------------------------------------------------------

    define_ssh_port "$MODE"
    define_firewall_engine "$MODE"
    define_wireguard "$MODE"
    define_docker_integration "$MODE"
    define_os_hardening "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
    define_ha_cluster "$MODE"

    # Run the interactive/setup phases for the SIEM early so questions are asked up front.
    # The actual OS modification happens inside this function.
    setup_siem_logging "$MODE"

    configure_fail2ban
fi

# --- FIX 1: THE SOURCE GAP ---
# Force sourcing the config to ensure variables (GEOIP_ENABLED, ASN_ENABLED, etc.)
# are loaded in RAM even during a fresh install.
if [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
fi
# -----------------------------

select_list_type "$MODE"
select_mirror "$MODE"
download_list
download_osint

# --- FIX 2: THE COLD BOOT INJECTION (FRESH INSTALL ONLY) ---
# Initialize base chains/sets before downloading massive lists to prevent
# service dependency crashes (like Fail2ban starting too early).
if [[ "$MODE" != "update" ]]; then
    discover_active_services
    apply_firewall_rules
fi

download_geoip
download_asn
# --------------------------------------

# --- FIX 3: THE POST-DOWNLOAD RELOAD (INSTALL & UPDATE) ---
# Now that massive lists are downloaded/updated on disk, we ALWAYS reload
# the firewall to inject the freshest GeoIP, ASN, and Blocklist data.
log "INFO" "Applying massive downloaded lists to active firewall..."
discover_active_services
apply_firewall_rules

# --- NEW DEVSECOPS UPGRADE LOGIC ---
# Ensures that both fresh installs and in-place upgrades receive the
# absolute latest Layer 7 application firewall rules and regex payloads.
log "INFO" "Applying Layer 7 Application Firewall Rules (Fail2ban)..."
configure_fail2ban
# -----------------------------------

detect_protected_services

# --- HOTFIX: STATEFUL REPORTER RESTART LOGIC ---
# We check if the service is ENABLED (configured to run by the user),
# not ACTIVE, because the pre-upgrade hook explicitly killed it earlier.
if command -v systemctl >/dev/null && systemctl is-enabled --quiet syswarden-reporter 2>/dev/null; then
    log "INFO" "Restarting SysWarden Unified Reporter..."

    # --- DEVSECOPS FIX: SYSTEMD/SELINUX STATE MIGRATION ---
    # If upgrading from a version that used DynamicUser=yes, Systemd leaves a symlink
    # pointing to /var/lib/private/syswarden. SELinux (on RHEL/Alma) will actively block
    # Systemd from unlinking this during transition, causing a fatal Code 238 crash.
    # We forcefully purge the legacy structure before restarting the daemon.
    if [[ -L "/var/lib/syswarden" ]] || [[ -d "/var/lib/private/syswarden" ]]; then
        log "INFO" "Purging legacy DynamicUser state directories to prevent SELinux conflicts..."
        rm -rf /var/lib/syswarden /var/lib/private/syswarden 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    # ------------------------------------------------------

    systemctl restart syswarden-reporter >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null && rc-update show default 2>/dev/null | grep -q "syswarden-reporter"; then
    log "INFO" "Restarting SysWarden Unified Reporter (OpenRC)..."
    rc-service syswarden-reporter restart >/dev/null 2>&1 || true
fi

# --- HOTFIX: DASHBOARD & TELEMETRY ORCHESTRATION ---
setup_telemetry_backend
generate_dashboard
# ---------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    # setup_siem_logging is now executed earlier during the interactive definition phase
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"

    # User-authorized IT hardening
    apply_os_hardening

    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> List loaded: $LIST_TYPE"

    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Universal (Interactive)"
    fi

    echo -e " -> Protection: Active"

    display_wireguard_qr
else
    # --- HOTFIX: FORCE CRON SYNTAX UPGRADE DURING UPDATE ---
    # Silently patches existing crontabs to use the safe 'cron-update' argument
    if [[ -f /etc/cron.d/syswarden-update ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/cron.d/syswarden-update 2>/dev/null || true
    fi
    if [[ -f /etc/crontabs/root ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/crontabs/root 2>/dev/null || true
    fi

    # Restart the appropriate Cron daemon natively (Debian=cron, RHEL/Alma=crond)
    if command -v systemctl >/dev/null; then
        systemctl restart crond 2>/dev/null || systemctl restart cron 2>/dev/null || true
    fi
    # --------------------------------------------------------------

    # Restart Fail2ban gracefully to compile the newly injected Python/Regex rules
    log "INFO" "Restarting Fail2ban engine to compile new definitions..."

    if command -v systemctl >/dev/null; then
        # --- HOTFIX: SOCKET RACE CONDITION PREVENTION ---
        # Stop the service explicitly, wait 5 seconds for the .sock file to be
        # purged from /var/run/ by the kernel, then start it cleanly.
        systemctl stop fail2ban >/dev/null 2>&1 || true
        sleep 5
        systemctl start fail2ban >/dev/null 2>&1 || true
    else
        # Fallback for SysVinit / OpenRC
        fail2ban-client stop >/dev/null 2>&1 || true
        sleep 5
        fail2ban-client start >/dev/null 2>&1 || true
    fi

    # Give clear feedback during an update
    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
    echo -e " -> SysWarden Engine (L2/L3 & L7) and Dashboard UI have been updated to the latest version."
fi
