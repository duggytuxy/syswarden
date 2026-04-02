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
NC='\033[0m' # No Color

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"
TMP_DIR=$(mktemp -d)
VERSION="v1.84"
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
    local missing_common=()

    # ==============================================================================
    # --- DEVSECOPS FIX: STATE TRACKER (Avoid God Mode Uninstall) ---
    # Record pre-existing critical services so we don't purge them on uninstall.
    # MUST BE EXECUTED BEFORE ANY APT/DNF COMMANDS!
    # ==============================================================================
    if [[ ! -f "$CONF_FILE" ]]; then
        touch "$CONF_FILE"
        chmod 600 "$CONF_FILE"
    fi
    if ! command -v nginx >/dev/null 2>&1; then
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
    if ! command -v python3 >/dev/null; then missing_common+=("python3"); fi
    if ! command -v whois >/dev/null; then missing_common+=("whois"); fi
    # --- FIX: Added 'jq' dependency required for telemetry JSON generation ---
    if ! command -v jq >/dev/null; then missing_common+=("jq"); fi
    # -----------------------------------------------------------------------

    # --- DEVSECOPS FIX: NGINX & OPENSSL AS CORE DEPENDENCIES ---
    if ! command -v nginx >/dev/null; then missing_common+=("nginx"); fi
    if ! command -v openssl >/dev/null; then missing_common+=("openssl"); fi
    # -----------------------------------------------------------

    # Check if array is not empty
    if [[ ${#missing_common[@]} -gt 0 ]]; then

        # --- DEVSECOPS FIX: GHOST CONFIGURATION PREVENTION ---
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

    # --- DEVSECOPS FIX: PREEMPTIVE NGINX LOG CREATION ---
    # We guarantee the existence of Nginx logs immediately after package installation.
    # This ensures Fail2ban naturally detects them and activates Layer 7 Web Jails natively.
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log /var/log/nginx/error.log
    chmod 640 /var/log/nginx/*.log 2>/dev/null || true
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

        # --- SECURITY FIX: UNIVERSAL KERNEL LOGGING & LOG INJECTION PREVENTION ---
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

    # --- SECURITY FIX: DISABLE TCP FORWARDING (ANTI-PIVOTING) ---
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

    # --- SECURITY FIX: BULLETPROOF KERNEL SOCKET DETECTION ---
    # If the user ran 'su -' or 'sudo su', SSH variables are wiped.
    # We query active SSH sockets directly. Order-independent grep ensures
    # compatibility across all versions of ss and netstat, while grep -oE
    # perfectly extracts IPv4 even from IPv4-mapped IPv6 addresses (::ffff:IP).
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Use 'ss' if available (modern iproute2)
        if command -v ss >/dev/null; then
            admin_ip=$(ss -tnp 2>/dev/null | grep -i 'estab' | grep -i 'sshd' | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        # Fallback to 'netstat' (net-tools / Alpine busybox)
        elif command -v netstat >/dev/null; then
            admin_ip=$(netstat -tnpa 2>/dev/null | grep -i 'established' | grep -i 'sshd' | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    # 3. Final Fallback: 'who' command
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        admin_ip=$(who 2>/dev/null | awk '{print $5}' | tr -d '()' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
    fi
    # ---------------------------------------------------------

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
        1) LIST_TYPE="Standard" ;;
        2) LIST_TYPE="Critical" ;;
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
        4) LIST_TYPE="None" ;;
        *)
            log "WARN" "Invalid choice detected. Defaulting to Standard List."
            LIST_TYPE="Standard"
            ;;
    esac

    echo "LIST_TYPE='$LIST_TYPE'" >>"$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >>"$CONF_FILE"; fi
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
    echo "GEOBLOCK_COUNTRIES='$GEOBLOCK_COUNTRIES'" >>"$CONF_FILE"
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
    echo "BLOCK_ASNS='$BLOCK_ASNS'" >>"$CONF_FILE"
    echo "USE_SPAMHAUS_ASN='$USE_SPAMHAUS_ASN'" >>"$CONF_FILE"
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
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION ---
        # Validates exact octet ranges (0-255) and subnet masks (0-32) to prevent firewall crash (F13)
        tr -d '\r' <"$output_file" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >"$TMP_DIR/clean_list.txt"
        # -----------------------------------------------------ist.txt"
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
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION ---
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
    # On sort si l'utilisateur n'a rien mis en perso ET a dit non à Spamhaus
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

        # --- SECURITY FIX: ATOMIC NFTABLES RELOAD (ANTI-OOM) ---
        # By formatting the entire ruleset and massive IP sets into a single
        # structured file, 'nft -f' will execute a 100% atomic swap at the kernel level.
        # We define sets as empty first, then append elements in chunks using xargs.
        # This completely bypasses the Nftables parser memory spike and prevents
        # the OOM Killer from crashing small VMs when ingesting 250k+ IPs.

        # 1. Start building the atomic configuration file
        cat <<EOF >"$TMP_DIR/syswarden.nft"
# Flush the table atomically (if it exists) and recreate it
table inet syswarden_table
delete table inet syswarden_table
table inet syswarden_table {

    # 2. Define massive IP sets (Empty initially)
    set $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            cat <<EOF >>"$TMP_DIR/syswarden.nft"
    set $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            cat <<EOF >>"$TMP_DIR/syswarden.nft"
    set $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF
        fi

        # --- DEVSECOPS FIX: THE PRIORITY SANDWICH ARCHITECTURE ---
        # 3. FRONTLINE CHAIN (Executes BEFORE Fail2ban at priority -10)
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
            echo "        iifname { \"wg0\", \"lo\" } accept comment \"SysWarden: Global Trust for VPN\"" >>"$TMP_DIR/syswarden.nft"
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

        # --- DEVSECOPS FIX: WG BACKEND SURVIVAL ---
        # WG traffic explicitly allowed in Frontline must ALSO be allowed in the Zero-Trust Backend
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "        iifname { \"wg0\", \"lo\" } accept" >>"$TMP_DIR/syswarden.nft"
        fi
        # ------------------------------------------

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
        # The Catch-All Drop: Any packet surviving Frontline and Fail2ban hits this.
        log prefix "[SysWarden-BLOCK] [Catch-All] " drop
    }
}
EOF

        # 4. APPEND ELEMENTS IN CHUNKS (Anti-OOM Killer)
        log "INFO" "Populating Nftables sets atomically in chunks (Bypassing memory limits)..."

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

        log "INFO" "Applying Atomic Nftables Transaction to the Kernel..."
        nft -f "$TMP_DIR/syswarden.nft"
        # --------------------------------------------

        # --- FIX: KERNEL FORWARDING & OS-LEVEL BYPASS FOR WIREGUARD ---
        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            log "INFO" "Applying WireGuard routing bypass to native OS tables..."
            if nft list table inet filter >/dev/null 2>&1; then
                # 1. Open UDP port and allow wg0 interface in OS default input chain
                if nft list chain inet filter input >/dev/null 2>&1; then
                    # DEVSECOPS FIX: grep >/dev/null prevents SIGPIPE pipefail crashes that cause ghost duplicates
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

                # --- DEVSECOPS FIX: BACKUP NATIVE TABLE ---
                echo '#!/usr/sbin/nft -f' >/etc/nftables.conf
                echo 'flush ruleset' >>/etc/nftables.conf
                nft list table inet filter >>/etc/nftables.conf 2>/dev/null || true
                # ----------------------------------------------------------
            fi
        fi
        # --------------------------------------------------------------

        # --- MODULAR PERSISTENCE (ZERO-TOUCH) ---
        log "INFO" "Saving SysWarden Nftables table to isolated config..."
        mkdir -p /etc/syswarden
        # FIX: Export ONLY our specific table, preserving user custom rules
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft

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

            # --- STRICT ZERO TRUST HIERARCHY (v1.84) - DEBIAN PARITY) ---

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
                # DEVSECOPS FIX: Use dynamic ACTIVE_ZONE instead of hardcoded public
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

            # Priority 2: DEVSECOPS FIX - Global Trust for WireGuard Interface (Fixes Ping & UI)
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

        if ! iptables -C INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "

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

            if ! iptables -C INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Pushed down by GeoIP later if exists)
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
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

            if ! iptables -C INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
                # Insert at position 1 (Top priority, enforced before ASN and standard list)
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j DROP
                iptables -I INPUT 1 -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] "
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

        # --- DEVSECOPS FIX: IDEMPOTENCY FOR IPTABLES (ANTI-CRON DUPLICATION) ---
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
            # --- DEVSECOPS FIX: STATEFUL DOCKER BYPASS (Priority 0 - Absolute Top) ---
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

    # --- DEVSECOPS FIX: TELNET HONEYPOT FAIL-SAFE ---
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

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS ---
        # Default OS files (like defaults-debian.conf) override our strict jail.local settings.
        # We delete all existing configurations in jail.d/ to enforce Zero Trust.
        if [[ -d /etc/fail2ban/jail.d ]]; then
            find /etc/fail2ban/jail.d/ -type f -name "*.conf" -exec rm -f {} +
            log "INFO" "Purged default jail.d configurations to enforce Zero Trust."
        fi
        # -----------------------------------------------------

        # --- Add backup Fai2ban jail ---
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi
        # -------------------------------------------------------

        # 1. Standardized Log Target (Crucial for Recidive Jail and Telemetry JSON)
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
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

        # --- DEVSECOPS FIX: SYSTEMD BACKEND OPTIMIZATION ---
        local OS_BACKEND="auto"
        if command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-journald 2>/dev/null; then
            OS_BACKEND="systemd"
            log "INFO" "Systemd-journald detected. OS-native jails will be optimized for maximum performance."
        fi
        # ---------------------------------------------------

        # --- DEVSECOPS FIX: LONG-TERM RECIDIVE FILTER ---
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
# Strictly catches Ban events in Fail2ban's own log to identify persistent horizontal movement
failregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Ban|Found) <HOST>\s*$
ignoreregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Restore )?(?:Unban|unban) <HOST>\s*$
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
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"(GET|POST|HEAD).*\" (400|401|403|404|444) .*$\nignoreregex =" >/etc/fail2ban/filter.d/nginx-scanner.conf
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
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"(GET|POST|HEAD) .+\" (400|401|403|404) .+\$\nignoreregex =" >/etc/fail2ban/filter.d/apache-scanner.conf
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
            # Catches: "Authentication failed", "SASL authentication failed", "unauthorized", "not authorized"
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).* <HOST>(:[0-9]+)?.*\$\nignoreregex =" >/etc/fail2ban/filter.d/mongodb-guard.conf
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
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*[Aa]ccess denied for user .*@'<HOST>'.*\$\nignoreregex =" >/etc/fail2ban/filter.d/mariadb-auth.conf
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
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"POST .*(wp-login\.php|xmlrpc\.php) HTTP.*\" 200\nignoreregex =" >/etc/fail2ban/filter.d/wordpress-auth.conf
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
            # Matches POST requests to /user/login (Modern Clean URLs) and ?q=user/login (Legacy D7)
            # Logic: A failed login returns HTTP 200 (Form reloads with error). Success returns HTTP 302/303.
            if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/user/login|\?q=user/login) HTTP.*" 200.*$
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
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Login failed: .* \(Remote IP: '<HOST>'\).*$\nignoreregex =" >/etc/fail2ban/filter.d/nextcloud.conf
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
                echo -e "[Definition]\nfailregex = ^.*failed login of user .* from <HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/zabbix-auth.conf
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
                echo -e "[Definition]\nfailregex = ^.* <HOST>:\d+ .+(400|403|404|429) .+\$\nignoreregex =" >/etc/fail2ban/filter.d/haproxy-guard.conf
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
                    echo -e "[Definition]\nfailregex = ^.*wireguard: .* Handshake for peer .* \\(<HOST>:[0-9]+\\) did not complete.*\$\nignoreregex =" >/etc/fail2ban/filter.d/wireguard.conf
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

                # Create Filter for POST requests to PMA (Bruteforce usually returns 200 OK)
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                    echo -e "[Definition]\nfailregex = ^<HOST> \\S+ \\S+ \\[.*?\\] \"POST .*phpmyadmin.* HTTP.*\" 200\nignoreregex =" >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
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
                echo -e "[Definition]\nfailregex = ^.*Failed authentication attempt for .* from <HOST>:.*\$\nignoreregex =" >/etc/fail2ban/filter.d/gitea-custom.conf
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
                echo -e "[Definition]\nfailregex = ^.*cockpit-ws.*(?:authentication failed|invalid user).*from <HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/cockpit-custom.conf
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
[Definition]
failregex = ^.*(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^.*(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^.* PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
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
failregex = ^.* <HOST>:[0-9]+ .* [Aa]uthentication failed.*\s*$
            ^.* Client <HOST>:[0-9]+ disconnected, .* [Aa]uthentication.*\s*$
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
failregex = ^.*HTTP access denied: .* from <HOST>.*\s*$
            ^.*AMQP connection <HOST>:[0-9]+ .* failed: .*authentication failure.*\s*$
            ^.*<HOST>:[0-9]+ .* (?:invalid credentials|authentication failed).*\s*$
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
# FIX: Strict anchor ^%(__prefix_line)s prevents Log Injection from users.
failregex = ^%(__prefix_line)s(?:kernel: |\[[0-9. ]+\] ).*\[SysWarden-BLOCK\].*SRC=<HOST> .*$
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
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc\s+-e|nc\x2520-e|nc\s+-c|curl\s+http|curl\x2520http|wget\s+http|wget\x2520http|python\s+-c|php\s+-r|;\s*bash\s+-i|&\s*bash\s+-i).*" .*$
ignoreregex = 
EOF
            fi

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
bantime  = 24h
EOF
        fi

        # 32. DYNAMIC DETECTION: MALICIOUS AI BOTS & SCRAPERS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

            # Create Filter for aggressive AI Scrapers, Crawlers, and LLM data miners
            # Matches HTTP requests containing known AI User-Agents regardless of the HTTP status code (\d{3})
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) .*" \d{3} .* ".*(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai).*".*$
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
            # Matches HTTP requests containing known offensive User-Agents regardless of the HTTP status code (\d{3})
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) .*" \d{3} .* ".*(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf).*".*$
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
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "POST .*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads).*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?.*)? HTTP/.*" \d{3} .*$
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
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F).*" \d{3} .*$
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
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] ".*" \d{3} .* "(?:\$\{jndi:|\x2524\x257Bjndi:).*"$
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
            # Triggers strictly on 403/404 errors, meaning the attacker is GUESSING the endpoint paths
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) .*(?:/swagger-ui[^ ]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ ]*|/graphiql|/graphql/schema) HTTP/.*" (403|404) .*$
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

        # 41. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

            # Create Filter for Advanced Local File Inclusion and PHP Wrapper abuse
            # Catches: php://, file://, expect://, /etc/passwd, /etc/shadow, and null byte (%00) injections
            # Note: We use \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/passwd|\x252Fetc\x252Fpasswd|/etc/shadow|/windows/win\.ini|/windows/system32|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb)).* HTTP/.*" \d{3} .*$
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
            # Why? Attackers often spoof legitimate User-Agents (e.g., Chrome) to bypass the 'badbots' jail.
            # This jail detects the BEHAVIOR of directory brute-forcing (blind guessing paths) rather than the signature.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-silent-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-silent-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PROPFIND) .*" (?:400|401|403|404|405|444) .*$
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
            # Attackers send absolute URIs (GET http://target.com) or use the CONNECT method
            # to check if your web server can be abused as an anonymous forward proxy for botnets.
            # Also catches TRACE/TRACK (Cross-Site Tracing) and WebDAV methods (PROPFIND, MKCOL)
            # often used by ransomware to discover or mount network drives.
            # Note: We use \x253A for the URL-encoded colon ':' to ensure strict matching.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) .*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//.*" \d{3} .*$
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
                    # DEVSECOPS FIX: Strict ConfigParser multiline format (newline + 10 spaces)
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

        # --- DEVSECOPS FIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
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
        fi
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
            # DEVSECOPS FIX: We use single quotes around nft commands to avoid \' escaping issues in wg-quick.
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

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS ---
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

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS ---
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

        # --- DEVSECOPS FIX: Strict Validation with CI/CD Auto-Mode support ---
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
                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type} Port {port})")).start()
                    continue

            # --- FAIL2BAN LOGIC (Layer 7) ---
            if ENABLE_F2B:
                match_f2b = regex_f2b.search(line)
                if match_f2b and "SysWarden-BLOCK" not in line:
                    jail = match_f2b.group(1).lower()
                    ip = match_f2b.group(2)
                    
                    cats = []
                    
                    # 1. Web Vulnerability Scanners & Pentest Tools
                    if any(x in jail for x in ["badbot", "scanner", "apimapper", "secretshunter"]): cats.extend(["14", "15", "19", "21"])
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
                    # 12. Web App Logins (Auth/CMS/SSO)
                    elif any(x in jail for x in ["auth", "wordpress", "drupal", "nextcloud", "phpmyadmin", "laravel", "grafana", "zabbix", "gitea", "cockpit", "vaultwarden", "sso"]): cats.extend(["18", "21"])
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

        # --- SECURITY FIX: SECURE ABUSEIPDB API KEY ---
        # The python script contains the API key in plain text.
        # We restrict ownership to root and the 'adm' group (used by the DynamicUser).
        # Permissions 750 (rwxr-x---) ensure standard users cannot read the API key.
        chown root:adm /usr/local/bin/syswarden_reporter.py
        chmod 750 /usr/local/bin/syswarden_reporter.py
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

setup_siem_logging() {
    echo -e "\n${BLUE}=== Step 6: SIEM Logging Status ===${NC}"
    log "INFO" "Logs are ready in journalctl and /var/log/."
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

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation (Scorched Earth)..."

    # Load config to retrieve variables
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # --- DEVSECOPS FIX: GLOBAL ZOMBIE PROCESS PURGE ---
    log "INFO" "Terminating all SysWarden background processes..."
    pkill -9 -f syswarden-telemetry 2>/dev/null || true
    pkill -9 -f syswarden_reporter 2>/dev/null || true
    pkill -9 -f syswarden-ui 2>/dev/null || true
    pkill -9 -f syswarden-ui-sync 2>/dev/null || true
    # --------------------------------------------------

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

    # --- DEVSECOPS FIX: SCORCHED EARTH TELEMETRY PURGE ---
    # Destroys any hidden databases or dashboard memory files
    rm -rf /var/log/syswarden 2>/dev/null || true
    rm -rf /opt/syswarden 2>/dev/null || true
    # -----------------------------------------------------

    systemctl daemon-reload

    # --- DEVSECOPS FIX: SURGICAL WIREGUARD CLEANUP ---
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
        nft delete table inet syswarden_table 2>/dev/null || true
        # DEVSECOPS FIX: Purge WG NAT table left by PostUp
        nft delete table inet syswarden_wg 2>/dev/null || true
        rm -f /etc/syswarden/syswarden.nft

        # DEVSECOPS FIX: Purge ALL Ghost Rules injected in OS tables (Loops through duplicates)
        for rule in 'tcp dport 9999 accept' 'udp dport 51820 accept' 'iifname "wg0" accept' 'oifname "wg0" accept'; do
            # Clean INPUT chain
            while nft -a list chain inet filter input 2>/dev/null | grep -q "$rule"; do
                local handle
                handle=$(nft -a list chain inet filter input 2>/dev/null | grep "$rule" | awk '{print $NF}' | head -n 1)
                if [[ -n "$handle" ]]; then
                    nft delete rule inet filter input handle "$handle" 2>/dev/null || true
                else
                    break
                fi
            done
            # Clean FORWARD chain
            while nft -a list chain inet filter forward 2>/dev/null | grep -q "$rule"; do
                local handle
                handle=$(nft -a list chain inet filter forward 2>/dev/null | grep "$rule" | awk '{print $NF}' | head -n 1)
                if [[ -n "$handle" ]]; then
                    nft delete rule inet filter forward handle "$handle" 2>/dev/null || true
                else
                    break
                fi
            done
        done

        if [[ -f "/etc/nftables.conf" ]]; then
            sed -i '\|include "/etc/syswarden/syswarden.nft"|d' /etc/nftables.conf
            sed -i '/# Added by SysWarden/d' /etc/nftables.conf

            # DEVSECOPS FIX: Persist the cleaned table!
            # The installer overwrote this file originally, so we must snapshot the cleaned memory back to it.
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

        # IPtables Standard (Purge des IPsets)
        while iptables -D INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done

        # --- DEVSECOPS FIX: IPTABLES-NFT GHOST RULE PURGE ---
        # We must explicitly delete old dynamically injected ports using the exact iptables syntax
        # so the iptables-nft translation layer can find and destroy them properly.
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

    # --- DEVSECOPS FIX: DOCKER NETWORK RESURRECTION ---
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
        log "INFO" "Restarting Docker daemon to rebuild NAT & Masquerade routing..."
        systemctl restart docker
        sleep 3
    fi
    # --------------------------------------------------

    # 4. Revert Fail2ban Configuration (State Aware)

    # --- DEVSECOPS FIX: SCORCHED EARTH FAIL2BAN & TELEMETRY PURGE ---
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
    # --- DEVSECOPS FIX: SCORCHED EARTH OS LOG SCRUBBING (ANTI-GHOST) ---
    # System logs and Systemd journals retain a deep history of "Ban" events.
    # A future re-installation would parse these old logs and resurrect ghost IPs.

    # 1. Surgically scrub plaintext files (Alma/RHEL heavily uses /var/log/messages)
    for os_log in "/var/log/messages" "/var/log/syslog" "/var/log/daemon.log"; do
        if [[ -f "$os_log" ]]; then
            sed -i '/\] Ban /d' "$os_log" 2>/dev/null || true
            sed -i '/\] Restore Ban /d' "$os_log" 2>/dev/null || true
        fi
    done

    # 2. Flush the Systemd Journal (The actual source of ghosts on AlmaLinux)
    # We rotate the active journal and vacuum it to forcefully wipe old binary traces.
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

    for filter in nginx-scanner mariadb-auth mongodb-guard syswarden-privesc syswarden-portscan \
        syswarden-revshell syswarden-aibots syswarden-badbots syswarden-httpflood syswarden-webshell \
        syswarden-sqli-xss syswarden-secretshunter syswarden-ssrf syswarden-jndi-ssti syswarden-apimapper \
        syswarden-lfi-advanced syswarden-vaultwarden syswarden-sso syswarden-silent-scanner syswarden-recidive \
        syswarden-proxy-abuse syswarden-jenkins syswarden-gitlab syswarden-redis syswarden-rabbitmq \
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

    # 5. Remove Nginx Dashboard (State Aware)

    # --- DEVSECOPS FIX: CLEAN UNINSTALL ---
    # Remove Nginx virtual host configurations unconditionally
    log "INFO" "Removing Nginx UI configuration..."
    rm -f /etc/nginx/conf.d/syswarden-ui.conf
    rm -f /etc/nginx/sites-available/syswarden-ui.conf
    rm -f /etc/nginx/sites-enabled/syswarden-ui.conf

    # Reload Nginx gracefully if it is still running
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx >/dev/null 2>&1 || true
    fi
    # --------------------------------------

    if [[ "${NGINX_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Nginx (installed by SysWarden)..."
        systemctl stop nginx 2>/dev/null || true
        if [[ -f /etc/debian_version ]]; then apt-get purge -y nginx 2>/dev/null || true; else dnf remove -y nginx 2>/dev/null || true; fi
    fi

    # 6. Remove Wazuh Agent
    if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q wazuh-agent; then
        read -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
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
    if [[ -f /etc/rsyslog.conf ]]; then
        sed -i '/kern-firewall\.log/d' /etc/rsyslog.conf
        sed -i '/auth-syswarden\.log/d' /etc/rsyslog.conf
        if command -v systemctl >/dev/null; then systemctl restart rsyslog 2>/dev/null || true; fi
    fi

    # --- DEVSECOPS FIX: PURGE PHYSICAL ISOLATED LOGS ---
    rm -f /var/log/kern-firewall.log 2>/dev/null || true
    rm -f /var/log/auth-syswarden.log 2>/dev/null || true
    # --------------------------------------------------

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

    # DEVSECOPS FIX: RESTORE GROUPS
    if [[ -f "$SYSWARDEN_DIR/group_backup.txt" ]]; then
        while IFS=':' read -r grp members; do
            for user in $(echo "$members" | tr ',' ' '); do
                if [[ -n "$user" ]] && id "$user" >/dev/null 2>&1; then usermod -aG "$grp" "$user" 2>/dev/null || true; fi
            done
        done <"$SYSWARDEN_DIR/group_backup.txt"
    fi
    # --------------------------------

    # --- DEVSECOPS FIX: ABSOLUTE FILE SYSTEM SCORCHED EARTH ---
    rm -rf "$SYSWARDEN_DIR"
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

    # Fail-Safe: Interdire l'installation si l'IP n'est pas fournie en mode auto
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
# SYSWARDEN v1.84 - TELEMETRY BACKEND (SERVERLESS - IP REGISTRY UPDATE)
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

# --- SECURITY FIX: ZOMBIE PROCESS PREVENTION ---
trap 'wait' EXIT

# --- DEVSECOPS FIX: ABSOLUTE MUTEX LOCK (ANTI-OVERLAP) ---
exec 9>"/tmp/syswarden-telemetry.lock"
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

# --- DEVSECOPS FIX: UNIVERSAL PACKAGE MANAGER ---
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

# --- Layer 3 Metrics ---
L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

# --- Layer 7 Metrics & IP Registry (SECURE JSON ARRAYS) ---
L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"
BANNED_IPS_JSON="[]"

# DEVSECOPS FIX: Strict timeouts to prevent Fail2ban socket deadlocks
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

# --- DEVSECOPS: Top 10 Historical Attacking IPs (Aggregated & Bulletproof) ---
TOP_ATTACKERS_JSON="[]"
TOP_STATS=""

# FIX: We rely exclusively on Fail2ban's core log to avoid 100% CPU spikes from journalctl 7-day queries.
TOP_STATS=$( { 
    cat /var/log/fail2ban.log 2>/dev/null || true
} | grep -E "\] (Restore )?Ban " | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr | head -n 10 || true )

if [[ -n "$TOP_STATS" ]]; then
    while IFS=" " read -r count ip; do
        if [[ -n "$ip" && -n "$count" ]]; then
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --argjson c "$count" '. + [{"ip": $ip, "count": $c}]')
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

# FIX: Strict ownership for Nginx web server (Universal OS handles both www-data and nginx users)
mv -f "$TMP_FILE" "$DATA_FILE"
chown www-data:www-data "$DATA_FILE" 2>/dev/null || chown nginx:nginx "$DATA_FILE" 2>/dev/null || true
chmod 640 "$DATA_FILE"
EOF

    # 2. Make executable
    chmod +x "$BIN_PATH"

    # 3. Injection into CRON tasks (Execution every minute)
    if ! crontab -l 2>/dev/null | grep "$BIN_PATH" >/dev/null; then
        (
            crontab -l 2>/dev/null || true
            echo "* * * * * $BIN_PATH >/dev/null 2>&1"
        ) | crontab -
    fi

    # 4. First immediate run to generate data.json before the UI starts
    if ! "$BIN_PATH"; then
        log "WARN" "Initial telemetry run failed, but script will continue."
    fi
}

# ==============================================================================
# SYSWARDEN v1.84 - NGINX SECURE DASHBOARD (HTTPS / CSP / LOCAL FONTS / BENTO-DARK)
# ==============================================================================
function generate_dashboard() {
    log "INFO" "Generating the Nginx-secured Dashboard UI (HTTPS/CSP/Local-Fonts)..."

    local UI_DIR="/etc/syswarden/ui"
    mkdir -p "$UI_DIR"

    # DEVSECOPS FIX: Directory Traversal for Nginx worker (Fixes 403 Forbidden)
    chmod 755 /etc/syswarden
    chmod 755 "$UI_DIR"

    # --- DEVSECOPS FIX: DOWNLOAD LOCAL FONTS ---
    log "INFO" "Downloading local JetBrains Mono fonts..."
    wget -qO "$UI_DIR/JetBrainsMono-Regular.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Regular.woff2" || true
    wget -qO "$UI_DIR/JetBrainsMono-Bold.woff2" "https://raw.githubusercontent.com/duggytuxy/syswarden/main/fonts/JetBrainsMono-Bold.woff2" || true
    chmod 644 "$UI_DIR"/*.woff2 2>/dev/null || true
    # -------------------------------------------

    # 1. Generating the HTML file
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
                    SYSWARDEN&nbsp;<span class="text-brand">v1.84</span>
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

    chmod 644 "$UI_DIR/index.html"

    # --- 3. DYNAMIC ACCESS CONTROL (Nginx IP Whitelisting) ---
    local NGINX_ALLOW_RULES=""
    if [[ -s "$WHITELIST_FILE" ]]; then
        while IFS= read -r wl_ip; do
            [[ -z "$wl_ip" ]] || [[ "$wl_ip" =~ ^# ]] && continue
            NGINX_ALLOW_RULES+="        allow $wl_ip;\n"
        done <"$WHITELIST_FILE"
    fi

    # Allow WireGuard Subnet if active
    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        NGINX_ALLOW_RULES+="        allow ${WG_SUBNET};\n"
    fi

    # Fallback to Localhost and Drop the rest
    NGINX_ALLOW_RULES+="        allow 127.0.0.1;\n"
    NGINX_ALLOW_RULES+="        deny all;"

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

    # --- 5. NGINX VHOST CONFIGURATION (Multi-OS Paths) ---
    log "INFO" "Configuring Nginx reverse proxy for port 9999..."
    local NGINX_CONF_DIR="/etc/nginx/conf.d"
    if [[ -d "/etc/nginx/sites-available" ]]; then
        NGINX_CONF_DIR="/etc/nginx/sites-available"
    fi

    cat <<EOF >"$NGINX_CONF_DIR/syswarden-ui.conf"
server {
    # --- DEVSECOPS FIX: NGINX 1.24+ / UBUNTU 24.04 COMPATIBILITY ---
    # The standalone 'http2 on;' directive is deprecated and causes fatal 
    # syntax errors in modern Nginx versions. It must be declared directly 
    # within the listen directive to ensure Cross-OS parity.
    listen 9999 ssl http2;
    server_name _;

    # TLS Encryption
    ssl_certificate $SSL_DIR/syswarden.crt;
    ssl_certificate_key $SSL_DIR/syswarden.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root $UI_DIR;
    index index.html;

    # --- Security Access Control (Only Admin IP) ---
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

    # Routing
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Block access to hidden files (.git, .env, etc.)
    location ~ /\. {
        deny all;
    }
}
EOF

    # Symlink for Debian/Ubuntu environments
    if [[ -d "/etc/nginx/sites-enabled" ]]; then
        ln -sf "$NGINX_CONF_DIR/syswarden-ui.conf" "/etc/nginx/sites-enabled/syswarden-ui.conf"
        # Remove default site to prevent conflicts on fresh installs
        rm -f /etc/nginx/sites-enabled/default
    fi

    # --- 6. EXPOSE DASHBOARD PORT NATIVELY (Let Nginx handle the drops) ---
    log "INFO" "Opening Port 9999 in OS Firewall to enable Nginx routing..."
    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        # DEVSECOPS FIX: Dynamic Zone detection for Dashboard UI
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
            # DEVSECOPS FIX: grep >/dev/null prevents SIGPIPE pipefail crashes
            if ! nft list chain inet filter input 2>/dev/null | grep "tcp dport 9999 accept" >/dev/null; then
                nft insert rule inet filter input tcp dport 9999 accept 2>/dev/null || true
                # DEVSECOPS FIX: OS Persistence
                echo '#!/usr/sbin/nft -f' >/etc/nftables.conf
                echo 'flush ruleset' >>/etc/nftables.conf
                nft list table inet filter >>/etc/nftables.conf 2>/dev/null || true

                # SYSWARDEN INCLUDE
                echo -e '\n# Added by SysWarden' >>/etc/nftables.conf
                echo 'include "/etc/syswarden/syswarden.nft"' >>/etc/nftables.conf
                # -------------------------------------------------------
            fi
        fi
    fi

    # --- 7. DAEMON ORCHESTRATION ---
    # Cleanup legacy Python server & Systemd unit if upgrading
    if systemctl is-active --quiet syswarden-ui; then
        systemctl stop syswarden-ui >/dev/null 2>&1 || true
        systemctl disable syswarden-ui >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/syswarden-ui.service /usr/local/bin/syswarden-ui-server.py
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    # Start or Reload Nginx
    systemctl enable nginx >/dev/null 2>&1 || true
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx >/dev/null 2>&1 || true
    else
        systemctl restart nginx >/dev/null 2>&1 || true
    fi

    log "INFO" "Dashboard UI secured by Nginx at https://<YOUR_IP>:9999"
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
        nft delete element inet syswarden_table "$SET_NAME" '{' "$WL_IP" '}' 2>/dev/null || true
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

    # --- DEVSECOPS FIX: DEPENDENCY & STATE VERIFICATION ---
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

        # --- DEVSECOPS FIX: STATEFUL DOCKER BYPASS RE-ENFORCEMENT ---
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

        # --- SECURITY FIX: MITM PROTECTION & SECURE UPDATE ---
        echo -e "${YELLOW}Downloading and verifying update securely...${NC}"

        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$TMP_DIR/install-syswarden.sh" "$download_url"
        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$TMP_DIR/install-syswarden.sh.sha256" "$hash_url"

        cd "$TMP_DIR" || exit 1

        if ! sha256sum -c install-syswarden.sh.sha256 --status; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The downloaded script failed cryptographic validation!${NC}"
            echo -e "${RED}Possible causes: Man-In-The-Middle (MITM) attack, DNS poisoning, or incomplete download.${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            rm -f "$TMP_DIR/install-syswarden.sh*"
            exit 1
        fi

        echo -e "${GREEN}Checksum validated successfully. Applying update...${NC}"

        mv "$TMP_DIR/install-syswarden.sh" "/root/install-syswarden.sh"
        chmod 700 "/root/install-syswarden.sh"

        echo -e "${GREEN}Update secured and installed in /root/install-syswarden.sh${NC}"
        echo -e "Please run ${YELLOW}./install-syswarden.sh update${NC} to apply the new orchestrator rules."
        # -----------------------------------------------------
    fi
}

show_alerts_dashboard() {
    # Trap Ctrl+C/Exit to restore cursor safely
    trap "tput cnorm; echo -e '\n${GREEN}Exiting Dashboard...${NC}'; exit 0" INT TERM
    tput civis # Hide cursor for cleaner UI

    echo -e "\n${BLUE}=========================================================================================${NC}"
    echo -e "${GREEN}                        SYSWARDEN CLI DASHBOARD (Live Alerts)                            ${NC}"
    echo -e "${BLUE}=========================================================================================${NC}"
    echo -e "${YELLOW}[i] Tailing live Threat Intelligence Logs... (Press Ctrl+C to stop)${NC}\n"

    # --- TABLE HEADER ---
    printf "\033[1m\033[36m%-19s | %-16s | %-10s | %-15s | %s\033[0m\n" "TIMESTAMP" "MODULE" "ACTION" "SOURCE IP" "TARGET (PORT/JAIL)"
    echo -e "${BLUE}--------------------+------------------+------------+-----------------+--------------------${NC}"

    # Multiplex Systemd Journal and Flat files safely without creating orphan processes
    (
        P1=""
        if command -v journalctl >/dev/null 2>&1; then
            journalctl -f -q 2>/dev/null &
            P1=$!
        fi

        P2=""
        local LOGS=()
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
    ) | awk '
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

    # --- SECURITY FIX: SECURE AUTO-CONF FILE ---
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

    # --- DEVSECOPS FIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
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
    download_geoip
    download_asn

    # 2. Inject silently into Kernel (Zero-Downtime)
    discover_active_services
    apply_firewall_rules

    log "INFO" "CRON Update Complete. Firewall rules refreshed securely."
    # Vital exit 0
    exit 0
fi

if [[ "$MODE" != "update" ]]; then
    clear
    echo -e "${GREEN}#############################################################"
    echo -e "#     SysWarden Tool Installer (Universal v1.84)     #"
    echo -e "#############################################################${NC}"
fi

check_root
detect_os_backend

# --- PREVENT ADMIN LOCK-OUT (EXECUTE BEFORE FAIL2BAN/FIREWALL) ---
auto_whitelist_admin
process_auto_whitelist "$MODE"
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
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v1.84 - PRE-FLIGHT CHECKLIST                     ${NC}"
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "Before proceeding with the deployment, please ensure you have the following"
        echo -e "information ready. If you lack any required data, press [Ctrl+C] to abort,"
        echo -e "gather the info, and restart the script.\n"

        echo -e "${BOLD}1. SSH CONFIGURATION${NC}"
        echo -e "   You will need to confirm the custom SSH port used to connect to this server."

        echo -e "\n${BOLD}2. WIREGUARD VPN${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Decide if you need a stealth admin VPN. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}3. DOCKER INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires Layer 3 routing adjustments for containers. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}4. OS HARDENING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Strict restrictions for privileged groups (Sudo/Wheel) & Cron. Recommended for NEW servers only."

        echo -e "\n${BOLD}5. GEOIP BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   ISO country codes to drop instantly (e.g., RU,CN,KP)."
        echo -e "   Reference: ${CYAN}https://www.ipdeny.com/ipblocks/${NC}"

        echo -e "\n${BOLD}6. ASN BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Target Autonomous System Numbers to drop (e.g., AS1234, AS5678)."
        echo -e "   Reference: ${CYAN}https://www.spamhaus.org/drop/asndrop.json${NC}"

        echo -e "\n${BOLD}7. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] Disabled"

        echo -e "\n${BOLD}8. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."
        echo -e "   Get one at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"

        echo -e "\n${BOLD}9. WAZUH SIEM AGENT${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Required: Manager IP, Enrollment Port (1515), Listen Port (1514), Agent Group."
        echo -e "   If unsure about your SIEM architecture, consult your Security Admin."

        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        read -p "$(echo -e "${YELLOW}Press [ENTER] to begin the configuration, or [Ctrl+C] to abort... ${NC}")"
        echo ""
        log "INFO" "Pre-Flight Checklist acknowledged. Starting interactive configuration..."
    fi
    # ---------------------------------------------------------------

    define_ssh_port "$MODE"
    define_wireguard "$MODE"
    define_docker_integration "$MODE"
    define_os_hardening "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
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
# --------------------------------------

detect_protected_services

if command -v systemctl >/dev/null && systemctl is-active --quiet syswarden-reporter; then
    systemctl restart syswarden-reporter >/dev/null 2>&1 || true
fi

# --- DEVSECOPS FIX: DASHBOARD & FAIL2BAN ORCHESTRATION ---
# Telemetry & Dashboard ALWAYS run (Install & Update) to deploy/update Nginx and the UI.
setup_telemetry_backend
generate_dashboard
# ---------------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    setup_siem_logging
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
    # --- DEVSECOPS FIX: FORCE CRON SYNTAX UPGRADE DURING UPDATE ---
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

    # Give clear feedback during an update
    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
    echo -e " -> SysWarden Engine & Dashboard UI have been updated to the latest version."
fi
