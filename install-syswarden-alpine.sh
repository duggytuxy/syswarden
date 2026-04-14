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

    if [ -f /etc/alpine-release ]; then
        OS="Alpine Linux"
    else
        log "ERROR" "This specific script is designed ONLY for Alpine Linux."
        exit 1
    fi

    # --- FIX: THE EGG & CHICKEN PARADOX ---
    # On a fresh install, 'nft' is not installed yet, causing a fallback to 'ipset'.
    # Since Alpine kernels often lack 'ip_set' modules by default, rules fail to load.
    # We now FORCE Nftables as the absolute native standard for Alpine 3+.
    FIREWALL_BACKEND="nftables"

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Installing required dependencies..."

    # ==============================================================================
    # --- HOTFIX: STATE TRACKER (Avoid God Mode Uninstall) ---
    # Record pre-existing critical services so we don't purge them on uninstall.
    # MUST BE EXECUTED BEFORE ANY APK COMMANDS!
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

    local deps="curl python3 py3-requests ipset fail2ban bash coreutils grep gawk sed procps logrotate ncurses whois rsyslog util-linux wireguard-tools libqrencode libqrencode-tools nginx openssl rsync openssh-client"

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

    # --- HOTFIX: PREEMPTIVE NGINX LOG CREATION ---
    mkdir -p /var/log/nginx
    touch /var/log/nginx/access.log /var/log/nginx/error.log
    chmod 640 /var/log/nginx/*.log 2>/dev/null || true
    # ----------------------------------------------------

    if ! command -v rc-update >/dev/null; then
        log "ERROR" "OpenRC is missing. This script requires a standard Alpine setup."
        exit 1
    fi

    # Ensure standard syslog is active to capture Kernel Firewall Drops
    rc-update add rsyslog default >/dev/null 2>&1 || true

    # --- SECURITY FIX: ALPINE KERNEL LOGGING & LOG INJECTION PREVENTION ---
    # Force rsyslog to write all Netfilter/Nftables drops and Auth logs to DEDICATED files.
    # This prevents unprivileged users from injecting fake logs via logger(1)
    # into /var/log/messages, stopping Fail2ban Log Injection & Mass DoS attacks.
    rm -f /etc/rsyslog.d/99-syswarden-siem.conf 2>/dev/null || true
    if [[ -f /etc/rsyslog.conf ]]; then
        # 1. Isolate Kernel Firewall logs
        sed -i '/^kern\./d' /etc/rsyslog.conf
        echo "kern.* /var/log/kern-firewall.log" >>/etc/rsyslog.conf
        touch /var/log/kern-firewall.log && chmod 600 /var/log/kern-firewall.log

        # 2. Isolate Auth/PAM logs (su, sudo, sshd)
        sed -i '/^authpriv\./d' /etc/rsyslog.conf
        sed -i '/^auth\./d' /etc/rsyslog.conf
        echo "auth,authpriv.* /var/log/auth.log" >>/etc/rsyslog.conf
        touch /var/log/auth.log && chmod 600 /var/log/auth.log
    fi
    # ----------------------------------------------------------------------

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

    echo "SSH_PORT='$SSH_PORT'" >>"$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"

    # --- SECURITY FIX: DISABLE TCP FORWARDING (ANTI-PIVOTING & EXPOSURE) ---
    # TCP Forwarding allows non-privileged users to bypass firewall rules and expose
    # internal services. We strictly enforce it to 'no'. Dashboard access MUST use WireGuard.
    if [[ -f /etc/ssh/sshd_config ]]; then
        log "INFO" "Ensuring SSH TCP Forwarding is strictly DISABLED..."

        sed -i 's/^#AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
        sed -i 's/^[[:space:]]*AllowTcpForwarding[[:space:]]*yes/AllowTcpForwarding no/' /etc/ssh/sshd_config

        rc-service sshd restart >/dev/null 2>&1 || true
    fi
    # ------------------------------------------------------------------------
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
        echo -e "${YELLOW}WARNING: Strict OS hardening will restrict CRON to root and remove non-root users from wheel/sudo groups.${NC}"
        read -p "Apply strict OS Hardening? (Recommended for NEW servers only) [y/N]: " input_hard
    fi

    if [[ "$input_hard" =~ ^[Yy]$ ]]; then
        APPLY_OS_HARDENING="y"
        log "INFO" "OS Hardening ENABLED. Privileged groups and Cron will be strictly restricted."
    else
        APPLY_OS_HARDENING="n"
        log "INFO" "OS Hardening DISABLED. Preserving existing Alpine system permissions."
    fi
    echo "APPLY_OS_HARDENING='$APPLY_OS_HARDENING'" >>"$CONF_FILE"
}

apply_os_hardening() {
    if [[ "${APPLY_OS_HARDENING:-n}" != "y" ]]; then
        return
    fi

    log "INFO" "Applying strict OS hardening (Crontab, Wheel group, Profiles)..."

    # 1. Lock down Crontab (Only root can schedule tasks)
    echo "root" >/etc/cron.allow
    chmod 600 /etc/cron.allow
    rm -f /etc/cron.deny 2>/dev/null || true

    # 2. Backup and Purge non-root users from privileged groups (wheel/adm/sudo)
    # FIX: Alpine natively places 'daemon' in the 'adm' group.
    mkdir -p "$SYSWARDEN_DIR"
    local current_admin="${SUDO_USER:-}"

    for grp in wheel adm sudo; do
        if grep -q "^${grp}:" /etc/group 2>/dev/null; then
            # Backup current members
            local members
            members=$(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group)
            if [[ -n "$members" && "$members" != "root" ]]; then
                echo "${grp}:${members}" >>"$SYSWARDEN_DIR/group_backup.txt"
            fi

            # Purge non-root users using Alpine's delgroup
            for user in $(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group | tr ',' ' ' 2>/dev/null); do
                if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                    # --- SAFEGUARD: Never purge the executing admin ---
                    if [[ -n "$current_admin" ]] && [[ "$user" == "$current_admin" ]]; then
                        log "INFO" "SAFEGUARD: Preserving current admin '$user' in '$grp' group."
                        continue
                    fi
                    delgroup "$user" "$grp" >/dev/null 2>&1 || true
                    log "INFO" "Removed user '$user' from '$grp' group to prevent privilege escalation."
                fi
            done
        fi
    done

    # 3. Lock down .profile for existing standard users (Prevents SSH Login backdoors)
    for user_dir in /home/*; do
        if [[ -d "$user_dir" ]]; then
            local user_name
            user_name=$(basename "$user_dir")

            # --- SAFEGUARD: Preserve current admin's profile to avoid breaking active SSH sessions
            if [[ -n "$current_admin" ]] && [[ "$user_name" == "$current_admin" ]]; then
                continue
            fi

            local profile_file="$user_dir/.profile"
            # Remove immutable flag if it exists, create/own it, then lock it forever
            chattr -i "$profile_file" 2>/dev/null || true
            touch "$profile_file"
            chown "$user_name:$user_name" "$profile_file"
            chmod 644 "$profile_file"
            chattr +i "$profile_file" 2>/dev/null || true

            # Also lock .bashrc and .bash_profile if they exist (for users with bash installed)
            for extra_file in "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                if [[ -f "$extra_file" ]]; then
                    chattr -i "$extra_file" 2>/dev/null || true
                    chown "$user_name:$user_name" "$extra_file"
                    chmod 644 "$extra_file"
                    chattr +i "$extra_file" 2>/dev/null || true
                fi
            done
        fi
    done
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
    echo "GEOBLOCK_COUNTRIES='$GEOBLOCK_COUNTRIES'" >>"$CONF_FILE"
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
        read -p "Enter choice [1/2/3]: " choice
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
            CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d " '\"\;\\$\|\&\<\>\`")
            if [[ -z "$CUSTOM_URL" ]]; then
                log "WARN" "Custom URL is empty. Defaulting to Standard List."
                LIST_TYPE="Standard"
            fi
            ;;
        *)
            log "ERROR" "Invalid choice. Exiting."
            exit 1
            ;;
    esac

    echo "LIST_TYPE='$LIST_TYPE'" >>"$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >>"$CONF_FILE"; fi
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

    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION ---
        # Validates exact octet ranges (0-255) and subnet masks (0-32) to prevent iptables crash (F13)
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
    if [[ "${GEOBLOCK_COUNTRIES:-none}" == "none" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading Geo-Blocking Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : >"$TMP_DIR/geoip_raw.txt"

    for country in $(echo "$GEOBLOCK_COUNTRIES" | tr ' ' '\n'); do
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
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading ASN Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : >"$TMP_DIR/asn_raw.txt"

    if [[ "${USE_SPAMHAUS_ASN:-y}" == "y" ]]; then
        echo -n "Fetching Spamhaus ASN-DROP list (Cybercrime Hosters)... "
        local spamhaus_url="https://www.spamhaus.org/drop/asndrop.json"

        local spamhaus_asns
        spamhaus_asns=$(curl -sS -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --retry 2 --connect-timeout 5 "$spamhaus_url" 2>/dev/null | grep -Eo '"asn":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+' | sed 's/^/AS/' | tr '\n' ' ' || true)

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

    local combined_asns
    combined_asns=$(echo "$BLOCK_ASNS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

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
            if echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >>"$TMP_DIR/asn_raw.txt"; then
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
        log "INFO" "Configuring Nftables via Atomic Transaction (Alpine Flat Syntax + Hardware Drop L2)..."

        local ACTIVE_IF
        ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n 1)
        [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

        rc-update add nftables default >/dev/null 2>&1 || true
        rc-service nftables start >/dev/null 2>&1 || true

        cat <<EOF >"$TMP_DIR/syswarden.nft"
add table inet syswarden_table
flush table inet syswarden_table
add table netdev syswarden_hw_drop
flush table netdev syswarden_hw_drop

add set netdev syswarden_hw_drop $SET_NAME { type ipv4_addr; flags interval; auto-merge; }
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "add set netdev syswarden_hw_drop $GEOIP_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "add set netdev syswarden_hw_drop $ASN_SET_NAME { type ipv4_addr; flags interval; auto-merge; }" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
add chain netdev syswarden_hw_drop ingress_frontline { type filter hook ingress device "$ACTIVE_IF" priority -500; policy accept; }
EOF

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "add rule netdev syswarden_hw_drop ingress_frontline ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
            done <"$WHITELIST_FILE"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
add rule netdev syswarden_hw_drop ingress_frontline ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " drop
EOF

        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            echo "add rule netdev syswarden_hw_drop ingress_frontline ip saddr @$GEOIP_SET_NAME log prefix \"[SysWarden-GEO] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            echo "add rule netdev syswarden_hw_drop ingress_frontline ip saddr @$ASN_SET_NAME log prefix \"[SysWarden-ASN] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

        cat <<EOF >>"$TMP_DIR/syswarden.nft"
add chain inet syswarden_table input { type filter hook input priority filter - 10; policy accept; }
add rule inet syswarden_table input ct state established,related accept
EOF

        if [[ -s "$WHITELIST_FILE" ]]; then
            while IFS= read -r wl_ip; do
                [[ -z "$wl_ip" ]] && continue
                echo "add rule inet syswarden_table input ip saddr $wl_ip accept" >>"$TMP_DIR/syswarden.nft"
            done <"$WHITELIST_FILE"
        fi

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "add rule inet syswarden_table input udp dport ${WG_PORT:-51820} accept" >>"$TMP_DIR/syswarden.nft"
            echo "add rule inet syswarden_table input iifname { \"wg0\", \"lo\" } accept comment \"SysWarden: Global Trust for VPN\"" >>"$TMP_DIR/syswarden.nft"
            echo "add rule inet syswarden_table input tcp dport ${SSH_PORT:-22} log prefix \"[SysWarden-SSH-DROP] \" drop" >>"$TMP_DIR/syswarden.nft"
        fi

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

        # --- MODULAR PERSISTENCE (ZERO-TOUCH) ---
        log "INFO" "Saving SysWarden Nftables table to isolated config..."
        mkdir -p /etc/syswarden
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft

        local MAIN_NFT_CONF="/etc/nftables.nft"
        if [[ -f "$MAIN_NFT_CONF" ]]; then
            if ! grep -q 'include "/etc/syswarden/syswarden.nft"' "$MAIN_NFT_CONF"; then
                echo -e '\n# Added by SysWarden' >>"$MAIN_NFT_CONF"
                echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
            fi
            if ! grep -q 'include "/etc/nftables.d/\*.nft"' "$MAIN_NFT_CONF"; then
                echo 'include "/etc/nftables.d/*.nft"' >>"$MAIN_NFT_CONF"
            fi
        fi

        # --- NEW HOTFIX: IDEMPOTENT ALPINE NATIVE FIREWALL AUTO-BYPASS ---
        log "INFO" "Configuring Native OS Firewall Bypass for active services & VPN..."
        mkdir -p /etc/nftables.d

        local OS_BYPASS_FILE="/etc/nftables.d/syswarden-os-bypass.nft"

        # HOTFIX: Atomic structure to safely reload directly via 'nft -f'
        cat <<EOF >"$OS_BYPASS_FILE"
add table inet filter
add chain inet filter input { type filter hook input priority filter; policy drop; }
flush chain inet filter input
EOF

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            cat <<EOF >>"$OS_BYPASS_FILE"
add chain inet filter forward { type filter hook forward priority filter; policy drop; }
flush chain inet filter forward
EOF
        fi

        cat <<EOF >>"$OS_BYPASS_FILE"
table inet filter {
    chain input {
        ct state established,related accept
        iifname "lo" accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        tcp dport { ${SSH_PORT:-22}, 9999 } accept comment "SysWarden: Auto-allow SSH & UI"
EOF

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            echo "        udp dport ${WG_PORT:-51820} accept comment \"SysWarden: WireGuard Port\"" >>"$OS_BYPASS_FILE"
            echo "        iifname \"wg0\" accept comment \"SysWarden: WireGuard Interface\"" >>"$OS_BYPASS_FILE"
        fi

        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            echo "        tcp dport { $ACTIVE_PORTS } accept comment \"SysWarden: Auto-allow Discovered Services\"" >>"$OS_BYPASS_FILE"
        fi

        # HOTFIX: Log packets before they hit the Guillotine so Fail2ban can catch portscans
        echo "        log prefix \"[SysWarden-BLOCK] [Catch-All] \"" >>"$OS_BYPASS_FILE"

        echo "    }" >>"$OS_BYPASS_FILE"

        if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
            cat <<EOF >>"$OS_BYPASS_FILE"
    chain forward {
        ct state established,related accept
        iifname "wg0" accept comment "SysWarden: WireGuard Forwarding"
        oifname "wg0" accept comment "SysWarden: WireGuard Forwarding"
    }
EOF
        fi
        echo "}" >>"$OS_BYPASS_FILE"

        # HOTFIX: Force injection into RAM immediately
        nft -f "$OS_BYPASS_FILE"

        # --- MODULAR PERSISTENCE (ZERO-TOUCH) ---
        log "INFO" "Saving SysWarden Nftables table to isolated config..."
        mkdir -p /etc/syswarden
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft

        local MAIN_NFT_CONF="/etc/nftables.nft"

        # HOTFIX: Robust fallback if the OS file is completely missing
        if [[ ! -f "$MAIN_NFT_CONF" ]]; then
            log "WARN" "$MAIN_NFT_CONF not found. Creating basic layout."
            echo '#!/usr/sbin/nft -f' >"$MAIN_NFT_CONF"
            echo 'flush ruleset' >>"$MAIN_NFT_CONF"
            chmod 755 "$MAIN_NFT_CONF"
        fi

        if ! grep -q 'include "/etc/syswarden/syswarden.nft"' "$MAIN_NFT_CONF"; then
            echo -e '\n# Added by SysWarden' >>"$MAIN_NFT_CONF"
            echo 'include "/etc/syswarden/syswarden.nft"' >>"$MAIN_NFT_CONF"
        fi
        if ! grep -q 'include "/etc/nftables.d/\*.nft"' "$MAIN_NFT_CONF"; then
            echo 'include "/etc/nftables.d/*.nft"' >>"$MAIN_NFT_CONF"
        fi

        # Save state natively for OpenRC
        rc-service nftables save >/dev/null 2>&1 || true
        # -------------------------------------------------------------

    else
        # Fallback IPSET / IPTABLES
        log "INFO" "Applying Iptables rules and loading IPSet lists..."

        # FIX: Start the service BEFORE injecting rules to prevent OpenRC state overwrite
        rc-update add iptables default >/dev/null 2>&1 || true
        rc-service iptables start >/dev/null 2>&1 || true

        ipset create "${SET_NAME}_tmp" hash:net maxelem 1000000 -exist
        # Shellcheck fix: -! prevents crash on duplicates
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore -!
        ipset create "$SET_NAME" hash:net maxelem 1000000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"

        if ! iptables -t raw -C PREROUTING -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -t raw -I PREROUTING 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
        fi

        # --- ASN INJECTION (Priority 2) ---
        if [[ "${BLOCK_ASNS:-none}" != "none" ]] && [[ -s "$ASN_FILE" ]]; then
            ipset create "${ASN_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            sed "s/^/add ${ASN_SET_NAME}_tmp /" "$ASN_FILE" | ipset restore -!
            ipset create "$ASN_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${ASN_SET_NAME}_tmp" "$ASN_SET_NAME"
            ipset destroy "${ASN_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; then
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j DROP
                iptables -t raw -I PREROUTING 1 -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] "
            fi
        fi

        # --- GEOIP INJECTION (Priority 1) ---
        if [[ "${GEOBLOCK_COUNTRIES:-none}" != "none" ]] && [[ -s "$GEOIP_FILE" ]]; then
            ipset create "${GEOIP_SET_NAME}_tmp" hash:net maxelem 1000000 -exist
            sed "s/^/add ${GEOIP_SET_NAME}_tmp /" "$GEOIP_FILE" | ipset restore -!
            ipset create "$GEOIP_SET_NAME" hash:net maxelem 1000000 -exist
            ipset swap "${GEOIP_SET_NAME}_tmp" "$GEOIP_SET_NAME"
            ipset destroy "${GEOIP_SET_NAME}_tmp"

            if ! iptables -t raw -C PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; then
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
        # >>> INJECTION DU ZERO TRUST (DYNAMIC ALLOW & CATCH-ALL)
        # ==========================================================

        # 1. Allow discovered ports explicitly (using a loop to bypass multiport limits)
        iptables -I INPUT 1 -p tcp --dport 9999 -j ACCEPT
        iptables -I INPUT 1 -p tcp --dport "${SSH_PORT:-22}" -j ACCEPT
        if [[ -n "$ACTIVE_PORTS" ]] && [[ "$ACTIVE_PORTS" != "none" ]]; then
            for port in $(echo "$ACTIVE_PORTS" | tr ',' ' '); do
                iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
            done
        fi

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

        # Save IPtables persistence for Alpine / OpenRC
        /etc/init.d/iptables save >/dev/null 2>&1 || true
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

            # --- HOTFIX: STATEFUL DOCKER BYPASS (Priority 0 - Absolute Top) ---
            # Ensures outbound traffic (like S3 uploads) never times out on the way back.
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
            iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
            # -------------------------------------------------------------------------

            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Docker firewall rules applied successfully."
        else
            log "WARN" "DOCKER-USER chain not found. Docker might not be running yet."
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
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Alpine Zero Trust Mode)..."

        # --- SECURITY FIX: ALPINE SSH CONFLICT (ANTI-LOCKOUT) ---
        # Alpine's default jail.d/alpine-ssh.conf overrides our jail.local maxretry (10 vs 3)
        # and port settings. We must delete it to enforce SysWarden's strict rules.
        if [[ -f /etc/fail2ban/jail.d/alpine-ssh.conf ]]; then
            rm -f /etc/fail2ban/jail.d/alpine-ssh.conf
            log "INFO" "Removed conflicting default Alpine SSH jail configuration."
        fi
        # --------------------------------------------------------

        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
# DEVSECOPS FIX: Prevent SQLite database bloat and memory exhaustion.
# Synchronized to 8 days (691200s) to perfectly match the 1-week findtime of the 'recidive' jail.
dbpurgeage = 691200
EOF

        # 2. Dynamic Action based on Firewall Backend
        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then f2b_action="nftables-multiport"; fi

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

        # --- HOTFIX: LONG-TERM RECIDIVE FILTER ---
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
# Strictly catches Ban events in Fail2ban's own log to identify persistent horizontal movement
failregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Ban|Found) <HOST>\s*$
ignoreregex = ^.*(?:fail2ban\.actions|fail2ban\.filter).*\[[a-zA-Z0-9_-]+\] (?:Restore )?(?:Unban|unban) <HOST>\s*$
EOF
        fi
        # ------------------------------------------------

        # 3. HEADER & SSH (Always Active - Backend MUST be auto for Alpine)
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
logpath = /var/log/messages
backend = auto

# --- ALPINE FIX: Disable redundant default jails ---
[sshd-ddos]
enabled = false
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
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
            APACHE_LOG="/var/log/apache2/error.log"
            APACHE_ACCESS="/var/log/apache2/access.log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."
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
            MARIADB_LOG="/var/log/mysql/error.log"
        elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then MARIADB_LOG="/var/log/mariadb/mariadb.log"; fi

        if [[ -n "$MARIADB_LOG" ]]; then
            log "INFO" "MariaDB logs detected. Enabling MariaDB Jail."
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
            POSTFIX_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/messages" ]]; then POSTFIX_LOG="/var/log/messages"; fi

        if [[ -n "$POSTFIX_LOG" ]] && command -v postfix >/dev/null 2>&1; then
            log "INFO" "Postfix detected. Enabling SMTP Jails."
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

        # 10. DYNAMIC DETECTION: WORDPRESS
        WP_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then
            WP_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."
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
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then
                NC_LOG="$path"
                break
            fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."
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

        # 12. DYNAMIC DETECTION: ASTERISK
        ASTERISK_LOG=""
        if [[ -f "/var/log/asterisk/messages" ]]; then
            ASTERISK_LOG="/var/log/asterisk/messages"
        elif [[ -f "/var/log/asterisk/full" ]]; then ASTERISK_LOG="/var/log/asterisk/full"; fi

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
            log "INFO" "Zabbix logs detected. Enabling Zabbix Jail."
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
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."
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
        PMA_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then
            PMA_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."
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
        for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
            if [[ -f "$path" ]]; then
                LARAVEL_LOG="$path"
                break
            fi
        done
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."
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
            SM_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/messages" ]]; then SM_LOG="/var/log/messages"; fi

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
        fi

        # 21. DYNAMIC DETECTION: DOVECOT (IMAP/POP3)
        DOVECOT_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then
            DOVECOT_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/messages" ]]; then DOVECOT_LOG="/var/log/messages"; fi

        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."
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
            PVE_LOG="/var/log/messages"
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
        elif [[ -f "/var/log/messages" ]]; then OVPN_LOG="/var/log/messages"; fi

        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."
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

        # 25. DYNAMIC DETECTION: COCKPIT
        if [[ -d "/etc/cockpit" ]]; then
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
logpath = /var/log/messages
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 26. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth.log" ]]; then
            AUTH_LOG="/var/log/auth.log"
        elif [[ -f "/var/log/messages" ]]; then AUTH_LOG="/var/log/messages"; fi

        if [[ -n "$AUTH_LOG" ]]; then
            log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."
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
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 27. DYNAMIC DETECTION: CI/CD & DEVOPS INFRASTRUCTURE (JENKINS / GITLAB)
        if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
            log "INFO" "Jenkins CI/CD logs detected. Enabling Jenkins Guard."
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

        GITLAB_LOG=""
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
            GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi

        if [[ -n "$GITLAB_LOG" ]]; then
            log "INFO" "GitLab logs detected. Enabling GitLab Guard."
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
        REDIS_LOG=""
        if [[ -f "/var/log/redis/redis-server.log" ]]; then
            REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi

        if [[ -n "$REDIS_LOG" ]]; then
            log "INFO" "Redis logs detected. Enabling Redis Guard."
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

        RABBIT_LOG=""
        if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then
            RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
        fi

        if [[ -n "$RABBIT_LOG" ]]; then
            log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."
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

        # 29. DYNAMIC DETECTION: PORT SCANNERS (Alpine kernel logs)
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

        # 30. DYNAMIC DETECTION: SENSITIVE FILE INTEGRITY & AUDITD ANOMALIES
        AUDIT_LOG="/var/log/audit/audit.log"
        if command -v auditd >/dev/null 2>&1 && [[ -f "$AUDIT_LOG" ]]; then
            log "INFO" "Auditd logs detected. Enabling System Integrity Guard."
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

        # 40.5. DYNAMIC DETECTION: BEHAVIORAL IDOR ENUMERATION & API BRUTE-FORCING
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

        # 41. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

            # Create Filter for Advanced Local File Inclusion and PHP Wrapper abuse
            # Catches: php://, file://, expect://, /etc/passwd, /etc/shadow, and null byte (%00) injections
            # Note: We use \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*?(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb)).* HTTP/.*" \d{3} .*$
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

        # 49. DYNAMIC DETECTION: PRESTASHOP E-COMMERCE
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

        # 50. DYNAMIC DETECTION: ATLASSIAN JIRA & CONFLUENCE
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

        log "INFO" "Configuring Unified SysWarden Reporter for Alpine..."

        # Create cache directory securely
        mkdir -p /var/lib/syswarden

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

    # v2.15 Logic: STRICT filter on [SysWarden-BLOCK] only.
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
                        
                        # Base: Scanning for open ports and vulnerable services (Cat 14)
                        cats = ["14"]
                        attack_type = "Port Scan / Probing"

                        if port in [80, 443, 4443, 8080, 8443]: cats.extend(["15", "21"]); attack_type = "Web Attack"
                        elif port in [22, 2222, 22222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                        elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT Attack"
                        elif port == 88: cats.extend(["15", "18"]); attack_type = "Kerberos Attack"
                        elif port in [139, 445]: cats.extend(["15", "18"]); attack_type = "SMB/Ransomware Probe"
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

                        cats = list(set(cats)) # Deduplicate array
                        threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type})")).start()
						continue

                # --- FAIL2BAN LOGIC ---
                elif source == 'f2b' and ENABLE_F2B:
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

                        cats = list(set(cats)) # Deduplicate array
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

        # --- SECURITY FIX: SECURE ABUSEIPDB API KEY (ALPINE) ---
        # Permissions 750 (rwxr-x---) and ownership given to root and nobody.
        chown root:nobody /usr/local/bin/syswarden_reporter.py
        chmod 750 /usr/local/bin/syswarden_reporter.py
        # -------------------------------------------------------

        log "INFO" "Creating OpenRC service for Reporter..."
        cat <<'EOF' >/etc/init.d/syswarden-reporter
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
        log "INFO" "Auto Mode: SIEM config loaded via env vars."
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
        rc-service rsyslog restart 2>/dev/null || true
        log "INFO" "SIEM Log Forwarding is ACTIVE. (Target: $SIEM_IP:$SIEM_PORT/$SIEM_PROTO)"
    else
        log "INFO" "SIEM Log Forwarding DISABLED."
        rm -f /etc/rsyslog.d/99-syswarden-siem.conf
        rc-service rsyslog restart 2>/dev/null || true
    fi
}

setup_cron_autoupdate() {
    # Prevent recreating the cron during manual or silent updates
    if [[ "${1:-}" != "update" ]] && [[ "${1:-}" != "cron-update" ]]; then
        local script_path
        script_path=$(realpath "$0")
        local random_min=$((RANDOM % 60))

        # Add to root's crontab natively for Alpine with cron-update mode
        if ! grep -q "syswarden-update" /etc/crontabs/root 2>/dev/null; then
            echo "$random_min * * * * $script_path cron-update >/dev/null 2>&1 # syswarden-update" >>/etc/crontabs/root
            rc-update add crond default >/dev/null 2>&1 || true
            rc-service crond restart >/dev/null 2>&1 || true
            log "INFO" "Automatic updates enabled via Crond."
        fi

        cat <<EOF >/etc/logrotate.d/syswarden
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
    echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/99-syswarden-wireguard.conf
    sysctl -p /etc/sysctl.d/99-syswarden-wireguard.conf >/dev/null 2>&1 || true

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

    local ACTIVE_IF
    ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oEo 'dev [a-zA-Z0-9]+' | awk '{print $2}' | head -n 1)
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

    local SERVER_IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
        curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null ||
        curl -4 -s --connect-timeout 3 icanhazip.com 2>/dev/null ||
        ip -4 addr show "$ACTIVE_IF" | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | head -n 1)

    local SUBNET_BASE
    SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
    local SERVER_VPN_IP="${SUBNET_BASE}.1"
    local CLIENT_VPN_IP="${SUBNET_BASE}.2"

    local POSTUP=""
    local POSTDOWN=""

    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        # HOTFIX: Use single quotes for nft commands to avoid wg-quick shell escaping crashes.
        # Note: Forwarding rules for wg0 are already handled globally by syswarden-os-bypass.nft on Alpine.
        POSTUP="nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname \"$ACTIVE_IF\" masquerade'"
        POSTDOWN="nft delete table inet syswarden_wg 2>/dev/null || true"
    else
        POSTUP="iptables -t nat -A POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT"
        POSTDOWN="iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT"
    fi

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS ---
    # Enclosing file creation in a umask 077 subshell to ensure native 600 permissions
    (
        umask 077

        log "INFO" "Deploying WireGuard Server Profile..."
        cat <<EOF >/etc/wireguard/wg0.conf
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

    # --- OPENRC SPECIFIC SERVICE HANDLING ---
    log "INFO" "Starting WireGuard Tunnel Interface (wg0)..."
    if [[ ! -L "/etc/init.d/wg-quick.wg0" ]]; then
        ln -s /etc/init.d/wg-quick /etc/init.d/wg-quick.wg0
    fi
    rc-update add wg-quick.wg0 default >/dev/null 2>&1 || true
    rc-service wg-quick.wg0 restart >/dev/null 2>&1 || true

    log "INFO" "WireGuard VPN deployed successfully."

    # --- FIX: Restore default OS umask to prevent strict permission leaks to other functions ---
    umask 022
}

display_wireguard_qr() {
    if [[ "${USE_WIREGUARD:-n}" == "y" ]] && [[ -f "/etc/wireguard/clients/admin-pc.conf" ]]; then
        echo -e "\n${RED}========================================================================${NC}"
        echo -e "${YELLOW}           WIREGUARD MANAGEMENT VPN - SCAN TO CONNECT${NC}"
        echo -e "${RED}========================================================================${NC}\n"

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
    (
        umask 077

        # 3. Cryptography
        CLIENT_PRIV=$(wg genkey)
        CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
        PRESHARED_KEY=$(wg genpsk)

        # 4. Extract Server Params
        SERVER_PUB=$(grep "PublicKey" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')
        ENDPOINT=$(grep "Endpoint" "$admin_conf" | head -n 1 | awk -F'= ' '{print $2}' | tr -d '\r')

        # 5. IP Calculation
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

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden (Alpine) ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation..."

    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # --- HOTFIX: SURGICAL WIREGUARD CLEANUP (OPENRC) ---
    if [[ "${USE_WIREGUARD:-n}" == "y" ]]; then
        log "INFO" "Stopping and removing SysWarden WireGuard VPN..."
        rc-service wg-quick.wg0 stop 2>/dev/null || true
        rc-update del wg-quick.wg0 default 2>/dev/null || true
        rm -f /etc/init.d/wg-quick.wg0

        # Only remove SysWarden configs, protect user's custom WireGuard tunnels
        rm -f /etc/wireguard/wg0.conf
        rm -rf /etc/wireguard/clients
        if [[ -d /etc/wireguard ]] && [[ -z "$(ls -A /etc/wireguard 2>/dev/null)" ]]; then
            rmdir /etc/wireguard 2>/dev/null || true
        fi

        rm -f /etc/sysctl.d/99-syswarden-wireguard.conf
        sysctl -p 2>/dev/null || true

        # EMERGENCY SSH RESTORE FOR IPTABLES
        if command -v iptables >/dev/null; then
            while iptables -D INPUT -p tcp --dport "${SSH_PORT:-22}" -j DROP 2>/dev/null; do :; done
            /etc/init.d/iptables save >/dev/null 2>&1 || true
        fi
    fi
    # ----------------------------------------------------------

    # 1. Stop & Remove Reporter & UI Services
    log "INFO" "Removing SysWarden Reporter & UI Dashboard..."
    rc-service syswarden-reporter stop 2>/dev/null || true
    rc-update del syswarden-reporter default 2>/dev/null || true
    rm -f /etc/init.d/syswarden-reporter /usr/local/bin/syswarden_reporter.py
    rm -rf /var/lib/syswarden

    rc-service syswarden-ui stop 2>/dev/null || true
    rc-update del syswarden-ui default 2>/dev/null || true
    rm -f /etc/init.d/syswarden-ui /usr/local/bin/syswarden-telemetry.sh /usr/local/bin/syswarden-ui-server.py /usr/local/bin/syswarden-ui-sync.sh
    rm -rf /etc/syswarden/ui
    rm -f /var/log/syswarden-audit.log

    # --- HOTFIX: SCORCHED EARTH TELEMETRY PURGE ---
    # Destroys any hidden databases or dashboard memory files specific to Alpine paths
    rm -rf /var/log/syswarden 2>/dev/null || true
    rm -rf /opt/syswarden 2>/dev/null || true
    # -----------------------------------------------------

    log "INFO" "Removing HA Cluster Sync Engine..."
    rm -f /usr/local/bin/syswarden-sync.sh
    if crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
        crontab -l 2>/dev/null | grep -v "syswarden-sync" | crontab -
    fi

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    sed -i '/syswarden-update/d' /etc/crontabs/root 2>/dev/null || true
    rc-service crond restart 2>/dev/null || true
    rm -f "/etc/logrotate.d/syswarden"

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."

    # Nftables
    if command -v nft >/dev/null; then
        nft delete table netdev syswarden_hw_drop 2>/dev/null || true
        nft delete table inet syswarden_table 2>/dev/null || true
        # HOTFIX: Purge WG NAT table
        nft delete table inet syswarden_wg 2>/dev/null || true

        # 1. Clean physical files
        rm -f /etc/syswarden/syswarden.nft
        rm -f /etc/nftables.d/syswarden-os-bypass.nft 2>/dev/null || true

        # 2. HOTFIX: Purge rules from RAM matching the SysWarden comments
        for chain in input forward; do
            while nft -a list chain inet filter "$chain" 2>/dev/null | grep -q "SysWarden:"; do
                local handle
                handle=$(nft -a list chain inet filter "$chain" 2>/dev/null | grep "SysWarden:" | awk '{print $NF}' | head -n 1)
                if [[ -n "$handle" ]]; then
                    nft delete rule inet filter "$chain" handle "$handle" 2>/dev/null || true
                else
                    break
                fi
            done
        done

        # 3. HOTFIX: Alpine uses .nft, Debian uses .conf
        local MAIN_NFT_CONF="/etc/nftables.nft"
        if [[ -f "$MAIN_NFT_CONF" ]]; then
            sed -i '\|include "/etc/syswarden/syswarden.nft"|d' "$MAIN_NFT_CONF"
            sed -i '/# Added by SysWarden/d' "$MAIN_NFT_CONF"

            # Save the clean RAM state to disk to prevent reboot ghosts
            if grep -q "flush ruleset" "$MAIN_NFT_CONF"; then
                echo '#!/usr/sbin/nft -f' >"$MAIN_NFT_CONF"
                echo 'flush ruleset' >>"$MAIN_NFT_CONF"
                nft list table inet filter >>"$MAIN_NFT_CONF" 2>/dev/null || true
            fi
        fi

        # Reload the clean state cleanly via OpenRC
        rc-service nftables reload >/dev/null 2>&1 || true
    fi

    # Docker (DOCKER-USER chain)
    if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        while iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null; do :; done
        while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
    fi

    # IPSet / Iptables (Legacy)
    if command -v ipset >/dev/null; then
        while iptables -t raw -D PREROUTING -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] " 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$GEOIP_SET_NAME" src -j LOG --log-prefix "[SysWarden-GEO] " 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -t raw -D PREROUTING -m set --match-set "$ASN_SET_NAME" src -j LOG --log-prefix "[SysWarden-ASN] " 2>/dev/null; do :; done

        while iptables -D INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$GEOIP_SET_NAME" src -j DROP 2>/dev/null; do :; done
        while iptables -D INPUT -m set --match-set "$ASN_SET_NAME" src -j DROP 2>/dev/null; do :; done

        ipset destroy "$SET_NAME" 2>/dev/null || true
        ipset destroy "$GEOIP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_SET_NAME" 2>/dev/null || true
        /etc/init.d/iptables save 2>/dev/null || true
    fi

    # --- HOTFIX: DOCKER NETWORK RESURRECTION ---
    if command -v docker >/dev/null 2>&1 && rc-service docker status 2>/dev/null | grep -q "started"; then
        log "INFO" "Restarting Docker daemon to rebuild NAT & Masquerade routing..."
        rc-service docker restart 2>/dev/null || true
        sleep 3
    fi
    # --------------------------------------------------

    # 4. Revert Fail2ban Configuration (State Aware)

    # --- HOTFIX: SCORCHED EARTH FAIL2BAN & TELEMETRY PURGE (ALPINE) ---
    log "INFO" "Executing Scorched Earth purge on Alpine telemetry..."

    # 1. Brutal kill of OpenRC services and background loops
    rc-service fail2ban stop 2>/dev/null || true
    rc-service syswarden-reporter stop 2>/dev/null || true
    rc-service syswarden-ui stop 2>/dev/null || true

    # 2. Hunt down any surviving processes or active cron jobs
    pkill -9 fail2ban 2>/dev/null || true
    pkill -9 -f syswarden-telemetry 2>/dev/null || true
    pkill -9 -f syswarden_reporter 2>/dev/null || true
    pkill -9 -f syswarden-ui 2>/dev/null || true
    pkill -9 -f syswarden-ui-sync 2>/dev/null || true
    # --------------------------------------------------

    # 3. Destroy the SQLite database
    rm -f /var/lib/fail2ban/fail2ban.sqlite3

    # 3. Truncate historical logs
    if [[ -f /var/log/fail2ban.log ]]; then
        : >/var/log/fail2ban.log
    fi

    # OPTIONAL: Remove Ban history from system messages (Precise cleaning)
    if [[ -f /var/log/messages ]]; then
        sed -i '/\] Ban /d' /var/log/messages 2>/dev/null || true
        sed -i '/\] Restore Ban /d' /var/log/messages 2>/dev/null || true
    fi

    # 4. Wipe JSON data to ensure amnesia
    rm -f /etc/syswarden/ui/data.json
    rm -rf /var/lib/syswarden/* 2>/dev/null || true
    # -------------------------------------------------------------------------

    # --- Clean up all SysWarden Fail2ban filters (Including v2.15 additions) ---
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
    rm -f /etc/fail2ban/fail2ban.local /etc/fail2ban/action.d/syswarden-docker.conf /etc/fail2ban/jail.local

    if [[ "${FAIL2BAN_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Fail2ban (installed by SysWarden)..."
        # Already stopped by Scorched Earth
        rc-update del fail2ban default 2>/dev/null || true
        apk del fail2ban 2>/dev/null || true
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
backend = pyinotify
[sshd]
enabled = true
port = ssh
logpath = /var/log/messages
backend = pyinotify
EOF
        fi
        rc-service fail2ban restart 2>/dev/null || true
    fi

    # 5. Remove Nginx Dashboard (State Aware)

    # --- HOTFIX: CLEAN UNINSTALL ---
    # Remove Nginx virtual host configuration unconditionally
    log "INFO" "Removing Nginx UI configuration..."
    rm -f /etc/nginx/http.d/syswarden-ui.conf

    # Reload Nginx gracefully if it is still running
    if rc-service nginx status 2>/dev/null | grep -q "started"; then
        rc-service nginx reload >/dev/null 2>&1 || true
    fi
    # --------------------------------------

    if [[ "${NGINX_INSTALLED_BY_SYSWARDEN:-n}" == "y" ]]; then
        log "INFO" "Purging Nginx (installed by SysWarden)..."
        rc-service nginx stop 2>/dev/null || true
        rc-update del nginx default 2>/dev/null || true
        apk del nginx 2>/dev/null || true
    fi

    # 6. Remove Wazuh Agent (If installed)
    if apk info -e wazuh-agent >/dev/null 2>&1; then
        read -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            rc-service wazuh-agent stop 2>/dev/null || true
            rc-update del wazuh-agent default 2>/dev/null || true
            apk del wazuh-agent
            rm -rf /var/ossec
            log "INFO" "Wazuh Agent removed."
        fi
    fi

    # --- 7. OS & SECURITY REVERT ---
    log "INFO" "Reverting OS Hardening & Log Routing..."
    if [[ -f /etc/rsyslog.conf ]]; then
        sed -i '/kern-firewall\.log/d' /etc/rsyslog.conf
        rc-service rsyslog restart 2>/dev/null || true
    fi

    # --- HOTFIX: PURGE DES LOGS PHYSIQUES ---
    rm -f /var/log/kern-firewall.log 2>/dev/null || true
    rm -f /var/log/auth-syswarden.log 2>/dev/null || true
    rm -f /var/log/syswarden* 2>/dev/null || true
    # -----------------------------------------------

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
        rc-service sshd restart 2>/dev/null || true
    fi

    if [[ -f /etc/cron.allow ]] && [[ "$(cat /etc/cron.allow)" == "root" ]]; then rm -f /etc/cron.allow; fi

    # HOTFIX: RESTORE GROUPS (ALPINE ADDGROUP)
    if [[ -f "$SYSWARDEN_DIR/group_backup.txt" ]]; then
        while IFS=':' read -r grp members; do
            for user in $(echo "$members" | tr ',' ' '); do
                if [[ -n "$user" ]] && id "$user" >/dev/null 2>&1; then addgroup "$user" "$grp" 2>/dev/null || true; fi
            done
        done <"$SYSWARDEN_DIR/group_backup.txt"
    fi
    # --------------------------------

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
        if [[ -z "$WAZUH_IP" ]]; then
            log "ERROR" "Missing IP. Skipping."
            return
        fi

        read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
        W_PORT_COMM=${W_PORT_COMM:-1514}

        read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
        W_PORT_ENROLL=${W_PORT_ENROLL:-1515}
    fi

    # Fail-Safe: Interdire l'installation si l'IP n'est pas fournie en mode auto
    if [[ -z "$WAZUH_IP" ]]; then
        log "ERROR" "Missing Wazuh IP. Skipping."
        return
    fi

    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on Alpine Firewall..."

    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
        # Modular Persistence
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft
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

        echo "WAZUH_IP='$WAZUH_IP'" >>"$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >>"$CONF_FILE"
        log "INFO" "Wazuh Agent installed and started."
    else
        log "ERROR" "Failed to install Wazuh Agent package."
    fi
}

# ==============================================================================
# SYSWARDEN v2.15 - TELEMETRY BACKEND (SERVERLESS - IP REGISTRY UPDATE)
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
# Ensures all background processes spawned by Fail2ban checks are cleanly reaped.
trap 'wait' EXIT

# --- HOTFIX: ABSOLUTE MUTEX LOCK (ANTI-OVERLAP) ---
# Prevents CPU leaks by ensuring only ONE instance can ever run mathematically
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

# Ensure jq is installed for atomic and safe JSON serialization
if ! command -v jq >/dev/null; then apk add --no-cache jq >/dev/null 2>&1 || true; fi

# --- System Metrics Gathering ---
SYS_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SYS_HOSTNAME=$(hostname)
# --- FIX: KERNEL EXTRACTION & FAULT-TOLERANT VARIABLES ---
# 'uptime -p' crashes on Alpine/BusyBox. We calculate uptime directly from the kernel.
SYS_UPTIME=$(awk '{d=int($1/86400); h=int(($1%86400)/3600); m=int(($1%3600)/60); if(d>0) printf "%dd %dh %dm", d, h, m; else printf "%dh %dm", h, m}' /proc/uptime 2>/dev/null || echo "Unknown")
SYS_LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}' || echo "0, 0, 0")

# Bulletproof RAM parsing: Prevents 'set -e' crashes if 'free' output changes format
SYS_RAM_USED=$(free -m 2>/dev/null | awk '/^Mem:/{print $3}')
SYS_RAM_USED=${SYS_RAM_USED:-0}
SYS_RAM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
SYS_RAM_TOTAL=${SYS_RAM_TOTAL:-0}
# ---------------------------------------------------------

# --- Layer 3 Metrics ---
L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

# --- Layer 7 Metrics & IP Registry (SECURE JSON ARRAYS) ---
L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"
BANNED_IPS_JSON="[]"

# HOTFIX: Strict timeouts to prevent Fail2ban socket deadlocks freezing the cron
if command -v fail2ban-client >/dev/null && timeout 2 fail2ban-client ping >/dev/null 2>&1; then
    JAIL_LIST=$(timeout 2 fail2ban-client status 2>/dev/null | awk -F'Jail list:[ \t]*' '/Jail list:/ {print $2}' | tr -d ' ' | tr ',' '\n' || true)
    
    for JAIL in $JAIL_LIST; do
        [[ -z "$JAIL" ]] && continue
        L7_ACTIVE_JAILS=$((L7_ACTIVE_JAILS + 1))
        
        # HOTFIX: Abort jail query if it hangs for more than 3 seconds
        STATUS_OUT=$(timeout 3 fail2ban-client status "$JAIL" 2>/dev/null || echo "")
        
        if [[ -n "$STATUS_OUT" ]]; then
            BANNED_COUNT=$(echo "$STATUS_OUT" | awk '/Currently banned:/ {print $4}' || echo "0")
            BANNED_COUNT=${BANNED_COUNT:-0}
            L7_TOTAL_BANNED=$((L7_TOTAL_BANNED + BANNED_COUNT))
            
            if [[ "$BANNED_COUNT" -gt 0 ]]; then
                # Safely append jail object using jq
                JAILS_JSON=$(echo "$JAILS_JSON" | jq --arg n "$JAIL" --argjson c "$BANNED_COUNT" '. + [{"name": $n, "count": $c}]')
                
                # Extract and safely append IPs
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

# --- DEVSECOPS: Top 10 Historical Attacking IPs (Aggregated & Bulletproof Alpine) ---
TOP_ATTACKERS_JSON="[]"
TOP_STATS=""

# We aggregate all possible log sources and catch both fresh "Ban" and F2B restart "Restore Ban"
TOP_STATS=$( { 
    cat /var/log/fail2ban.log /var/log/messages 2>/dev/null || true
} | grep -E "\] (Restore )?Ban " | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -nr | head -n 10 || true )

if [[ -n "$TOP_STATS" ]]; then
    while IFS=" " read -r count ip; do
        if [[ -n "$ip" && -n "$count" ]]; then
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --argjson c "$count" '. + [{"ip": $ip, "count": $c}]')
        fi
    done <<< "$TOP_STATS"
fi
# ------------------------------------------------------------------------------------

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

# --- Generate Atomic JSON Payload (SECURITY FIX: jq escaping) ---
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

# FIX: Strict ownership for Nginx web server (Read-Only access)
mv -f "$TMP_FILE" "$DATA_FILE"
chown nginx:nginx "$DATA_FILE" 2>/dev/null || true
chmod 640 "$DATA_FILE"
EOF

    # 2. Make executable
    chmod +x "$BIN_PATH"

    # 3. Injection into CRON tasks (Execution every minute)
    if ! crontab -l 2>/dev/null | grep -q "$BIN_PATH"; then
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
        
        /* Overrides - Absolute Zero Border Policy */
        .table { --bs-table-bg: transparent !important; }
        .table > :not(caption) > * > * { background-color: transparent !important; }
        .table, .table tbody, .table tr, .table td, .table th, .table thead { border: none !important; box-shadow: none !important; }
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
                                        <thead style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2; border: none; box-shadow: none;">
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
                                        <thead style="position: sticky; top: 0; background: var(--sw-card-bg); z-index: 2; border: none; box-shadow: none;">
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
                    <li class="list-group-item d-flex justify-content-between align-items-center bg-transparent px-0 border-0 py-2">
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

    # --- 5. NGINX VHOST CONFIGURATION (ALPINE SPECIFIC PATH) ---
    log "INFO" "Configuring Nginx reverse proxy for port 9999..."
    cat <<EOF >/etc/nginx/http.d/syswarden-ui.conf
server {
    # --- HOTFIX: CROSS-OS NGINX COMPATIBILITY ---
    # Using 'listen ... http2' instead of 'http2 on;' ensures compatibility
    # with older Nginx versions (<1.25.1) while remaining functional (with a warning) on modern versions.
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
    
    # --- HOTFIX: EXPLICIT MIME TYPES ---
    # Older OS/Nginx combinations lack .woff2 in their mime.types.
    # Combined with 'nosniff', browsers strictly reject the font.
    include mime.types;
    types {
        font/woff2 woff2;
    }

    # --- Security Access Control (Only Admin IP) ---
$(echo -e "$NGINX_ALLOW_RULES")

    # --- Strict Security Headers (Updated CSP for Bootstrap & ChartJS Source Maps) ---
    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;" always;
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

    # --- 6. DAEMON ORCHESTRATION (ALPINE OPENRC) ---
    # Cleanup legacy Python server if upgrading
    if rc-service syswarden-ui status 2>/dev/null | grep -q "started"; then
        rc-service syswarden-ui stop >/dev/null 2>&1 || true
        rc-update del syswarden-ui default >/dev/null 2>&1 || true
        rm -f /etc/init.d/syswarden-ui /usr/local/bin/syswarden-ui-server.py
    fi

    # Start or Reload Nginx
    if rc-service nginx status 2>/dev/null | grep -q "started"; then
        rc-service nginx reload >/dev/null 2>&1 || true
    else
        rc-update add nginx default >/dev/null 2>&1
        rc-service nginx start >/dev/null 2>&1 || true
    fi

    # --- HOTFIX: DYNAMIC IP RESOLUTION ---
    # 1. Tries to get the Public IPv4 via curl or wget
    # 2. Fallbacks to the primary active local IP via routing table if offline
    # 3. Failsafe to '<YOUR_IP>' if everything else fails
    local SERVER_IP
    SERVER_IP=$(curl -sL4 https://ifconfig.me 2>/dev/null || wget -qO- https://ifconfig.me 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i == "src") print $(i+1)}' | head -n 1 || echo "<YOUR_IP>")

    log "INFO" "Dashboard UI secured by Nginx at https://${SERVER_IP}:9999"
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    # --- FIX: SAFE DYNAMIC WHITELISTING (STATE MACHINE) ---
    # 1. Add IP to the Single Source of Truth (if not already present)
    if ! grep -q "^${WL_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$WL_IP" >>"$WHITELIST_FILE"
        log "INFO" "IP $WL_IP securely saved to $WHITELIST_FILE."
    else
        log "INFO" "IP $WL_IP is already in the whitelist file."
    fi

    log "INFO" "Rebuilding firewall framework to safely integrate the new IP..."

    # 2. Force loading config to ensure core variables (SSH_PORT, USE_WIREGUARD) are in RAM
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
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

    if command -v fail2ban-client >/dev/null && rc-service fail2ban status 2>/dev/null | grep -q "started"; then
        local active_jails
        active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
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

        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >>"$temp_file"
    done <"$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."
    rc-service fail2ban restart >/dev/null 2>&1 || true
    log "INFO" "Fail2ban service restarted."

    # --- HOTFIX: STATEFUL DOCKER BYPASS RE-ENFORCEMENT ---
    # Fail2ban restarts will inject new chains at the top of DOCKER-USER.
    # We MUST ensure the ESTABLISHED, RELATED rule remains at Absolute Priority 0.
    if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
        iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
        log "INFO" "Stateful Docker bypass successfully re-enforced at Priority 0."

        # Persist state so the new order survives reboots (Alpine OpenRC natively)
        /etc/init.d/iptables save >/dev/null 2>&1 || true
    fi
    # ------------------------------------------------------------
}

check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker (Alpine) ===${NC}"
    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response

    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden-alpine\.sh"' | head -n 1 | cut -d'"' -f4)

    local hash_url
    hash_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*/install-syswarden-alpine\.sh\.sha256"' | head -n 1 | cut -d'"' -f4)

    if [[ -z "$download_url" ]]; then
        echo -e "${GREEN}No specific update found for the Alpine version in the latest release. You are up to date!${NC}"
        return
    fi

    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new Alpine version ($latest_version) is available!${NC}"

        # --- DEVSECOPS: INTERACTIVE CONFIRMATION ---
        read -p "Do you want to proceed with the automated in-place upgrade now? (y/N): " proceed_upgrade
        if [[ ! "$proceed_upgrade" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Upgrade aborted by user. System remains on $VERSION.${NC}"
            return
        fi

        # --- SECURITY FIX: MITM PROTECTION & SECURE UPDATE ---
        echo -e "${YELLOW}Downloading and verifying update securely...${NC}"

        # --- HOTFIX: SAME-FILE COLLISION PREVENTION ---
        # Create an isolated sub-directory for the update payload to guarantee
        # it never collides with the script's current execution path, even if
        # the user runs the orchestrator directly from within /tmp.
        local UPGRADE_DIR="$TMP_DIR/syswarden_upgrade_payload"
        mkdir -p "$UPGRADE_DIR"

        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden-alpine.sh" "$download_url"
        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=2 --no-hsts -qO "$UPGRADE_DIR/install-syswarden-alpine.sh.sha256" "$hash_url"

        cd "$UPGRADE_DIR" || exit 1

        if ! sha256sum -c install-syswarden-alpine.sh.sha256 --status; then
            echo -e "${RED}[ CRITICAL ALERT ]${NC}"
            echo -e "${RED}The downloaded script failed cryptographic validation!${NC}"
            echo -e "${RED}Possible causes: Man-In-The-Middle (MITM) attack, DNS poisoning, or incomplete download.${NC}"
            echo -e "${RED}Update aborted to protect system integrity.${NC}"
            rm -rf "$UPGRADE_DIR"
            exit 1
        fi

        echo -e "${GREEN}Checksum validated successfully. Preparing in-place upgrade...${NC}"

        # --- PRE-UPGRADE: SURGICAL PROCESS TERMINATION (OPENRC) ---
        log "INFO" "Terminating existing SysWarden background processes safely..."
        pkill -9 -f syswarden-telemetry 2>/dev/null || true
        pkill -9 -f syswarden_reporter 2>/dev/null || true

        if command -v rc-service >/dev/null; then
            rc-service syswarden-ui stop 2>/dev/null || true
            rc-service syswarden-reporter stop 2>/dev/null || true
        fi

        # --- IN-PLACE SCRIPT REPLACEMENT ---
        local current_script
        current_script=$(realpath "$0")

        log "INFO" "Replacing current orchestrator at $current_script..."

        # We explicitly copy instead of move in case the OS locks the executing file,
        # ensuring the atomicity of the operation across all edge cases.
        cp -f "$UPGRADE_DIR/install-syswarden-alpine.sh" "$current_script"
        chmod 700 "$current_script"

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

    local NOW_SEC
    NOW_SEC=$(date +%s)

    # Multiplex Alpine dmesg and fail2ban logs safely without creating orphan processes
    (
        P1=""
        if command -v dmesg >/dev/null 2>&1; then
            dmesg -w 2>/dev/null &
            P1=$!
        fi

        P2=""
        if [[ -f /var/log/fail2ban.log ]]; then
            tail -F -q /var/log/fail2ban.log 2>/dev/null &
            P2=$!
        fi

        trap '[[ -n "$P1" ]] && kill $P1 2>/dev/null; [[ -n "$P2" ]] && kill $P2 2>/dev/null' EXIT
        wait
    ) | awk -v script_start="$NOW_SEC" '
    BEGIN {
        # Alpine specific: Calculate boot time for pure kernel (dmesg) timestamps
        if ((getline uptime_str < "/proc/uptime") > 0) {
            split(uptime_str, up_arr, " ")
            uptime_sec = up_arr[1]
            boot_sec = script_start - uptime_sec
        }
        close("/proc/uptime")

        # Map syslog months to ISO numbers and fetch current year (Fallback)
        m["Jan"]="01"; m["Feb"]="02"; m["Mar"]="03"; m["Apr"]="04"; m["May"]="05"; m["Jun"]="06";
        m["Jul"]="07"; m["Aug"]="08"; m["Sep"]="09"; m["Oct"]="10"; m["Nov"]="11"; m["Dec"]="12";
        "date +%Y" | getline current_year; close("date +%Y")
    }
    /SysWarden-BLOCK|SysWarden-GEO|SysWarden-ASN|Catch-All/ {
        # Transform Alpine dmesg timestamp [  1234.56 ] to ISO (YYYY-MM-DD HH:MM:SS)
        if ($0 ~ /^\[[ \t]*[0-9]+\.[0-9]+\]/) {
            match($0, /[0-9]+\.[0-9]+/)
            ksec = substr($0, RSTART, RLENGTH)
            event_sec = boot_sec + ksec
            
            # --- HOTFIX: Drop old dmesg history to only show LIVE events ---
            if (event_sec < script_start - 5) next;
            # ----------------------------------------------------------------------
            
            cmd = "date -d @" int(event_sec) " \"+%Y-%m-%d %H:%M:%S\" 2>/dev/null"
            if ((cmd | getline dtime) > 0) {
                date = dtime
            } else {
                date = "Kernel-TS"
            }
            close(cmd)
        } 
        # Transform traditional syslog date (Apr 2 12:56:01) to ISO if rsyslog is present
        else if ($1 in m) {
            date = sprintf("%s-%s-%02d %s", current_year, m[$1], $2, $3)
        } 
        else {
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
if [[ -f "${1:-}" ]]; then
    echo -e "${GREEN}>>> Unattended configuration file detected: $1${NC}"

    # --- SECURITY FIX: SECURE AUTO-CONF FILE ---
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
        if [[ "$key" =~ ^SYSWARDEN_[A-Z0-9_]+$ ]]; then
            export "$key"="$val"
        fi
    done <"$1"

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
    # Crucial exit to prevent background process duplication
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
    echo -e "${GREEN}               Advanced Firewall & Blocklist Orchestrator | v2.15                  ${NC}"
    echo -e "${BLUE}===================================================================================${NC}\n"
fi

check_root
detect_os_backend

# --- PREVENT ADMIN LOCK-OUT (EXECUTE BEFORE FAIL2BAN/FIREWALL) ---
auto_whitelist_admin
process_auto_whitelist "$MODE"
# -----------------------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    install_dependencies

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

        echo -e "\n${BOLD}7. HA CLUSTER SYNC${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Standby Node IP for automatic threat intelligence replication."

        echo -e "\n${BOLD}8. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] Disabled"

        echo -e "\n${BOLD}9. SIEM LOG FORWARDING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   External SIEM IP, Port (Default: 6514), and Protocol for central log auditing."
        echo -e "   Required for strict ISO 27001 / NIS2 compliance."

        echo -e "\n${BOLD}10. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."
        echo -e "   Get one at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"

        echo -e "\n${BOLD}11. WAZUH SIEM AGENT${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Required: Manager IP, Enrollment Port (1515), Listen Port (1514)."
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
    define_ha_cluster "$MODE"
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
if [[ "$MODE" != "update" ]]; then
    discover_active_services
    apply_firewall_rules
fi

download_geoip
download_asn
# --------------------------------------

# --- FIX 3: THE POST-DOWNLOAD RELOAD (INSTALL & UPDATE) ---
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

if command -v rc-service >/dev/null && rc-service syswarden-reporter status 2>/dev/null | grep -q "started"; then
    rc-service syswarden-reporter restart >/dev/null 2>&1 || true
fi

# --- HOTFIX: DASHBOARD & TELEMETRY ORCHESTRATION ---
setup_telemetry_backend
generate_dashboard
# ---------------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"

    # --- EXECUTE OS HARDENING (If authorized by the user) ---
    apply_os_hardening

    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> OS Detected: Alpine Linux (OpenRC)"
    echo -e " -> List loaded: $LIST_TYPE"

    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Alpine (Interactive)"
    fi

    echo -e " -> Protection: Active"

    display_wireguard_qr
else
    # --- HOTFIX: FORCE CRON SYNTAX UPGRADE DURING UPDATE ---
    if [[ -f /etc/crontabs/root ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/crontabs/root 2>/dev/null || true
        rc-service crond restart 2>/dev/null || true
    fi
    if [[ -f /etc/cron.d/syswarden-update ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/cron.d/syswarden-update 2>/dev/null || true
    fi
    # --------------------------------------------------------------

    # Restart Fail2ban gracefully to compile the newly injected Python/Regex rules
    log "INFO" "Restarting Fail2ban engine to compile new definitions..."

    if command -v rc-service >/dev/null; then
        # --- HOTFIX: SOCKET RACE CONDITION PREVENTION (OPENRC) ---
        rc-service fail2ban stop >/dev/null 2>&1 || true
        sleep 5
        rc-service fail2ban start >/dev/null 2>&1 || true
    else
        # Fallback directly to client if OpenRC fails
        fail2ban-client stop >/dev/null 2>&1 || true
        sleep 5
        fail2ban-client start >/dev/null 2>&1 || true
    fi

    # Give clear feedback during an update
    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
    echo -e " -> SysWarden Engine (L3/L4 & L7) and Dashboard UI have been updated to the latest version."
fi
