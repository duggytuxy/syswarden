#!/bin/bash

# SysWarden Manager - Blocklists and Whitelists Manager
# Copyright (C) 2026 duggytuxy - Laurent M.
# Version: v1.96
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# --- SAFETY & ENVIRONMENT ---
set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- CONSTANTS ---
SYSWARDEN_DIR="/etc/syswarden"
WHITELIST_FILE="$SYSWARDEN_DIR/whitelist.txt"
BLOCKLIST_FILE="$SYSWARDEN_DIR/blocklist.txt"
SSH_WHITELIST_FILE="$SYSWARDEN_DIR/ssh_whitelist.txt"
SET_NAME="syswarden_blacklist"
VERSION="v1.96"

# --- ROOT ENFORCEMENT ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}ERROR: SysWarden Manager requires root privileges.${NC}"
    exit 1
fi

# --- HOTFIX: OS DETECTION ---
OS_TYPE="Universal"
if [[ -f /etc/alpine-release ]]; then OS_TYPE="Alpine"; fi
if [[ -f /etc/slackware-version ]]; then OS_TYPE="Slackware"; fi

# --- FIREWALL BACKEND DETECTION ---
detect_backend() {
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        FW_BACKEND="ufw"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        FW_BACKEND="firewalld"
    elif command -v nft >/dev/null 2>&1 && nft list table inet syswarden_table >/dev/null 2>&1; then
        FW_BACKEND="nftables"
    elif command -v ipset >/dev/null 2>&1 && ipset list "$SET_NAME" >/dev/null 2>&1; then
        FW_BACKEND="ipset"
    else
        FW_BACKEND="unknown"
    fi
}

# --- HOTFIX: DYNAMIC NFTABLES CHAIN RESOLUTION ---
# Slackware & Debian use 'input_frontline', Alpine uses 'input'
get_nft_chain() {
    if nft list chain inet syswarden_table input_frontline >/dev/null 2>&1; then
        NFT_CHAIN="input_frontline"
    elif nft list chain inet syswarden_table input >/dev/null 2>&1; then
        NFT_CHAIN="input"
    else
        NFT_CHAIN="input" # Fallback failsafe
    fi
}

# --- EXTRACT ACTIVE SSH PORT ---
get_ssh_port() {
    SSH_PORT=""

    # 1. Dynamic Kernel Socket Detection (Ultimate Truth)
    if command -v ss >/dev/null; then
        SSH_PORT=$(ss -tlnp 2>/dev/null | grep -i 'sshd' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -u | head -n 1 || true)
    fi

    if [[ -z "$SSH_PORT" ]] && command -v netstat >/dev/null; then
        SSH_PORT=$(netstat -tlnp 2>/dev/null | grep -i 'sshd' | awk '{print $4}' | awk -F':' '{print $NF}' | sort -u | head -n 1 || true)
    fi

    # 2. Persistence File Fallback
    if [[ -z "$SSH_PORT" ]] && [[ -f "/etc/syswarden.conf" ]]; then
        # shellcheck source=/dev/null
        source /etc/syswarden.conf 2>/dev/null || true
    fi

    # 3. Absolute Fallback
    SSH_PORT=${SSH_PORT:-22}
}

# --- STRICT SEMANTIC IP VALIDATION ---
validate_ip() {
    local ip="$1"
    if ! echo "$ip" | awk -F'.' 'NF==4 && $1>=0 && $1<=255 && $2>=0 && $2<=255 && $3>=0 && $3<=255 && $4>=0 && $4<=255 {exit 0} {exit 1}'; then
        echo -e "${RED}ERROR: Invalid or mathematically impossible IPv4 address: '$ip'${NC}"
        exit 1
    fi
}

# --- DIAGNOSTIC ENGINE: CHECK IP STATUS ---
check_ip() {
    local target_ip="$1"
    validate_ip "$target_ip"

    echo -e "\n${CYAN}=== SysWarden Global XDR Search: $target_ip ===${NC}"
    detect_backend

    echo -n "[Storage] Global Whitelist : "
    if grep -q "^${target_ip}$" "$WHITELIST_FILE" 2>/dev/null; then echo -e "${GREEN}PRESENT${NC}"; else echo -e "${YELLOW}Not Found${NC}"; fi

    echo -n "[Storage] SSH-Only Bypass  : "
    if grep -q "^${target_ip}" "$SSH_WHITELIST_FILE" 2>/dev/null; then echo -e "${GREEN}PRESENT${NC}"; else echo -e "${YELLOW}Not Found${NC}"; fi

    echo -n "[Storage] Global Blocklist : "
    if grep -q "^${target_ip}$" "$BLOCKLIST_FILE" 2>/dev/null; then echo -e "${RED}PRESENT${NC}"; else echo -e "${YELLOW}Not Found${NC}"; fi

    echo -n "[Kernel]  L3 Firewall      : "
    local is_blocked_fw=false

    case "$FW_BACKEND" in
        nftables)
            if nft get element inet syswarden_table "$SET_NAME" "{ $target_ip }" >/dev/null 2>&1; then is_blocked_fw=true; fi
            ;;
        firewalld | ipset | ufw)
            if ipset test "$SET_NAME" "$target_ip" >/dev/null 2>&1; then is_blocked_fw=true; fi
            ;;
    esac

    if [ "$is_blocked_fw" = true ]; then
        echo -e "${RED}DROPPED (In Active Set)${NC}"
    else
        echo -e "${GREEN}CLEAR (Not in main drop set)${NC}"
    fi

    echo -n "[WAF]     L7 Fail2ban      : "
    local is_banned_f2b=false
    local f2b_jails=""

    if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
        local active_jails
        active_jails=$(fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list:[ \t]*//' | tr -d ' ' | tr ',' '\n')

        for jail in $active_jails; do
            if fail2ban-client status "$jail" 2>/dev/null | grep -q "$target_ip"; then
                is_banned_f2b=true
                f2b_jails="$f2b_jails $jail"
            fi
        done
    fi

    if [ "$is_banned_f2b" = true ]; then
        echo -e "${RED}BANNED${NC} -> Triggered by:${YELLOW}$f2b_jails${NC}"
    else
        echo -e "${GREEN}CLEAR (No active behavioral bans)${NC}"
    fi
    echo ""
}

# --- SURGICAL UNBAN ---
unblock_ip() {
    local target_ip="$1"
    validate_ip "$target_ip"
    detect_backend

    echo -e "\n${BLUE}>> Initiating Surgical Unban for $target_ip...${NC}"

    if [[ -f "$BLOCKLIST_FILE" ]]; then
        sed -i "\|^${target_ip}$|d" "$BLOCKLIST_FILE"
        sed -i '/^$/d' "$BLOCKLIST_FILE"
        echo -e "${GREEN}[✔] Removed from persistent $BLOCKLIST_FILE${NC}"
    fi

    case "$FW_BACKEND" in
        nftables)
            nft delete element inet syswarden_table "$SET_NAME" "{ $target_ip }" 2>/dev/null || true
            ;;
        firewalld)
            firewall-cmd --permanent --ipset="$SET_NAME" --remove-entry="$target_ip" >/dev/null 2>&1 || true
            ipset del "$SET_NAME" "$target_ip" 2>/dev/null || true
            ;;
        ipset | ufw)
            ipset del "$SET_NAME" "$target_ip" 2>/dev/null || true
            ;;
    esac
    echo -e "${GREEN}[✔] Removed from Active Kernel Set ($FW_BACKEND)${NC}"

    if command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client ping >/dev/null 2>&1; then
        local active_jails
        active_jails=$(fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list:[ \t]*//' | tr -d ' ' | tr ',' '\n')
        local f2b_cleared=false

        for jail in $active_jails; do
            local result
            result=$(fail2ban-client set "$jail" unbanip "$target_ip" 2>/dev/null || echo "0")
            if [[ "$result" == "1" ]]; then
                echo -e "${GREEN}[✔] Amnesty granted on Fail2ban Jail: $jail${NC}"
                f2b_cleared=true
            fi
        done
        if [ "$f2b_cleared" = false ]; then
            echo -e "${GREEN}[✔] Checked Fail2ban (IP was not currently in behavioral timeout)${NC}"
        fi
    fi
    echo -e "${CYAN}>> IP $target_ip is now fully unblocked.${NC}\n"
}

# --- HOT WHITELIST (GLOBAL VIP ACCESS) ---
whitelist_ip() {
    local target_ip="$1"
    validate_ip "$target_ip"
    detect_backend

    echo -e "\n${BLUE}>> Whitelisting IP $target_ip globally...${NC}"

    unblock_ip "$target_ip" >/dev/null 2>&1 || true

    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    chmod 600 "$WHITELIST_FILE"

    if ! grep -q "^${target_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$target_ip" >>"$WHITELIST_FILE"
        echo -e "${GREEN}[✔] Saved to persistent $WHITELIST_FILE${NC}"
    else
        echo -e "${YELLOW}[i] IP is already in $WHITELIST_FILE${NC}"
    fi

    case "$FW_BACKEND" in
        nftables)
            get_nft_chain
            nft insert rule inet syswarden_table "$NFT_CHAIN" ip saddr "$target_ip" accept 2>/dev/null || true
            nft list table inet syswarden_table >/etc/syswarden/syswarden.nft 2>/dev/null || true
            ;;
        firewalld)
            local ACTIVE_ZONE
            ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
            firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-rich-rule="rule priority='-32000' family='ipv4' source address='$target_ip' accept" >/dev/null 2>&1 || true
            firewall-cmd --zone="$ACTIVE_ZONE" --add-rich-rule="rule priority='-32000' family='ipv4' source address='$target_ip' accept" >/dev/null 2>&1 || true
            ;;
        ufw)
            ufw insert 1 allow from "$target_ip" >/dev/null 2>&1 || true
            ;;
        ipset | unknown)
            iptables -I INPUT 1 -s "$target_ip" -j ACCEPT 2>/dev/null || true

            # HOTFIX: Persistence for Slackware vs Systemd environments
            if [[ "$OS_TYPE" == "Slackware" ]]; then
                iptables-save >/etc/syswarden/iptables.save 2>/dev/null || true
                ipset save >/etc/syswarden/ipsets.save 2>/dev/null || true
            elif command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v /etc/init.d/iptables >/dev/null; then
                /etc/init.d/iptables save 2>/dev/null || true
            fi
            ;;
    esac
    echo -e "${GREEN}[✔] Hot-injected VIP Accept Rule into Kernel ($FW_BACKEND)${NC}"

    # ==============================================================================
    # --- HOTFIX: DYNAMIC NGINX ACL INJECTION ---
    # ==============================================================================
    local nginx_conf="/etc/nginx/conf.d/syswarden-ui.conf"

    if [[ -f "/etc/nginx/sites-available/syswarden-ui.conf" ]]; then
        nginx_conf="/etc/nginx/sites-available/syswarden-ui.conf"
    elif [[ -f "/etc/nginx/http.d/syswarden-ui.conf" ]]; then
        nginx_conf="/etc/nginx/http.d/syswarden-ui.conf"
    fi

    if [[ -f "$nginx_conf" ]]; then
        echo -e "${BLUE}>> Injecting $target_ip into Nginx UI Access Control List (ACL)...${NC}"

        if ! grep -q "allow $target_ip;" "$nginx_conf"; then
            awk -v ip="$target_ip" '/^[[:space:]]*deny all;/ { print "    allow " ip ";" } { print }' "$nginx_conf" >"${nginx_conf}.tmp" && cat "${nginx_conf}.tmp" >"$nginx_conf" && rm -f "${nginx_conf}.tmp"

            if command -v nginx >/dev/null && nginx -t >/dev/null 2>&1; then
                # HOTFIX: Slackware Nginx Reload Support
                if [[ "$OS_TYPE" == "Slackware" ]] && [[ -x /etc/rc.d/rc.nginx ]]; then
                    /etc/rc.d/rc.nginx restart >/dev/null 2>&1 || true
                elif command -v systemctl >/dev/null; then
                    systemctl reload nginx >/dev/null 2>&1 || true
                elif command -v rc-service >/dev/null; then
                    rc-service nginx reload >/dev/null 2>&1 || true
                fi
                echo -e "${GREEN}[✔] Dashboard UI access instantly granted to $target_ip via Nginx.${NC}"
            else
                echo -e "${RED}[!] Nginx configuration test failed. Reverting ACL injection.${NC}"
                sed -i "/allow $target_ip;/d" "$nginx_conf"
            fi
        else
            echo -e "${YELLOW}[i] IP $target_ip is already authorized in Nginx ACL.${NC}"
        fi
    fi
    # ==============================================================================

    echo -e "${CYAN}>> IP $target_ip is now Whitelisted.${NC}\n"
}

# --- HOT SSH BYPASS: ALLOW SPECIFIC IP TO BYPASS WG GUILLOTINE ---
allow_ssh_ip() {
    local target_ip="$1"
    local custom_port="${2:-}"
    local silent_mode="${3:-no}"

    validate_ip "$target_ip"
    detect_backend

    if [[ -n "$custom_port" ]] && [[ "$custom_port" =~ ^[0-9]+$ ]]; then
        SSH_PORT="$custom_port"
    else
        get_ssh_port
    fi

    local entry="$target_ip:$SSH_PORT"

    if [[ "$silent_mode" == "no" ]]; then
        echo -e "\n${BLUE}>> Allowing direct SSH access (Port $SSH_PORT) for IP $target_ip...${NC}"
    fi

    # 1. Persistence
    mkdir -p "$SYSWARDEN_DIR"
    touch "$SSH_WHITELIST_FILE"
    chmod 600 "$SSH_WHITELIST_FILE"

    sed -i "\|^${target_ip}:|d" "$SSH_WHITELIST_FILE" 2>/dev/null || true
    sed -i "\|^${target_ip}$|d" "$SSH_WHITELIST_FILE" 2>/dev/null || true

    echo "$entry" >>"$SSH_WHITELIST_FILE"
    [[ "$silent_mode" == "no" ]] && echo -e "${GREEN}[✔] Saved to persistent $SSH_WHITELIST_FILE${NC}"

    # 2. Kernel Injection
    case "$FW_BACKEND" in
        nftables)
            get_nft_chain
            nft insert rule inet syswarden_table "$NFT_CHAIN" ip saddr "$target_ip" tcp dport "$SSH_PORT" accept 2>/dev/null || true
            nft list table inet syswarden_table >/etc/syswarden/syswarden.nft 2>/dev/null || true
            ;;
        firewalld)
            local ACTIVE_ZONE
            ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
            firewall-cmd --permanent --zone="$ACTIVE_ZONE" --add-rich-rule="rule priority='-1000' family='ipv4' source address='$target_ip' port port='$SSH_PORT' protocol='tcp' accept" >/dev/null 2>&1 || true
            firewall-cmd --zone="$ACTIVE_ZONE" --add-rich-rule="rule priority='-1000' family='ipv4' source address='$target_ip' port port='$SSH_PORT' protocol='tcp' accept" >/dev/null 2>&1 || true
            ;;
        ufw)
            ufw insert 1 allow from "$target_ip" to any port "$SSH_PORT" proto tcp >/dev/null 2>&1 || true
            ;;
        ipset | unknown)
            iptables -I INPUT 1 -p tcp -s "$target_ip" --dport "$SSH_PORT" -j ACCEPT 2>/dev/null || true

            if [[ "$OS_TYPE" == "Slackware" ]]; then
                iptables-save >/etc/syswarden/iptables.save 2>/dev/null || true
                ipset save >/etc/syswarden/ipsets.save 2>/dev/null || true
            elif command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v /etc/init.d/iptables >/dev/null; then
                /etc/init.d/iptables save 2>/dev/null || true
            fi
            ;;
    esac

    if [[ "$silent_mode" == "no" ]]; then
        echo -e "${GREEN}[✔] Hot-injected SSH Bypass Rule into Kernel ($FW_BACKEND)${NC}"
        echo -e "${CYAN}>> IP $target_ip can now access SSH directly.${NC}\n"
    fi
}

# --- REVOKE SSH BYPASS ---
revoke_ssh_ip() {
    local target_ip="$1"
    validate_ip "$target_ip"
    detect_backend

    echo -e "\n${BLUE}>> Revoking direct SSH access for IP $target_ip...${NC}"

    local saved_port=""
    if [[ -f "$SSH_WHITELIST_FILE" ]]; then
        saved_port=$(grep "^${target_ip}:" "$SSH_WHITELIST_FILE" | cut -d':' -f2 | head -n 1 || true)
    fi

    if [[ -n "$saved_port" ]]; then
        SSH_PORT="$saved_port"
    else
        get_ssh_port
    fi

    # 1. Remove Persistence
    if [[ -f "$SSH_WHITELIST_FILE" ]]; then
        sed -i "\|^${target_ip}:|d" "$SSH_WHITELIST_FILE"
        sed -i "\|^${target_ip}$|d" "$SSH_WHITELIST_FILE"
        sed -i '/^$/d' "$SSH_WHITELIST_FILE"
        echo -e "${GREEN}[✔] Removed from persistent $SSH_WHITELIST_FILE${NC}"
    fi

    # 2. Kernel Extraction
    case "$FW_BACKEND" in
        nftables)
            get_nft_chain
            local handle
            handle=$(nft -a list chain inet syswarden_table "$NFT_CHAIN" 2>/dev/null | grep -E "ip saddr $target_ip tcp dport $SSH_PORT accept" | grep -oP 'handle \K[0-9]+' | head -n 1 || true)
            if [[ -n "$handle" ]]; then
                nft delete rule inet syswarden_table "$NFT_CHAIN" handle "$handle" 2>/dev/null || true
            fi
            nft list table inet syswarden_table >/etc/syswarden/syswarden.nft 2>/dev/null || true
            ;;
        firewalld)
            local ACTIVE_ZONE
            ACTIVE_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "public")
            firewall-cmd --permanent --zone="$ACTIVE_ZONE" --remove-rich-rule="rule priority='-1000' family='ipv4' source address='$target_ip' port port='$SSH_PORT' protocol='tcp' accept" >/dev/null 2>&1 || true
            firewall-cmd --zone="$ACTIVE_ZONE" --remove-rich-rule="rule priority='-1000' family='ipv4' source address='$target_ip' port port='$SSH_PORT' protocol='tcp' accept" >/dev/null 2>&1 || true
            ;;
        ufw)
            ufw delete allow from "$target_ip" to any port "$SSH_PORT" proto tcp >/dev/null 2>&1 || true
            ;;
        ipset | unknown)
            while iptables -D INPUT -p tcp -s "$target_ip" --dport "$SSH_PORT" -j ACCEPT 2>/dev/null; do :; done

            if [[ "$OS_TYPE" == "Slackware" ]]; then
                iptables-save >/etc/syswarden/iptables.save 2>/dev/null || true
            elif command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v /etc/init.d/iptables >/dev/null; then
                /etc/init.d/iptables save 2>/dev/null || true
            fi
            ;;
    esac

    echo -e "${GREEN}[✔] Removed SSH Bypass Rule from Kernel ($FW_BACKEND)${NC}"
    echo -e "${CYAN}>> IP $target_ip is now subject to the standard WireGuard restrictions.${NC}\n"
}

# --- HOT BLOCK: IMMEDIATE KERNEL DROP ---
block_ip() {
    local target_ip="$1"
    validate_ip "$target_ip"
    detect_backend

    echo -e "\n${BLUE}>> Manually Blocking IP $target_ip...${NC}"

    if grep -q "^${target_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo -e "${RED}ERROR: IP is in the Whitelist. Unwhitelist it first!${NC}"
        exit 1
    fi

    mkdir -p "$SYSWARDEN_DIR"
    touch "$BLOCKLIST_FILE"
    chmod 600 "$BLOCKLIST_FILE"

    if ! grep -q "^${target_ip}$" "$BLOCKLIST_FILE" 2>/dev/null; then
        echo "$target_ip" >>"$BLOCKLIST_FILE"
        echo -e "${GREEN}[✔] Saved to persistent $BLOCKLIST_FILE${NC}"
    fi

    case "$FW_BACKEND" in
        nftables)
            nft add element inet syswarden_table "$SET_NAME" "{ $target_ip }" 2>/dev/null || true
            ;;
        firewalld)
            firewall-cmd --permanent --ipset="$SET_NAME" --add-entry="$target_ip" >/dev/null 2>&1 || true
            ipset add "$SET_NAME" "$target_ip" 2>/dev/null || true
            ;;
        ipset | ufw)
            ipset add "$SET_NAME" "$target_ip" 2>/dev/null || true
            ;;
    esac

    echo -e "${GREEN}[✔] Injected into Active Kernel Drop Set ($FW_BACKEND)${NC}"
    echo -e "${CYAN}>> IP $target_ip is now Blocked.${NC}\n"
}

# --- LIST ALL CUSTOM IPs ---
list_ips() {
    echo -e "\n${CYAN}=== SysWarden Custom IP Registry ===${NC}"

    echo -e "\n${GREEN}[ Global Whitelisted IPs (VIP) ]${NC}"
    if [[ -s "$WHITELIST_FILE" ]]; then
        cat "$WHITELIST_FILE" | while read -r line; do echo "  -> $line"; done
    else
        echo -e "${YELLOW}  No custom global whitelisted IPs.${NC}"
    fi

    echo -e "\n${CYAN}[ SSH-Only Whitelisted IPs (WireGuard Bypass) ]${NC}"
    if [[ -s "$SSH_WHITELIST_FILE" ]]; then
        cat "$SSH_WHITELIST_FILE" | while read -r line; do
            local lip lport
            lip=$(echo "$line" | cut -d':' -f1)
            lport=$(echo "$line" | cut -s -d':' -f2)
            if [[ -n "$lport" ]]; then
                echo "  -> $lip (Port: $lport)"
            else
                echo "  -> $lip (Default Port)"
            fi
        done
    else
        echo -e "${YELLOW}  No SSH-specific whitelisted IPs.${NC}"
    fi

    echo -e "\n${RED}[ Manually Blocked IPs ]${NC}"
    if [[ -s "$BLOCKLIST_FILE" ]]; then
        cat "$BLOCKLIST_FILE" | while read -r line; do echo "  -> $line"; done
    else
        echo -e "${YELLOW}  No custom manually blocked IPs.${NC}"
    fi
    echo ""
}

# --- CLI ROUTER & HELP MENU ---
show_help() {
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${YELLOW}  SysWarden Manager CLI ($VERSION) - Day 2 Operations ${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo -e "Usage: syswarden-manager.sh [COMMAND] [IP] [PORT]"
    echo -e ""
    echo -e "Commands:"
    echo -e "  ${CYAN}check${NC} <IP>             : Full XDR diagnostic of an IP (Files, F2B, Kernel)"
    echo -e "  ${CYAN}block${NC} <IP>             : Hot-adds IP to kernel drop set and blocklist file"
    echo -e "  ${CYAN}unblock${NC} <IP>           : Purges IP from blocklist, kernel, and Fail2ban"
    echo -e "  ${CYAN}whitelist${NC} <IP>         : Grants absolute VIP access & bypasses firewall"
    echo -e "  ${CYAN}allow-ssh${NC} <IP> [PORT]  : Allows direct SSH access for this IP"
    echo -e "  ${CYAN}revoke-ssh${NC} <IP>        : Revokes direct SSH access for this IP"
    echo -e "  ${CYAN}list${NC}                   : Displays all manually whitelisted and blocked IPs"
    echo -e "  ${CYAN}reload${NC}                 : Forces main scripts to safely re-sync entirely"
    echo -e ""
    echo -e "Examples:"
    echo -e "  syswarden-manager.sh allow-ssh 203.0.113.50 2222"
    echo -e "  syswarden-manager.sh block 8.8.8.8"
    echo -e "  syswarden-manager.sh list"
    echo -e "======================================================"
}

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

COMMAND=$(echo "$1" | tr '[:upper:]' '[:lower:]')

case "$COMMAND" in
    check)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        check_ip "$2"
        ;;
    block)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        block_ip "$2"
        ;;
    unblock)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        unblock_ip "$2"
        ;;
    whitelist)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        whitelist_ip "$2"
        ;;
    allow-ssh)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        allow_ssh_ip "$2" "${3:-}" "no"
        ;;
    revoke-ssh)
        if [[ -z "${2:-}" ]]; then
            echo "Missing IP address."
            exit 1
        fi
        revoke_ssh_ip "$2"
        ;;
    reload)
        echo -e "${YELLOW}Triggering full orchestrator synchronization...${NC}"

        if [[ -f "/usr/local/bin/install-syswarden.sh" ]]; then
            bash /usr/local/bin/install-syswarden.sh update
        elif [[ -f "/usr/local/bin/install-syswarden-alpine.sh" ]]; then
            bash /usr/local/bin/install-syswarden-alpine.sh update
        elif [[ -f "/usr/local/bin/install-syswarden-slackware.sh" ]]; then
            bash /usr/local/bin/install-syswarden-slackware.sh update
        elif [[ -f "/root/install-syswarden.sh" ]]; then
            bash /root/install-syswarden.sh update
        elif [[ -f "/root/install-syswarden-alpine.sh" ]]; then
            bash /root/install-syswarden-alpine.sh update
        elif [[ -f "/root/install-syswarden-slackware.sh" ]]; then
            bash /root/install-syswarden-slackware.sh update
        else
            echo -e "${RED}Main orchestrator script not found in /usr/local/bin/ or /root/. Please run it manually.${NC}"
        fi

        # --- HOTFIX: PERSISTENCE DURING RELOAD ---
        if [[ -s "$SSH_WHITELIST_FILE" ]]; then
            echo -e "\n${BLUE}>> Re-applying SSH Bypass rules from persistence...${NC}"
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                wl_ip=$(echo "$line" | cut -d':' -f1)
                wl_port=$(echo "$line" | cut -s -d':' -f2)
                allow_ssh_ip "$wl_ip" "$wl_port" "silent"
            done <"$SSH_WHITELIST_FILE"
        fi
        ;;
    list)
        list_ips
        ;;
    *)
        show_help
        exit 1
        ;;
esac
