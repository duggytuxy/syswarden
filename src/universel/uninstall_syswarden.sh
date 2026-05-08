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
        syswarden-modsec syswarden-tls-guard syswarden-apache-tls \
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
