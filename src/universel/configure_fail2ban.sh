configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS ---
        if [[ -d /etc/fail2ban/jail.d ]]; then
            rm -rf /etc/fail2ban/jail.d
        fi
        mkdir -p /etc/fail2ban/jail.d
        chmod 755 /etc/fail2ban/jail.d
        log "INFO" "Purged fail2ban/jail.d/ directory entirely to enforce absolute Zero Trust."

        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
dbpurgeage = 691200
EOF

        # 2. Firewall Backend & OS Optimization
        export SYSW_F2B_ACTION="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
            export SYSW_F2B_ACTION="firewallcmd-ipset"
        elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            export SYSW_F2B_ACTION="nftables-multiport"
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then export SYSW_F2B_ACTION="ufw"; fi

        export SYSW_OS_BACKEND="auto"
        if command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-journald 2>/dev/null; then
            export SYSW_OS_BACKEND="systemd"
        fi

        # 3. Dynamic Whitelist Array Construction
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"
        local public_ip=$(ip -4 addr show | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | grep -v '127.0.0.1' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi

        local local_subnets=$(ip -4 route | grep -v default | awk '{print $1}' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi

        if [[ -f /etc/resolv.conf ]]; then
            local dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi

        if [[ -s "$WHITELIST_FILE" ]]; then
            local wl_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            f2b_ignoreip="$f2b_ignoreip $wl_ips"
        fi

        # 4. Generate Core jail.local (Defaults & SSH)
        cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
banaction = $SYSW_F2B_ACTION

[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $SYSW_F2B_ACTION
maxretry = 3
findtime = 1w
bantime  = 4w

[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-22}
logpath = %(sshd_log)s
backend = $SYSW_OS_BACKEND
EOF

        # Recidive Filter
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
failregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Ban|Found)\s+<HOST>\s*$
ignoreregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Restore )?(?:Unban|unban)\s+<HOST>\s*$
EOF
        fi

        # 5. GLOBAL VARIABLES DETECTION (For Jail Modules)
        export SYSW_APACHE_ACCESS=""
        if [[ -f "/var/log/apache2/access.log" ]]; then
            SYSW_APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/access_log" ]]; then SYSW_APACHE_ACCESS="/var/log/httpd/access_log"; fi

        export SYSW_RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "$SYSW_APACHE_ACCESS"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_RCE_LOGS" ]]; then
                    SYSW_RCE_LOGS="$log_file"
                else SYSW_RCE_LOGS+=$'\n          '"$log_file"; fi
            fi
        done

        export SYSW_MODSEC_ACTIVE=0
        export SYSW_MODSEC_LOGS=""
        if [[ ! -f "/var/log/modsec_audit.log" ]]; then
            touch /var/log/modsec_audit.log
            chmod 640 /var/log/modsec_audit.log
            chown root:root /var/log/modsec_audit.log 2>/dev/null || true
        fi

        for log_file in "/var/log/nginx/error.log" "/var/log/apache2/error.log" "/var/log/httpd/error_log" "/var/log/modsec_audit.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_MODSEC_LOGS" ]]; then
                    SYSW_MODSEC_LOGS="$log_file"
                else SYSW_MODSEC_LOGS+=$'\n          '"$log_file"; fi
            fi
        done
        if [[ -n "$SYSW_MODSEC_LOGS" ]] && [[ -d "/etc/modsecurity" ]] && [[ -f "/etc/modsecurity/main.conf" ]]; then
            export SYSW_MODSEC_ACTIVE=1
        fi

        # 6. DYNAMIC MODULE INVOCATION
        log "INFO" "Executing modular jail definitions..."
        local jail_functions=$(compgen -A function | grep '^syswarden_jail_' || true)
        if [[ -n "$jail_functions" ]]; then
            for func in $jail_functions; do
                "$func"
            done
        else
            log "WARN" "No external jail modules loaded. Only SSH and Recidive are active."
        fi

        # 7. SERVICE RESTART & SOCKET WAIT
        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
            chown root:root /var/log/fail2ban.log 2>/dev/null || true
        fi

        log "INFO" "Starting Fail2ban service..."
        if command -v systemctl >/dev/null; then
            systemctl enable --now fail2ban >/dev/null 2>&1 || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
        else
            fail2ban-client reload >/dev/null 2>&1 || true
        fi

        for _ in {1..10}; do
            if fail2ban-client ping >/dev/null 2>&1; then break; fi
            sleep 1
        done
    fi
}
