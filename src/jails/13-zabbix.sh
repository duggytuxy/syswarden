syswarden_jail_zabbix() {
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

        cat <<EOF >/etc/fail2ban/jail.d/zabbix.conf
[zabbix-auth]
enabled = true
port    = http,https,10050,10051
filter  = zabbix-auth
logpath = /var/log/zabbix/zabbix_server.log
maxretry = 3
bantime  = 24h
EOF
    fi
}
