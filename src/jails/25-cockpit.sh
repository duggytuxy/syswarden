syswarden_jail_cockpit() {
    if systemctl is-active --quiet cockpit.socket 2>/dev/null || [[ -d "/etc/cockpit" ]]; then
        log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."

        if [[ ! -f "/etc/fail2ban/filter.d/cockpit-custom.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
failregex = ^.*?cockpit-ws.*?(?:authentication failed|invalid user).*?from <HOST>.*$
ignoreregex = 
EOF
        fi

        # Utilise la variable globale SYSW_OS_BACKEND propagée par le moteur principal
        cat <<EOF >/etc/fail2ban/jail.d/cockpit.conf
[cockpit-custom]
enabled = true
port    = 9090
filter  = cockpit-custom
logpath = /var/log/secure
backend = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
bantime  = 24h
EOF
    fi
}
