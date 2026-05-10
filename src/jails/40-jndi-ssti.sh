syswarden_jail_jndi_ssti() {
    # Exclusive mutual exclusion: disabled if ModSecurity is active to prevent double-banning
    if [[ -n "${SYSW_RCE_LOGS:-}" ]] && [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 0 ]]; then
        log "INFO" "Web access logs detected. Enabling JNDI & SSTI Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*?(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] ".*?" \d{3} .*? "(?:\$\{jndi:|\x2524\x257Bjndi:).*?"$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-jndi-ssti.conf
[syswarden-jndi-ssti]
enabled  = true
port     = http,https
filter   = syswarden-jndi-ssti
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
