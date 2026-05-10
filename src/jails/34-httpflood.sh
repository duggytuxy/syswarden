syswarden_jail_httpflood() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Layer 7 Anti-DDoS Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-httpflood.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-httpflood.conf
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 300
findtime = 5
bantime  = 24h
EOF
    fi
}
