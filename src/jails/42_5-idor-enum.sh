syswarden_jail_idor_enum() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Behavioral IDOR Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-idor-enum.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-idor-enum.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH) [^"]*(?:/api/v[0-9]+/|/users?/|/profile/|/invoices?/|/downloads?/|/docs?/|/id/|/view\?id=)[a-zA-Z0-9_-]+/?(?:[^"]*)? HTTP/[^"]*" (401|403|404)
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-idor-enum.conf
[syswarden-idor-enum]
enabled  = true
port     = http,https
filter   = syswarden-idor-enum
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 15
findtime = 10
bantime  = 24h
EOF
    fi
}
