syswarden_jail_haproxy() {
    if [[ -f "/var/log/haproxy.log" ]]; then
        log "INFO" "HAProxy logs detected. Enabling HAProxy Jail."

        # Create Filter for HTTP Errors (403 Forbidden, 404 Scan, 429 RateLimit)
        if [[ ! -f "/etc/fail2ban/filter.d/haproxy-guard.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/haproxy-guard.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? (?:400|403|404|429) .*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/haproxy.conf
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
}
