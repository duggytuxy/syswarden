syswarden_jail_nginx() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! systemctl is-active --quiet nginx 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/nginx/access.log" ]] && [[ ! -f "/var/log/nginx/error.log" ]]; then
        return 0
    fi

    log "INFO" "Nginx daemon and logs detected. Enabling Nginx Jails."

    if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/nginx-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405|444)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/nginx.conf
[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log
backend  = auto

[nginx-scanner]
enabled  = true
port     = http,https
filter   = nginx-scanner
logpath  = /var/log/nginx/access.log
backend  = auto
maxretry = 15
bantime  = 24h
EOF
}
