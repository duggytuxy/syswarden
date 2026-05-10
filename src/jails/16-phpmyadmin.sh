syswarden_jail_phpmyadmin() {
    local PMA_LOG=""

    # Reuses global web log variables detected by the core engine
    if [[ -n "${SYSW_APACHE_ACCESS:-}" ]]; then
        PMA_LOG="$SYSW_APACHE_ACCESS"
    elif [[ -f "/var/log/nginx/access.log" ]]; then
        PMA_LOG="/var/log/nginx/access.log"
    fi

    # Check if phpMyAdmin is installed (common paths)
    if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/etc/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
        if [[ -n "$PMA_LOG" ]]; then
            log "INFO" "phpMyAdmin detected. Enabling PMA Jail."

            # Create Filter for POST requests to PMA
            if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?phpmyadmin[^"]*? HTTP[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >/etc/fail2ban/jail.d/phpmyadmin.conf
[phpmyadmin-custom]
enabled = true
port    = http,https
filter  = phpmyadmin-custom
logpath = $PMA_LOG
maxretry = 3
bantime  = 24h
EOF
        fi
    fi
}
