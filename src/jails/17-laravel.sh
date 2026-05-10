syswarden_jail_laravel() {
    local LARAVEL_LOG=""

    # Check standard Laravel log paths
    for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
        if [[ -f "$path" ]]; then
            LARAVEL_LOG="$path"
            break
        fi
    done

    # Fallback: search in /var/www (max depth 4)
    if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
        LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1 || true)
    fi

    if [[ -n "$LARAVEL_LOG" ]]; then
        log "INFO" "Laravel log detected. Enabling Laravel Jail."

        # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
        if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/laravel-auth.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/laravel.conf
[laravel-auth]
enabled = true
port    = http,https
filter  = laravel-auth
logpath = $LARAVEL_LOG
maxretry = 5
bantime  = 24h
EOF
    fi
}
