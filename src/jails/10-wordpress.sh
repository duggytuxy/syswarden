syswarden_jail_wordpress() {
    local WP_LOG=""

    # Reuses global variables from core configuration engine safely
    if [[ -n "${SYSW_APACHE_ACCESS:-}" ]]; then
        WP_LOG="$SYSW_APACHE_ACCESS"
    elif [[ -f "/var/log/nginx/access.log" ]]; then
        WP_LOG="/var/log/nginx/access.log"
    fi

    if [[ -n "$WP_LOG" ]]; then
        log "INFO" "Web logs available. Configuring WordPress Jail."

        # Create specific filter for WP Login & XMLRPC
        if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/wordpress-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:wp-login\.php|xmlrpc\.php)[^"]*?" 200
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/wordpress.conf
[wordpress-auth]
enabled = true
port = http,https
filter = wordpress-auth
logpath = $WP_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
