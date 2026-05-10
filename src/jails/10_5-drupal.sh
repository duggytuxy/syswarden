syswarden_jail_drupal() {
    local DRUPAL_LOG=""
    if [[ -n "${SYSW_APACHE_ACCESS:-}" ]]; then
        DRUPAL_LOG="$SYSW_APACHE_ACCESS"
    elif [[ -f "/var/log/nginx/access.log" ]]; then
        DRUPAL_LOG="/var/log/nginx/access.log"
    fi

    if [[ -n "$DRUPAL_LOG" ]]; then
        log "INFO" "Web logs detected. Enabling Drupal Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/user/login|\?q=user/login)[^"]*?" 200
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/drupal.conf
[drupal-auth]
enabled  = true
port     = http,https
filter   = drupal-auth
logpath  = $DRUPAL_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
