syswarden_jail_nextcloud() {
    local NC_LOG=""

    # Check common paths for Nextcloud log file
    for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
        if [[ -f "$path" ]]; then
            NC_LOG="$path"
            break
        fi
    done

    if [[ -n "$NC_LOG" ]]; then
        log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."

        # Create Filter (Supports both JSON and Legacy text logs)
        if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
failregex = ^.*?Login failed: .*? \(Remote IP: '<HOST>'\).*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/nextcloud.conf
[nextcloud]
enabled = true
port    = http,https
filter  = nextcloud
logpath = $NC_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
