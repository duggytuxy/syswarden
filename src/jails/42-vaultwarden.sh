syswarden_jail_vaultwarden() {
    local VW_LOG=""
    for path in "/var/log/vaultwarden/vaultwarden.log" "/vw-data/vaultwarden.log" "/opt/vaultwarden/vaultwarden.log"; do
        if [[ -f "$path" ]]; then
            VW_LOG="$path"
            break
        fi
    done

    if [[ -n "$VW_LOG" ]]; then
        log "INFO" "Vaultwarden logs detected. Enabling Vaultwarden Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-vaultwarden.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-vaultwarden.conf
[Definition]
failregex = ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Invalid password.*from <HOST>.*\s*$
            ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Client IP: <HOST>.*\s*$
            ^.*\[(?:ERROR|WARN)\].*Failed login attempt.*from <HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-vaultwarden.conf
[syswarden-vaultwarden]
enabled  = true
port     = http,https,80,443,8080
filter   = syswarden-vaultwarden
logpath  = $VW_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
