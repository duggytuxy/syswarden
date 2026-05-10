syswarden_jail_secretshunter() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Stealth Secrets Hunter Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-secretshunter.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-secretshunter.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/\.env[^ ]*|/\.git/?.*|/\.aws/?.*|/\.ssh/?.*|/id_rsa[^ ]*|/id_ed25519[^ ]*|/[^ ]*\.(?:sql|bak|swp|db|sqlite3?)(?:\.gz|\.zip)?|/docker-compose\.ya?ml|/wp-config\.php\.(?:bak|save|old|txt|zip)) HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-secretshunter.conf
[syswarden-secretshunter]
enabled  = true
port     = http,https
filter   = syswarden-secretshunter
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
