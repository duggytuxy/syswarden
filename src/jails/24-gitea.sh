syswarden_jail_gitea() {
    local GITEA_LOG=""

    if [[ -f "/var/log/gitea/gitea.log" ]]; then
        GITEA_LOG="/var/log/gitea/gitea.log"
    elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then
        GITEA_LOG="/var/log/forgejo/forgejo.log"
    fi

    if [[ -n "$GITEA_LOG" ]]; then
        log "INFO" "Gitea/Forgejo detected. Enabling Git Server Jail."

        # Filter for Git Web UI Auth Failures
        if [[ ! -f "/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/gitea-custom.conf
[Definition]
failregex = ^.*?Failed authentication attempt for .*? from <HOST>:.*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/gitea.conf
[gitea-custom]
enabled = true
port    = http,https,3000
filter  = gitea-custom
logpath = $GITEA_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
