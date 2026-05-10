syswarden_jail_sso() {
    local SSO_LOG=""

    # Check standard output logs for major open-source SSO providers
    for path in "/var/log/authelia/authelia.log" "/var/log/authentik/authentik.log" "/opt/authelia/authelia.log" "/opt/authentik/authentik.log"; do
        if [[ -f "$path" ]]; then
            SSO_LOG="$path"
            break
        fi
    done

    if [[ -n "$SSO_LOG" ]]; then
        log "INFO" "SSO (Authelia/Authentik) logs detected. Enabling IAM Guard."

        # Create Filter for Identity and Access Management credential stuffing
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sso.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sso.conf
[Definition]
failregex = ^.*(?:level=error|level=\"error\").*msg=\"Authentication failed\".*remote_ip=\"<HOST>\".*$
            ^.*(?:\"event\":\"Failed login\"|event=\'Failed login\').*(?:\"client_ip\":\"<HOST>\"|\"remote_ip\":\"<HOST>\").*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-sso.conf
[syswarden-sso]
enabled  = true
port     = http,https
filter   = syswarden-sso
logpath  = $SSO_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
