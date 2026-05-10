syswarden_jail_modsec() {
    if [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 1 ]] && [[ -n "${SYSW_MODSEC_LOGS:-}" ]]; then
        log "INFO" "ModSecurity WAF detected. Enabling Purple Team integration."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-modsec.conf
[Definition]
failregex = ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Access denied with code [45]\d\d.*$
            ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Warning\. Pattern match.*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-modsec.conf
[syswarden-modsec]
enabled  = true
port     = http,https
filter   = syswarden-modsec
logpath  = $SYSW_MODSEC_LOGS
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
    fi
}
