syswarden_jail_ssrf() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling SSRF & Cloud Metadata Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:169\.254\.169\.254|latest/meta-data|metadata\.google\.internal|/v1/user-data|/metadata/v1).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-ssrf.conf
[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
