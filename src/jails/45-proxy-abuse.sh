syswarden_jail_proxy_abuse() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Open Proxy & Exotic Method Guard."

        # Create Filter for Open Proxy Probing and Tunneling attempts
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) [^"]*?" \d{3}
            ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//[^"]*?" \d{3}
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-proxy-abuse.conf
[syswarden-proxy-abuse]
enabled  = true
port     = http,https
filter   = syswarden-proxy-abuse
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
