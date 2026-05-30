syswarden_jail_proxy_abuse() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Open Proxy & Exotic Method Guard."

    # Create Filter for Open Proxy Probing and Tunneling attempts
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
# [DEVSECOPS FIX] Detects exotic methods (SSTP, WebDAV), proxy probes, and buffer overflow fuzzing in URIs
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SSTP_DUPLEX_POST) [^"]*?" \d{3}
            ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//[^"]*?" \d{3}
            ^.* \[error\] \d+#\d+: \*\d+ .* client: <HOST>, .* request: "(?:SSTP_DUPLEX_POST|[^"]*\\x[0-9a-fA-F]{2})
ignoreregex = 
EOF
    fi

    local ERR_LOGS="/var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log"

    # Write directly to jail.d
    # maxretry = 1: Zero tolerance for proxy probes and exotic tunneling methods
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-proxy-abuse.conf
[syswarden-proxy-abuse]
enabled  = true
port     = http,https
filter   = syswarden-proxy-abuse
logpath  = $SYSW_RCE_LOGS
           $ERR_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
