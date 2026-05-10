syswarden_jail_apache_tls() {
    local APACHE_ERR_LOG=""

    if [[ -f "/var/log/apache2/error.log" ]]; then
        APACHE_ERR_LOG="/var/log/apache2/error.log"
    elif [[ -f "/var/log/httpd/error_log" ]]; then
        APACHE_ERR_LOG="/var/log/httpd/error_log"
    fi

    if [[ -n "$APACHE_ERR_LOG" ]]; then
        log "INFO" "Apache error logs detected. Enabling mod_ssl Protocol Guard."

        # Create Filter for Apache mod_ssl TLS Handshake failures, SNI mismatch, and mTLS bypass attempts
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apache-tls.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apache-tls.conf
[Definition]
# [DEVSECOPS FIX] Targets mod_ssl specific error codes (AH02033 for SNI bypass, AH02261/AH02008 for handshake/cert failures)
failregex = ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH\d+: .*?(?:certificate verify failed|SSL Library Error|handshake failed|SSL_accept failed|peer closed connection).*$
            ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] SSL Library Error: .*$
            ^.*? \[core:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH02033: No hostname was provided via SNI.*$
            ^.*? \[ssl:(?:error|warn)\].*? \[client <HOST>(?::\d+)?\] AH02039: Certificate Verification: Error.*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-apache-tls.conf
[syswarden-apache-tls]
enabled  = true
port     = https,443,8443
filter   = syswarden-apache-tls
logpath  = $APACHE_ERR_LOG
backend  = auto
# Policy: 10 SSL errors in 1 minute indicates active TLS Fuzzing or massive direct IP scanning.
maxretry = 10
findtime = 60
bantime  = 24h
EOF
    fi
}
