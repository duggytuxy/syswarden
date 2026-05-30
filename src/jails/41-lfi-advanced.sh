syswarden_jail_lfi_advanced() {
    # 1. Fail-Fast: Exclusive mutual exclusion and detection check
    # Aborts if no web logs exist OR if ModSecurity is already handling WAF duties
    if [[ -z "${SYSW_RCE_LOGS:-}" ]] || [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 1 ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

    # Create Filter for Advanced LFI, PHP Wrappers and Null Byte injections
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
# [DEVSECOPS FIX] Included Nginx/Apache error log monitoring and advanced obfuscation support
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT) [^"]*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb))[^"]*" \d{3}
            ^.* \[error\] \d+#\d+: \*\d+ .* client: <HOST>, .* request: "(?:GET|POST|HEAD|PUT) [^"]*(?:php://|file://|zip://|phar://|/etc/(?:passwd|shadow|hosts)|/windows/(?:win\.ini|system32))
ignoreregex = 
EOF
    fi

    # Include daemon error logs for payloads rejected natively by the web server
    local ERR_LOGS="/var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log"

    # Write directly to jail.d
    # maxretry = 1: Critical LFI detection, instant 48h ban
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-lfi-advanced.conf
[syswarden-lfi-advanced]
enabled  = true
port     = http,https
filter   = syswarden-lfi-advanced
logpath  = $SYSW_RCE_LOGS
           $ERR_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
