syswarden_jail_lfi_advanced() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]] && [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 0 ]]; then
        log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT) [^"]*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb))[^"]*" \d{3}
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-lfi-advanced.conf
[syswarden-lfi-advanced]
enabled  = true
port     = http,https
filter   = syswarden-lfi-advanced
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
