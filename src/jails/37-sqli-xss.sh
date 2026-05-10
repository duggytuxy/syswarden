syswarden_jail_sqli_xss() {
    # Exclusive mutual exclusion: disabled if ModSecurity is active to prevent double-banning/conflicts
    if [[ -n "${SYSW_RCE_LOGS:-}" ]] && [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 0 ]]; then
        log "INFO" "Web access logs detected. Enabling SQLi & XSS Payload Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sqli-xss.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|PATCH|DELETE) [^"]*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F)[^"]*" \d{3}
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-sqli-xss.conf
[syswarden-sqli-xss]
enabled  = true
port     = http,https
filter   = syswarden-sqli-xss
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
