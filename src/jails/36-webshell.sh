syswarden_jail_webshell() {
    # Exclusive mutual exclusion: disabled if ModSecurity is active to prevent double-banning/conflicts
    if [[ -n "${SYSW_RCE_LOGS:-}" ]] && [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 0 ]]; then
        log "INFO" "Web access logs detected. Enabling WebShell Upload Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads)[^"]*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?[^"]*)? HTTP/[^"]*" \d{3}
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-webshell.conf
[syswarden-webshell]
enabled  = true
port     = http,https
filter   = syswarden-webshell
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
