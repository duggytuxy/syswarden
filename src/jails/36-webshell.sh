syswarden_jail_webshell() {
    # 1. Fail-Fast: Exclusive mutual exclusion and detection check
    # Aborts if no web logs exist OR if ModSecurity is already handling WAF duties
    if [[ -z "${SYSW_RCE_LOGS:-}" ]] || [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 1 ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling WebShell Upload Guard."

    # Create Filter for suspicious script uploads/executions in sensitive paths
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
# Detects POST requests to upload/asset directories involving executable extensions
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"POST [^"]*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads)[^"]*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?[^"]*)? HTTP/[^"]*" \d{3}
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Critical alert, instant ban for 48h
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
}
