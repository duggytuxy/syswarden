syswarden_jail_phpmyadmin() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    # Aborts instantly if phpMyAdmin was not found OR if no web logs exist
    if [[ "${SYSW_HAS_PHPMYADMIN:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "phpMyAdmin detected. Enabling specific protections."

    # Create Filter for POST requests to PMA
    if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
[Definition]
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"POST [^"]*?phpmyadmin[^"]*? HTTP[^"]*?" 200
ignoreregex = 
EOF
    fi

    # Write directly to jail.d using the dynamic centralized log path
    cat <<EOF >/etc/fail2ban/jail.d/phpmyadmin.conf
[phpmyadmin-custom]
enabled  = true
port     = http,https
filter   = phpmyadmin-custom
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
