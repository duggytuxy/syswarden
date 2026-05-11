syswarden_jail_prestashop() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    if [[ "${SYSW_HAS_PRESTASHOP:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling PrestaShop Guard."

    # Create Filter for PrestaShop Backoffice Brute-Force
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-prestashop.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-prestashop.conf
[Definition]
# RED TEAM FIX: Bounded the URI parsing to strictly prevent query string ReDoS.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?index\.php\?[^"]*?controller=AdminLogin[^"]*?" 200
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-prestashop.conf
[syswarden-prestashop]
enabled  = true
port     = http,https
filter   = syswarden-prestashop
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
