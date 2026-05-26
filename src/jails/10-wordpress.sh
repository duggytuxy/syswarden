syswarden_jail_wordpress() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    # Aborts instantly if WordPress was not found OR if no web logs exist
    if [[ "${SYSW_HAS_WORDPRESS:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "WordPress CMS detected. Enabling specific protections."

    # Create specific filter for WP Login & XMLRPC
    if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/wordpress-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "POST [^"]*?(?:wp-login\.php|xmlrpc\.php)[^"]*?" 200
ignoreregex = 
EOF
    fi

    # Write directly to jail.d using the dynamic centralized log path
    cat <<EOF >/etc/fail2ban/jail.d/wordpress.conf
[wordpress-auth]
enabled  = true
port     = http,https
filter   = wordpress-auth
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
