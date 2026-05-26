syswarden_jail_drupal() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    # Aborts instantly if Drupal was not found OR if no web logs exist
    if [[ "${SYSW_HAS_DRUPAL:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Drupal CMS detected. Enabling specific protections."

    # Create Filter for Drupal Authentication Failures
    if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "POST [^"]*?(?:/user/login|\?q=user/login)[^"]*?" 200
ignoreregex = 
EOF
    fi

    # Write directly to jail.d using the dynamic centralized log path
    cat <<EOF >/etc/fail2ban/jail.d/drupal.conf
[drupal-auth]
enabled  = true
port     = http,https
filter   = drupal-auth
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
