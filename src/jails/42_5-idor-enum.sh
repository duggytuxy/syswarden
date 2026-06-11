syswarden_jail_idor_enum() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Behavioral IDOR Guard."

    # Create Filter for IDOR Enumeration and Object Brute-Force
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-idor-enum.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-idor-enum.conf
[Definition]
# Detects rapid sequential or random access to sensitive endpoints resulting in 401/403/404
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT|DELETE|PATCH) [^"]*(?:/api/v[0-9]+/|/users?/|/profile/|/invoices?/|/downloads?/|/docs?/|/id/|/view\?id=)[a-zA-Z0-9_-]+/?(?:[^"]*)? HTTP/[^"]*" (401|403|404)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # High maxretry (15) paired with very short findtime (10s) to catch aggressive enumeration only
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-idor-enum.conf
[syswarden-idor-enum]
enabled  = true
port     = http,https
filter   = syswarden-idor-enum
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 15
findtime = 10
bantime  = 24h
EOF
}
