syswarden_jail_silent_scanner() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Behavioral Scanner Guard."

    # Create Filter for high-frequency 400/401/403/404/405/444 errors
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-silent-scanner.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-silent-scanner.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
# [DEVSECOPS FIX] Added HTTP 30x redirects to capture topology discovery probes
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PROPFIND) [^"]*" (?:30[1278]|400|401|403|404|405|444)
ignoreregex =
EOF
    fi

    # Write directly to jail.d
    # High maxretry (20) in a very short findtime (10s) to catch automated directory/vulnerability brute-forcing
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-silent-scanner.conf
[syswarden-silent-scanner]
enabled  = true
port     = http,https
filter   = syswarden-silent-scanner
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 20
findtime = 10
bantime  = 48h
EOF
}
