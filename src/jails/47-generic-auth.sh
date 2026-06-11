syswarden_jail_generic_auth() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Generic Brute-Force & Password Spraying Guard."

    # Create Filter for generic login endpoints
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-generic-auth.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-generic-auth.conf
[Definition]
# Detects excessive POST requests to common authentication paths to prevent credential stuffing
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"POST [^"]*?(?:/login|/sign-in|/signin|/log-in|/auth|/authenticate|/admin/login|/user/login|/member/login)[^"]*?(?:\.php|\.html|\.htm|\.jsp|\.aspx)?[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-generic-auth.conf
[syswarden-generic-auth]
enabled  = true
port     = http,https
filter   = syswarden-generic-auth
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 5
findtime = 10m
bantime  = 24h
EOF
}
