syswarden_jail_generic_auth() {
    # Relies on SYSW_RCE_LOGS aggregated earlier in the core engine
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Generic Brute-Force & Password Spraying Guard."

        # Create Filter for generic login endpoints
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-generic-auth.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-generic-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login|/sign-in|/signin|/log-in|/auth|/authenticate|/admin/login|/user/login|/member/login)[^"]*?(?:\.php|\.html|\.htm|\.jsp|\.aspx)?[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
        fi

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
    fi
}
