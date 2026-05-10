syswarden_jail_dolibarr() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Dolibarr ERP Guard."

        # Create Filter for Dolibarr Authentication Failures
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-dolibarr.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-dolibarr.conf
[Definition]
# [DEVSECOPS FIX] Bounded the URI parsing to strictly prevent query string ReDoS.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/htdocs/index\.php|/index\.php|/api/index\.php/login)[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-dolibarr.conf
[syswarden-dolibarr]
enabled  = true
port     = http,https
filter   = syswarden-dolibarr
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
