syswarden_jail_jndi_ssti() {
    # 1. Fail-Fast: Exclusive mutual exclusion and detection check
    # Aborts if no web logs exist OR if ModSecurity is already handling WAF duties
    if [[ -z "${SYSW_RCE_LOGS:-}" ]] || [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 1 ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling JNDI & SSTI Guard."

    # Create Filter for JNDI (Log4Shell) and SSTI (Spring/Java) patterns
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf
[Definition]
# Detects JNDI lookups (raw and encoded) and common SSTI/Spring boot exploits in URI and User-Agent
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT) .*?(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?".*?" \d{3} .*? "(?:\$\{jndi:|\x2524\x257Bjndi:).*?"$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Critical RCE detection, instant 48h ban
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-jndi-ssti.conf
[syswarden-jndi-ssti]
enabled  = true
port     = http,https
filter   = syswarden-jndi-ssti
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
