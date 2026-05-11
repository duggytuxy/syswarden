syswarden_jail_atlassian() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    if [[ "${SYSW_HAS_ATLASSIAN:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Atlassian Guard."

    # Create Filter for Jira and Confluence Auth Failures
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-atlassian.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-atlassian.conf
[Definition]
# RED TEAM FIX: Strict non-greedy bounds inside the HTTP method quotes to prevent ReDoS.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login\.jsp|/dologin\.action|/rest/auth/\d+/session)[^"]*?" (?:401|403|200)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-atlassian.conf
[syswarden-atlassian]
enabled  = true
port     = http,https,8080,8090
filter   = syswarden-atlassian
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
