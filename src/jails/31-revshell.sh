syswarden_jail_revshell() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."

    # Create Filter for RCE & Reverse Shell patterns
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
# Detects common RCE patterns, shell invocations, and encoded payloads in URI/Requests
# [DEVSECOPS FIX: F-010 & F-004] Unified regex normalization: Optional dates, Case-insensitivity (?i), Double-URL encoding interception (\x25252f), and expanded LOLBins.
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?i)(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:(?:/|\x252f|\x25252f)(?:bin|usr(?:/|\x252f|\x25252f)bin)(?:/|\x252f|\x25252f)(?:bash|sh|dash|zsh|ash)|(?:nc|ncat|socat)(?:\s+|\x2520|\x252520|\x2509|\+)+(?:-e|-c)|(?:curl|wget|fetch|tftp)(?:\s+|\x2520|\x252520|\x2509|\+)+(?:-q|-s|-O|http)|(?:python|perl|ruby|php|node|lua|awk)(?:\s+|\x2520|\x252520|\x2509|\+)+-(?:c|e|r)|(?:;|\x253b|\x25253b|\||\x257c|\x25257c|`|\x2560|\x252560|\$|\x2524|\x252524)(?:\s+|\x2520|\x252520|\x2509|\+)*(?:bash|sh|nc|ncat|socat|curl|wget|chmod|openssl)).*?" .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1 for immediate banning on RCE detection
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-revshell.conf
[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
findtime = 3600
bantime  = 24h
EOF
}
