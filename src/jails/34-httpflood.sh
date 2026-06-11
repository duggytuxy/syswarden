syswarden_jail_httpflood() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Layer 7 Anti-DDoS Guard."

    # --- DEVSECOPS FIX: DYNAMIC WHITELIST INJECTION FOR L7 FLOOD ---
    # Convert whitelist file to a regex pattern to prevent Fail2ban from evaluating
    # whitelisted IPs. This eliminates "Found" log spam and UI 'DETECTED' false positives.
    local WL_REGEX=""
    if [[ -f "/etc/syswarden/whitelist.txt" ]]; then
        WL_REGEX=$(grep -vE '^\s*#|^\s*$' /etc/syswarden/whitelist.txt | awk '{print $1}' | sed 's/\./\\./g' | tr '\n' '|' | sed 's/|$//')
    fi

    local IGNORE_LINE="ignoreregex ="
    if [[ -n "$WL_REGEX" ]]; then
        IGNORE_LINE="ignoreregex = ^($WL_REGEX) "
    fi

    # Always overwrite to ensure filter stays in sync with whitelist updates
    cat <<EOF >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
# Generic request match for high-frequency counting
# [DEVSECOPS FIX: F-004] Optional date brackets for universal log compatibility.
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?
$IGNORE_LINE
EOF

    # Write directly to jail.d
    # High maxretry paired with very short findtime to catch flooding bursts
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-httpflood.conf
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 300
findtime = 5
bantime  = 24h
EOF
}
