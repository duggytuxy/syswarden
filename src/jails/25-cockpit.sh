syswarden_jail_cockpit() {
    # 1. Fail-Fast: Verify native socket execution or config presence at the absolute top
    if ! systemctl is-active --quiet cockpit.socket 2>/dev/null && [[ ! -d "/etc/cockpit" ]]; then
        return 0
    fi

    local COCKPIT_LOG=""
    local JAIL_BACKEND="${SYSW_OS_BACKEND:-auto}"

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/secure" ]]; then
        COCKPIT_LOG="/var/log/secure" # RHEL/Alma/Rocky/CentOS with rsyslog active
    elif [[ -f "/var/log/auth.log" ]]; then
        COCKPIT_LOG="/var/log/auth.log" # Debian/Ubuntu
    fi

    # 3. Hybrid Fallback: Handle modern systemd journal-only environments (e.g., default CentOS Stream 10)
    if [[ -z "$COCKPIT_LOG" ]]; then
        if systemctl is-active --quiet systemd-journald 2>/dev/null; then
            log "INFO" "No traditional log file found. Switching Cockpit Jail to systemd journal backend."
            JAIL_BACKEND="systemd"
        else
            log "WARN" "Neither traditional log files nor systemd-journald found for Cockpit. Skipping jail."
            return 0
        fi
    fi

    log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."

    # Force overwrite on deployment to ensure filter updates are applied during upgrades
    cat <<'EOF' >/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
# Purified ultra-compatible patterns matching both syslog files and systemd journal streams
failregex = pam_unix\(cockpit:auth\): authentication failure;.* rhost=(?:::ffff:)?<HOST>
            (?:authentication failed|invalid user).*?from (?:::ffff:)?<HOST>
ignoreregex = 
EOF

    # 4. Generate jail configuration depending on the selected backend engine
    if [[ "$JAIL_BACKEND" == "systemd" ]]; then
        cat <<EOF >/etc/fail2ban/jail.d/cockpit.conf
[cockpit-custom]
enabled  = true
port     = 9090
filter   = cockpit-custom
backend  = systemd
maxretry = 3
bantime  = 24h
EOF
    else
        cat <<EOF >/etc/fail2ban/jail.d/cockpit.conf
[cockpit-custom]
enabled  = true
port     = 9090
filter   = cockpit-custom
logpath  = $COCKPIT_LOG
backend  = $JAIL_BACKEND
maxretry = 3
bantime  = 24h
EOF
    fi
}
