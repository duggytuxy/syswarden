syswarden_jail_telnet() {
    local TELNET_LOG=""

    # Dynamically aggregate auth and system logs securely
    for log_file in "/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/auth-syswarden.log"; do
        if [[ -f "$log_file" ]]; then
            if [[ -z "$TELNET_LOG" ]]; then
                TELNET_LOG="$log_file"
            else
                # HOTFIX: Strict ConfigParser multiline format (newline + 10 spaces)
                TELNET_LOG+=$'\n          '"$log_file"
            fi
        fi
    done

    # Check if Port 23 is actively listening or if telnetd is installed
    if [[ -n "$TELNET_LOG" ]] && { command -v telnetd >/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -qE ':(23)\b'; }; then
        log "INFO" "Telnet service detected on Port 23. Enabling IoT Botnet Guard."

        # Create Filter for Telnet Brute-force and IoT Botnet probing
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-telnet.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-telnet.conf
[Definition]
failregex = ^.*(?:in\.telnetd|telnetd)(?:\[\d+\])?: connect from (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+FAILED LOGIN.*(?:FROM|from) (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+.*(?:authentication failure|invalid password).*rhost=(?:::f{4}:)?<HOST>.*\s*$
            ^.*pam_unix\(login:auth\): authentication failure;.*rhost=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-telnet.conf
[syswarden-telnet]
enabled  = true
port     = 23,telnet
filter   = syswarden-telnet
logpath  = $TELNET_LOG
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 48h
EOF
    fi
}
