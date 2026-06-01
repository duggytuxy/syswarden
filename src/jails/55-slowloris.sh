syswarden_jail_slowloris() {
    # 1. Dynamic log discovery for accurate bindings
    local SLOW_LOGS=""
    for log_file in /var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log; do
        if [[ -f "$log_file" ]]; then
            # Align padding for the Fail2ban configuration file
            if [[ -z "$SLOW_LOGS" ]]; then
                SLOW_LOGS="$log_file"
            else
                # [DEVSECOPS FIX] Use ANSI C quoting $'\n' to inject a real newline instead of a literal '\n' string
                SLOW_LOGS="$SLOW_LOGS"$'\n'"           $log_file"
            fi
        fi
    done

    # 2. Fail-Fast: Abort and cleanup if no error logs exist
    if [[ -z "$SLOW_LOGS" ]]; then
        # [DEVSECOPS FIX] Dynamic teardown to prevent Fail2ban status=255 crash on missing logs
        if [[ -f "/etc/fail2ban/jail.d/syswarden-slowloris.conf" ]]; then
            rm -f "/etc/fail2ban/jail.d/syswarden-slowloris.conf"
            log "WARN" "Web error logs not found. Auto-disabled Slowloris jail to prevent Fail2ban crash."
        fi
        return 0
    fi

    log "INFO" "Web error logs detected. Enabling Asynchronous Low & Slow Guard (Slowloris)."

    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-slowloris.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-slowloris.conf
[Definition]
# Detects asynchronous timeouts and slow read/post operations (Slowloris/Slow-Read)
# Nginx: client timed out (110: Connection timed out) while reading client request line/headers/body
# Apache: AH01382: Request header/body read timeout
failregex = ^.* \[(?:info|error)\] \d+#\d+: \*\d+ client timed out \(\d+: [^)]+\) while reading client request .*, client: <HOST>, .*
            ^.* \[reqtimeout:(?:info|error)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH\d+: Request .* read timeout
ignoreregex = 
EOF
    fi

    cat <<EOF >/etc/fail2ban/jail.d/syswarden-slowloris.conf
[syswarden-slowloris]
enabled  = true
port     = http,https
filter   = syswarden-slowloris
logpath  = $SLOW_LOGS
backend  = auto
maxretry = 4
findtime = 60
bantime  = 24h
EOF
}
