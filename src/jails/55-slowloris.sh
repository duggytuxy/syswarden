syswarden_jail_slowloris() {
    # 1. Dynamic log discovery for accurate bindings
    local SLOW_LOGS=""
    for log_file in /var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log; do
        if [[ -f "$log_file" ]]; then
            # Align padding for the Fail2ban configuration file
            if [[ -z "$SLOW_LOGS" ]]; then
                SLOW_LOGS="$log_file"
            else
                SLOW_LOGS="${SLOW_LOGS}
           ${log_file}"
            fi
        fi
    done

    # 2. Fail-Fast: Abort and cleanup if no error logs exist
    if [[ -z "$SLOW_LOGS" ]]; then
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
# Detects asynchronous timeouts, slow read/post operations, and HTTP/2 Multiplexing Attacks (HTTP/2 Bomb / HPACK Stall)
# Nginx: client timed out, HTTP/2 frame violations, stream processing limits
# Apache: AH01382 (reqtimeout), AH03198 (HTTP/2 stream timeout), AH10400 (excessive WINDOW_UPDATE frames)
failregex = ^.* \[(?:info|error)\] \d+#\d+: \*\d+ client timed out \(\d+: [^)]+\) while reading client request .*, client: <HOST>, .*
            ^.* \[(?:info|error)\] \d+#\d+: \*\d+ client timed out \(\d+: [^)]+\) while processing HTTP/2 connection.*, client: <HOST>, .*
            ^.* \[(?:info|error|warn)\] \d+#\d+: \*\d+ client sent invalid HTTP/2 frame.*, client: <HOST>, .*
            ^.* \[(?:info|error|warn)\] \d+#\d+: \*\d+ client sent excessive HTTP/2 frames.*, client: <HOST>, .*
            ^.* \[reqtimeout:(?:info|error)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH01382: Request header read timeout
            ^.* \[reqtimeout:(?:info|error)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH01382: Request body read timeout
            ^.* \[http2:(?:info|error|warn)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH03198: .* timeout on stream
            ^.* \[http2:(?:info|error|warn)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH10400: .* excessive WINDOW_UPDATE frames
            ^.* \[core:(?:info|error)\] \[pid \d+(?::tid \d+)?\] \[client <HOST>:\d+\] AH00524: Handler for .* returned invalid result code 70007
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
