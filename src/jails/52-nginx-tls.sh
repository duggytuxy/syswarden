syswarden_jail_nginx_tls() {
    if [[ -d "/etc/nginx" ]] && command -v nginx >/dev/null 2>&1; then
        log "INFO" "Nginx detected. Preparing TLS error logging for Syswarden."

        local NGINX_CONF="/etc/nginx/nginx.conf"
        local NGINX_LOG="/var/log/nginx/error.log"

        # --- HOTFIX: AUTOMATED NGINX LOG LEVEL HARDENING ---
        if grep -qE "^\s*error_log\s+.*info;" "$NGINX_CONF" 2>/dev/null; then
            log "INFO" "Nginx error_log is already set to 'info'. No changes needed."
        elif [[ -f "$NGINX_CONF" ]]; then
            log "INFO" "Modifying Nginx error_log to 'info' level to expose TLS attacks..."
            cp "$NGINX_CONF" "${NGINX_CONF}.syswarden.bak"

            # Safely replace existing error_log directive or inject it
            if grep -q "error_log" "$NGINX_CONF"; then
                sed -i -E 's|^\s*#?\s*error_log\s+.*|error_log /var/log/nginx/error.log info;|' "$NGINX_CONF"
            else
                sed -i '1i error_log /var/log/nginx/error.log info;' "$NGINX_CONF"
            fi

            # Verify Nginx syntax before applying to prevent web server crash
            if nginx -t >/dev/null 2>&1; then
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl reload nginx >/dev/null 2>&1 || true
                fi
                log "INFO" "Nginx TLS logging enabled and reloaded successfully."
            else
                log "ERROR" "Nginx syntax check failed. Reverting changes to prevent crash."
                mv "${NGINX_CONF}.syswarden.bak" "$NGINX_CONF"
            fi
        fi
        # ----------------------------------------------------

        # Ensure the log file exists so Fail2ban doesn't crash on startup
        if [[ ! -f "$NGINX_LOG" ]]; then
            touch "$NGINX_LOG"
            chown nginx:nginx "$NGINX_LOG" 2>/dev/null || chown www-data:adm "$NGINX_LOG" 2>/dev/null || chown root:root "$NGINX_LOG"
            chmod 640 "$NGINX_LOG"
        fi

        # Create Filter for TLS Handshake failures, SNI mismatch, and mTLS bypass attempts
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-tls-guard.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-tls-guard.conf
[Definition]
# [DEVSECOPS FIX] Non-greedy parsing to catch core SSL errors natively emitted by Nginx
failregex = ^.*? \[info\] \d+#\d+: \*\d+ SSL_do_handshake\(\) failed .*? client: <HOST>
            ^.*? \[info\] \d+#\d+: \*\d+ peer closed connection in SSL handshake .*? client: <HOST>
            ^.*? \[error\] \d+#\d+: \*\d+ no "ssl_certificate" is defined in server listening on SSL port .*? client: <HOST>
            ^.*? \[error\] \d+#\d+: \*\d+ client SSL certificate verify error: .*? client: <HOST>
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-tls-guard.conf
[syswarden-tls-guard]
enabled  = true
port     = https,443,8443
filter   = syswarden-tls-guard
logpath  = $NGINX_LOG
backend  = auto
# Policy: 10 SSL errors in 1 minute indicates active TLS Fuzzing or massive direct IP scanning.
maxretry = 10
findtime = 60
bantime  = 24h
EOF
    fi
}
