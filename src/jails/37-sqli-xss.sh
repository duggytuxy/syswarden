syswarden_jail_sqli_xss() {
    # 1. Fail-Fast: Exclusive mutual exclusion and detection check
    # Aborts if no web logs exist OR if ModSecurity is already handling WAF duties
    if [[ -z "${SYSW_RCE_LOGS:-}" ]] || [[ "${SYSW_MODSEC_ACTIVE:-0}" -eq 1 ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling SQLi & XSS Payload Guard."

    # Create Filter for SQL Injection, XSS and Path Traversal patterns
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sqli-xss.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
# [DEVSECOPS FIX] Integrated advanced evasion patterns for Path Traversal (hybrid dots/url-encoding)
# Added fallback pattern to extract malicious attempts logged into daemon error logs
# [HOTFIX] Replaced literal '%' with '\x25' to prevent Python ConfigParser interpolation crash
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT|PATCH|DELETE) [^"]*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F|\.(?:\.|\x252[eE]|\x25252[eE]|\x25\x2532\x2565)(?:/|\x252[fF]|\x25252[fF]|\x25\x2532\x2566))[^"]*" \d{3}
            ^.* \[error\] \d+#\d+: \*\d+ .* client: <HOST>, .* request: "(?:GET|POST|HEAD|PUT|PATCH|DELETE) [^"]*(?:\.\./\.\./|\x252E\x252E\x252F|\.(?:\.|\x252[eE]|\x25252[eE]|\x25\x2532\x2565)(?:/|\x252[fF]|\x25252[fF]|\x25\x2532\x2566))
EOF
    fi

    # Include daemon error logs for invalid request parsing payloads
    local ERR_LOGS="/var/log/nginx/error.log /var/log/apache2/error.log /var/log/httpd/error_log"

    # Write directly to jail.d
    # maxretry = 1: Instant ban for clear injection attempts
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-sqli-xss.conf
[syswarden-sqli-xss]
enabled  = true
port     = http,https
filter   = syswarden-sqli-xss
logpath  = $SYSW_RCE_LOGS
           $ERR_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
