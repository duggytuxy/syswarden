syswarden_jail_ssrf() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling SSRF & Cloud Metadata Guard."

    # Create Filter for SSRF & Cloud Metadata Exfiltration attempts
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
# Detects requests targeting Cloud Metadata IP (169.254.169.254) and specific provider endpoints
# [DEVSECOPS FIX: F-004 & F-005] Optional date brackets for universal log compatibility.
# Added Case-insensitivity (?i), URL-encoding interception, and comprehensive IMDS numeric encodings (Octal, Dotted Hex).
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?i)(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:169\.254\.169\.254|2852039166|0xa9fea9fe|0251\.0376\.0251\.0376|0xa9\.0xfe\.0xa9\.0xfe|\x2531\x2536\x2539\x252e|(?:/|\x252f|\x25252f)metadata(?:/|\x252f|\x25252f)(?:instance|identity|v1)|latest(?:/|\x252f|\x25252f)meta-data|metadata\.google\.internal|(?:/|\x252f|\x25252f)v1(?:/|\x252f|\x25252f)user-data|100\.100\.100\.200|192\.0\.0\.192).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Critical alert, instant ban for 48h to protect infrastructure credentials
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-ssrf.conf
[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
