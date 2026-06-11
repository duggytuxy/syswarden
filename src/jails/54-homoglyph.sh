syswarden_jail_homoglyph() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Unicode Obfuscation & Homoglyph Guard."

    # Create Filter for Mathematical Alphanumeric Symbols and Zero-Width formatters.
    # PYTHON CONFIGPARSER FIX: In Fail2ban .conf files, the '%' character is reserved
    # for interpolation. To match a literal '%' in the regex for URL encoding,
    # it MUST be escaped as '%%'.
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-homoglyph.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-homoglyph.conf
[Definition]
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) [^"]*(?:(?:(?:%%|\\x)F0(?:%%|\\x)9D(?:%%|\\x)9[0-9a-fA-F](?:%%|\\x)[89a-bA-B][0-9a-fA-F]){2,}|(?:(?:%%|\\x)E2(?:%%|\\x)80(?:%%|\\x)(?:8[b-fB-F]|A[a-eA-E])){2,})[^"]*" \d{3}
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # Zero-Tolerance policy: 1 attempt to use homoglyph/zero-width obfuscation = 48 hours kernel ban
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-homoglyph.conf
[syswarden-homoglyph]
enabled  = true
port     = http,https
filter   = syswarden-homoglyph
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
