syswarden_jail_homoglyph() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Unicode Obfuscation & Homoglyph Guard."

        # Create Filter for Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF)
        # and Zero-Width/Directional formatters (U+200B-U+200F, U+202A-U+202E).
        # Attackers use these to bypass WAFs by obfuscating standard keywords (e.g., d𝑒f instead of def).
        # DEVSECOPS FIX: We strictly match the URL-encoded (%) or Nginx hex-escaped (\x)
        # byte sequences of these specific Unicode blocks. We require at least 2 consecutive
        # sequences to mathematically prevent any false positives with legitimate foreign UTF-8 characters.
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-homoglyph.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-homoglyph.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) [^"]*(?:(?:(?:%|\\x)F0(?:%|\\x)9D(?:%|\\x)9[0-9a-fA-F](?:%|\\x)[89a-bA-B][0-9a-fA-F]){2,}|(?:(?:%|\\x)E2(?:%|\\x)80(?:%|\\x)(?:8[b-fB-F]|A[a-eA-E])){2,})[^"]*" \d{3}
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-homoglyph.conf
[syswarden-homoglyph]
enabled  = true
port     = http,https
filter   = syswarden-homoglyph
logpath  = $SYSW_RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to use homoglyph/zero-width obfuscation = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
    fi
}
