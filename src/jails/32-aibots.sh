syswarden_jail_aibots() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|OPTIONS) [^"]*?" \d{3} [^"]*? "[^"]*?(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai)[^"]*?"
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-aibots.conf
[syswarden-aibots]
enabled  = true
port     = http,https
filter   = syswarden-aibots
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
