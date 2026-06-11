syswarden_jail_aibots() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

    # Create Filter for AI Scrapers and LLM Crawlers
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
# Matches known AI/LLM User-Agents in web access logs
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT|OPTIONS) [^"]*?" \d{3} [^"]*? "[^"]*?(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai)[^"]*?"
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1 for aggressive blocking of data scrapers
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
}
