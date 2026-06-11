syswarden_jail_cms_honeypot() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Deploying CMS Recon Honeypot (Zero Tolerance for unsolicited CMS probes)."

    # Create Filter for WordPress, Joomla, and Magento forced browsing
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-cms-honeypot.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-cms-honeypot.conf
[Definition]
# [DEVSECOPS FIX] Matches aggressive path traversals and double-slash bypasses (//wp/wp-includes/)
# Instantly flags 4xx errors on standard CMS core directories/files.
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD) [^"]*?/(?:wp-includes|wp-admin|wp-content|wp-login\.php|xmlrpc\.php|wlwmanifest\.xml|joomla|administrator/index\.php|magento)[^"]*?" (?:404|403|400|405)
ignoreregex = 
EOF
    fi

    # Dynamic Aggressiveness:
    # If the server does NOT run WordPress, ban on the absolute first strike (maxretry = 1).
    # If it DOES run WordPress, allow a small margin (maxretry = 3) for broken plugins triggering 404s.
    local max_retries=1
    if [[ "${SYSW_HAS_WORDPRESS:-false}" == "true" ]]; then
        max_retries=3
    fi

    # Write directly to jail.d
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-cms-honeypot.conf
[syswarden-cms-honeypot]
enabled  = true
port     = http,https
filter   = syswarden-cms-honeypot
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = $max_retries
bantime  = 48h
EOF
}
