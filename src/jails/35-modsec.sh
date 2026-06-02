syswarden_jail_modsec() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ "${SYSW_MODSEC_ACTIVE:-0}" -ne 1 ]] || [[ -z "${SYSW_MODSEC_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "ModSecurity WAF detected. Enabling Purple Team integration."

    # Create Filter for ModSecurity Access Denied events
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-modsec.conf
[Definition]
# Matches ModSecurity 4xx/5xx denials and pattern matches (Native and Reverse-Proxy X-Forwarded-For aware)
failregex = ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Access denied with code [45]\d\d.*$
            ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Warning\. Pattern match.*$
            ^.*ModSecurity: Access denied.* \[client <HOST>\].*
            ^.*ModSecurity: Warning.* \[client <HOST>\].*
ignoreregex =
EOF
    fi

    # Determine correct banaction if Docker is globally enabled for L3 isolation
    local banaction_config=""
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        banaction_config="banaction = syswarden-docker"
        log "INFO" "ModSecurity Jail: Docker integration enabled. Forcing routing to DOCKER-USER chain."
    fi

    # Support CI/CD override for multi-tenant log aggregation
    local target_modsec_logs="${SYSWARDEN_MODSEC_LOGS:-$SYSW_MODSEC_LOGS}"

    # Interactive prompt for multi-tenant WAF architecture logs
    if [[ "${1:-}" != "auto" ]]; then
        read -p "Enter ModSecurity log path (default: $target_modsec_logs, e.g. /var/log/modsec/*.log for multi-tenant): " user_modsec_logs
        target_modsec_logs="${user_modsec_logs:-$target_modsec_logs}"
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-modsec.conf
[syswarden-modsec]
enabled  = true
port     = http,https,8080,8443
filter   = syswarden-modsec
logpath  = $target_modsec_logs
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 24h
$banaction_config
EOF
}
