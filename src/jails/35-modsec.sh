syswarden_jail_modsec() {
    # [DEVSECOPS FIX] Intercept Multi-Tenant Docker logs prior to native fail-fast evaluation.
    # Expands wildcards dynamically to ensure at least one container log file exists.
    if [[ -n "${SYSWARDEN_MODSEC_LOGS:-}" ]] && ls ${SYSWARDEN_MODSEC_LOGS} >/dev/null 2>&1; then
        SYSW_MODSEC_ACTIVE=1
        SYSW_MODSEC_LOGS="${SYSWARDEN_MODSEC_LOGS}"
    fi

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

    # Determine correct backend and banaction for Docker isolation
    local banaction_config=""
    local jail_backend="auto"

    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        banaction_config="banaction = syswarden-docker"
        jail_backend="polling"
        log "INFO" "ModSecurity Jail: Docker integration enabled. Forcing DOCKER-USER routing and polling backend."
    fi

    # Support CI/CD override for multi-tenant log aggregation (Inherited from define_docker_integration.sh)
    local target_modsec_logs="${SYSWARDEN_MODSEC_LOGS:-$SYSW_MODSEC_LOGS}"

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-modsec.conf
[syswarden-modsec]
enabled  = true
port     = http,https,8080,8443
filter   = syswarden-modsec
logpath  = $target_modsec_logs
backend  = $jail_backend
maxretry = 3
findtime = 10m
bantime  = 24h
$banaction_config
EOF
}
