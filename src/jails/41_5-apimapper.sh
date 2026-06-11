syswarden_jail_apimapper() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling API Mapper Guard."

    # Create Filter for API Documentation and Schema discovery attempts
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
# Detects reconnaissance on Swagger, OpenAPI, and GraphQL endpoints resulting in 403/404
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD) [^"]*(?:/swagger-ui[^ "]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ "]*|/graphiql|/graphql/schema) HTTP/[^"]*" (403|404)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 2: Allows for one accidental hit, bans on the second mapping attempt
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-apimapper.conf
[syswarden-apimapper]
enabled  = true
port     = http,https
filter   = syswarden-apimapper
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 2
bantime  = 48h
EOF
}
