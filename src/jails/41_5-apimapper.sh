syswarden_jail_apimapper() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling API Mapper Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) [^"]*(?:/swagger-ui[^ "]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ "]*|/graphiql|/graphql/schema) HTTP/[^"]*" (403|404)
ignoreregex = 
EOF
        fi

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
    fi
}
