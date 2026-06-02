define_docker_integration() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_DOCKER:-}" ]]; then USE_DOCKER="n"; fi
        log "INFO" "Update Mode: Preserving Docker integration setting ($USE_DOCKER)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Docker Integration ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_docker=${SYSWARDEN_USE_DOCKER:-n}
        log "INFO" "Auto Mode: Docker integration loaded via env var [${input_docker}]"
    else
        read -p "Do you use Docker on this server? (y/N): " input_docker
    fi
    # -----------------------------

    if [[ "$input_docker" =~ ^[Yy]$ ]]; then
        USE_DOCKER="y"
        log "INFO" "Docker integration ENABLED."

        # CI/CD Auto-load Docker configuration
        local input_jails="${SYSWARDEN_DOCKER_JAILS:-syswarden-modsec}"
        local target_modsec_logs="${SYSWARDEN_MODSEC_LOGS:-/var/log/modsec/*.log}"

        if [[ "${1:-}" != "auto" ]]; then
            read -p "Enter Fail2ban jails to route via Docker (comma-separated, default: $input_jails): " user_jails
            input_jails="${user_jails:-$input_jails}"

            read -p "Enter ModSecurity log path (default: $target_modsec_logs, e.g. /var/log/modsec/*.log for multi-tenant): " user_modsec_logs
            target_modsec_logs="${user_modsec_logs:-$target_modsec_logs}"
        fi

        DOCKER_JAILS="$input_jails"
        SYSWARDEN_MODSEC_LOGS="$target_modsec_logs"
        echo "DOCKER_JAILS='$DOCKER_JAILS'" >>"$CONF_FILE"
        echo "SYSWARDEN_MODSEC_LOGS='$SYSWARDEN_MODSEC_LOGS'" >>"$CONF_FILE"
        log "INFO" "Docker Jails routed: $DOCKER_JAILS"
    else
        USE_DOCKER="n"
        log "INFO" "Docker integration DISABLED."
        echo "DOCKER_JAILS=''" >>"$CONF_FILE"
    fi
    echo "USE_DOCKER='$USE_DOCKER'" >>"$CONF_FILE"
}
