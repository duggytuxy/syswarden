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

        # CI/CD Auto-load Docker Jails routing configuration
        local input_jails="${SYSWARDEN_DOCKER_JAILS:-syswarden-modsec}"
        if [[ "${1:-}" != "auto" ]]; then
            read -p "Enter Fail2ban jails to route via Docker (comma-separated, default: $input_jails): " user_jails
            input_jails="${user_jails:-$input_jails}"
        fi
        DOCKER_JAILS="$input_jails"
        echo "DOCKER_JAILS='$DOCKER_JAILS'" >>"$CONF_FILE"
        log "INFO" "Docker Jails routed: $DOCKER_JAILS"
    else
        USE_DOCKER="n"
        log "INFO" "Docker integration DISABLED."
        echo "DOCKER_JAILS=''" >>"$CONF_FILE"
    fi
    echo "USE_DOCKER='$USE_DOCKER'" >>"$CONF_FILE"
}
