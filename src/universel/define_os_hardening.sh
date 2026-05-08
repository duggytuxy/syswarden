define_os_hardening() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${APPLY_OS_HARDENING:-}" ]]; then APPLY_OS_HARDENING="n"; fi
        log "INFO" "Update Mode: Preserving OS Hardening setting ($APPLY_OS_HARDENING)"
        return
    fi

    echo -e "\n${BLUE}=== Step: OS Security & Hardening ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_hard=${SYSWARDEN_HARDENING:-n}
        log "INFO" "Auto Mode: OS Hardening choice loaded via env var [${input_hard}]"
    else
        echo -e "${YELLOW}WARNING: Strict OS hardening will restrict CRON to root and remove non-root users from sudo/wheel groups.${NC}"
        read -p "Apply strict OS Hardening? (Recommended for NEW servers only) [y/N]: " input_hard
    fi

    if [[ "$input_hard" =~ ^[Yy]$ ]]; then
        APPLY_OS_HARDENING="y"
        log "INFO" "OS Hardening ENABLED. Sudo/Cron will be strictly restricted."
    else
        APPLY_OS_HARDENING="n"
        log "INFO" "OS Hardening DISABLED. Preserving existing system permissions."
    fi
    echo "APPLY_OS_HARDENING='$APPLY_OS_HARDENING'" >>"$CONF_FILE"
}
