define_cis_hardening() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${APPLY_CIS_L2_HARDENING:-}" ]]; then APPLY_CIS_L2_HARDENING="n"; fi
        log "INFO" "Update Mode: Preserving CIS Level 2 setting ($APPLY_CIS_L2_HARDENING)"
        return
    fi

    echo -e "\n${BLUE}=== Step: CIS Benchmark Level 2 Hardening ===${NC}"

    if [[ "${1:-}" == "auto" ]]; then
        # DevSecOps Fix: Catching legacy and strictly named variables to prevent accidental overrides
        input_cis=${SYSWARDEN_CIS_HARDENING:-${APPLY_CIS_L2_HARDENING:-n}}
        log "INFO" "Auto Mode: CIS Hardening choice loaded via env var [${input_cis}]"
    else
        echo -e "${YELLOW}WARNING: CIS Level 2 enforces strict Kernel, eBPF, and Network restrictions.${NC}"
        read -p "Apply advanced CIS Level 2 Hardening? (Recommended for exposed prod) [y/N]: " input_cis
    fi

    if [[ "$input_cis" =~ ^[Yy]$ ]]; then
        APPLY_CIS_L2_HARDENING="y"
        log "INFO" "CIS Level 2 Hardening ENABLED. Advanced restrictions will be applied."
    else
        APPLY_CIS_L2_HARDENING="n"
        log "INFO" "CIS Level 2 Hardening DISABLED. Preserving standard behavior."
    fi

    echo "APPLY_CIS_L2_HARDENING='$APPLY_CIS_L2_HARDENING'" >>"$CONF_FILE"
}
