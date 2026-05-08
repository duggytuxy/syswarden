define_asnblocking() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${BLOCK_ASNS:-}" ]]; then BLOCK_ASNS="none"; fi
        # Backward compatibility: if Spamhaus variable doesn't exist in config, enable by default
        if [[ -z "${USE_SPAMHAUS_ASN:-}" ]]; then USE_SPAMHAUS_ASN="y"; fi
        log "INFO" "Update Mode: Preserving ASN-Blocking setting ($BLOCK_ASNS, Spamhaus: $USE_SPAMHAUS_ASN)"
        return
    fi

    echo -e "\n${BLUE}=== Step: ASN Blocking (Hosters/ISPs) ===${NC}"

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_asn=${SYSWARDEN_ENABLE_ASN:-n}
        log "INFO" "Auto Mode: ASN-Blocking choice loaded via env var [${input_asn}]"
    else
        echo "Do you want to block entire Autonomous Systems (e.g., AS16276 for OVH)?"
        read -p "Enable ASN Blocking? (y/N): " input_asn
    fi
    # -----------------------------

    if [[ "$input_asn" =~ ^[Yy]$ ]]; then
        if [[ "${1:-}" == "auto" ]]; then
            asn_list=${SYSWARDEN_ASN_LIST:-""}
            use_spamhaus=${SYSWARDEN_USE_SPAMHAUS:-y}
            log "INFO" "Auto Mode: ASN List and Spamhaus preference loaded via env vars."
        else
            read -p "Enter custom ASN numbers separated by space (Leave empty for none): " asn_list
            echo -e "${YELLOW}Note: Fetching and resolving the Spamhaus ASN-DROP list can take more than 5 minutes.${NC}"
            read -p "Include Spamhaus ASN-DROP list (Cybercrime Hosters)? (Y/n): " use_spamhaus
        fi

        BLOCK_ASNS=${asn_list:-none}
        USE_SPAMHAUS_ASN=${use_spamhaus:-y} # Default to yes if user just hits Enter

        # Normalize Spamhaus choice
        if [[ "$USE_SPAMHAUS_ASN" =~ ^[Nn]$ ]]; then
            USE_SPAMHAUS_ASN="n"
        else
            USE_SPAMHAUS_ASN="y"
        fi

        # Fail-Safe: If user typed nothing AND declined Spamhaus
        if [[ "$BLOCK_ASNS" == "none" ]] && [[ "$USE_SPAMHAUS_ASN" == "n" ]]; then
            BLOCK_ASNS="none"
            log "WARN" "No custom ASNs provided and Spamhaus declined. ASN Blocking DISABLED."
        else
            # --- SECURITY FIX: STRICT INPUT SANITIZATION (CWE-20: Improper Input Validation) ---
            # Allow only alphanumeric characters and spaces to prevent whois command injection.
            if [[ "$BLOCK_ASNS" != "none" ]]; then
                BLOCK_ASNS=$(echo "$BLOCK_ASNS" | tr -cd 'a-zA-Z0-9 ' | tr '[:lower:]' '[:upper:]')
            fi
            log "INFO" "ASN Blocking ENABLED. Custom: [$BLOCK_ASNS], Spamhaus: [$USE_SPAMHAUS_ASN]"
        fi
    else
        BLOCK_ASNS="none"
        USE_SPAMHAUS_ASN="n"
        log "INFO" "ASN Blocking DISABLED."
    fi
    echo "BLOCK_ASNS='$BLOCK_ASNS'" >>"$CONF_FILE"
    echo "USE_SPAMHAUS_ASN='$USE_SPAMHAUS_ASN'" >>"$CONF_FILE"
}
