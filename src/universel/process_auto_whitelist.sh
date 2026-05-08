process_auto_whitelist() {
    # Only execute in auto mode and if the variable is populated
    if [[ "${1:-}" != "auto" ]] || [[ -z "${SYSWARDEN_WHITELIST_IPS:-}" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Processing Automated Whitelist ===${NC}"
    log "INFO" "Processing custom Whitelist from auto-configuration..."

    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    # --- HOTFIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global strict IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------

    for ip in $SYSWARDEN_WHITELIST_IPS; do
        # Ignore empty strings
        if [[ -z "$ip" ]]; then continue; fi

        # --- SECURITY FIX: STRICT IPV4 VALIDATION (CWE-20: Improper Input Validation) ---
        # Prevents malicious or malformed strings from crashing the firewall daemon
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$ip" != "127.0.0.1" ]]; then
            if ! grep -q "^${ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-configuration: Whitelisting IP $ip"
                echo "$ip" >>"$WHITELIST_FILE"
            else
                log "INFO" "Auto-configuration: IP $ip is already whitelisted."
            fi
        else
            log "WARN" "Auto-configuration: Invalid IP format skipped -> '$ip'"
        fi
    done

    # Restore strict security IFS
    IFS="$OLD_IFS"
}
