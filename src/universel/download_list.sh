download_list() {
    echo -e "\n${BLUE}=== Step 3: Downloading Blocklist ===${NC}"
    log "INFO" "Fetching list from $SELECTED_URL..."

    if [[ "$SELECTED_URL" == "none" ]]; then
        log "INFO" "No global blocklist selected. Skipping download."
        touch "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        return
    fi

    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION (CWE-20: Improper Input Validation) ---
        # Validates exact octet ranges (0-255) and subnet masks (0-32) to prevent firewall crash (F13)
        tr -d '\r' <"$output_file" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >"$TMP_DIR/clean_list.txt"
        # -----------------------------------------------------
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        log "INFO" "Download success."
    else
        log "ERROR" "Failed to download blocklist."
        exit 1
    fi
}
