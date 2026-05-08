download_osint() {
    if [[ "${LIST_TYPE:-Standard}" == "None" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading Free OSINT Threat Feeds ===${NC}"
    log "INFO" "Fetching CINS Army & Blocklist.de threat feeds..."

    local osint_raw="$TMP_DIR/osint_raw.txt"
    : >"$osint_raw"

    # 1. CINS Army (CI Army) - Active Botnets & Scanners
    echo -n "Fetching CINS Army badguys list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://cinsscore.com/list/ci-badguys.txt" >>"$osint_raw"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log "WARN" "Failed to download CINS Army list."
    fi

    # 2. Blocklist.de - Bruteforce & SSH/Web Attacks
    echo -n "Fetching Blocklist.de (All) list... "
    if curl -sS -L --retry 3 --connect-timeout 10 "https://lists.blocklist.de/lists/all.txt" >>"$osint_raw"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        log "WARN" "Failed to download Blocklist.de list."
    fi

    # 3. Thorough cleaning and atomic fusion
    if [[ -s "$osint_raw" ]]; then
        log "INFO" "Sanitizing OSINT IPs and merging with the main blocklist..."

        # --- SECURITY FIX: STRICT CIDR SEMANTIC VALIDATION (CWE-20: Improper Input Validation) ---
        # Ensures that only valid IPv4 addresses are passed to the firewall engine (Anti-Crash)
        tr -d '\r' <"$osint_raw" | awk -F'[/.]' 'NF==4 || NF==5 {
            valid=1; for(i=1;i<=4;i++) if($i<0 || $i>255 || $i=="") valid=0;
            if(NF==5 && ($5<0 || $5>32 || $5=="")) valid=0;
            if(valid) print $0;
        }' >>"$FINAL_LIST"
        # -----------------------------------------------------

        log "INFO" "OSINT feeds successfully merged into the core firewall memory."
    else
        log "WARN" "OSINT feeds are empty. Continuing with standard blocklist."
    fi
}
