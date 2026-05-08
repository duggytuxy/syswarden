download_asn() {
    # Exit if user provided no custom ASNs AND declined Spamhaus
    if [[ "${BLOCK_ASNS:-none}" == "none" ]] && [[ "${USE_SPAMHAUS_ASN:-n}" == "n" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Downloading ASN Data ===${NC}"
    mkdir -p "$TMP_DIR"
    mkdir -p "$SYSWARDEN_DIR"
    : >"$TMP_DIR/asn_raw.txt"

    # --- SPAMHAUS ASN-DROP INTEGRATION (CONDITIONAL) ---
    if [[ "${USE_SPAMHAUS_ASN:-y}" == "y" ]]; then
        echo -n "Fetching Spamhaus ASN-DROP list (Cybercrime Hosters)... "
        local spamhaus_url="https://www.spamhaus.org/drop/asndrop.json"

        # Extract ASNs from JSON format securely using grep and sed
        local spamhaus_asns
        spamhaus_asns=$(curl -sS -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --retry 2 --connect-timeout 5 "$spamhaus_url" 2>/dev/null | grep -Eo '"asn":[[:space:]]*[0-9]+' | grep -Eo '[0-9]+' | sed 's/^/AS/' | tr '\n' ' ' || true)

        if [[ -n "$spamhaus_asns" ]]; then
            echo -e "${GREEN}OK${NC}"
            # Clean merge: replace 'none' or 'auto' from older configs
            if [[ "$BLOCK_ASNS" == "none" ]] || [[ "$BLOCK_ASNS" == "auto" ]]; then
                BLOCK_ASNS="$spamhaus_asns"
            else
                BLOCK_ASNS="$BLOCK_ASNS $spamhaus_asns"
            fi
        else
            echo -e "${YELLOW}Failed/Skipped${NC}"
            log "WARN" "Could not fetch Spamhaus ASN-DROP. Proceeding with custom ASNs only."
        fi
    else
        log "INFO" "Spamhaus ASN-DROP integration skipped by user."
    fi
    # -------------------------------------

    # --- FIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------

    local combined_asns
    combined_asns=$(echo "$BLOCK_ASNS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

    for asn in $combined_asns; do
        # Ignore empty strings or our keywords
        if [[ -z "$asn" ]] || [[ "$asn" == "auto" ]] || [[ "$asn" == "none" ]]; then continue; fi

        # Format the input properly
        if [[ ! "$asn" =~ ^AS[0-9]+$ ]]; then
            local clean_num="${asn//[!0-9]/}"
            if [[ -z "$clean_num" ]]; then continue; fi # Failsafe
            asn="AS${clean_num}"
        fi

        echo -n "Fetching IP blocks for ${asn}... "

        # --- FIX: SMART RETRY (Distinguish Network Error vs Empty ASN) ---
        local success=false
        local whois_out=""

        for _ in 1 2 3; do
            # Capture total output (stdout + stderr)
            whois_out=$(whois -h whois.radb.net -- "-i origin $asn" 2>&1 || true)

            # If the RADB server drops the connection, pause and retry
            if [[ "$whois_out" == *"Connection reset by peer"* ]] || [[ "$whois_out" == *"Timeout"* ]] || [[ "$whois_out" == *"refused"* ]]; then
                sleep 2
                continue
            fi

            # If we reach this point, the query succeeded (even if the result is empty)
            success=true
            break
        done

        if [ "$success" = true ]; then
            # Now search for IPv4 CIDRs in the valid response
            if echo "$whois_out" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' >>"$TMP_DIR/asn_raw.txt"; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}Empty (IPv6-only/No routes)${NC}"
            fi
        else
            echo -e "${RED}FAIL (Blocked by RADB)${NC}"
            log "WARN" "Failed to fetch data for $asn (Network dropped)."
        fi

        # Ultra-short pause to prevent getting rate-limited while staying fast
        sleep 0.5
        # ---------------------------------------------------------------
    done

    # Restore strict security IFS
    IFS="$OLD_IFS"

    if [[ -s "$TMP_DIR/asn_raw.txt" ]]; then
        # Use Python to mathematically collapse overlapping CIDRs and prevent Firewalld INVALID_ENTRY errors
        python3 -c '
import sys, ipaddress
nets = []
for line in sys.stdin:
    line = line.strip()
    if line and ":" not in line:
        try: nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError: pass
for net in ipaddress.collapse_addresses(nets):
    print(net)' <"$TMP_DIR/asn_raw.txt" >"$ASN_FILE"

        log "INFO" "ASN Blocklist updated successfully."
    else
        log "WARN" "ASN Blocklist is empty."
        touch "$ASN_FILE"
    fi
}
