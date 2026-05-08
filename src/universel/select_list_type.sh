select_list_type() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Update Mode: Loaded configuration (Type: $LIST_TYPE)"
        return
    fi

    echo -e "\n${BLUE}=== Step 1: Select Blocklist Type ===${NC}"

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        # Preemptive cleanup of spaces/newlines to prevent switch-case bypass
        choice=$(echo "${SYSWARDEN_LIST_CHOICE:-1}" | tr -d '[:space:]')
        log "INFO" "Auto Mode: Blocklist choice loaded via env var [${choice}]"
    else
        echo "1) Standard List (~85,000 IPs) - Recommended for Web Servers"
        echo "2) Critical List (~100,000 IPs) - Recommended for High Security"
        echo "3) Custom List"
        echo "4) No List (Geo-Blocking / Local rules only)"
        read -p "Enter choice [1/2/3/4]: " choice
    fi
    # -----------------------------

    case "$choice" in
        1) LIST_TYPE="Standard" ;;
        2) LIST_TYPE="Critical" ;;
        3)
            LIST_TYPE="Custom"
            if [[ "${1:-}" == "auto" ]]; then
                CUSTOM_URL=${SYSWARDEN_CUSTOM_URL:-""}

                # --- SECURITY FIX: Strict URL Validation & Anti-Poisoning (CWE-20: Improper Input Validation) ---
                # Strip newlines (\r\n) and dangerous escape characters
                CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d "\r\n '\"\;\$\|\&\<\>\`")

                # Strict Regex: Must have a valid domain or IP, and no exotic characters (Anti-SSRF)
                if [[ -n "$CUSTOM_URL" && ! "$CUSTOM_URL" =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]+)?(/.*)?$ ]]; then
                    log "ERROR" "Auto Mode: Invalid CUSTOM_URL. Bad format or invalid characters. Defaulting to Standard List."
                    LIST_TYPE="Standard"
                    CUSTOM_URL=""
                fi
                # ---------------------------------------------------------
                log "INFO" "Auto Mode: Custom URL loaded via env var"
            else
                # --- SECURITY FIX: STRICT URL VALIDATION (INTERACTIVE) (CWE-20: Improper Input Validation) ---
                while true; do
                    read -p "Enter the full URL (must be raw .txt format): " CUSTOM_URL

                    # Absolute sanitization
                    CUSTOM_URL=$(echo "$CUSTOM_URL" | tr -d "\r\n '\"\;\$\|\&\<\>\`")

                    if [[ -z "$CUSTOM_URL" ]]; then
                        log "WARN" "URL cannot be empty."
                    elif [[ ! "$CUSTOM_URL" =~ ^https?://[a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})?(:[0-9]+)?(/.*)?$ ]]; then
                        echo -e "${RED}ERROR: Invalid URL format. Must start with http:// or https:// and contain a valid domain/IP.${NC}"
                    else
                        break
                    fi
                done
                # -------------------------------------------
            fi

            # Fail-Safe
            if [[ -z "$CUSTOM_URL" ]]; then
                log "WARN" "Custom URL is empty. Defaulting to Standard List."
                LIST_TYPE="Standard"
            fi
            ;;
        4) LIST_TYPE="None" ;;
        *)
            log "WARN" "Invalid choice detected. Defaulting to Standard List."
            LIST_TYPE="Standard"
            ;;
    esac

    echo "LIST_TYPE='$LIST_TYPE'" >>"$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then
        echo "CUSTOM_URL='$CUSTOM_URL'" >>"$CONF_FILE"
    fi
    log "INFO" "User selected: $LIST_TYPE Blocklist"
}
