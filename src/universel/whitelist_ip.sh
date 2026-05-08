whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    # Simple IP validation
    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    # --- LOCAL PERSISTENCE (SINGLE SOURCE OF TRUTH) ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    if ! grep -q "^${WL_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$WL_IP" >>"$WHITELIST_FILE"
        log "INFO" "IP $WL_IP securely saved to $WHITELIST_FILE."
    else
        log "INFO" "IP $WL_IP is already in the whitelist file."
    fi
    # --------------------------------------------------

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    # --- FIX: SAFE DYNAMIC WHITELISTING (STATE MACHINE) ---
    log "INFO" "Rebuilding firewall framework to safely integrate the new IP..."

    # 1. Force loading config to ensure core variables (SSH_PORT, USE_WIREGUARD) are in RAM
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    # 2. Universally remove the IP from the active blocklist in memory to prevent conflicts
    if command -v ipset >/dev/null; then
        ipset del "$SET_NAME" "$WL_IP" 2>/dev/null || true
    fi
    if command -v nft >/dev/null; then
        # Bypasses the active drop rule temporarily before reload
        nft delete element netdev syswarden_hw_drop "$SET_NAME" '{' "$WL_IP" '}' 2>/dev/null || true
    fi

    # 3. Trigger the orchestrator to rebuild rules with the strict hierarchy
    apply_firewall_rules

    log "SUCCESS" "IP $WL_IP safely whitelisted. Strict firewall hierarchy preserved."
    # ------------------------------------------------------
}
