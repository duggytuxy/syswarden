detect_os_backend() {
    log "INFO" "Detecting Operating System and Firewall Backend..."

    # --- HOTFIX: PREVENT BACKEND AMNESIA ---
    if [[ -f "$CONF_FILE" ]] && grep -q "FIREWALL_BACKEND=" "$CONF_FILE"; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Loaded saved Firewall Backend: $FIREWALL_BACKEND"
        return
    fi
    # ---------------------------------------

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        OS_ID=$ID
    else
        OS="Unknown"
        OS_ID="unknown"
    fi

    # Logic to select the best firewall for the OS
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        FIREWALL_BACKEND="ufw"
    elif [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]]; then
        FIREWALL_BACKEND="nftables"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_BACKEND="firewalld" # RHEL/Alma default
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="ipset" # Fallback
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"

    # Save detection for future cron jobs
    echo "FIREWALL_BACKEND='$FIREWALL_BACKEND'" >>"$CONF_FILE"
}
