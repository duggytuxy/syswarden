define_wireguard() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_WIREGUARD:-}" ]]; then USE_WIREGUARD="n"; fi
        log "INFO" "Update Mode: Preserving WireGuard setting ($USE_WIREGUARD)"
        return
    fi

    echo -e "\n${BLUE}=== Step: WireGuard Management VPN ===${NC}"
    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        input_wg=${SYSWARDEN_ENABLE_WG:-n}
        log "INFO" "Auto Mode: WireGuard choice loaded via env var [${input_wg}]"

        if [[ "$input_wg" =~ ^[Yy]$ ]]; then
            WG_PORT=${SYSWARDEN_WG_PORT:-51820}
            WG_SUBNET=${SYSWARDEN_WG_SUBNET:-"10.66.66.0/24"}

            # --- SECURITY FIX: Strict Input Validation for Auto Mode (CWE-20: Improper Input Validation) ---
            if ! [[ "$WG_PORT" =~ ^[0-9]+$ ]] || [ "$WG_PORT" -lt 1 ] || [ "$WG_PORT" -gt 65535 ]; then
                log "WARN" "Auto Mode: Invalid WG_PORT format. Defaulting to 51820."
                WG_PORT=51820
            fi

            if ! [[ "$WG_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
                log "WARN" "Auto Mode: Invalid WG_SUBNET CIDR format. Defaulting to 10.66.66.0/24."
                WG_SUBNET="10.66.66.0/24"
            fi
            # -----------------------------------------------------------
        fi
    else
        echo -e "${YELLOW}Deploy an ultra-secure, invisible WireGuard VPN for administration?${NC}"
        read -p "Enable WireGuard Management VPN? (y/N): " input_wg
    fi

    if [[ "$input_wg" =~ ^[Yy]$ ]]; then
        USE_WIREGUARD="y"
        if [[ "${1:-}" == "auto" ]]; then
            WG_PORT=${SYSWARDEN_WG_PORT:-51820}
            WG_SUBNET=${SYSWARDEN_WG_SUBNET:-"10.66.66.0/24"}
        else
            # --- SECURITY FIX: STRICT WG PORT & SUBNET VALIDATION (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter WireGuard Port [Default: 51820]: " input_wg_port
                WG_PORT=${input_wg_port:-51820}
                if [[ "$WG_PORT" =~ ^[0-9]+$ ]] && [ "$WG_PORT" -ge 1 ] && [ "$WG_PORT" -le 65535 ]; then break; else echo -e "${RED}Invalid Port. Must be 1-65535.${NC}"; fi
            done

            while true; do
                read -p "Enter VPN Subnet (CIDR) [Default: 10.66.66.0/24]: " input_wg_subnet
                WG_SUBNET=${input_wg_subnet:-"10.66.66.0/24"}
                # Strict Regex for IPv4 CIDR notation
                if [[ "$WG_SUBNET" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then break; else echo -e "${RED}Invalid CIDR format (e.g. 10.66.66.0/24).${NC}"; fi
            done
            # --------------------------------------------------------
        fi

        # PRE-CREATION: Ensure /etc/wireguard exists EARLY so Fail2ban detects it globally
        mkdir -p /etc/wireguard
        log "INFO" "WireGuard ENABLED (Port: $WG_PORT, Subnet: $WG_SUBNET)."
    else
        USE_WIREGUARD="n"
        log "INFO" "WireGuard DISABLED."
    fi

    echo "USE_WIREGUARD='$USE_WIREGUARD'" >>"$CONF_FILE"
    if [[ "$USE_WIREGUARD" == "y" ]]; then
        echo "WG_PORT='$WG_PORT'" >>"$CONF_FILE"
        echo "WG_SUBNET='$WG_SUBNET'" >>"$CONF_FILE"
    fi
}
