setup_siem_logging() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SIEM_ENABLED:-}" ]]; then SIEM_ENABLED="n"; fi
        log "INFO" "Update Mode: Preserving SIEM Log Forwarding setting ($SIEM_ENABLED)"
        return
    fi

    echo -e "\n${BLUE}=== Step: SIEM Log Forwarding (ISO 27001/NIS2) ===${NC}"
    if [[ "${1:-}" == "auto" ]]; then
        SIEM_ENABLED=${SYSWARDEN_SIEM_ENABLED:-n}
        SIEM_IP=${SYSWARDEN_SIEM_IP:-""}
        SIEM_PORT=${SYSWARDEN_SIEM_PORT:-514}
        SIEM_PROTO=${SYSWARDEN_SIEM_PROTO:-udp}

        # --- SECURITY FIX: Strict Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ "$SIEM_ENABLED" =~ ^[Yy]$ ]]; then
            if ! [[ "$SIEM_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then
                log "ERROR" "Auto Mode: Invalid SIEM_IP hostname/IP format. Disabling SIEM."
                SIEM_ENABLED="n"
            fi
            if ! [[ "$SIEM_PORT" =~ ^[0-9]+$ ]] || [ "$SIEM_PORT" -lt 1 ] || [ "$SIEM_PORT" -gt 65535 ]; then
                log "WARN" "Auto Mode: Invalid SIEM_PORT. Defaulting to 514."
                SIEM_PORT=514
            fi
            SIEM_PROTO=$(echo "$SIEM_PROTO" | tr '[:upper:]' '[:lower:]')
            if [[ "$SIEM_PROTO" != "tcp" && "$SIEM_PROTO" != "udp" ]]; then
                log "WARN" "Auto Mode: Invalid SIEM_PROTO. Defaulting to udp."
                SIEM_PROTO="udp"
            fi
        fi
        # -----------------------------------------------------
        log "INFO" "Auto Mode: SIEM config loaded via env vars."
    else
        echo "Forward EXCLUSIVELY Fail2ban L7 attack logs to an external SIEM?"
        read -p "Enable SIEM Forwarding? (y/N): " response_siem
        if [[ "$response_siem" =~ ^[Yy]$ ]]; then
            SIEM_ENABLED="y"

            # --- SECURITY FIX: STRICT INPUT VALIDATION LOOPS (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter SIEM IP/Hostname: " SIEM_IP
                # Basic Hostname/IP validation (alphanumeric, dots, hyphens)
                if [[ "$SIEM_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then break; else echo -e "${RED}Invalid IP/Hostname format.${NC}"; fi
            done

            while true; do
                read -p "Enter SIEM Port [Default: 514]: " SIEM_PORT
                SIEM_PORT=${SIEM_PORT:-514}
                if [[ "$SIEM_PORT" =~ ^[0-9]+$ ]] && [ "$SIEM_PORT" -ge 1 ] && [ "$SIEM_PORT" -le 65535 ]; then break; else echo -e "${RED}Invalid Port. Must be between 1 and 65535.${NC}"; fi
            done

            while true; do
                read -p "Enter SIEM Protocol (tcp/udp) [Default: udp]: " SIEM_PROTO
                SIEM_PROTO=${SIEM_PROTO:-udp}
                SIEM_PROTO=$(echo "$SIEM_PROTO" | tr '[:upper:]' '[:lower:]')
                if [[ "$SIEM_PROTO" == "tcp" || "$SIEM_PROTO" == "udp" ]]; then break; else echo -e "${RED}Must be tcp or udp.${NC}"; fi
            done
        else
            SIEM_ENABLED="n"
        fi
    fi

    echo "SIEM_ENABLED='$SIEM_ENABLED'" >>"$CONF_FILE"
    if [[ "$SIEM_ENABLED" == "y" ]] && [[ -n "$SIEM_IP" ]]; then
        echo "SIEM_IP='$SIEM_IP'" >>"$CONF_FILE"
        echo "SIEM_PORT='$SIEM_PORT'" >>"$CONF_FILE"
        echo "SIEM_PROTO='$SIEM_PROTO'" >>"$CONF_FILE"

        log "INFO" "Configuring Rsyslog to forward ONLY Fail2ban logs to SIEM..."

        cat <<EOF >/etc/rsyslog.d/99-syswarden-siem.conf
# SysWarden SIEM Forwarder - Exclusive Fail2ban Routing
module(load="imfile")

input(type="imfile"
      File="/var/log/fail2ban.log"
      Tag="fail2ban"
      Severity="warning"
      Facility="local7")

if \$programname == 'fail2ban' then {
    action(type="omfwd" target="$SIEM_IP" port="$SIEM_PORT" protocol="$SIEM_PROTO")
    stop
}
EOF
        if command -v systemctl >/dev/null 2>&1; then
            systemctl restart rsyslog 2>/dev/null || true
        else
            service rsyslog restart 2>/dev/null || true
        fi
        log "INFO" "SIEM Log Forwarding is ACTIVE. (Target: $SIEM_IP:$SIEM_PORT/$SIEM_PROTO)"
    else
        log "INFO" "SIEM Log Forwarding DISABLED."
        rm -f /etc/rsyslog.d/99-syswarden-siem.conf
        if command -v systemctl >/dev/null 2>&1; then systemctl restart rsyslog 2>/dev/null || true; fi
    fi
}
