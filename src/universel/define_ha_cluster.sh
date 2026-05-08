define_ha_cluster() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${HA_ENABLED:-}" ]]; then HA_ENABLED="n"; fi
        log "INFO" "Update Mode: Preserving HA Cluster setting ($HA_ENABLED)"
        return
    fi

    echo -e "\n${BLUE}=== Step: High Availability Cluster (HA Sync) ===${NC}"

    if [[ "${1:-}" == "auto" ]]; then
        HA_ENABLED=${SYSWARDEN_HA_ENABLED:-n}
        HA_PEER_IP=${SYSWARDEN_HA_PEER_IP:-""}

        # --- SECURITY FIX: Strict IPV4 Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ "$HA_ENABLED" =~ ^[Yy]$ ]] && ! [[ "$HA_PEER_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            log "ERROR" "Auto Mode: Invalid HA_PEER_IP IPv4 format. Disabling HA Cluster."
            HA_ENABLED="n"
            HA_PEER_IP=""
        fi
        # ----------------------------------------------------------
        log "INFO" "Auto Mode: HA choice loaded via env var."
    else
        echo "SysWarden can automatically replicate its threat intelligence state to a standby node."
        read -p "Enable HA Cluster Sync? (y/N): " input_ha

        if [[ "$input_ha" =~ ^[Yy]$ ]]; then
            HA_ENABLED="y"
            # --- SECURITY FIX: STRICT IPV4 VALIDATION LOOP (CWE-20: Improper Input Validation) ---
            while true; do
                read -p "Enter Standby Node IP (Must be accessible via SSH keys): " HA_PEER_IP
                if [[ "$HA_PEER_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
                    break
                else
                    echo -e "${RED}ERROR: Invalid IPv4 address format. Please try again.${NC}"
                fi
            done
        else
            HA_ENABLED="n"
        fi
    fi

    echo "HA_ENABLED='$HA_ENABLED'" >>"$CONF_FILE"

    if [[ "$HA_ENABLED" == "y" ]] && [[ -n "$HA_PEER_IP" ]]; then
        echo "HA_PEER_IP='$HA_PEER_IP'" >>"$CONF_FILE"

        log "INFO" "Configuring HA Synchronization Engine..."
        local SYNC_SCRIPT="/usr/local/bin/syswarden-sync.sh"

        cat <<EOF >"$SYNC_SCRIPT"
#!/bin/bash
# SysWarden HA State Synchronization
# Runs securely via Cron to replicate states to the standby node

PEER="$HA_PEER_IP"
SSH_PORT="${SSH_PORT:-22}"

# 1. Sync custom lists
rsync -a -e "ssh -p \$SSH_PORT -o StrictHostKeyChecking=no" /etc/syswarden/whitelist.txt /etc/syswarden/blocklist.txt root@\$PEER:/etc/syswarden/ 2>/dev/null

# 2. Trigger remote reload securely
ssh -p \$SSH_PORT -o StrictHostKeyChecking=no root@\$PEER "/usr/local/bin/syswarden-telemetry.sh >/dev/null 2>&1" 2>/dev/null
EOF
        chmod +x "$SYNC_SCRIPT"

        # Inject into Crontab (Syncs every 30 mins)
        if ! crontab -l 2>/dev/null | grep -q "syswarden-sync"; then
            (
                crontab -l 2>/dev/null || true
                echo "*/30 * * * * $SYNC_SCRIPT >/dev/null 2>&1"
            ) | crontab -
        fi
        log "INFO" "HA Cluster Sync ENABLED. Target: $HA_PEER_IP"
    else
        log "INFO" "HA Cluster Sync DISABLED."
    fi
}
