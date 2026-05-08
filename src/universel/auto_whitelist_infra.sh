auto_whitelist_infra() {
    # 1. State Machine: Handle silent background updates (No Prompts)
    if [[ "${1:-}" == "update" ]] || [[ "${1:-}" == "cron-update" ]]; then
        # Ensure config is loaded to read the user's initial choice
        if [[ -f "$CONF_FILE" ]] && ! grep -q "WHITELIST_INFRA=" <<<"$(set)"; then
            # shellcheck source=/dev/null
            source "$CONF_FILE" 2>/dev/null || true
        fi

        if [[ "${WHITELIST_INFRA:-y}" == "n" ]]; then
            return
        fi
    else
        # 2. Interactive & Auto Mode (Initial Installation)
        echo -e "\n${BLUE}=== Step: Critical Infrastructure Whitelist ===${NC}"

        # --- CI/CD AUTO MODE CHECK ---
        if [[ "${1:-}" == "auto" ]]; then
            input_infra=${SYSWARDEN_WHITELIST_INFRA:-y}
            log "INFO" "Auto Mode: Infra Whitelist choice loaded via env var [${input_infra}]"
        else
            echo -e "${YELLOW}To prevent server lockouts, SysWarden can automatically detect and whitelist"
            echo -e "your DNS, DHCP, Default Gateway, and Cloud Metadata IPs.${NC}"
            read -p "Enable Critical Infrastructure Whitelisting? (Y/n): " input_infra
        fi

        # Normalize and Save to configuration
        if [[ "$input_infra" =~ ^[Nn]$ ]]; then
            WHITELIST_INFRA="n"
            echo "WHITELIST_INFRA='n'" >>"$CONF_FILE"
            log "WARN" "Auto-whitelisting of critical infrastructure is DISABLED."
            return
        else
            WHITELIST_INFRA="y"
            echo "WHITELIST_INFRA='y'" >>"$CONF_FILE"
        fi
    fi

    log "INFO" "Scanning and whitelisting critical infrastructure IPs (DNS, Gateway, Cloud Metadata)..."

    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    local infra_ips=""

    # 1. Extract DNS Resolvers
    if [[ -f /etc/resolv.conf ]]; then
        local dns_ips
        dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        infra_ips="$infra_ips $dns_ips"
    fi

    # 2. Extract Default Gateway(s)
    if command -v ip >/dev/null; then
        local gw_ips
        gw_ips=$(ip -4 route show default 2>/dev/null | grep -Eo 'via [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' || true)
        infra_ips="$infra_ips $gw_ips"
    fi

    # 3. Add Cloud Metadata IP (Universal AWS, GCP, Azure, OVH, Scaleway)
    infra_ips="$infra_ips 169.254.169.254"

    # 4. Extract DHCP Server IP (from common dhclient lease files)
    if [[ -f /var/lib/dhcp/dhclient.leases ]]; then
        local dhcp_ips
        dhcp_ips=$(grep -E 'dhcp-server-identifier' /var/lib/dhcp/dhclient.leases 2>/dev/null | awk '{print $3}' | tr -d ';' | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
        infra_ips="$infra_ips $dhcp_ips"
    fi

    # 5. Extract Host's own public/local IPs (Prevents self-routing drops in extreme cases)
    if command -v ip >/dev/null; then
        local host_ips
        host_ips=$(ip -4 addr show | grep -oEo 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | grep -v '^127\.' || true)
        infra_ips="$infra_ips $host_ips"
    fi

    # --- HOTFIX: TEMPORARY IFS RESTORE ---
    # We must allow space separation just for this loop, bypassing the global strict IFS=$'\n\t'
    local OLD_IFS="$IFS"
    IFS=$' \n\t'
    # ----------------------------------

    # Filter, validate, and inject into the master whitelist
    for ip in $infra_ips; do
        if [[ -n "$ip" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if ! grep -q "^${ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting critical Infra IP: $ip"
                echo "$ip" >>"$WHITELIST_FILE"
            fi
        fi
    done

    # Restore strict security IFS
    IFS="$OLD_IFS"
}
