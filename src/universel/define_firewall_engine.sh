define_firewall_engine() {
    local mode="$1"

    # Do not execute during standard upgrades
    if [[ "$mode" == "update" ]]; then return; fi

    # --- BUG FIX: ALMALINUX DEAD-SERVICE PARADOX ---
    # Cloud images often ship Firewalld installed but disabled.
    # We trigger the swap logic if the binary exists, regardless of systemd state.
    if command -v firewall-cmd >/dev/null 2>&1; then

        # --- AUTOMATED MODE (CI/CD & Cloud-init) ---
        if [[ "$mode" == "auto" ]]; then
            local backend_choice="${SYSWARDEN_FIREWALL_BACKEND:-keep}"

            if [[ "$backend_choice" == "nftables" ]]; then
                log "INFO" "Auto-Deploy: Bypassing Firewalld for pure Nftables..."
                systemctl disable --now firewalld >/dev/null 2>&1 || true

                # --- FIX: Dynamic Nftables installation ---
                if ! command -v nft >/dev/null; then
                    if command -v dnf >/dev/null; then
                        dnf install -y nftables >/dev/null 2>&1 || true
                    elif command -v yum >/dev/null; then yum install -y nftables >/dev/null 2>&1 || true; fi
                fi
                # ------------------------------------------

                systemctl enable --now nftables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="nftables"
            elif [[ "$backend_choice" == "iptables" ]]; then
                log "INFO" "Auto-Deploy: Bypassing Firewalld for classic Iptables..."
                systemctl disable --now firewalld >/dev/null 2>&1 || true
                if command -v dnf >/dev/null; then
                    dnf install -y iptables-services >/dev/null 2>&1 || true
                elif command -v yum >/dev/null; then
                    yum install -y iptables-services >/dev/null 2>&1 || true
                fi
                systemctl enable --now iptables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="iptables"
            else
                log "INFO" "Auto-Deploy: Keeping Firewalld active."
            fi
            return
        fi

        # --- INTERACTIVE MODE ---
        echo -e "\n${BLUE}=== Step: Firewall Engine Optimization ===${NC}"
        echo -e "${YELLOW}WARNING: Firewalld is currently installed on your system.${NC}"
        echo -e "Because Firewalld uses D-Bus, injecting massive Threat Intelligence blocklists"
        echo -e "(100k+ IPs) can cause severe CPU bottlenecks and extremely slow reload times."
        echo -e "For production servers, we highly recommend bypassing Firewalld and using"
        echo -e "pure Nftables or classic Iptables directly in the kernel."

        local swap_fw
        read -p "Do you want SysWarden to replace Firewalld natively? (y/N): " swap_fw
        if [[ "$swap_fw" =~ ^[Yy]$ ]]; then
            echo -e "\nChoose your target Kernel backend:"
            echo -e "  1) Nftables (Modern, Recommended, Hardware Offload support)"
            echo -e "  2) Iptables (Classic SysAdmin choice, via iptables-services)"

            local fw_choice
            while true; do
                read -p "Select backend [1-2]: " fw_choice
                if [[ "$fw_choice" =~ ^[1-2]$ ]]; then break; fi
            done

            log "INFO" "Stopping and safely disabling Firewalld..."
            systemctl disable --now firewalld >/dev/null 2>&1 || true

            if [[ "$fw_choice" == "2" ]]; then
                log "INFO" "Installing and enabling classic Iptables persistence..."
                if command -v dnf >/dev/null; then
                    dnf install -y iptables-services >/dev/null 2>&1 || true
                elif command -v yum >/dev/null; then yum install -y iptables-services >/dev/null 2>&1 || true; fi
                systemctl enable --now iptables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="iptables"
                sed -i '/^FIREWALL_BACKEND=/d' "$CONF_FILE" 2>/dev/null || true
                echo "FIREWALL_BACKEND='iptables'" >>"$CONF_FILE"
                log "INFO" "Engine swapped: IPtables Active. Firewalld bypassed."
            else
                log "INFO" "Enabling pure Nftables persistence..."

                # --- FIX: Dynamic Nftables installation ---
                if ! command -v nft >/dev/null; then
                    if command -v dnf >/dev/null; then
                        dnf install -y nftables >/dev/null 2>&1 || true
                    elif command -v yum >/dev/null; then yum install -y nftables >/dev/null 2>&1 || true; fi
                fi
                # ------------------------------------------

                systemctl enable --now nftables >/dev/null 2>&1 || true
                FIREWALL_BACKEND="nftables"
                sed -i '/^FIREWALL_BACKEND=/d' "$CONF_FILE" 2>/dev/null || true
                echo "FIREWALL_BACKEND='nftables'" >>"$CONF_FILE"
                log "INFO" "Engine swapped: Nftables Active. Firewalld bypassed."
            fi
        else
            echo -e "${YELLOW}Keeping Firewalld. Note: Firewall reload operations will take longer.${NC}"
            log "INFO" "User opted to keep Firewalld despite performance warnings."
        fi
    fi
}
