setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (Custom) ===${NC}"

    # --- CI/CD AUTO MODE CHECK ---
    if [[ "${1:-}" == "auto" ]]; then
        response=${SYSWARDEN_ENABLE_WAZUH:-n}
        log "INFO" "Auto Mode: Wazuh Agent choice loaded via env var [${response}]"
    else
        # 1. Ask for confirmation
        read -p "Install Wazuh Agent? (y/N): " response
    fi
    # -----------------------------

    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping Wazuh Agent installation."
        return
    fi

    # 2. Gather Configuration Data
    if [[ "${1:-}" == "auto" ]]; then
        WAZUH_IP=${SYSWARDEN_WAZUH_IP:-""}
        W_NAME=${SYSWARDEN_WAZUH_NAME:-$(hostname)}
        W_GROUP=${SYSWARDEN_WAZUH_GROUP:-default}
        W_PORT_COMM=${SYSWARDEN_WAZUH_COMM_PORT:-1514}
        W_PORT_ENROLL=${SYSWARDEN_WAZUH_ENROLL_PORT:-1515}

        # --- SECURITY FIX: Strict Validation for Auto Mode (CWE-20: Improper Input Validation) ---
        if [[ -n "$WAZUH_IP" && ! "$WAZUH_IP" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && ! "$WAZUH_IP" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            log "ERROR" "Auto Mode: Invalid WAZUH_IP format. Skipping Wazuh installation."
            return
        fi
        if ! [[ "$W_PORT_COMM" =~ ^[0-9]+$ ]] || [ "$W_PORT_COMM" -lt 1 ] || [ "$W_PORT_COMM" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_COMM. Defaulting to 1514."
            W_PORT_COMM=1514
        fi
        if ! [[ "$W_PORT_ENROLL" =~ ^[0-9]+$ ]] || [ "$W_PORT_ENROLL" -lt 1 ] || [ "$W_PORT_ENROLL" -gt 65535 ]; then
            log "WARN" "Auto Mode: Invalid W_PORT_ENROLL. Defaulting to 1515."
            W_PORT_ENROLL=1515
        fi
        # -----------------------------------------------------
        log "INFO" "Auto Mode: Wazuh settings loaded via env vars."
    else
        # IP Serveur
        read -p "Enter Wazuh Manager IP: " WAZUH_IP
        if [[ -z "$WAZUH_IP" ]]; then
            log "ERROR" "Missing IP. Skipping."
            return
        fi

        # Hostname (Agent Name)
        read -p "Agent Name [Press Enter for '$(hostname)']: " W_NAME
        W_NAME=${W_NAME:-$(hostname)}

        # Group
        read -p "Agent Group [Press Enter for 'default']: " W_GROUP
        W_GROUP=${W_GROUP:-default}

        # Agent Port (Communication)
        read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
        W_PORT_COMM=${W_PORT_COMM:-1514}

        # Enrollment Port (Registration)
        read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
        W_PORT_ENROLL=${W_PORT_ENROLL:-1515}
    fi

    # --- SECURITY FIX: SANITIZE WAZUH STRINGS (CWE-20: Improper Input Validation) ---
    # Strip dangerous characters that could break the agent's OS environment exports
    W_NAME=$(echo "$W_NAME" | tr -cd 'a-zA-Z0-9.-')
    W_GROUP=$(echo "$W_GROUP" | tr -cd 'a-zA-Z0-9_-')

    # Fail-Safe
    if [[ -z "$WAZUH_IP" ]]; then
        log "ERROR" "Missing Wazuh IP. Skipping."
        return
    fi

    # Protocol (Default TCP)
    W_PROTO="TCP"

    # 3. Whitelist Wazuh Manager (Universal Firewall)
    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on ports $W_PORT_COMM & $W_PORT_ENROLL..."

    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        # RHEL / Alma / Rocky
        # Rules for Custom Ports
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_COMM' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_ENROLL' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
        firewall-cmd --reload

    elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        # Debian / Ubuntu (Modern)
        # We accept all traffic from Manager IP (Highest Priority) to ensure connectivity & Active Response
        nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
        log "INFO" "Nftables rule added for Wazuh Manager (Full Trust)."

        # ### MODULAR PERSISTENCE FIX ###
        log "INFO" "Saving SysWarden Nftables table to isolated config..."
        nft list table inet syswarden_table >/etc/syswarden/syswarden.nft
        # Enable service just in case
        systemctl enable nftables >/dev/null 2>&1 || true

    else
        # Fallback Iptables / IPSet
        if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT

            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi
    fi

    log "INFO" "Starting Wazuh Agent installation..."

    # 4. OS-Specific Installation Logic with EXPORTS
    # These variables are automatically read by the Wazuh package installer
    export WAZUH_MANAGER="$WAZUH_IP"
    export WAZUH_AGENT_NAME="$W_NAME"
    export WAZUH_AGENT_GROUP="$W_GROUP"
    export WAZUH_MANAGER_PORT="$W_PORT_COMM"        # Custom Agent Port
    export WAZUH_REGISTRATION_PORT="$W_PORT_ENROLL" # Custom Enrollment Port
    export WAZUH_PROTOCOL="$W_PROTO"

    if [[ -f /etc/debian_version ]]; then
        # --- DEBIAN / UBUNTU ---
        log "INFO" "Detected Debian/Ubuntu system."
        apt-get install -y gnupg apt-transport-https

        if curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import; then
            chmod 644 /usr/share/keyrings/wazuh.gpg
        else
            log "ERROR" "Failed to import GPG key."
            return
        fi
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

        apt-get update -qq
        apt-get install -y wazuh-agent

    elif [[ -f /etc/redhat-release ]]; then
        # --- RHEL / ALMA / ROCKY ---
        log "INFO" "Detected RHEL/Alma/Rocky system."
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat >/etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF
        dnf install -y wazuh-agent
    else
        log "ERROR" "Unsupported OS."
        return
    fi

    # 5. Enable and Persistence
    if systemctl list-unit-files | grep -q wazuh-agent; then
        systemctl daemon-reload
        systemctl enable --now wazuh-agent

        # Save config for uninstall reference
        echo "WAZUH_IP='$WAZUH_IP'" >>"$CONF_FILE"
        echo "WAZUH_AGENT_NAME='$W_NAME'" >>"$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >>"$CONF_FILE"
        echo "WAZUH_ENROLL_PORT='$W_PORT_ENROLL'" >>"$CONF_FILE"

        log "INFO" "Wazuh Agent '$W_NAME' installed (Group: $W_GROUP, Ports: $W_PORT_COMM/$W_PORT_ENROLL)."
    else
        log "ERROR" "Wazuh Agent installation seemed to fail."
    fi
}
