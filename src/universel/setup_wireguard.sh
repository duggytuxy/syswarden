setup_wireguard() {
    if [[ "${USE_WIREGUARD:-n}" != "y" ]]; then
        return
    fi

    echo -e "\n${BLUE}=== Step: Configuring WireGuard VPN ===${NC}"

    # 1. IDEMPOTENCY CHECK: Never overwrite existing keys!
    if [[ -f "/etc/wireguard/wg0.conf" ]]; then
        log "INFO" "WireGuard configuration already exists. Skipping key generation to prevent VPN lockout."
        return
    fi

    log "INFO" "Initializing WireGuard cryptographic engine..."

    # 2. STRICT DIRECTORY SANDBOXING
    mkdir -p /etc/wireguard/clients
    chmod 700 /etc/wireguard
    chmod 700 /etc/wireguard/clients

    # 3. KERNEL ROUTING (IP FORWARDING)
    # Required for the VPN tunnel to access the internet and internal services
    log "INFO" "Enabling Kernel IPv4 Forwarding..."
    echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/99-syswarden-wireguard.conf
    sysctl -p /etc/sysctl.d/99-syswarden-wireguard.conf >/dev/null 2>&1 || true

    # 4. SECURE IN-MEMORY KEY GENERATION
    # Using local variables prevents keys from leaking into stdout or logs
    local SERVER_PRIV
    SERVER_PRIV=$(wg genkey)
    local SERVER_PUB
    SERVER_PUB=$(echo "$SERVER_PRIV" | wg pubkey)
    local CLIENT_PRIV
    CLIENT_PRIV=$(wg genkey)
    local CLIENT_PUB
    CLIENT_PUB=$(echo "$CLIENT_PRIV" | wg pubkey)
    local PRESHARED_KEY
    PRESHARED_KEY=$(wg genpsk)

    # 5. DYNAMIC NETWORK CALCULATIONS
    local ACTIVE_IF
    ACTIVE_IF=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+' | head -n 1)
    [[ -z "$ACTIVE_IF" ]] && ACTIVE_IF="eth0"

    local SERVER_IP
    SERVER_IP=$(curl -4 -s --connect-timeout 3 api.ipify.org 2>/dev/null ||
        curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null ||
        curl -4 -s --connect-timeout 3 icanhazip.com 2>/dev/null ||
        ip -4 addr show "$ACTIVE_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

    # Safely extract base network (e.g., 10.66.66.0/24 -> 10.66.66)
    local SUBNET_BASE
    SUBNET_BASE=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
    local SERVER_VPN_IP="${SUBNET_BASE}.1"
    local CLIENT_VPN_IP="${SUBNET_BASE}.2"

    # 6. DYNAMIC FIREWALL NAT (MASQUERADE)
    # Adapts WireGuard PostUp/PostDown hooks to the active firewall engine
    local POSTUP=""
    local POSTDOWN=""

    case "$FIREWALL_BACKEND" in
        "nftables")
            # NATIVE DEBIAN/UBUNTU
            # HOTFIX: We use single quotes around nft commands to avoid \' escaping issues in wg-quick.
            # We also explicitly inject FORWARD rules to allow internet access through the VPN.
            POSTUP="nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname \"$ACTIVE_IF\" masquerade'; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname \"wg0\" accept'; nft 'insert rule inet filter forward oifname \"wg0\" accept'"
            POSTDOWN="nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname \"wg0\" accept 2>/dev/null || true; nft delete rule inet filter forward oifname \"wg0\" accept 2>/dev/null || true"
            ;;
        "firewalld")
            # --- FIX ALMA/RHEL 10: NATIVE FIREWALLD ROUTING ---
            # No iptables/nft hacks. Firewalld handles NAT natively via its trusted zone.
            POSTUP=""
            POSTDOWN=""
            ;;
        *)
            # Fallback for UFW / Alpine Legacy
            POSTUP="iptables -t nat -I POSTROUTING 1 -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT"
            POSTDOWN="iptables -t nat -D POSTROUTING -s $WG_SUBNET -o $ACTIVE_IF -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true"
            ;;
    esac

    # --- SECURITY FIX: PREVENT TOCTOU RACE CONDITION ON KEYS (CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition) ---
    # Enclosing file creation in a umask 077 subshell to ensure native 600 permissions
    (
        umask 077

        # 7. WRITE SERVER CONFIGURATION (wg0.conf)
        log "INFO" "Deploying WireGuard Server Profile..."
        cat <<EOF >/etc/wireguard/wg0.conf
# SysWarden WireGuard Server Configuration
[Interface]
Address = ${SERVER_VPN_IP}/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
PostUp = $POSTUP
PostDown = $POSTDOWN

[Peer]
# Admin Workstation Client
PublicKey = $CLIENT_PUB
PresharedKey = $PRESHARED_KEY
AllowedIPs = ${CLIENT_VPN_IP}/32
EOF

        # 8. WRITE CLIENT CONFIGURATION (admin-pc.conf)
        log "INFO" "Generating Secure Client Profile..."
        cat <<EOF >/etc/wireguard/clients/admin-pc.conf
[Interface]
PrivateKey = $CLIENT_PRIV
Address = ${CLIENT_VPN_IP}/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $PRESHARED_KEY
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    )
    # -----------------------------------------------------------
    chmod 600 /etc/wireguard/clients/admin-pc.conf

    # 9. SERVICE ORCHESTRATION
    log "INFO" "Starting WireGuard Tunnel Interface (wg0)..."
    if command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl enable --now wg-quick@wg0 >/dev/null 2>&1 || true
    fi

    log "INFO" "WireGuard VPN deployed successfully."

    # --- FIX: Restore default OS umask to prevent strict permission leaks to other functions ---
    umask 022
}
