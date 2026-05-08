auto_whitelist_admin() {
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"

    local admin_ip=""

    # 1. Standard SSH env variables
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        admin_ip=$(echo "$SSH_CLIENT" | awk '{print $1}' || true)
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        admin_ip=$(echo "$SSH_CONNECTION" | awk '{print $1}' || true)
    fi

    # --- SECURITY FIX: BULLETPROOF KERNEL SOCKET DETECTION (CWE-345: Insufficient Verification of Data Authenticity) ---
    # Query active SSH sockets directly instead of relying on easily wiped SSH variables.
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        local current_tty
        current_tty=$(tty 2>/dev/null | sed 's#/dev/##' || true)

        if [[ -n "$current_tty" && "$current_tty" != "not a tty" ]]; then
            admin_ip=$(who 2>/dev/null | grep "$current_tty" | awk '{print $5}' | tr -d '()' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    # Ultimate fallback via SSHD sockets if no TTY is detected (e.g. CI/CD Pipeline)
    if [[ -z "$admin_ip" || ! "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if command -v ss >/dev/null; then
            admin_ip=$(ss -tnp 2>/dev/null | grep -i 'estab' | grep -i 'sshd' | awk '{print $5}' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
        fi
    fi

    # Process the IP
    if [[ "$admin_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$admin_ip" != "127.0.0.1" ]]; then
        # --- FIX: DO NOT AUTO-WHITELIST THE VPN SUBNET ---
        # If the admin is connected via WireGuard, we skip the absolute whitelist
        # because the VPN subnet is already allowed natively (Priority -50).
        local is_vpn_ip=0
        if [[ -n "${WG_SUBNET:-}" ]]; then
            local subnet_base
            subnet_base=$(echo "$WG_SUBNET" | cut -d'.' -f1,2,3)
            if [[ "$admin_ip" == "${subnet_base}."* ]]; then
                is_vpn_ip=1
            fi
        fi

        if [[ $is_vpn_ip -eq 1 ]]; then
            log "INFO" "Admin connected via VPN ($admin_ip). Skipping absolute whitelist."
        else
            if ! grep -q "^${admin_ip}$" "$WHITELIST_FILE" 2>/dev/null; then
                log "INFO" "Auto-whitelisting current admin SSH session IP: $admin_ip"
                echo "$admin_ip" >>"$WHITELIST_FILE"
            fi
        fi
    else
        log "WARN" "CRITICAL: Could not auto-detect admin SSH IP. You risk being locked out!"
    fi
}
