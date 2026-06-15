syswarden_jail_wireguard() {
    # 1. Fail-Fast: Verify kernel module or active interface at the absolute top
    if ! ip link show type wireguard >/dev/null 2>&1 && ! lsmod 2>/dev/null | grep -q wireguard; then
        return 0
    fi

    local WG_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/kern-firewall.log" ]]; then
        WG_LOG="/var/log/kern-firewall.log"
    elif [[ -f "/var/log/kern.log" ]]; then
        WG_LOG="/var/log/kern.log"
    elif [[ -f "/var/log/messages" ]]; then
        WG_LOG="/var/log/messages"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$WG_LOG" ]]; then
        return 0
    fi

    log "INFO" "WireGuard interface and kernel logs detected. Enabling UDP Jail."

    # Create Filter for Handshake Failures (Requires Kernel Logging)
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-wireguard.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-wireguard.conf
[Definition]
failregex = ^.*?wireguard: .*? Handshake for peer .*? \(<HOST>:\d+\) did not complete.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    # [DEVSECOPS FIX] Enforced 'syswarden-' namespace to prevent OS collisions and allow surgical updates
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-wireguard.conf
[syswarden-wireguard]
enabled  = true
port     = 51820
protocol = udp
filter   = syswarden-wireguard
logpath  = $WG_LOG
maxretry = 5
bantime  = 24h
EOF
}
