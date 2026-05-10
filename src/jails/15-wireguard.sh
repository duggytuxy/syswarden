syswarden_jail_wireguard() {
    if [[ -d "/etc/wireguard" ]]; then
        local WG_LOG=""

        if [[ -f "/var/log/kern-firewall.log" ]]; then
            WG_LOG="/var/log/kern-firewall.log"
        elif [[ -f "/var/log/kern.log" ]]; then
            WG_LOG="/var/log/kern.log"
        elif [[ -f "/var/log/messages" ]]; then
            WG_LOG="/var/log/messages"
        fi

        if [[ -n "$WG_LOG" ]]; then
            log "INFO" "WireGuard detected. Enabling UDP Jail."

            # Create Filter for Handshake Failures (Requires Kernel Logging)
            if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/wireguard.conf
[Definition]
failregex = ^.*?wireguard: .*? Handshake for peer .*? \(<HOST>:\d+\) did not complete.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >/etc/fail2ban/jail.d/wireguard.conf
[wireguard]
enabled = true
port    = 51820
protocol= udp
filter  = wireguard
logpath = $WG_LOG
maxretry = 5
bantime  = 24h
EOF
        fi
    fi
}
