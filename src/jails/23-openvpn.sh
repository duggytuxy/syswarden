syswarden_jail_openvpn() {
    local OVPN_LOG=""

    if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
        OVPN_LOG="/var/log/openvpn/openvpn.log"
    elif [[ -f "/var/log/openvpn.log" ]]; then
        OVPN_LOG="/var/log/openvpn.log"
    elif [[ -f "/var/log/syslog" ]]; then
        OVPN_LOG="/var/log/syslog"
    fi

    if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
        log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."

        # Filter for OpenVPN TLS Handshake & Verification Errors
        if [[ ! -f "/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*\$\nignoreregex =" >/etc/fail2ban/filter.d/openvpn-custom.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/openvpn.conf
[openvpn-custom]
enabled = true
port    = 1194
protocol= udp
filter  = openvpn-custom
logpath = $OVPN_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
