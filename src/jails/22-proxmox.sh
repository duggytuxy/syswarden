syswarden_jail_proxmox() {
    if command -v pveversion >/dev/null 2>&1; then
        log "INFO" "Proxmox VE detected. Enabling PVE Jail."

        local PVE_LOG="/var/log/daemon.log"
        if [[ ! -f "$PVE_LOG" ]]; then
            PVE_LOG="/var/log/syslog"
        fi

        # Filter for Proxmox Web GUI Auth Failures
        if [[ ! -f "/etc/fail2ban/filter.d/proxmox-custom.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^.*pvedaemon\\[\\d+\\]: authentication failure; rhost=<HOST> user=.*\$\nignoreregex =" >/etc/fail2ban/filter.d/proxmox-custom.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/proxmox.conf
[proxmox-custom]
enabled = true
port    = https,8006
filter  = proxmox-custom
logpath = $PVE_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
