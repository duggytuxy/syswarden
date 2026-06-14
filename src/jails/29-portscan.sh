syswarden_jail_portscan() {
    local FIREWALL_LOG=""

    # 1. Dynamic log path discovery for Kernel/Netfilter messages
    if [[ -f "/var/log/kern-firewall.log" ]]; then
        FIREWALL_LOG="/var/log/kern-firewall.log"
    elif [[ -f "/var/log/kern.log" ]]; then
        FIREWALL_LOG="/var/log/kern.log"
    elif [[ -f "/var/log/messages" ]]; then
        FIREWALL_LOG="/var/log/messages"
    elif [[ -f "/var/log/syslog" ]]; then
        FIREWALL_LOG="/var/log/syslog"
    fi

    # 2. Fail-Fast: Ensure kernel logs exist to prevent Fail2ban crash
    if [[ -z "$FIREWALL_LOG" ]]; then
        return 0
    fi

    log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."

    # Create Filter for SysWarden kernel drop prefixes (BLOCK, GEO, ASN)
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-portscan.conf" ]]; then
        # Safe Heredoc with literal parsing
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-portscan.conf
[INCLUDES]
before = common.conf

[Definition]
# Matches ONLY the Catch-All drops to detect actual probing on closed ports.
# Prevents double-punishment for IPs already dropped by HW/Kernel sets (GEO/ASN).
failregex = ^%(__prefix_line)s(?:kernel:\s+)?(?:\[\s*\d+\.\d+\]\s+)?\[SysWarden-BLOCK\] \[Catch-All\].*?SRC=<HOST> 
EOF

        # [DEVSECOPS FIX] Dynamic Whitelist Injection to bypass Fail2ban global ignoreip
        local WL_REGEX=""
        if [[ -f "/etc/syswarden/whitelist.txt" ]]; then
            WL_REGEX=$(grep -vE '^\s*#|^\s*$' /etc/syswarden/whitelist.txt | awk '{print $1}' | sed 's/\./\\./g' | tr '\n' '|' | sed 's/|$//')
        fi

        if [[ -n "$WL_REGEX" ]]; then
            echo "ignoreregex = SRC=($WL_REGEX) " >>/etc/fail2ban/filter.d/syswarden-portscan.conf
        else
            echo "ignoreregex =" >>/etc/fail2ban/filter.d/syswarden-portscan.conf
        fi
    fi

    # [DEVSECOPS FIX] Dynamic Banaction to prevent dead-routing on backend swaps
    # Resolves the RHEL/Alma paradox where Fail2ban attempts to use firewalld
    # rich-rules while SysWarden has engaged pure native nftables offloading.
    local f2b_banaction="iptables-allports"
    if [[ "${FIREWALL_BACKEND}" == "nftables" ]]; then
        f2b_banaction="nftables-allports"
    elif [[ "${FIREWALL_BACKEND}" == "firewalld" ]]; then
        f2b_banaction="firewallcmd-allports"
    elif [[ "${FIREWALL_BACKEND}" == "ufw" ]]; then
        f2b_banaction="ufw"
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-portscan.conf
[syswarden-portscan]
enabled   = true
port      = 0:65535
filter    = syswarden-portscan
logpath   = $FIREWALL_LOG
backend   = \${SYSW_OS_BACKEND:-auto}
banaction = $f2b_banaction
maxretry  = 10
findtime  = 10m
bantime   = 24h
EOF
}
