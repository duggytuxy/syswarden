syswarden_jail_revshell() {
    if [[ -n "$SYSW_RCE_LOGS" ]]; then
        log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc(?:\s+|\x2520|\x2509|\+)+(?:-e|-c)|(?:curl|wget)(?:\s+|\x2520|\x2509|\+)+(?:-q|-s|-O|http)|python(?:\s+|\x2520|\x2509|\+)+-c|php(?:\s+|\x2520|\x2509|\+)+-r|(?:\x253B|;|\x257C|\||`|\x2560|\$|\x2524)(?:\s+|\x2520|\x2509|\+)*(?:bash|sh|nc|curl|wget|chmod)).*?" .*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-revshell.conf
[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
findtime = 3600
bantime  = 24h
EOF
    fi
}
