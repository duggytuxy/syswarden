syswarden_jail_privesc() {
    local AUTH_LOG=""
    if [[ -f "/var/log/auth-syswarden.log" ]]; then
        AUTH_LOG="/var/log/auth-syswarden.log"
    elif [[ -f "/var/log/auth.log" ]]; then
        AUTH_LOG="/var/log/auth.log"
    elif [[ -f "/var/log/secure" ]]; then
        AUTH_LOG="/var/log/secure"
    fi

    if [[ -n "$AUTH_LOG" ]]; then
        log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-privesc.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-privesc.conf
[INCLUDES]
before = common.conf

[Definition]
failregex = ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^%(__prefix_line)s PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-privesc.conf
[syswarden-privesc]
enabled = true
port    = 0:65535
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
bantime  = 24h
EOF
    fi
}
