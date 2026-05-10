syswarden_jail_auditd() {
    local AUDIT_LOG="/var/log/audit/audit.log"

    if command -v auditd >/dev/null 2>&1 && [[ -f "$AUDIT_LOG" ]]; then
        log "INFO" "Auditd logs detected. Enabling System Integrity Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-auditd.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-auditd.conf
[syswarden-auditd]
enabled  = true
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
bantime  = 24h
EOF
    fi
}
