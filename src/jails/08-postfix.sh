syswarden_jail_postfix() {
    local POSTFIX_LOG=""

    if [[ -f "/var/log/mail.log" ]]; then
        POSTFIX_LOG="/var/log/mail.log"
    elif [[ -f "/var/log/maillog" ]]; then
        POSTFIX_LOG="/var/log/maillog"
    fi

    if [[ -n "$POSTFIX_LOG" ]]; then
        log "INFO" "Postfix logs detected. Enabling SMTP Jails."

        cat <<EOF >/etc/fail2ban/jail.d/postfix.conf
[postfix]
enabled = true
mode    = aggressive
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto

[postfix-sasl]
enabled = true
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
