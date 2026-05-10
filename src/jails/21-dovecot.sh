syswarden_jail_dovecot() {
    local DOVECOT_LOG=""

    if [[ -f "/var/log/mail.log" ]]; then
        DOVECOT_LOG="/var/log/mail.log"
    elif [[ -f "/var/log/maillog" ]]; then
        DOVECOT_LOG="/var/log/maillog"
    fi

    if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
        log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."

        # Filter for Dovecot Auth Failures (catches standard rip=IP format)
        if [[ ! -f "/etc/fail2ban/filter.d/dovecot-custom.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*\$\nignoreregex =" >/etc/fail2ban/filter.d/dovecot-custom.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/dovecot.conf
[dovecot-custom]
enabled = true
port    = pop3,pop3s,imap,imaps,submission,465,587
filter  = dovecot-custom
logpath = $DOVECOT_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
