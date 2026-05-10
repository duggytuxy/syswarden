syswarden_jail_sendmail() {
    local SM_LOG=""

    if [[ -f "/var/log/mail.log" ]]; then
        SM_LOG="/var/log/mail.log" # Debian/Ubuntu
    elif [[ -f "/var/log/maillog" ]]; then
        SM_LOG="/var/log/maillog" # RHEL/Alma
    fi

    # Check if Sendmail is installed to avoid conflict with Postfix
    if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
        log "INFO" "Sendmail detected. Enabling Sendmail Jails."

        cat <<EOF >/etc/fail2ban/jail.d/sendmail.conf
[sendmail-auth]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 3
bantime  = 24h

[sendmail-reject]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
