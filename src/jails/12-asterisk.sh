syswarden_jail_asterisk() {
    local ASTERISK_LOG=""

    if [[ -f "/var/log/asterisk/messages" ]]; then
        ASTERISK_LOG="/var/log/asterisk/messages"
    elif [[ -f "/var/log/asterisk/full" ]]; then
        ASTERISK_LOG="/var/log/asterisk/full"
    fi

    if [[ -n "$ASTERISK_LOG" ]]; then
        log "INFO" "Asterisk logs detected. Enabling VoIP Jail."

        cat <<EOF >/etc/fail2ban/jail.d/asterisk.conf
[asterisk]
enabled  = true
filter   = asterisk
port     = 5060,5061
logpath  = $ASTERISK_LOG
maxretry = 5
bantime  = 24h
EOF
    fi
}
