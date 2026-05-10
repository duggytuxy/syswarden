syswarden_jail_rabbitmq() {
    local RABBIT_LOG=""
    if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
        RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
    elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then
        RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
    fi

    if [[ -n "$RABBIT_LOG" ]]; then
        log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-rabbitmq.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-rabbitmq.conf
[Definition]
failregex = ^.*?HTTP access denied: .*? from <HOST>.*$
            ^.*?AMQP connection <HOST>:\d+ .*? failed: .*?authentication failure.*$
            ^.*?<HOST>:\d+ .*? (?:invalid credentials|authentication failed).*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-rabbitmq.conf
[syswarden-rabbitmq]
enabled  = true
port     = 5672,15672
filter   = syswarden-rabbitmq
logpath  = $RABBIT_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
    fi
}
