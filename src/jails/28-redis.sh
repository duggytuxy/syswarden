syswarden_jail_redis() {
    local REDIS_LOG=""
    if [[ -f "/var/log/redis/redis-server.log" ]]; then
        REDIS_LOG="/var/log/redis/redis-server.log"
    elif [[ -f "/var/log/redis/redis.log" ]]; then
        REDIS_LOG="/var/log/redis/redis.log"
    fi

    if [[ -n "$REDIS_LOG" ]]; then
        log "INFO" "Redis logs detected. Enabling Redis Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-redis.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-redis.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? [Aa]uthentication failed.*$
            ^.*? Client <HOST>:\d+ disconnected, .*? [Aa]uthentication.*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-redis.conf
[syswarden-redis]
enabled  = true
port     = 6379
filter   = syswarden-redis
logpath  = $REDIS_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
    fi
}
