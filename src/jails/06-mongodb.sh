syswarden_jail_mongodb() {
    if [[ -f "/var/log/mongodb/mongod.log" ]]; then
        log "INFO" "MongoDB logs detected. Enabling Mongo Jail."

        # Create strict Filter for Auth failures & Unauthorized commands
        if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/mongodb-guard.conf
[Definition]
failregex = ^.*? (?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).*? (?:<HOST>|remote:\s*<HOST>:\d+)
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/mongodb.conf
[mongodb-guard]
enabled = true
port = 27017
filter = mongodb-guard
logpath = /var/log/mongodb/mongod.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
