syswarden_jail_squid() {
    if [[ -f "/var/log/squid/access.log" ]]; then
        log "INFO" "Squid Proxy logs detected. Enabling Squid Jail."

        # Create Filter for Proxy Abuse (TCP_DENIED / 403 / 407)
        if [[ ! -f "/etc/fail2ban/filter.d/squid-custom.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" >/etc/fail2ban/filter.d/squid-custom.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/squid.conf
[squid-custom]
enabled = true
port    = 3128,8080
filter  = squid-custom
logpath = /var/log/squid/access.log
maxretry = 5
bantime  = 24h
EOF
    fi
}
