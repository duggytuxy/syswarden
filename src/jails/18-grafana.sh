syswarden_jail_grafana() {
    if [[ -f "/var/log/grafana/grafana.log" ]]; then
        log "INFO" "Grafana logs detected. Enabling Grafana Jail."

        # Create Filter for Grafana Auth Failures
        if [[ ! -f "/etc/fail2ban/filter.d/grafana-auth.conf" ]]; then
            echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/grafana-auth.conf
        fi

        cat <<EOF >/etc/fail2ban/jail.d/grafana.conf
[grafana-auth]
enabled = true
port    = 3000,http,https
filter  = grafana-auth
logpath = /var/log/grafana/grafana.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
