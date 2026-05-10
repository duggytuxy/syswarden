syswarden_jail_odoo() {
    local ODOO_LOG=""

    # Search for standard Odoo log files
    if [[ -f "/var/log/odoo/odoo-server.log" ]]; then
        ODOO_LOG="/var/log/odoo/odoo-server.log"
    elif [[ -f "/var/log/odoo/odoo.log" ]]; then
        ODOO_LOG="/var/log/odoo/odoo.log"
    fi

    if [[ -n "$ODOO_LOG" ]]; then
        log "INFO" "Odoo ERP logs detected. Enabling Odoo Guard."

        # Create Filter for Odoo Authentication Failures
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-odoo.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-odoo.conf
[Definition]
failregex = ^.*? \d+ INFO \S+ odoo\.addons\.base\.models\.res_users: Login failed for db:.*? login:.*? from <HOST>.*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-odoo.conf
[syswarden-odoo]
enabled  = true
port     = http,https,8069
filter   = syswarden-odoo
logpath  = $ODOO_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
    fi
}
