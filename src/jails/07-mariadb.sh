syswarden_jail_mariadb() {
    local MARIADB_LOG=""

    if [[ -f "/var/log/mysql/error.log" ]]; then
        MARIADB_LOG="/var/log/mysql/error.log"
    elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then
        MARIADB_LOG="/var/log/mariadb/mariadb.log"
    fi

    if [[ -n "$MARIADB_LOG" ]]; then
        log "INFO" "MariaDB logs detected. Enabling MariaDB Jail."

        # Create Filter for Authentication Failures
        if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/mariadb-auth.conf
[Definition]
failregex = ^.*? \[?(?:Note|Warning|ERROR)\]? [Aa]ccess denied for user .*?@'<HOST>'(?: \(using password: (?:YES|NO)\))?
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/mariadb.conf
[mariadb-auth]
enabled = true
port = 3306
filter = mariadb-auth
logpath = $MARIADB_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
    fi
}
