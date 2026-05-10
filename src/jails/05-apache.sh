syswarden_jail_apache() {
    local APACHE_LOG=""
    local APACHE_ACCESS=""

    if [[ -f "/var/log/apache2/error.log" ]]; then
        APACHE_LOG="/var/log/apache2/error.log"
        APACHE_ACCESS="/var/log/apache2/access.log"
    elif [[ -f "/var/log/httpd/error_log" ]]; then
        APACHE_LOG="/var/log/httpd/error_log"
        APACHE_ACCESS="/var/log/httpd/access_log"
    fi

    if [[ -n "$APACHE_LOG" ]]; then
        log "INFO" "Apache logs detected. Enabling Apache Jail."

        # Create Filter for 404/403 scanners (Apache specific)
        if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/apache-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405)
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/apache.conf
[apache-auth]
enabled = true
port = http,https
logpath = $APACHE_LOG
backend = auto

[apache-scanner]
enabled = true
port    = http,https
filter  = apache-scanner
logpath = $APACHE_ACCESS
backend = auto
maxretry = 15
bantime  = 24h
EOF
    fi
}
