syswarden_jail_badbots() {
    if [[ -n "${SYSW_RCE_LOGS:-}" ]]; then
        log "INFO" "Web access logs detected. Enabling Bad-Bot & Scanner Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) [^"]*?" \d{3} [^"]*? "[^"]*?(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf)[^"]*?"
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-badbots.conf
[syswarden-badbots]
enabled  = true
port     = http,https
filter   = syswarden-badbots
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
    fi
}
