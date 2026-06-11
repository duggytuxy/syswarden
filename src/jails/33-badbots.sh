syswarden_jail_badbots() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Bad-Bot & Scanner Guard."

    # Create Filter for Vulnerability Scanners and Aggressive Recon Tools
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
# Matches signatures of common offensive security tools and aggressive scanners
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) [^"]*?" \d{3} [^"]*? "[^"]*?(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf)[^"]*?"
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Zero tolerance for security scanners
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
}
