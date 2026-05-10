syswarden_jail_jenkins() {
    if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
        log "INFO" "Jenkins CI/CD logs detected. Enabling Jenkins Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jenkins.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-jenkins.conf
[syswarden-jenkins]
enabled  = true
port     = http,https,8080
filter   = syswarden-jenkins
logpath  = /var/log/jenkins/jenkins.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
