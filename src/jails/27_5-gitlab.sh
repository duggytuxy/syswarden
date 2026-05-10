syswarden_jail_gitlab() {
    local GITLAB_LOG=""
    if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
        GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
    elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then
        GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"
    fi

    if [[ -n "$GITLAB_LOG" ]]; then
        log "INFO" "GitLab logs detected. Enabling GitLab Guard."

        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
        fi

        cat <<EOF >/etc/fail2ban/jail.d/syswarden-gitlab.conf
[syswarden-gitlab]
enabled  = true
port     = http,https
filter   = syswarden-gitlab
logpath  = $GITLAB_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
