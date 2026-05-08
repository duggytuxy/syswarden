setup_cron_autoupdate() {
    # No manuel cron update function
    if [[ "${1:-}" != "update" ]] && [[ "${1:-}" != "cron-update" ]]; then
        local script_path
        script_path=$(realpath "$0")
        local cron_file="/etc/cron.d/syswarden-update"
        local random_min=$((RANDOM % 60))

        # FIX DEVSECOPS
        echo "$random_min * * * * root $script_path cron-update >/dev/null 2>&1" >"$cron_file"
        chmod 644 "$cron_file"

        log "INFO" "Automatic updates enabled."

        cat <<EOF >/etc/logrotate.d/syswarden
/var/log/kern.log
/var/log/syslog
/var/log/messages
$LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
    fi
}
