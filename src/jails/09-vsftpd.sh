syswarden_jail_vsftpd() {
    if [[ -f "/var/log/vsftpd.log" ]]; then
        log "INFO" "VSFTPD logs detected. Enabling FTP Jail."

        cat <<EOF >/etc/fail2ban/jail.d/vsftpd.conf
[vsftpd]
enabled = true
port    = ftp,ftp-data,ftps,20,21
logpath = /var/log/vsftpd.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
    fi
}
