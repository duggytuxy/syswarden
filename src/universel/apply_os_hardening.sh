apply_os_hardening() {
    if [[ "${APPLY_OS_HARDENING:-n}" != "y" ]]; then
        return
    fi

    log "INFO" "Applying strict OS hardening (Crontab, Sudo/Wheel, Profiles)..."

    # 1. Lock down Crontab (Only root can schedule tasks)
    echo "root" >/etc/cron.allow
    chmod 600 /etc/cron.allow
    rm -f /etc/cron.deny 2>/dev/null || true

    # 2. Backup and Purge non-root users from privileged groups (sudo/wheel/adm)
    mkdir -p "$SYSWARDEN_DIR"

    # Cascade detection to reliably identify the authenticating user even if 'su -' was used
    local current_admin="${SUDO_USER:-}"
    if [[ -z "$current_admin" ]]; then
        current_admin=$(logname 2>/dev/null || true)
    fi
    if [[ -z "$current_admin" ]]; then
        current_admin=$(who am i | awk '{print $1}' 2>/dev/null || true)
    fi

    for grp in sudo wheel adm; do
        if grep -q "^${grp}:" /etc/group 2>/dev/null; then
            # Backup current members
            local members
            members=$(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group)
            if [[ -n "$members" && "$members" != "root" ]]; then
                echo "${grp}:${members}" >>"$SYSWARDEN_DIR/group_backup.txt"
            fi

            # Purge non-root users
            for user in $(awk -F':' -v g="$grp" '$1==g {print $4}' /etc/group | tr ',' ' ' 2>/dev/null); do
                if [[ -n "$user" ]] && [[ "$user" != "root" ]]; then
                    # --- SAFEGUARD: Never purge the executing admin ---
                    if [[ -n "$current_admin" ]] && [[ "$user" == "$current_admin" ]]; then
                        log "INFO" "SAFEGUARD: Preserving current admin '$user' in '$grp' group."
                        continue
                    fi
                    gpasswd -d "$user" "$grp" >/dev/null 2>&1 || true
                    log "INFO" "Removed user '$user' from '$grp' group."
                fi
            done
        fi
    done

    # 3. Lock down profiles for standard users (Prevents SSH Login backdoors)
    for user_dir in /home/*; do
        if [[ -d "$user_dir" ]]; then
            local user_name
            user_name=$(basename "$user_dir")
            # Preserve current admin's profile to avoid breaking their active SSH session
            if [[ -n "$current_admin" ]] && [[ "$user_name" == "$current_admin" ]]; then
                continue
            fi
            for profile_file in "$user_dir/.profile" "$user_dir/.bashrc" "$user_dir/.bash_profile"; do
                if [[ -f "$profile_file" ]]; then
                    chattr -i "$profile_file" 2>/dev/null || true
                    chown "$user_name:$user_name" "$profile_file"
                    chmod 644 "$profile_file"
                    chattr +i "$profile_file" 2>/dev/null || true
                fi
            done
        fi
    done

    # 4. Log Anti-Forging & CRLF Mitigation (Rsyslog & Journald)
    log "INFO" "Applying strict anti-forging rules to system logging daemons..."

    # Rsyslog Hardening: Escape control characters to block CRLF injection
    # This prevents attackers from injecting \n to forge fake "cron" or "syslog" entries
    if [[ -d "/etc/rsyslog.d" ]]; then
        local RSYSLOG_SEC_CONF="/etc/rsyslog.d/99-syswarden-antiforging.conf"

        cat <<'EOF' >"$RSYSLOG_SEC_CONF"
# --- SysWarden: Anti Log Forging & CRLF Mitigation ---
# Explicitly enforce escaping of control characters (including \n, \r)
# This converts malicious newlines into safe escape sequences (e.g., #012)
$EscapeControlCharactersOnReceive on

# Drop trailing line feeds to maintain log integrity
$DropTrailingLFOnReception on
EOF

        # Validate and restart rsyslog silently
        if rsyslogd -N1 >/dev/null 2>&1; then
            systemctl restart rsyslog 2>/dev/null || true
            log "SUCCESS" "Rsyslog anti-forging module deployed."
        else
            log "ERROR" "Rsyslog configuration validation failed. Reverting."
            rm -f "$RSYSLOG_SEC_CONF"
        fi
    fi

    # Systemd Journald Hardening (Defense in Depth)
    # Ensure ForwardToSyslog doesn't pass raw unescaped payloads if manipulated
    if [[ -f "/etc/systemd/journald.conf" ]]; then
        if ! grep -q "^ForwardToSyslog=yes" "/etc/systemd/journald.conf"; then
            sed -i 's/.*ForwardToSyslog.*/ForwardToSyslog=yes/' "/etc/systemd/journald.conf" 2>/dev/null || true
            systemctl restart systemd-journald 2>/dev/null || true
        fi
    fi
}
