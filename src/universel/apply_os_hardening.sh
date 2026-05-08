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
    local current_admin="${SUDO_USER:-}"

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
}
