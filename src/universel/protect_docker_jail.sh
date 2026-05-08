protect_docker_jail() {
    echo -e "\n${BLUE}=== SysWarden Docker Jail Protector ===${NC}"

    # --- HOTFIX: DEPENDENCY & STATE VERIFICATION ---
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    fi

    if [[ "${USE_DOCKER:-n}" != "y" ]]; then
        log "ERROR" "Docker integration is disabled in SysWarden. Run the installer to enable it."
        exit 1
    fi

    local action_file="/etc/fail2ban/action.d/syswarden-docker.conf"
    if [[ ! -f "$action_file" ]]; then
        log "ERROR" "Docker banaction ($action_file) is missing. Cannot protect Docker jails."
        exit 1
    fi
    # ------------------------------------------------------

    local jail_file="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_file" ]]; then
        log "ERROR" "Fail2ban configuration ($jail_file) not found."
        exit 1
    fi

    # Display active jails to help the user
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        local active_jails
        active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
        echo -e "Currently active Jails: ${YELLOW}${active_jails}${NC}"
    fi

    read -p "Enter the exact name of your custom Docker Jail (e.g. 'nginx-docker'): " jail_name

    # Trim whitespace and sanitize: allow only alphanumeric, dashes, and underscores
    jail_name=$(echo "$jail_name" | xargs | tr -cd 'a-zA-Z0-9_-')

    if [[ -z "$jail_name" ]]; then
        log "ERROR" "Jail name cannot be empty."
        exit 1
    fi

    # Check if the jail block exists in the configuration file
    if ! grep -q "^\[${jail_name}\]" "$jail_file"; then
        log "ERROR" "Jail [${jail_name}] not found in $jail_file. Please create it first."
        exit 1
    fi

    log "INFO" "Configuring jail [${jail_name}] to use Docker banaction..."

    # Safely inject or update banaction exclusively within the specified jail block
    local temp_file
    temp_file=$(mktemp)
    local in_target_jail=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            if [[ "$line" == "[${jail_name}]" ]]; then
                in_target_jail=1
                echo "$line" >>"$temp_file"
                echo "banaction = syswarden-docker" >>"$temp_file"
                continue
            else
                in_target_jail=0
            fi
        fi

        # If inside the target block, skip any pre-existing 'banaction' line to avoid duplicates
        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >>"$temp_file"
    done <"$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."

    if command -v systemctl >/dev/null; then
        systemctl restart fail2ban
        log "INFO" "Fail2ban service restarted to apply changes."

        # --- HOTFIX: STATEFUL DOCKER BYPASS RE-ENFORCEMENT ---
        # Fail2ban restarts will inject new chains at the top of DOCKER-USER.
        # We MUST ensure the ESTABLISHED, RELATED rule remains at Absolute Priority 0.
        if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            while iptables -D DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
            iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null || true
            log "INFO" "Stateful Docker bypass successfully re-enforced at Priority 0."

            # Persist state so the new order survives reboots
            if command -v netfilter-persistent >/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then
                service iptables save 2>/dev/null || true
            fi
        fi
        # ------------------------------------------------------------
    fi
}
