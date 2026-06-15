configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS & FILTERS ---
        log "INFO" "Purging legacy SysWarden definitions to prevent rule conflicts..."
        if [[ ! -d /etc/fail2ban/jail.d ]]; then
            mkdir -p /etc/fail2ban/jail.d
            chmod 755 /etc/fail2ban/jail.d
        else
            # 1. Surgical cleanup for the new strict namespace
            rm -f /etc/fail2ban/jail.d/syswarden-*.conf 2>/dev/null || true
            rm -f /etc/fail2ban/jail.d/syswarden-*.local 2>/dev/null || true

            # 2. [DEVSECOPS FIX] Legacy Cleanup (The Transition from v1.00 to Namespace)
            # We must explicitly destroy old SysWarden configurations that lacked the prefix
            # so they do not cause Double-Jail instances (e.g. cockpit-custom AND syswarden-cockpit).
            for legacy in nginx-scanner mariadb-auth mongodb-guard wordpress-auth drupal-auth nextcloud openvpn-custom gitea-custom cockpit-custom proxmox-custom haproxy-guard phpmyadmin-custom squid-custom dovecot-custom laravel-auth grafana-auth zabbix-auth wireguard nginx mariadb mongodb apache auditd slowloris homoglyph privesc portscan revshell aibots badbots httpflood webshell sqli-xss secretshunter ssrf jndi-ssti lfi-advanced apimapper vaultwarden idor-enum sso silent-scanner cms-honeypot proxy-abuse telnet generic-auth odoo prestashop atlassian dolibarr apache-tls nginx-tls apache-scanner; do
                rm -f "/etc/fail2ban/jail.d/${legacy}.conf" 2>/dev/null || true
                rm -f "/etc/fail2ban/filter.d/${legacy}.conf" 2>/dev/null || true
            done
        fi
        rm -f /etc/fail2ban/filter.d/syswarden-*.conf 2>/dev/null || true
        log "INFO" "Purged legacy SysWarden rules while strictly preserving third-party administrator configurations."

        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
dbpurgeage = 691200
EOF

        # --- DEVSECOPS FIX: NATIVE EL10 NFTABLES ENGINE ---
        # Deploys the POSIX-compliant multi-protocol (TCP/UDP/ICMP/QUIC) action.
        # Bypasses CLI flag parsing errors on 'priority -1' using '--'.
        log "INFO" "Deploying native syswarden-nft action for AlmaLinux 10+ compatibility..."
        cat <<'EOF_ACTION_NFT' >/etc/fail2ban/action.d/syswarden-nft.conf
[Definition]
actionstart = nft add table inet syswarden_f2b
              nft -- add chain inet syswarden_f2b <name> \{ type filter hook input priority -1 \; \}
              nft add set inet syswarden_f2b <addr_set> \{ type <addr_type> \; \}
              nft flush chain inet syswarden_f2b <name>
              nft add rule inet syswarden_f2b <name> <addr_family> saddr @<addr_set> drop

actionstop =  nft flush chain inet syswarden_f2b <name>
              nft delete chain inet syswarden_f2b <name>
              nft delete set inet syswarden_f2b <addr_set>

actioncheck = nft list set inet syswarden_f2b <addr_set> >/dev/null

actionban =   nft add element inet syswarden_f2b <addr_set> \{ <ip> \}

actionunban = nft delete element inet syswarden_f2b <addr_set> \{ <ip> \}

[Init]
name = default
addr_family = ip
addr_type = ipv4_addr
addr_set = f2b-<name>
EOF_ACTION_NFT

        # 2. Firewall Backend & OS Optimization (Zero Trust AllPorts)
        export SYSW_F2B_ACTION="iptables-allports"
        export SYSW_F2B_ACTION_ALLPORTS="iptables-allports"

        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
            export SYSW_F2B_ACTION="firewallcmd-ipset"
            export SYSW_F2B_ACTION_ALLPORTS="firewallcmd-ipset"
        elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            export SYSW_F2B_ACTION="syswarden-nft"
            export SYSW_F2B_ACTION_ALLPORTS="syswarden-nft"
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
            export SYSW_F2B_ACTION="ufw"
            export SYSW_F2B_ACTION_ALLPORTS="ufw"
        fi

        export SYSW_OS_BACKEND="auto"
        if command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-journald 2>/dev/null; then
            export SYSW_OS_BACKEND="systemd"
        fi

        # 3. Dynamic Whitelist Array Construction
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"

        local public_ip
        public_ip=$(ip -4 addr show | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | grep -v '127.0.0.1' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi

        # Short-circuit internal telemetry evaluation loops by forcing all local interfaces to be ignored
        local all_local_ips
        all_local_ips=$(ip -4 addr show | awk '/inet / {print $2}' | cut -d/ -f1 | tr '\n' ' ' || true)
        if [[ -n "$all_local_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $all_local_ips"; fi

        local local_subnets
        local_subnets=$(ip -4 route | grep -v default | awk '{print $1}' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi

        if [[ -f /etc/resolv.conf ]]; then
            local dns_ips
            dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi

        # --- SECURITY FIX: F-012 (Fail2ban ignoreip overlaps global allowlist) ---
        # Synchronize Fail2ban memory with the global Zero Trust whitelist to prevent rule shadowing
        if [[ -f "$WHITELIST_FILE" ]]; then
            local global_whitelisted_ips
            global_whitelisted_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            if [[ -n "$global_whitelisted_ips" ]]; then
                f2b_ignoreip="$f2b_ignoreip $global_whitelisted_ips"
                log "INFO" "Synchronized Fail2ban ignoreip with global whitelist."
            fi
        fi
        # -------------------------------------------------------------------------

        # --- WEBHOOK ACTION SCRIPT DEPLOYMENT ---
        if [[ "${SYSWARDEN_ENABLE_WEBHOOK:-n}" == "y" ]]; then
            log "INFO" "Deploying secure Webhook dispatcher for Fail2ban..."

            # Write the hardened payload dispatcher
            cat <<'EOF_SCRIPT' >/etc/syswarden/syswarden-webhook.sh
#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN SECURE WEBHOOK DISPATCHER
# ==============================================================================
set -euo pipefail

JAIL_NAME="${1:-Unknown}"
IP_ADDRESS="${2:-0.0.0.0}"
FAILURES="${3:-0}"

# Safely load configuration
if [[ -f /etc/syswarden.conf ]]; then
    # shellcheck source=/dev/null
    source /etc/syswarden.conf
else
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Capture local hostname for multi-server fleet identification
SERVER_NAME=$(hostname)

send_discord() {
    local url="$1"
    local payload
    # Formats the payload as a unified description block instead of separate JSON fields
    # to render as clean, consecutive text lines in the Discord client.
    payload=$(cat <<JSON
{
  "content": null,
  "embeds": [
    {
      "title": "SysWarden Alert: IP Blocked",
      "description": "A malicious IP has been banned by Fail2ban Layer 7.\nServer : ${SERVER_NAME}\nJail : ${JAIL_NAME}\nTarget IP : ${IP_ADDRESS}\nFailures : ${FAILURES}",
      "color": 16711680,
      "timestamp": "${TIMESTAMP}"
    }
  ]
}
JSON
)
    # Enforce strict HTTPS and minimum TLS 1.2 to prevent downgrade attacks and SSRF
    curl -s --proto =https --tlsv1.2 -X POST -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null || true
}

send_teams() {
    local url="$1"
    local payload
    payload=$(cat <<JSON
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "FF0000",
  "summary": "SysWarden Alert",
  "sections": [{
    "activityTitle": "SysWarden Alert: IP Blocked",
    "activitySubtitle": "Layer 7 Application Firewall",
    "facts": [
      { "name": "Server:", "value": "${SERVER_NAME}" },
      { "name": "Jail:", "value": "${JAIL_NAME}" },
      { "name": "Target IP:", "value": "${IP_ADDRESS}" },
      { "name": "Failures:", "value": "${FAILURES}" }
    ],
    "markdown": true
  }]
}
JSON
)
    # Enforce strict HTTPS and minimum TLS 1.2 to prevent downgrade attacks and SSRF
    curl -s --proto =https --tlsv1.2 -H "Content-Type: application/json" -d "$payload" "$url" >/dev/null || true
}

if [[ -n "${SYSWARDEN_WEBHOOK_URL_DISCORD:-}" ]]; then
    send_discord "$SYSWARDEN_WEBHOOK_URL_DISCORD"
fi

if [[ -n "${SYSWARDEN_WEBHOOK_URL_TEAMS:-}" ]]; then
    send_teams "$SYSWARDEN_WEBHOOK_URL_TEAMS"
fi

exit 0
EOF_SCRIPT
            chmod 700 /etc/syswarden/syswarden-webhook.sh
            chown root:root /etc/syswarden/syswarden-webhook.sh

            # Define the Fail2ban action mapped to the dispatcher
            cat <<'EOF_ACTION' >/etc/fail2ban/action.d/syswarden-webhook.conf
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /etc/syswarden/syswarden-webhook.sh <name> <ip> <failures>
actionunban = 
EOF_ACTION
        fi

        # --- L7 PERSISTENCE SCRIPT DEPLOYMENT ---
        log "INFO" "Deploying secure L7 behavioral persistence subsystem..."
        cat <<'EOF_PERSIST' >/etc/syswarden/syswarden-persistence.sh
#!/usr/bin/env bash
# ==============================================================================
# SYSWARDEN L7 BEHAVIORAL BANS PERSISTENCE DISPATCHER
# ==============================================================================
set -euo pipefail

# Enforce explicit standard bin paths to prevent command failures inside daemon environment
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ACTION="${1:-}"
IP_ADDRESS="${2:-}"
JAIL_NAME="${3:-Unknown}"

if [[ -z "$ACTION" ]] || [[ -z "$IP_ADDRESS" ]]; then
    exit 1
fi

CONF_FILE="/etc/syswarden.conf"
# Relocate database and locking handles inside Fail2ban native storage to satisfy SELinux and Systemd restrictions
F2B_BLOCKLIST="/var/lib/fail2ban/syswarden_f2b_blocklist.txt"
F2B_EXPIRY="/var/lib/fail2ban/syswarden_f2b_expiry.txt"
LOCK_FILE="/var/lib/fail2ban/syswarden_persistence.lock"
SET_NAME="syswarden_blacklist"

# Default fallback engine
FIREWALL_BACKEND="nftables"
if [[ -f "$CONF_FILE" ]]; then
    # Secure regex extraction avoiding execution vectors
    if grep -q 'FIREWALL_BACKEND="\(.*\)"' "$CONF_FILE"; then
        FIREWALL_BACKEND=$(grep 'FIREWALL_BACKEND=' "$CONF_FILE" | cut -d'"' -f2)
    fi
fi

exec_with_lock() {
    # Open lock file descriptor for exclusive atomic multithreaded operations (CWE-362)
    exec 9>"$LOCK_FILE"
    flock -x 9
    "$@"
    exec 9>&-
}

inject_into_kernel() {
    local ip="$1"
    # Hot-inject the persistent element into active kernel runtime structures to ensure zero-downtime protection
    case "$FIREWALL_BACKEND" in
        nftables)
            nft add element netdev syswarden_hw_drop "$SET_NAME" { "$ip" } 2>/dev/null || true
            ;;
        firewalld)
            firewall-cmd --ipset="$SET_NAME" --add-entry="$ip" >/dev/null 2>&1 || true
            ;;
        ufw | iptables)
            ipset add "$SET_NAME" "$ip" -exist >/dev/null 2>&1 || true
            ;;
    esac
}

handle_ban() {
    if [[ ! -f "$F2B_BLOCKLIST" ]]; then
        touch "$F2B_BLOCKLIST"
        chmod 600 "$F2B_BLOCKLIST"
    fi
    # Append target IP surgically without causing internal layout duplication
    if ! grep -qFx "$IP_ADDRESS" "$F2B_BLOCKLIST"; then
        echo "$IP_ADDRESS" >> "$F2B_BLOCKLIST"
    fi

    # Ensure frontline protection is immediately active at Tier 1 hardware driver level
    inject_into_kernel "$IP_ADDRESS"

    # Remove from scheduled expiries if the IP gets banned again before the 30-day window closes
    if [[ -f "$F2B_EXPIRY" ]]; then
        local tmp_exp
        tmp_exp=$(mktemp -p "$(dirname "$F2B_EXPIRY")")
        grep -v "^${IP_ADDRESS};" "$F2B_EXPIRY" > "$tmp_exp" || true
        mv "$tmp_exp" "$F2B_EXPIRY"
        chmod 600 "$F2B_EXPIRY"
    fi
}

handle_unban() {
    local expiry_time
    expiry_time=$(( $(date +%s) + 2592000 )) # Current epoch + 30 days (30 * 86400 seconds)

    if [[ ! -f "$F2B_EXPIRY" ]]; then
        touch "$F2B_EXPIRY"
        chmod 600 "$F2B_EXPIRY"
    fi

    # Update or append the expiry timestamp for this unbanned IP
    local tmp_exp
    tmp_exp=$(mktemp -p "$(dirname "$F2B_EXPIRY")")
    grep -v "^${IP_ADDRESS};" "$F2B_EXPIRY" > "$tmp_exp" || true
    echo "${IP_ADDRESS};${expiry_time}" >> "$tmp_exp"
    mv "$tmp_exp" "$F2B_EXPIRY"
    chmod 600 "$F2B_EXPIRY"

    # Retain the IP inside the main blocklist so it remains blocked across firewalls for 30 days
    if [[ ! -f "$F2B_BLOCKLIST" ]]; then
        touch "$F2B_BLOCKLIST"
        chmod 600 "$F2B_BLOCKLIST"
    fi
    if ! grep -qFx "$IP_ADDRESS" "$F2B_BLOCKLIST"; then
        echo "$IP_ADDRESS" >> "$F2B_BLOCKLIST"
    fi

    # Hard-override native unban deletions by forcing continuous kernel blocklist state survival
    inject_into_kernel "$IP_ADDRESS"
}

purge_expired_bans() {
    if [[ ! -f "$F2B_EXPIRY" ]] || [[ ! -s "$F2B_EXPIRY" ]]; then
        return
    fi

    local current_time
    current_time=$(date +%s)
    local tmp_exp ip exp
    
    tmp_exp=$(mktemp -p "$(dirname "$F2B_EXPIRY")")
    chmod 600 "$tmp_exp"
    
    # Instantiate array to batch blocklist disk mutations and avoid heavy nested disk writes
    local expired_ips=()

    while IFS=';' read -r ip exp || [[ -n "$ip" ]]; do
        [[ -z "$ip" || -z "$exp" ]] && continue
        if (( current_time >= exp )); then
            expired_ips+=("$ip")
            # Synchronize active kernel firewall structures instantly to release the 30-day quarantine
            case "$FIREWALL_BACKEND" in
                nftables)
                    nft delete element netdev syswarden_hw_drop "$SET_NAME" { "$ip" } 2>/dev/null || true
                    ;;
                firewalld)
                    firewall-cmd --ipset="$SET_NAME" --remove-entry="$ip" >/dev/null 2>&1 || true
                    ;;
                ufw | iptables)
                    ipset del "$SET_NAME" "$ip" >/dev/null 2>&1 || true
                    ;;
            esac
        else
            # Line is still valid, retain inside expiry database tracking structure
            echo "${ip};${exp}" >> "$tmp_exp"
        fi
    done < "$F2B_EXPIRY"
    
    mv "$tmp_exp" "$F2B_EXPIRY"
    chmod 600 "$F2B_EXPIRY"

    # Execute atomic single-pass batched file pruning to completely eliminate filesystem bottleneck
    if (( ${#expired_ips[@]} > 0 )); then
        if [[ -f "$F2B_BLOCKLIST" ]]; then
            local tmp_bl tmp_expired_file
            tmp_bl=$(mktemp -p "$(dirname "$F2B_BLOCKLIST")")
            tmp_expired_file=$(mktemp -p "$(dirname "$F2B_BLOCKLIST")")
            
            for e_ip in "${expired_ips[@]}"; do
                echo "$e_ip" >> "$tmp_expired_file"
            done
            
            # Enforce exact line matching with -x to prevent substring collision vulnerabilities (CWE-185)
            grep -vFxf "$tmp_expired_file" "$F2B_BLOCKLIST" > "$tmp_bl" || true
            mv "$tmp_bl" "$F2B_BLOCKLIST"
            chmod 600 "$F2B_BLOCKLIST"
            rm -f "$tmp_expired_file"
        fi
    fi
}

case "$ACTION" in
    ban)
        exec_with_lock purge_expired_bans
        exec_with_lock handle_ban
        ;;
    unban)
        exec_with_lock purge_expired_bans
        exec_with_lock handle_unban
        ;;
esac

exit 0
EOF_PERSIST
        chmod 700 /etc/syswarden/syswarden-persistence.sh
        chown root:root /etc/syswarden/syswarden-persistence.sh

        # Fix legacy SELinux security contexts for existing blocklist definitions
        if [[ -f "/var/lib/fail2ban/syswarden_f2b_blocklist.txt" ]]; then
            chmod 600 /var/lib/fail2ban/syswarden_f2b_blocklist.txt
            chown root:root /var/lib/fail2ban/syswarden_f2b_blocklist.txt
            if command -v restorecon >/dev/null 2>&1; then
                restorecon -F /var/lib/fail2ban/syswarden_f2b_blocklist.txt 2>/dev/null || true
            fi
        fi

        if [[ -f "/var/lib/fail2ban/syswarden_f2b_expiry.txt" ]]; then
            chmod 600 /var/lib/fail2ban/syswarden_f2b_expiry.txt
            chown root:root /var/lib/fail2ban/syswarden_f2b_expiry.txt
            if command -v restorecon >/dev/null 2>&1; then
                restorecon -F /var/lib/fail2ban/syswarden_f2b_expiry.txt 2>/dev/null || true
            fi
        fi

        # Define the Fail2ban action mapped to the persistence manager
        cat <<'EOF_PERSIST_ACTION' >/etc/fail2ban/action.d/syswarden-persistence.conf
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = /etc/syswarden/syswarden-persistence.sh ban <ip> <name>
actionunban = /etc/syswarden/syswarden-persistence.sh unban <ip> <name>
EOF_PERSIST_ACTION

        # --- HOTFIX: FAIL2BAN PYTHON CONFIGPARSER MULTILINE ALIGNMENT ---
        # Seamlessly construct the default multi-action list sequence
        SYSW_DEFAULT_ACTION="%(banaction)s"
        if [[ "${SYSWARDEN_ENABLE_WEBHOOK:-n}" == "y" ]]; then
            SYSW_DEFAULT_ACTION+=$'\n          syswarden-webhook'
        fi
        SYSW_DEFAULT_ACTION+=$'\n          syswarden-persistence'

        # 4. Generate Core jail.local (Defaults & SSH)
        cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
# Disable reverse DNS lookups to prevent blocking overhead and optimize performance during floods
usedns = no
banaction = $SYSW_F2B_ACTION
action = $SYSW_DEFAULT_ACTION

[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $SYSW_F2B_ACTION
maxretry = 3
findtime = 1w
bantime  = 4w

[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-ssh}
logpath = %(sshd_log)s
backend = $SYSW_OS_BACKEND
banaction = $SYSW_F2B_ACTION_ALLPORTS
findtime = 24h
maxretry = 2
EOF

        # Recidive Filter
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
# Matches fail2ban logs including PID and NOTICE tags for correct recidive escalation
failregex = fail2ban\.actions.*NOTICE\s+\[[^\]]+\]\s+(?:Ban|Found)\s+<HOST>
ignoreregex = fail2ban\.actions.*NOTICE\s+\[[^\]]+\]\s+(?:Restore )?(?:Unban|unban)\s+<HOST>
EOF
        fi

        # 5. GLOBAL VARIABLES DETECTION (For Jail Modules)
        export SYSW_APACHE_ACCESS=""
        if [[ -f "/var/log/apache2/access.log" ]]; then
            SYSW_APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/access_log" ]]; then SYSW_APACHE_ACCESS="/var/log/httpd/access_log"; fi

        export SYSW_RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "$SYSW_APACHE_ACCESS"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_RCE_LOGS" ]]; then
                    SYSW_RCE_LOGS="$log_file"
                else SYSW_RCE_LOGS+=$'\n          '"$log_file"; fi
            fi
        done

        export SYSW_MODSEC_ACTIVE=0
        export SYSW_MODSEC_LOGS=""
        if [[ ! -f "/var/log/modsec_audit.log" ]]; then
            touch /var/log/modsec_audit.log
            chmod 640 /var/log/modsec_audit.log
            chown root:root /var/log/modsec_audit.log 2>/dev/null || true
        fi

        for log_file in "/var/log/nginx/error.log" "/var/log/apache2/error.log" "/var/log/httpd/error_log" "/var/log/modsec_audit.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$SYSW_MODSEC_LOGS" ]]; then
                    SYSW_MODSEC_LOGS="$log_file"
                else SYSW_MODSEC_LOGS+=$'\n          '"$log_file"; fi
            fi
        done
        if [[ -n "$SYSW_MODSEC_LOGS" ]] && [[ -d "/etc/modsecurity" ]] && [[ -f "/etc/modsecurity/main.conf" ]]; then
            export SYSW_MODSEC_ACTIVE=1
        fi

        # 6. DYNAMIC MODULE INVOCATION
        log "INFO" "Applying Layer 7 Application Firewall Rules (Fail2ban)..."

        # --- SURGICAL WEB APP DISCOVERY ---
        # Instantiates variables to isolate Jails matching only the active environment.
        # This will securely override the fallback SYSW_RCE_LOGS defined in Step 5.
        if command -v discover_web_apps >/dev/null 2>&1; then
            discover_web_apps
        fi
        # ----------------------------------

        log "INFO" "Executing modular jail definitions..."
        local jail_functions
        jail_functions=$(compgen -A function | grep '^syswarden_jail_' || true)
        if [[ -n "$jail_functions" ]]; then
            for func in $jail_functions; do
                # Executes the function. The Fail-Fast pattern inside each
                # function will instantly abort if conditions aren't met.
                "$func"
            done
        else
            log "WARN" "No external jail modules loaded. Only SSH and Recidive are active."
        fi

        # ==============================================================================
        # --- HOTFIX: FAIL2BAN PYTHON CONFIGPARSER ALIGNMENT ---
        # Enforces strict multi-line indentation for all logpath arrays.
        # Automatically finds space-separated paths (e.g., flattened by Bash injection)
        # and replaces the space with an explicit newline and 10 spaces.
        # ==============================================================================
        log "INFO" "Sanitizing multi-line logpath arrays for strict ConfigParser alignment..."
        sed -i -E 's|[[:space:]]+(/var/log/[^[:space:]]+)|\n          \1|g' /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.d/*.local 2>/dev/null || true
        # ==============================================================================

        # 7. SERVICE RESTART & SOCKET WAIT
        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
            chown root:root /var/log/fail2ban.log 2>/dev/null || true
        fi

        log "INFO" "Reloading/Starting Fail2ban service..."
        if command -v systemctl >/dev/null; then
            systemctl enable fail2ban >/dev/null 2>&1 || true
            if systemctl is-active --quiet fail2ban; then
                # Graceful reload to prevent state amnesia and log rescanning on periodic executions
                fail2ban-client reload >/dev/null 2>&1 || true
            else
                systemctl start fail2ban >/dev/null 2>&1 || true
            fi
        else
            fail2ban-client reload >/dev/null 2>&1 || true
        fi

        for _ in {1..10}; do
            if fail2ban-client ping >/dev/null 2>&1; then break; fi
            sleep 1
        done
    fi
}
