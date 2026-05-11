MODE="${1:-install}"

# --- HEADLESS / UNATTENDED INSTALLATION PARSER ---
# Safely parses a provided .conf file to inject environment variables
if [[ -f "${1:-}" ]]; then
    echo -e "${GREEN}>>> Unattended configuration file detected: $1${NC}"

    # --- SECURITY FIX: SECURE AUTO-CONF FILE (CWE-732: Incorrect Permission Assignment for Critical Resource) ---
    # Restrict permissions immediately so local non-root users cannot read
    # the secrets inside (e.g., API keys, custom network configurations)
    chmod 600 "$1"
    # -------------------------------------------

    while IFS='=' read -r key val; do
        # Ignore comments and empty lines
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue

        # Clean up the key and value (remove whitespaces and quotes)
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | xargs | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")

        # STRICT SECURITY: Only export variables starting with SYSWARDEN_
        # Prevents arbitrary code execution or PATH manipulation
        if [[ "$key" =~ ^SYSWARDEN_[A-Z0-9_]+$ ]]; then
            export "$key"="$val"
        fi
    done <"$1"

    # Force auto mode to bypass all interactive prompts
    MODE="auto"
elif [[ "$MODE" == "--auto" ]]; then
    # Legacy CI/CD support
    MODE="auto"
fi
# -------------------------------------------------

if [[ "$MODE" == "whitelist" ]]; then
    check_root
    detect_os_backend
    whitelist_ip
    exit 0
fi

if [[ "$MODE" == "blocklist" ]]; then
    check_root
    detect_os_backend
    blocklist_ip
    exit 0
fi

if [[ "$MODE" == "wireguard-client" ]]; then
    check_root
    add_wireguard_client
    exit 0
fi

if [[ "$MODE" == "protect-docker" ]]; then
    check_root
    protect_docker_jail
    exit 0
fi

if [[ "$MODE" == "fail2ban-jails" ]]; then
    check_root
    detect_os_backend

    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${GREEN}SysWarden - Fail2ban Jails Auto-Discovery & Reload${NC}"
    echo -e "${BLUE}======================================================================${NC}"

    # 1. Load existing configuration to retrieve custom settings (e.g., SSH_PORT)
    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
        log "INFO" "Configuration loaded successfully."
    else
        log "ERROR" "Configuration file ($CONF_FILE) not found. Please install SysWarden first."
        exit 1
    fi

    # 2. Trigger the existing Fail2ban configuration function (Auto-Discovery)
    log "INFO" "Scanning system for active services and web applications..."
    discover_active_services 2>/dev/null || true
    discover_web_apps
    configure_fail2ban

    # --- HOTFIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
    # Ensure the log file exists before restarting, in case of logrotate or fresh env.
    if [[ ! -f /var/log/fail2ban.log ]]; then
        touch /var/log/fail2ban.log
        chmod 640 /var/log/fail2ban.log
        chown root:root /var/log/fail2ban.log 2>/dev/null || true
    fi
    # ------------------------------------------------------

    # 3. Reload the Fail2ban service natively based on the OS Init System
    log "INFO" "Restarting Fail2ban to apply new jails..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart fail2ban 2>/dev/null || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service fail2ban restart 2>/dev/null || true
    else
        fail2ban-client reload 2>/dev/null || true
    fi

    # --- HOTFIX: Calm Down boy ---
    sleep 5

    # 4. Show the final status to the administrator
    echo -e "\n${GREEN}[+] Fail2ban jails successfully updated! Active jails:${NC}"
    fail2ban-client status
    exit 0
fi

if [[ "$MODE" == "alerts" ]]; then
    check_root
    show_alerts_dashboard
    exit 0
fi

if [[ "$MODE" == "upgrade" ]]; then
    # We don't strictly need root just to check the API, but consistency is kept
    check_root
    check_upgrade
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    check_root
    detect_os_backend
    uninstall_syswarden
fi

if [[ "$MODE" == "cron-update" ]]; then
    log "INFO" "Starting silent CRON update (Threat Intelligence only)..."
    check_root
    detect_os_backend

    if [[ -f "$CONF_FILE" ]]; then
        # shellcheck source=/dev/null
        source "$CONF_FILE"
    else
        log "ERROR" "Config file missing. Aborting cron update."
        exit 1
    fi

    # 1. Download fresh lists
    select_list_type "update"
    select_mirror "update"
    download_list
    download_osint
    download_geoip
    download_asn

    # 2. Inject silently into Kernel (Zero-Downtime)
    discover_active_services
    discover_web_apps
    apply_firewall_rules

    log "INFO" "CRON Update Complete. Firewall rules refreshed securely."
    # Vital exit 0
    exit 0
fi

# --- CLI UI: Premium ASCII Banner ---
if [[ "$MODE" != "update" ]] && [[ "$MODE" != "uninstall" ]]; then
    clear
    echo -e "${BLUE}===================================================================================${NC}"
    echo -e "${RED} ██████╗██╗   ██╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗${NC}"
    echo -e "${RED}██╔════╝╚██╗ ██╔╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║${NC}"
    echo -e "${RED}███████╗ ╚████╔╝ ███████╗██║ █╗ ██║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║${NC}"
    echo -e "${RED}╚════██║  ╚██╔╝  ╚════██║██║███╗██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║${NC}"
    echo -e "${RED}███████║   ██║   ███████║╚███╔███╔╝██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║${NC}"
    echo -e "${RED}╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝${NC}"
    echo -e "${BLUE}===================================================================================${NC}"
    echo -e "${GREEN}               Host-based Security Orchestrator for Linux. | v0.32.9                  ${NC}"
    echo -e "${BLUE}===================================================================================${NC}\n"
fi

check_root
detect_os_backend

# --- PREVENT ADMIN LOCK-OUT (EXECUTE BEFORE FAIL2BAN/FIREWALL) ---
auto_whitelist_admin
process_auto_whitelist "$MODE"
auto_whitelist_infra "$MODE"
# -----------------------------------------------------------------

# --- SECURITY: ENFORCE STRICT PERMISSIONS ---
touch "$CONF_FILE" "$LOG_FILE" 2>/dev/null || true
chmod 600 "$CONF_FILE" 2>/dev/null || true
chmod 640 "$LOG_FILE" 2>/dev/null || true
# ------------------------------------------

if [[ "$MODE" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
fi

if [[ "$MODE" != "update" ]]; then
    : >"$CONF_FILE"
    install_dependencies

    # --- CRITICAL ARCHITECTURE FIX ---
    # Re-detect backend! DNF might have just installed Firewalld or Nftables (via fail2ban)
    detect_os_backend
    # ---------------------------------

    # --- DEVSECOPS: PRE-FLIGHT CHECKLIST (Interactive Mode Only) ---
    if [[ "$MODE" != "auto" ]]; then
        BOLD='\033[1m'
        CYAN='\033[0;36m'
        clear
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "${GREEN}${BOLD}                   SYSWARDEN v0.32.9 - PRE-FLIGHT CHECKLIST                     ${NC}"
        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        echo -e "Before proceeding with the deployment, please ensure you have the following"
        echo -e "information ready. If you lack any required data, press [Ctrl+C] to abort,"
        echo -e "gather the info, and restart the script.\n"

        echo -e "${BOLD}1. SSH CONFIGURATION${NC}"
        echo -e "   You will need to confirm the custom SSH port used to connect to this server."

        echo -e "\n${BOLD}2. FIREWALL ENGINE OPTIMIZATION${NC} ${YELLOW}(RHEL/Alma/Fedora only)${NC}"
        echo -e "   Decide whether to bypass Firewalld in favor of pure Nftables or Iptables"
        echo -e "   for extreme performance when loading massive Threat Intelligence blocklists."

        echo -e "\n${BOLD}3. WIREGUARD VPN${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Decide if you need a stealth admin VPN. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}4. DOCKER INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires Layer 3 routing adjustments for containers. If unsure, consult your SysAdmin."

        echo -e "\n${BOLD}5. OS HARDENING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Strict restrictions for privileged groups (Sudo/Wheel) & Cron. Recommended for NEW servers only."

        echo -e "\n${BOLD}6. GEOIP BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   ISO country codes to drop instantly (e.g., RU,CN,KP)."
        echo -e "   Reference: ${CYAN}https://www.ipdeny.com/ipblocks/${NC}"

        echo -e "\n${BOLD}7. ASN BLOCKING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Target Autonomous System Numbers to drop (e.g., AS1234, AS5678)."
        echo -e "   Reference: ${CYAN}https://www.spamhaus.org/drop/asndrop.json${NC}"

        echo -e "\n${BOLD}8. HA CLUSTER SYNC${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Standby Node IP for automatic threat intelligence replication."

        echo -e "\n${BOLD}9. THREAT INTEL BLOCKLISTS${NC}"
        echo -e "   [1] Standard (Web Servers)      [2] Critical (High Security)"
        echo -e "   [3] Custom (Plaintext URL .txt) [4] Disabled"

        echo -e "\n${BOLD}10. SIEM LOG FORWARDING${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   External SIEM IP, Port (Default: 6514), and Protocol for central log auditing."
        echo -e "   Required for strict ISO 27001 / NIS2 compliance."

        echo -e "\n${BOLD}11. ABUSEIPDB INTEGRATION${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Requires a valid API Key to automatically report Layer 7 attackers."
        echo -e "   Get one at: ${CYAN}https://www.abuseipdb.com/account/api${NC}"

        echo -e "\n${BOLD}12. WAZUH SIEM AGENT${NC} ${YELLOW}(Optional)${NC}"
        echo -e "   Required: Manager IP, Enrollment Port (1515), Listen Port (1514)."
        echo -e "   If unsure about your SIEM architecture, consult your Security Admin."

        echo -e "${BLUE}${BOLD}==============================================================================${NC}"
        read -p "$(echo -e "${YELLOW}Press [ENTER] to begin the configuration, or [Ctrl+C] to abort... ${NC}")"
        echo ""
        log "INFO" "Pre-Flight Checklist acknowledged. Starting interactive configuration..."
    fi
    # ---------------------------------------------------------------

    define_ssh_port "$MODE"
    define_firewall_engine "$MODE"
    define_wireguard "$MODE"
    define_docker_integration "$MODE"
    define_os_hardening "$MODE"
    define_geoblocking "$MODE"
    define_asnblocking "$MODE"
    define_ha_cluster "$MODE"

    # Run the interactive/setup phases for the SIEM early so questions are asked up front.
    # The actual OS modification happens inside this function.
    setup_siem_logging "$MODE"

    discover_web_apps
    configure_fail2ban
fi

# --- FIX 1: THE SOURCE GAP ---
# Force sourcing the config to ensure variables (GEOIP_ENABLED, ASN_ENABLED, etc.)
# are loaded in RAM even during a fresh install.
if [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
fi
# -----------------------------

select_list_type "$MODE"
select_mirror "$MODE"
download_list
download_osint

# --- FIX 2: THE COLD BOOT INJECTION (FRESH INSTALL ONLY) ---
# Initialize base chains/sets before downloading massive lists to prevent
# service dependency crashes (like Fail2ban starting too early).
if [[ "$MODE" != "update" ]]; then
    discover_active_services
    discover_web_apps
    apply_firewall_rules
fi

download_geoip
download_asn
# --------------------------------------

# --- FIX 3: THE POST-DOWNLOAD RELOAD (INSTALL & UPDATE) ---
# Now that massive lists are downloaded/updated on disk, we ALWAYS reload
# the firewall to inject the freshest GeoIP, ASN, and Blocklist data.
log "INFO" "Applying massive downloaded lists to active firewall..."
discover_active_services
discover_web_apps
apply_firewall_rules

# --- NEW DEVSECOPS UPGRADE LOGIC ---
# Ensures that both fresh installs and in-place upgrades receive the
# absolute latest Layer 7 application firewall rules and regex payloads.
log "INFO" "Applying Layer 7 Application Firewall Rules (Fail2ban)..."
# Redundant execution of discover_web_apps is skipped here as it was just cached
configure_fail2ban
# -----------------------------------

detect_protected_services

# --- HOTFIX: STATEFUL REPORTER RESTART LOGIC ---
# We check if the service is ENABLED (configured to run by the user),
# not ACTIVE, because the pre-upgrade hook explicitly killed it earlier.
if command -v systemctl >/dev/null && systemctl is-enabled --quiet syswarden-reporter 2>/dev/null; then
    log "INFO" "Restarting SysWarden Unified Reporter..."

    # --- DEVSECOPS FIX: SYSTEMD/SELINUX STATE MIGRATION ---
    # If upgrading from a version that used DynamicUser=yes, Systemd leaves a symlink
    # pointing to /var/lib/private/syswarden. SELinux (on RHEL/Alma) will actively block
    # Systemd from unlinking this during transition, causing a fatal Code 238 crash.
    # We forcefully purge the legacy structure before restarting the daemon.
    if [[ -L "/var/lib/syswarden" ]] || [[ -d "/var/lib/private/syswarden" ]]; then
        log "INFO" "Purging legacy DynamicUser state directories to prevent SELinux conflicts..."
        rm -rf /var/lib/syswarden /var/lib/private/syswarden 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    # ------------------------------------------------------

    systemctl restart syswarden-reporter >/dev/null 2>&1 || true
elif command -v rc-service >/dev/null && rc-update show default 2>/dev/null | grep -q "syswarden-reporter"; then
    log "INFO" "Restarting SysWarden Unified Reporter (OpenRC)..."
    rc-service syswarden-reporter restart >/dev/null 2>&1 || true
fi

# --- HOTFIX: DASHBOARD & TELEMETRY ORCHESTRATION ---
setup_telemetry_backend
generate_dashboard
# ---------------------------------------------------

if [[ "$MODE" != "update" ]]; then
    setup_wireguard
    # setup_siem_logging is now executed earlier during the interactive definition phase
    setup_abuse_reporting "$MODE"
    setup_wazuh_agent "$MODE"
    setup_cron_autoupdate "$MODE"

    # User-authorized IT hardening
    apply_os_hardening

    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> List loaded: $LIST_TYPE"

    if [[ "$MODE" == "auto" ]]; then
        echo -e " -> Mode: Automated (CI/CD Deployment)"
    else
        echo -e " -> Mode: Universal (Interactive)"
    fi

    echo -e " -> Protection: Active"

    display_wireguard_qr
else
    # --- HOTFIX: FORCE CRON SYNTAX UPGRADE DURING UPDATE ---
    # Silently patches existing crontabs to use the safe 'cron-update' argument
    if [[ -f /etc/cron.d/syswarden-update ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/cron.d/syswarden-update 2>/dev/null || true
    fi
    if [[ -f /etc/crontabs/root ]]; then
        sed -i 's/\.sh update >/\.sh cron-update >/g' /etc/crontabs/root 2>/dev/null || true
    fi

    # Restart the appropriate Cron daemon natively (Debian=cron, RHEL/Alma=crond)
    if command -v systemctl >/dev/null; then
        systemctl restart crond 2>/dev/null || systemctl restart cron 2>/dev/null || true
    fi
    # --------------------------------------------------------------

    # Restart Fail2ban gracefully to compile the newly injected Python/Regex rules
    log "INFO" "Restarting Fail2ban engine to compile new definitions..."

    if command -v systemctl >/dev/null; then
        # --- HOTFIX: SOCKET RACE CONDITION PREVENTION ---
        # Stop the service explicitly, wait 5 seconds for the .sock file to be
        # purged from /var/run/ by the kernel, then start it cleanly.
        systemctl stop fail2ban >/dev/null 2>&1 || true
        sleep 5
        systemctl start fail2ban >/dev/null 2>&1 || true
    else
        # Fallback for SysVinit / OpenRC
        fail2ban-client stop >/dev/null 2>&1 || true
        sleep 5
        fail2ban-client start >/dev/null 2>&1 || true
    fi

    # Give clear feedback during an update
    echo -e "\n${GREEN}UPDATE SUCCESSFUL${NC}"
    echo -e " -> SysWarden Engine (L2/L3 & L7) and Dashboard UI have been updated to the latest version."
fi
