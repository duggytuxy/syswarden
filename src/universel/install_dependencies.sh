install_dependencies() {
    log "INFO" "Checking dependencies..."
    local missing_common=()

    # ==============================================================================
    # --- HOTFIX: STATE TRACKER (Avoid God Mode Uninstall) ---
    # Record pre-existing critical services so we don't purge them on uninstall.
    # MUST BE EXECUTED BEFORE ANY APT/DNF COMMANDS!
    # ==============================================================================
    if [[ ! -f "$CONF_FILE" ]]; then
        touch "$CONF_FILE"
        chmod 600 "$CONF_FILE"
    fi
    # Detect if ANY web server is already present to prevent uninstall disasters
    if ! command -v nginx >/dev/null 2>&1 && ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        echo "NGINX_INSTALLED_BY_SYSWARDEN='y'" >>"$CONF_FILE"
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        echo "FAIL2BAN_INSTALLED_BY_SYSWARDEN='y'" >>"$CONF_FILE"
    fi
    # ==============================================================================

    if [[ -f /etc/debian_version ]]; then
        log "INFO" "Updating apt repositories..."
        apt-get update -qq
    fi

    if ! command -v curl >/dev/null; then missing_common+=("curl"); fi
    # --- HOTFIX: WGET DEPENDENCY (Required for UI Fonts & Upgrades) ---
    if ! command -v wget >/dev/null; then missing_common+=("wget"); fi
    # ------------------------------------------------------------------
    if ! command -v python3 >/dev/null; then missing_common+=("python3"); fi
    if ! command -v whois >/dev/null; then missing_common+=("whois"); fi
    # --- FIX: Added 'jq' dependency required for telemetry JSON generation ---
    if ! command -v jq >/dev/null; then missing_common+=("jq"); fi
    # -----------------------------------------------------------------------

    # --- HOTFIX: WEB SERVER & OPENSSL AS CORE DEPENDENCIES ---
    # We install Nginx only if absolutely no supported web server is found
    if ! command -v nginx >/dev/null 2>&1 && ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        missing_common+=("nginx")
    fi

    # --- FIX: RHEL/ROCKY APACHE MOD_SSL DEPENDENCY ---
    # Ensure mod_ssl is installed for httpd to recognize SSLEngine directives
    if command -v httpd >/dev/null 2>&1 && [[ -f /etc/redhat-release ]]; then
        if ! rpm -q mod_ssl >/dev/null 2>&1; then
            missing_common+=("mod_ssl")
        fi
    fi

    if ! command -v openssl >/dev/null; then missing_common+=("openssl"); fi
    # -----------------------------------------------------------

    # Check if array is not empty
    if [[ ${#missing_common[@]} -gt 0 ]]; then

        # --- HOTFIX: GHOST CONFIGURATION PREVENTION ---
        # Debian/Ubuntu automatically starts Nginx post-installation.
        # If a previous SysWarden configuration exists but the SSL certs were wiped,
        # dpkg will crash. We aggressively clean legacy configs before installing.
        if [[ -f /etc/debian_version ]] && [[ " ${missing_common[*]} " =~ " nginx " ]]; then
            log "INFO" "Cleaning up potential legacy Nginx configurations before install..."
            rm -f /etc/nginx/conf.d/syswarden-ui.conf
            rm -f /etc/nginx/sites-available/syswarden-ui.conf
            rm -f /etc/nginx/sites-enabled/syswarden-ui.conf
        fi
        # -----------------------------------------------------

        if [[ -f /etc/debian_version ]]; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y "${missing_common[@]}"
        elif [[ -f /etc/redhat-release ]]; then
            dnf install -y "${missing_common[@]}"
        fi
    fi

    # --- HOTFIX: PREEMPTIVE WEB LOG CREATION ---
    # We guarantee the existence of Web logs immediately after package installation.
    # This ensures Fail2ban naturally detects them and activates Layer 7 Web Jails natively.
    if command -v apache2 >/dev/null 2>&1 || [[ -d /etc/apache2 ]]; then
        mkdir -p /var/log/apache2
        touch /var/log/apache2/access.log /var/log/apache2/error.log
        chmod 640 /var/log/apache2/*.log 2>/dev/null || true
    elif command -v httpd >/dev/null 2>&1 || [[ -d /etc/httpd ]]; then
        mkdir -p /var/log/httpd
        touch /var/log/httpd/access_log /var/log/httpd/error_log
        chmod 640 /var/log/httpd/*_log 2>/dev/null || true
    else
        mkdir -p /var/log/nginx
        touch /var/log/nginx/access.log /var/log/nginx/error.log
        chmod 640 /var/log/nginx/*.log 2>/dev/null || true
    fi
    # ----------------------------------------------------

    # Python Requests (Required for AbuseIPDB Reporter)
    # PEP 668 COMPLIANCE: We strictly use system packages (apt/dnf) to avoid 'externally-managed-environment' errors.
    if ! python3 -c "import requests" 2>/dev/null; then
        log "INFO" "Installing Python Requests library..."

        if [[ -f /etc/debian_version ]]; then
            # Debian/Ubuntu: MANDATORY usage of apt to avoid breaking system python
            apt-get install -y python3-requests

        elif [[ -f /etc/redhat-release ]]; then
            # RHEL/Alma: Prioritize RPM. Fallback to pip only if RPM fails (RHEL behavior is less strict than Debian yet)
            if ! dnf install -y python3-requests; then
                log "WARN" "python3-requests RPM not found. Trying pip fallback..."
                dnf install -y python3-pip
                pip3 install requests
            fi
        fi

        # Verification post-install
        if ! python3 -c "import requests" 2>/dev/null; then
            log "ERROR" "Failed to install 'python3-requests'. AbuseIPDB reporting feature will be disabled."
        fi
    fi

    # --- CRON DEPENDENCY (For modern minimal OS like Fedora / RHEL 9+) ---
    if ! command -v crond >/dev/null && ! command -v cron >/dev/null; then
        log "WARN" "Installing package: cron daemon"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y cron
        elif [[ -f /etc/redhat-release ]]; then dnf install -y cronie; fi
    fi

    # Ensure it's enabled and started (moved outside the install check)
    if command -v systemctl >/dev/null; then
        systemctl enable --now crond 2>/dev/null || systemctl enable --now cron 2>/dev/null || true
    fi
    # --------------------------------------------------------------------

    # --- RSYSLOG DEPENDENCY (For modern OS like Debian 12+ / Ubuntu 24.04+) ---
    # Required to generate /var/log/auth.log and /var/log/kern.log for Fail2ban
    if ! command -v rsyslogd >/dev/null && [ ! -f /usr/sbin/rsyslogd ]; then
        log "WARN" "Installing package: rsyslog"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y rsyslog
        elif [[ -f /etc/redhat-release ]]; then dnf install -y rsyslog; fi
    fi

    if command -v systemctl >/dev/null; then
        systemctl enable --now rsyslog 2>/dev/null || true
        touch /var/log/auth.log /var/log/kern.log /var/log/secure /var/log/messages 2>/dev/null || true

        # --- SECURITY FIX: UNIVERSAL KERNEL LOGGING & LOG INJECTION PREVENTION (CWE-117: Improper Output Neutralization for Logs) ---
        # Force rsyslog to write all Netfilter drops and Auth logs to DEDICATED files.
        # This prevents unprivileged users from spoofing firewall drops (F3, F4, F5).
        if [[ -f /etc/rsyslog.conf ]]; then
            # 1. Isolate Kernel Firewall logs
            sed -i '/^kern\./d' /etc/rsyslog.conf
            echo "kern.* /var/log/kern-firewall.log" >>/etc/rsyslog.conf
            touch /var/log/kern-firewall.log && chmod 600 /var/log/kern-firewall.log

            # 2. Isolate Auth/PAM logs (su, sudo, sshd)
            sed -i '/^authpriv\./d' /etc/rsyslog.conf
            sed -i '/^auth\./d' /etc/rsyslog.conf
            echo "auth,authpriv.* /var/log/auth-syswarden.log" >>/etc/rsyslog.conf
            touch /var/log/auth-syswarden.log && chmod 600 /var/log/auth-syswarden.log
        fi
        # -------------------------------------------------------------------------

        systemctl restart rsyslog 2>/dev/null || true
    fi

    # --- WIREGUARD & QR-CODE DEPENDENCIES ---
    if ! command -v wg >/dev/null || ! command -v qrencode >/dev/null; then
        log "WARN" "Installing package: WireGuard & Qrencode"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y wireguard qrencode
        elif [[ -f /etc/redhat-release ]]; then
            log "INFO" "Enabling EPEL repository (Required for Qrencode)..."
            dnf install -y epel-release || true
            dnf install -y wireguard-tools qrencode
        fi
    fi
    # ----------------------------------------

    if ! command -v ipset >/dev/null; then
        log "WARN" "Installing package: ipset"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y ipset
        elif [[ -f /etc/redhat-release ]]; then dnf install -y ipset; fi
    fi

    if ! command -v fail2ban-client >/dev/null; then
        log "WARN" "Installing package: fail2ban"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y fail2ban
        elif [[ -f /etc/redhat-release ]]; then
            log "INFO" "Enabling EPEL repository (Required for Fail2ban)..."
            dnf install -y epel-release || true
            dnf install -y fail2ban
        fi
    fi

    if [[ "$FIREWALL_BACKEND" == "nftables" ]] && ! command -v nft >/dev/null; then
        log "WARN" "Installing package: nftables"
        if [[ -f /etc/debian_version ]]; then
            apt-get install -y nftables
        elif [[ -f /etc/redhat-release ]]; then dnf install -y nftables; fi
    fi

    # --- RHEL/ROCKY/CENTOS 10 ZERO-REBOOT FIX ---
    # Moved to the VERY END of the function to ensure all DNF transactions are flushed to disk
    if [[ "$FIREWALL_BACKEND" != "nftables" ]] && [[ "$FIREWALL_BACKEND" != "ufw" ]]; then
        log "INFO" "Synchronizing Kernel modules..."
        /sbin/depmod -a 2>/dev/null || true
        /sbin/modprobe ip_set 2>/dev/null || true
        /sbin/modprobe ip_set_hash_net 2>/dev/null || true

        # Give Netlink sockets 2 seconds to bind
        sleep 2

        if command -v systemctl >/dev/null && systemctl is-active --quiet firewalld; then
            systemctl restart firewalld 2>/dev/null || true
        fi
    fi
    # --------------------------------------------

    log "INFO" "All dependencies check complete."
}
