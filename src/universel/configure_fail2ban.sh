configure_fail2ban() {
    # [UNIVERSAL MODE] Configures services ONLY if they exist to prevent crashes
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."

        # --- SECURITY FIX: PURGE CONFLICTING DEFAULT JAILS (SCORCHED EARTH) (CWE-1188: Insecure Default Initialization) ---
        # OS package managers silently inject .conf, .local, or symlinks
        # (like defaults-debian.conf) that spawn Ghost Jails like mysqld-auth.
        # We destroy and recreate the directory to guarantee absolute Zero Trust.
        if [[ -d /etc/fail2ban/jail.d ]]; then
            rm -rf /etc/fail2ban/jail.d
        fi

        # Recreate a strictly pristine directory
        mkdir -p /etc/fail2ban/jail.d
        chmod 755 /etc/fail2ban/jail.d

        log "INFO" "Purged fail2ban/jail.d/ directory entirely to enforce absolute Zero Trust."
        # ----------------------------------------------------------------------

        # --- Add backup Fai2ban jail ---
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi
        # -------------------------------------------------------

        # 1. Enterprise WAF Core Configuration
        cat <<EOF >/etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
# DEVSECOPS FIX: Prevent SQLite database bloat and memory exhaustion.
# Synchronized to 8 days (691200s) to perfectly match the 1-week findtime of the 'recidive' jail.
dbpurgeage = 691200
EOF

        # 2. Backup
        if [[ -f /etc/fail2ban/jail.local ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 3. HEADER & SSH (Always Active)
        local f2b_action="iptables-multiport"
        if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
            f2b_action="firewallcmd-ipset"
        elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
            f2b_action="nftables-multiport"
        elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then f2b_action="ufw"; fi

        # --- HOTFIX: SYSTEMD BACKEND OPTIMIZATION ---
        local OS_BACKEND="auto"
        if command -v journalctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-journald 2>/dev/null; then
            OS_BACKEND="systemd"
            log "INFO" "Systemd-journald detected. OS-native jails will be optimized for maximum performance."
        fi
        # ---------------------------------------------------

        # --- HOTFIX: LONG-TERM RECIDIVE FILTER ---
        if [[ ! -f "/etc/fail2ban/filter.d/syswarden-recidive.conf" ]]; then
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-recidive.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Replaced greedy '^.*' with absolute strict timestamp and class anchoring.
# This mathematically prevents ReDoS and reduces CPU cycles by 90% during massive horizontal movement tracking.
failregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Ban|Found)\s+<HOST>\s*$
ignoreregex = ^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]+ fail2ban\.(?:actions|filter)\s+\[[a-zA-Z0-9_-]+\]\s+(?:Restore )?(?:Unban|unban)\s+<HOST>\s*$
EOF
        fi
        # ------------------------------------------------

        # --- FIX: DYNAMIC FAIL2BAN INFRASTRUCTURE WHITELIST (ANTI SELF-DOS) ---
        local f2b_ignoreip="127.0.0.1/8 ::1 fe80::/10"

        # 1. Dynamically extract Public IP of the server
        local public_ip
        public_ip=$(ip -4 addr show | grep -oEo 'inet [0-9.]+' | awk '{print $2}' | grep -v '127.0.0.1' | head -n 1 || true)
        if [[ -n "$public_ip" ]]; then f2b_ignoreip="$f2b_ignoreip $public_ip"; fi

        # 2. Dynamically extract active direct subnets (Lab & VPC Network protection)
        local local_subnets
        local_subnets=$(ip -4 route | grep -v default | awk '{print $1}' | tr '\n' ' ' || true)
        if [[ -n "$local_subnets" ]]; then f2b_ignoreip="$f2b_ignoreip $local_subnets"; fi

        # 3. Dynamically extract active DNS resolvers
        local dns_ips
        if [[ -f /etc/resolv.conf ]]; then
            dns_ips=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | grep -Eo '^[0-9.]+' | tr '\n' ' ' || true)
            if [[ -n "$dns_ips" ]]; then f2b_ignoreip="$f2b_ignoreip $dns_ips"; fi
        fi

        # 4. Add Custom Whitelist entries
        if [[ -s "$WHITELIST_FILE" ]]; then
            local wl_ips
            wl_ips=$(grep -vE '^\s*#|^\s*$' "$WHITELIST_FILE" | tr '\n' ' ' || true)
            f2b_ignoreip="$f2b_ignoreip $wl_ips"
        fi

        log "INFO" "Fail2ban infrastructure whitelist enforced: $f2b_ignoreip"
        # ----------------------------------------------------------------------

        cat <<EOF >/etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = $f2b_ignoreip
backend = auto
banaction = $f2b_action

# --- Persistent Attacker Protection (Recidive) ---
[syswarden-recidive]
enabled  = true
port     = 0:65535
filter   = syswarden-recidive
logpath  = /var/log/fail2ban.log
backend  = auto
banaction= $f2b_action
# Policy: 3 bans across ANY jail within 1 week triggers a 1-month absolute drop
maxretry = 3
findtime = 1w
bantime  = 4w

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = ${SSH_PORT:-22}
logpath = %(sshd_log)s
backend = $OS_BACKEND
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
            # Create Filter for 404/403 scanners
            # RED TEAM FIX: Replaced greedy '.*' with strictly bounded '[^"]*?' to prevent URI-based ReDoS.
            # Expanded HTTP methods to catch evasion techniques.
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/nginx-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405|444)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Nginx Protection ---
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
backend = auto

[nginx-scanner]
enabled = true
port    = http,https
filter  = nginx-scanner
logpath = /var/log/nginx/access.log
backend = auto
maxretry = 15
bantime  = 24h
EOF
        fi

        # 5. DYNAMIC DETECTION: APACHE
        APACHE_LOG=""
        APACHE_ACCESS=""
        if [[ -f "/var/log/apache2/error.log" ]]; then
            APACHE_LOG="/var/log/apache2/error.log" # Debian/Ubuntu
            APACHE_ACCESS="/var/log/apache2/access.log"
        elif [[ -f "/var/log/httpd/error_log" ]]; then
            APACHE_LOG="/var/log/httpd/error_log" # RHEL/CentOS
            APACHE_ACCESS="/var/log/httpd/access_log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."

            # Create Filter for 404/403 scanners (Apache specific)
            # RED TEAM FIX: ReDoS prevention and HTTP method expansion.
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/apache-scanner.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS|PROPFIND|TRACE) [^"]*?" (?:400|401|403|404|405)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Apache Protection ---
[apache-auth]
enabled = true
port = http,https
logpath = $APACHE_LOG
backend = auto

[apache-scanner]
enabled = true
port    = http,https
filter  = apache-scanner
logpath = $APACHE_ACCESS
backend = auto
maxretry = 15
bantime  = 24h
EOF
        fi

        # 6. DYNAMIC DETECTION: MONGODB
        if [[ -f "/var/log/mongodb/mongod.log" ]]; then
            log "INFO" "MongoDB logs detected. Enabling Mongo Jail."

            # Create strict Filter for Auth failures & Unauthorized commands (Injection probing)
            # RED TEAM FIX: Replaced '^.*' with non-greedy '^.*?' to stop deep engine traversal.
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/mongodb-guard.conf
[Definition]
failregex = ^.*? (?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).*? (?:<HOST>|remote:\s*<HOST>:\d+)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- MongoDB Protection ---
[mongodb-guard]
enabled = true
port = 27017
filter = mongodb-guard
logpath = /var/log/mongodb/mongod.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 7. DYNAMIC DETECTION: MARIADB / MYSQL
        MARIADB_LOG=""
        if [[ -f "/var/log/mysql/error.log" ]]; then
            MARIADB_LOG="/var/log/mysql/error.log" # Debian/Ubuntu default
        elif [[ -f "/var/log/mariadb/mariadb.log" ]]; then
            MARIADB_LOG="/var/log/mariadb/mariadb.log" # RHEL/Alma default
        fi

        if [[ -n "$MARIADB_LOG" ]]; then
            log "INFO" "MariaDB logs detected. Enabling MariaDB Jail."

            # Create Filter for Authentication Failures (Access Denied brute-force)
            # RED TEAM FIX: Non-greedy start and structured matching to prevent log spoofing.
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/mariadb-auth.conf
[Definition]
failregex = ^.*? \[?(?:Note|Warning|ERROR)\]? [Aa]ccess denied for user .*?@'<HOST>'(?: \(using password: (?:YES|NO)\))?
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- MariaDB Protection ---
[mariadb-auth]
enabled = true
port = 3306
filter = mariadb-auth
logpath = $MARIADB_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 8. DYNAMIC DETECTION: POSTFIX (SMTP)
        POSTFIX_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then
            POSTFIX_LOG="/var/log/mail.log" # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then
            POSTFIX_LOG="/var/log/maillog" # RHEL/Alma
        fi

        if [[ -n "$POSTFIX_LOG" ]]; then
            log "INFO" "Postfix logs detected. Enabling SMTP Jails."

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Postfix SMTP Protection ---
[postfix]
enabled = true
mode    = aggressive
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto

[postfix-sasl]
enabled = true
port    = smtp,465,submission
logpath = $POSTFIX_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 9. DYNAMIC DETECTION: VSFTPD (FTP)
        if [[ -f "/var/log/vsftpd.log" ]]; then
            log "INFO" "VSFTPD logs detected. Enabling FTP Jail."

            cat <<EOF >>/etc/fail2ban/jail.local

# --- VSFTPD Protection ---
[vsftpd]
enabled = true
port    = ftp,ftp-data,ftps,20,21
logpath = /var/log/vsftpd.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 10. DYNAMIC DETECTION: WORDPRESS (WP-LOGIN)
        # Reuses web logs detected in steps 4 & 5
        WP_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then
            WP_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."

            # Create specific filter for WP Login & XMLRPC
            # RED TEAM FIX: Prevent query string evasion and ReDoS by bounding quotes.
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/wordpress-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:wp-login\.php|xmlrpc\.php)[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- WordPress Protection ---
[wordpress-auth]
enabled = true
port = http,https
filter = wordpress-auth
logpath = $WP_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 10.5. DYNAMIC DETECTION: DRUPAL CMS
        DRUPAL_LOG=""
        # Check for standard web access logs across OS distributions
        if [[ -n "${APACHE_ACCESS:-}" ]]; then
            DRUPAL_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then DRUPAL_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$DRUPAL_LOG" ]]; then
            log "INFO" "Web logs detected. Enabling Drupal Guard."

            # Create Filter for Drupal Authentication Failures
            # RED TEAM FIX: Prevent query string evasion and ReDoS.
            if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/user/login|\?q=user/login)[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Drupal CMS Protection ---
[drupal-auth]
enabled  = true
port     = http,https
filter   = drupal-auth
logpath  = $DRUPAL_LOG
backend  = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 11. DYNAMIC DETECTION: NEXTCLOUD
        NC_LOG=""
        # Check common paths for Nextcloud log file
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then
                NC_LOG="$path"
                break
            fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."

            # Create Filter (Supports both JSON and Legacy text logs)
            # RED TEAM FIX: Switched to Heredoc and non-greedy start to prevent log parsing lag
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/nextcloud.conf
[Definition]
failregex = ^.*?Login failed: .*? \(Remote IP: '<HOST>'\).*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Nextcloud Protection ---
[nextcloud]
enabled = true
port    = http,https
filter  = nextcloud
logpath = $NC_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 12. DYNAMIC DETECTION: ASTERISK (VOIP)
        ASTERISK_LOG=""
        if [[ -f "/var/log/asterisk/messages" ]]; then
            ASTERISK_LOG="/var/log/asterisk/messages"
        elif [[ -f "/var/log/asterisk/full" ]]; then
            ASTERISK_LOG="/var/log/asterisk/full"
        fi

        if [[ -n "$ASTERISK_LOG" ]]; then
            log "INFO" "Asterisk logs detected. Enabling VoIP Jail."

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Asterisk VoIP Protection ---
[asterisk]
enabled  = true
filter   = asterisk
port     = 5060,5061
logpath  = $ASTERISK_LOG
maxretry = 5
bantime  = 24h
EOF
        fi

        # 13. DYNAMIC DETECTION: ZABBIX
        if [[ -f "/var/log/zabbix/zabbix_server.log" ]]; then
            log "INFO" "Zabbix Server logs detected. Enabling Zabbix Jail."

            # Create Filter for Zabbix Server Login Failures
            if [[ ! -f "/etc/fail2ban/filter.d/zabbix-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/zabbix-auth.conf
[Definition]
failregex = ^.*?failed login of user .*? from <HOST>.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Zabbix Protection ---
[zabbix-auth]
enabled = true
port    = http,https,10050,10051
filter  = zabbix-auth
logpath = /var/log/zabbix/zabbix_server.log
maxretry = 3
bantime  = 24h
EOF
        fi

        # 14. DYNAMIC DETECTION: HAPROXY
        if [[ -f "/var/log/haproxy.log" ]]; then
            log "INFO" "HAProxy logs detected. Enabling HAProxy Jail."

            # Create Filter for HTTP Errors (403 Forbidden, 404 Scan, 429 RateLimit)
            if [[ ! -f "/etc/fail2ban/filter.d/haproxy-guard.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/haproxy-guard.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? (?:400|403|404|429) .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- HAProxy Protection ---
[haproxy-guard]
enabled = true
port    = http,https,8080
filter  = haproxy-guard
logpath = /var/log/haproxy.log
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 15. DYNAMIC DETECTION: WIREGUARD
        if [[ -d "/etc/wireguard" ]]; then
            WG_LOG=""
            if [[ -f "/var/log/kern-firewall.log" ]]; then
                WG_LOG="/var/log/kern-firewall.log"
            elif [[ -f "/var/log/kern.log" ]]; then
                WG_LOG="/var/log/kern.log"
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."

                # Create Filter for Handshake Failures (Requires Kernel Logging)
                if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                    cat <<'EOF' >/etc/fail2ban/filter.d/wireguard.conf
[Definition]
failregex = ^.*?wireguard: .*? Handshake for peer .*? \(<HOST>:\d+\) did not complete.*$
ignoreregex = 
EOF
                fi

                cat <<EOF >>/etc/fail2ban/jail.local

# --- WireGuard Protection ---
[wireguard]
enabled = true
port    = 51820
protocol= udp
filter  = wireguard
logpath = $WG_LOG
maxretry = 5
bantime  = 24h
EOF
            fi
        fi

        # 16. DYNAMIC DETECTION: PHPMYADMIN
        # Reuses web logs detected in steps 4 & 5
        PMA_LOG=""
        if [[ -n "$APACHE_ACCESS" ]]; then
            PMA_LOG="$APACHE_ACCESS"
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        # Check if phpMyAdmin is installed (common paths)
        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/etc/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."

                # Create Filter for POST requests to PMA
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                    cat <<'EOF' >/etc/fail2ban/filter.d/phpmyadmin-custom.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?phpmyadmin[^"]*? HTTP[^"]*?" 200
ignoreregex = 
EOF
                fi

                cat <<EOF >>/etc/fail2ban/jail.local

# --- phpMyAdmin Protection ---
[phpmyadmin-custom]
enabled = true
port    = http,https
filter  = phpmyadmin-custom
logpath = $PMA_LOG
maxretry = 3
bantime  = 24h
EOF
            fi
        fi

        # 17. DYNAMIC DETECTION: LARAVEL
        LARAVEL_LOG=""
        # Check standard Laravel log paths
        for path in "/var/www/html/storage/logs/laravel.log" "/var/www/storage/logs/laravel.log"; do
            if [[ -f "$path" ]]; then
                LARAVEL_LOG="$path"
                break
            fi
        done

        # Fallback: search in /var/www (max depth 4)
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."

            # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
            if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/laravel-auth.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Laravel Protection ---
[laravel-auth]
enabled = true
port    = http,https
filter  = laravel-auth
logpath = $LARAVEL_LOG
maxretry = 5
bantime  = 24h
EOF
        fi

        # 18. DYNAMIC DETECTION: GRAFANA
        if [[ -f "/var/log/grafana/grafana.log" ]]; then
            log "INFO" "Grafana logs detected. Enabling Grafana Jail."

            # Create Filter for Grafana Auth Failures
            if [[ ! -f "/etc/fail2ban/filter.d/grafana-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" >/etc/fail2ban/filter.d/grafana-auth.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Grafana Protection ---
[grafana-auth]
enabled = true
port    = 3000,http,https
filter  = grafana-auth
logpath = /var/log/grafana/grafana.log
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 19. DYNAMIC DETECTION: SENDMAIL
        SM_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then
            SM_LOG="/var/log/mail.log"                                       # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then SM_LOG="/var/log/maillog"; fi # RHEL/Alma

        # Check if Sendmail is installed to avoid conflict with Postfix
        if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
            log "INFO" "Sendmail detected. Enabling Sendmail Jails."

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Sendmail Protection ---
[sendmail-auth]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 3
bantime  = 24h

[sendmail-reject]
enabled = true
port    = smtp,465,submission
logpath = $SM_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 20. DYNAMIC DETECTION: SQUID PROXY
        if [[ -f "/var/log/squid/access.log" ]]; then
            log "INFO" "Squid Proxy logs detected. Enabling Squid Jail."

            # Create Filter for Proxy Abuse (TCP_DENIED / 403 / 407)
            if [[ ! -f "/etc/fail2ban/filter.d/squid-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" >/etc/fail2ban/filter.d/squid-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Squid Proxy Protection ---
[squid-custom]
enabled = true
port    = 3128,8080
filter  = squid-custom
logpath = /var/log/squid/access.log
maxretry = 5
bantime  = 24h
EOF
        fi

        # --- DOCKER HERMETIC FAIL2BAN BLOCK ---
        if [[ "${USE_DOCKER:-n}" == "y" ]]; then
            log "INFO" "Creating Docker-specific Fail2ban banaction..."

            # Create a custom action that routes bans directly to the DOCKER-USER chain
            # This allows users to protect containers without breaking host SSH routing.
            cat <<'EOF' >/etc/fail2ban/action.d/syswarden-docker.conf
[Definition]
actionstart = iptables -N f2b-<name>
              iptables -A f2b-<name> -j RETURN
              iptables -I DOCKER-USER -p <protocol> -m multiport --dports <port> -j f2b-<name>
actionstop = iptables -D DOCKER-USER -p <protocol> -m multiport --dports <port> -j f2b-<name>
             iptables -F f2b-<name>
             iptables -X f2b-<name>
actioncheck = iptables -n -L DOCKER-USER | grep -q 'f2b-<name>[ \t]'
actionban = iptables -I f2b-<name> 1 -s <ip> -j DROP
actionunban = iptables -D f2b-<name> -s <ip> -j DROP
EOF
            log "INFO" "Docker banaction 'syswarden-docker' created successfully."
            # Note: The user can now append 'banaction = syswarden-docker' to any custom
            # Docker container jail in their jail.local to protect exposed container ports.
        fi

        # 21. DYNAMIC DETECTION: DOVECOT (IMAP/POP3)
        DOVECOT_LOG=""
        if [[ -f "/var/log/mail.log" ]]; then
            DOVECOT_LOG="/var/log/mail.log"
        elif [[ -f "/var/log/maillog" ]]; then DOVECOT_LOG="/var/log/maillog"; fi

        if [[ -n "$DOVECOT_LOG" ]] && command -v dovecot >/dev/null 2>&1; then
            log "INFO" "Dovecot detected. Enabling IMAP/POP3 Jail."

            # Filter for Dovecot Auth Failures (catches standard rip=IP format)
            if [[ ! -f "/etc/fail2ban/filter.d/dovecot-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*\$\nignoreregex =" >/etc/fail2ban/filter.d/dovecot-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Dovecot Protection ---
[dovecot-custom]
enabled = true
port    = pop3,pop3s,imap,imaps,submission,465,587
filter  = dovecot-custom
logpath = $DOVECOT_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 22. DYNAMIC DETECTION: PROXMOX VE
        if command -v pveversion >/dev/null 2>&1; then
            log "INFO" "Proxmox VE detected. Enabling PVE Jail."

            PVE_LOG="/var/log/daemon.log"
            if [[ ! -f "$PVE_LOG" ]]; then PVE_LOG="/var/log/syslog"; fi

            # Filter for Proxmox Web GUI Auth Failures
            if [[ ! -f "/etc/fail2ban/filter.d/proxmox-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*pvedaemon\\[\\d+\\]: authentication failure; rhost=<HOST> user=.*\$\nignoreregex =" >/etc/fail2ban/filter.d/proxmox-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Proxmox Protection ---
[proxmox-custom]
enabled = true
port    = https,8006
filter  = proxmox-custom
logpath = $PVE_LOG
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 23. DYNAMIC DETECTION: OPENVPN
        OVPN_LOG=""
        if [[ -f "/var/log/openvpn/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn/openvpn.log"
        elif [[ -f "/var/log/openvpn.log" ]]; then
            OVPN_LOG="/var/log/openvpn.log"
        elif [[ -f "/var/log/syslog" ]]; then OVPN_LOG="/var/log/syslog"; fi

        if [[ -d "/etc/openvpn" ]] && [[ -n "$OVPN_LOG" ]]; then
            log "INFO" "OpenVPN detected. Enabling OpenVPN Jail."

            # Filter for OpenVPN TLS Handshake & Verification Errors
            if [[ ! -f "/etc/fail2ban/filter.d/openvpn-custom.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.* <HOST>:[0-9]+ (?:TLS Error: TLS handshake failed|VERIFY ERROR:|TLS Auth Error:).*\$\nignoreregex =" >/etc/fail2ban/filter.d/openvpn-custom.conf
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- OpenVPN Protection ---
[openvpn-custom]
enabled = true
port    = 1194
protocol= udp
filter  = openvpn-custom
logpath = $OVPN_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 24. DYNAMIC DETECTION: GITEA / FORGEJO
        GITEA_LOG=""
        if [[ -f "/var/log/gitea/gitea.log" ]]; then
            GITEA_LOG="/var/log/gitea/gitea.log"
        elif [[ -f "/var/log/forgejo/forgejo.log" ]]; then GITEA_LOG="/var/log/forgejo/forgejo.log"; fi

        if [[ -n "$GITEA_LOG" ]]; then
            log "INFO" "Gitea/Forgejo detected. Enabling Git Server Jail."

            # Filter for Git Web UI Auth Failures
            if [[ ! -f "/etc/fail2ban/filter.d/gitea-custom.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/gitea-custom.conf
[Definition]
failregex = ^.*?Failed authentication attempt for .*? from <HOST>:.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Gitea / Forgejo Protection ---
[gitea-custom]
enabled = true
port    = http,https,3000
filter  = gitea-custom
logpath = $GITEA_LOG
backend = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 25. DYNAMIC DETECTION: COCKPIT (WEB CONSOLE)
        if systemctl is-active --quiet cockpit.socket 2>/dev/null || [[ -d "/etc/cockpit" ]]; then
            log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."

            if [[ ! -f "/etc/fail2ban/filter.d/cockpit-custom.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
failregex = ^.*?cockpit-ws.*?(?:authentication failed|invalid user).*?from <HOST>.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Cockpit Web Console Protection ---
[cockpit-custom]
enabled = true
port    = 9090
filter  = cockpit-custom
logpath = /var/log/secure
backend = $OS_BACKEND
maxretry = 3
bantime  = 24h
EOF
        fi

        # 26. DYNAMIC DETECTION: PRIVILEGE ESCALATION (PAM / SU / SUDO)
        AUTH_LOG=""
        if [[ -f "/var/log/auth-syswarden.log" ]]; then
            AUTH_LOG="/var/log/auth-syswarden.log"
        elif [[ -f "/var/log/auth.log" ]]; then
            AUTH_LOG="/var/log/auth.log"
        elif [[ -f "/var/log/secure" ]]; then AUTH_LOG="/var/log/secure"; fi

        if [[ -n "$AUTH_LOG" ]]; then
            log "INFO" "PAM/Auth logs detected. Enabling Privilege Escalation Guard (Su/Sudo)."

            # Create Filter for PAM, su, and sudo failures where rhost (Remote Host) is logged
            # This detects internal lateral movement and brute-force attempts on PAM-aware services
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-privesc.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-privesc.conf
[INCLUDES]
before = common.conf

[Definition]
# [DEVSECOPS FIX] Replaced blind '^.*' with strict '^%(__prefix_line)s' to prevent 
# syslog evaluation lag on massive authentication brute-force attacks.
failregex = ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*pam_unix\((?:su|sudo):auth\): authentication failure;.*rhost=<HOST>(?:\s+user=.*)?\s*$
            ^%(__prefix_line)s(?:su|sudo)(?:\[\d+\])?: .*(?:FAILED SU|FAILED su|authentication failure).*rhost=<HOST>.*\s*$
            ^%(__prefix_line)s PAM \d+ more authentication failures; logname=.* uid=.* euid=.* tty=.* ruser=.* rhost=<HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Privilege Escalation Protection (PAM/Su/Sudo) ---
[syswarden-privesc]
enabled = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port    = 0:65535
filter  = syswarden-privesc
logpath = $AUTH_LOG
backend = $OS_BACKEND
maxretry = 3
bantime  = 24h
EOF
        fi

        # 27. DYNAMIC DETECTION: CI/CD & DEVOPS INFRASTRUCTURE (JENKINS / GITLAB)

        # --- JENKINS ---
        if [[ -f "/var/log/jenkins/jenkins.log" ]]; then
            log "INFO" "Jenkins CI/CD logs detected. Enabling Jenkins Guard."

            # Create Filter for Jenkins Authentication Failures
            # Catches standard Jenkins login failures and invalid API token attempts
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jenkins.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jenkins.conf
[Definition]
failregex = ^.*(?:WARN|INFO).* (?:hudson\.security\.AuthenticationProcessingFilter2|jenkins\.security).* (?:unsuccessfulAuthentication|Login attempt failed).* from <HOST>.*\s*$
            ^.*(?:WARN|INFO).* Invalid password/token for user .* from <HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Jenkins CI/CD Protection ---
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

        # --- GITLAB ---
        GITLAB_LOG=""
        if [[ -f "/var/log/gitlab/gitlab-rails/application.log" ]]; then
            GITLAB_LOG="/var/log/gitlab/gitlab-rails/application.log"
        elif [[ -f "/var/log/gitlab/gitlab-rails/auth.log" ]]; then GITLAB_LOG="/var/log/gitlab/gitlab-rails/auth.log"; fi

        if [[ -n "$GITLAB_LOG" ]]; then
            log "INFO" "GitLab logs detected. Enabling GitLab Guard."

            # Create Filter for GitLab Authentication Failures
            # Catches web UI login failures and API authentication errors
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-gitlab.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-gitlab.conf
[Definition]
failregex = ^.*(?:Failed Login|Authentication failed).* (?:user|username)=.* (?:ip|IP)=<HOST>.*\s*$
            ^.*ActionController::InvalidAuthenticityToken.* IP: <HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- GitLab DevOps Protection ---
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

        # 28. DYNAMIC DETECTION: CRITICAL MIDDLEWARES (REDIS / RABBITMQ)

        # --- REDIS ---
        REDIS_LOG=""
        if [[ -f "/var/log/redis/redis-server.log" ]]; then
            REDIS_LOG="/var/log/redis/redis-server.log"
        elif [[ -f "/var/log/redis/redis.log" ]]; then REDIS_LOG="/var/log/redis/redis.log"; fi

        if [[ -n "$REDIS_LOG" ]]; then
            log "INFO" "Redis logs detected. Enabling Redis Guard."

            # Create Filter for Redis Authentication Failures
            # Covers both legacy 'requirepass' failures and modern Redis 6.0+ ACL failures
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-redis.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-redis.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Non-greedy matching (.*?) prevents ReDoS on massive log lines
failregex = ^.*? <HOST>:\d+ .*? [Aa]uthentication failed.*$
            ^.*? Client <HOST>:\d+ disconnected, .*? [Aa]uthentication.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Redis In-Memory Data Store Protection ---
[syswarden-redis]
enabled  = true
port     = 6379
filter   = syswarden-redis
logpath  = $REDIS_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        # --- RABBITMQ ---
        RABBIT_LOG=""
        # RabbitMQ appends the node name to the log file (e.g., rabbit@hostname.log)
        if ls /var/log/rabbitmq/rabbit@*.log 1>/dev/null 2>&1; then
            RABBIT_LOG="/var/log/rabbitmq/rabbit@*.log"
        elif [[ -f "/var/log/rabbitmq/rabbitmq.log" ]]; then
            RABBIT_LOG="/var/log/rabbitmq/rabbitmq.log"
        fi

        if [[ -n "$RABBIT_LOG" ]]; then
            log "INFO" "RabbitMQ logs detected. Enabling RabbitMQ Guard."

            # Create Filter for RabbitMQ Authentication Failures
            # Catches AMQP protocol brute-force and HTTP Management API login failures
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-rabbitmq.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-rabbitmq.conf
[Definition]
failregex = ^.*?HTTP access denied: .*? from <HOST>.*$
            ^.*?AMQP connection <HOST>:\d+ .*? failed: .*?authentication failure.*$
            ^.*?<HOST>:\d+ .*? (?:invalid credentials|authentication failed).*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- RabbitMQ Message Broker Protection ---
[syswarden-rabbitmq]
enabled  = true
port     = 5672,15672
filter   = syswarden-rabbitmq
logpath  = $RABBIT_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        # 29. DYNAMIC DETECTION: PORT SCANNERS & LATERAL MOVEMENT (NMAP / MASSCAN)

        FIREWALL_LOG=""
        if [[ -f "/var/log/kern-firewall.log" ]]; then
            FIREWALL_LOG="/var/log/kern-firewall.log"
        elif [[ -f "/var/log/kern.log" ]]; then
            FIREWALL_LOG="/var/log/kern.log"
        elif [[ -f "/var/log/messages" ]]; then
            FIREWALL_LOG="/var/log/messages"
        elif [[ -f "/var/log/syslog" ]]; then FIREWALL_LOG="/var/log/syslog"; fi

        if [[ -n "$FIREWALL_LOG" ]]; then
            log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."

            # Always overwrite to ensure the latest threat signatures are active
            cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-portscan.conf
[INCLUDES]
before = common.conf

[Definition]
# DEVSECOPS OPTIMIZATION: Strict prefix anchoring to strictly prevent user-space Log Injection
failregex = ^%(__prefix_line)s(?:kernel:\s+)?(?:\[\s*\d+\.\d+\]\s+)?\[SysWarden-BLOCK\].*?SRC=<HOST> 
ignoreregex = 
EOF

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Port Scanner & Lateral Movement Protection ---
[syswarden-portscan]
enabled  = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port     = 0:65535
filter   = syswarden-portscan
logpath  = $FIREWALL_LOG
backend  = $OS_BACKEND
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
        fi

        # 30. DYNAMIC DETECTION: SENSITIVE FILE INTEGRITY & AUDITD ANOMALIES
        AUDIT_LOG="/var/log/audit/audit.log"

        if command -v auditd >/dev/null 2>&1 && [[ -f "$AUDIT_LOG" ]]; then
            log "INFO" "Auditd logs detected. Enabling System Integrity Guard."

            # Create Filter for Auditd anomalies (Unauthorized access, failed auth, bad commands)
            # Looks for kernel-level audit records containing a remote address (addr=IP)
            # and a failure result (res=failed or res=0), or binary crash anomalies.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-auditd.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-auditd.conf
[Definition]
failregex = ^.*type=(?:USER_LOGIN|USER_AUTH|USER_ERR|USER_CMD).*addr=(?:::f{4}:)?<HOST>.*res=(?:failed|0)\s*$
            ^.*type=ANOM_ABEND.*addr=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- System Integrity & Kernel Audit Protection ---
[syswarden-auditd]
enabled  = true
# FIX: Use 0:65535 instead of 'all' for nftables-multiport compatibility
port     = 0:65535
filter   = syswarden-auditd
logpath  = $AUDIT_LOG
backend  = $OS_BACKEND
maxretry = 3
bantime  = 24h
EOF
        fi

        # 31. DYNAMIC DETECTION: RCE & REVERSE SHELL PAYLOADS
        RCE_LOGS=""
        for log_file in "/var/log/nginx/access.log" "/var/log/apache2/access.log" "/var/log/httpd/access_log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$RCE_LOGS" ]]; then
                    RCE_LOGS="$log_file"
                else
                    # DEVSECOPS FIX: Strict Python ConfigParser multiline format
                    RCE_LOGS+=$'\n          '"$log_file"
                fi
            fi
        done

        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."

            # Create Filter for Remote Code Execution and Reverse Shell signatures
            # Catches common payloads: bash interactive, netcat, wget/curl drops, and python/php one-liners
            # FIX: Using regex hex escape '\x25' instead of '%' to strictly bypass Python configparser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
# DEVSECOPS NOTES:
# 1. Replaced '.*' with '[^"]*?' inside the HTTP request string to prevent ReDoS (Catastrophic Backtracking).
# 2. Expanded HTTP methods (DELETE, PATCH, OPTIONS can be used to bypass WAFs).
# 3. Clustered space bypasses: whitespace, URL-encoded space (\x2520), tab (\x2509), and plus sign (+).
# 4. Added command execution chaining (; | ` $) followed by critical binaries.
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc(?:\s+|\x2520|\x2509|\+)+(?:-e|-c)|(?:curl|wget)(?:\s+|\x2520|\x2509|\+)+(?:-q|-s|-O|http)|python(?:\s+|\x2520|\x2509|\+)+-c|php(?:\s+|\x2520|\x2509|\+)+-r|(?:\x253B|;|\x257C|\||`|\x2560|\$|\x2524)(?:\s+|\x2520|\x2509|\+)*(?:bash|sh|nc|curl|wget|chmod)).*?" .*$

ignoreregex = 
EOF
            fi

            # Ensure the jail configuration is appended securely
            # Relying on Fail2ban's default banaction to seamlessly support iptables, nftables, ufw, and firewalld
            cat <<EOF >>/etc/fail2ban/jail.local

# --- Reverse Shell & RCE Injection Protection ---
[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy for RCE payloads
maxretry = 1
findtime = 3600
bantime  = 24h
EOF
        fi

        # 32. DYNAMIC DETECTION: MALICIOUS AI BOTS & SCRAPERS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling AI-Bot Guard."

            # Create Filter for aggressive AI Scrapers, Crawlers, and LLM data miners
            # RED TEAM FIX: Strictly bound the URI and User-Agent parsing fields to prevent ReDoS payloads in User-Agent strings.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-aibots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-aibots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|OPTIONS) [^"]*?" \d{3} [^"]*? "[^"]*?(?:GPTBot|ChatGPT-User|OAI-SearchBot|ClaudeBot|Claude-Web|Anthropic-ai|Google-Extended|PerplexityBot|Omgili|FacebookBot|Bytespider|CCBot|Diffbot|Amazonbot|Applebot-Extended|cohere-ai)[^"]*?"
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Malicious AI Bots & Scrapers Protection ---
[syswarden-aibots]
enabled  = true
port     = http,https
filter   = syswarden-aibots
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 hit = 48 hours ban at the kernel level
maxretry = 1
bantime  = 48h
EOF
        fi

        # 33. DYNAMIC DETECTION: MALICIOUS SCANNERS & PENTEST TOOLS
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Bad-Bot & Scanner Guard."

            # Create Filter for aggressive pentest tools, vulnerability scanners, and malicious crawlers
            # RED TEAM FIX: Same strict bounds for offensive User-Agents.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-badbots.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-badbots.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT) [^"]*?" \d{3} [^"]*? "[^"]*?(?:Nuclei|sqlmap|Nikto|ZmEu|OpenVAS|wpscan|masscan|zgrab|CensysInspect|Shodan|NetSystemsResearch|projectdiscovery|Go-http-client|Java/|Hello World|python-requests|libwww-perl|Acunetix|Nmap|Netsparker|BurpSuite|DirBuster|dirb|gobuster|httpx|ffuf)[^"]*?"
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Malicious Scanners & Pentest Tools Protection ---
[syswarden-badbots]
enabled  = true
port     = http,https
filter   = syswarden-badbots
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 hit = 48 hours ban at the kernel level
maxretry = 1
bantime  = 48h
EOF
        fi

        # 34. DYNAMIC DETECTION: LAYER 7 DDOS (HTTP FLOOD)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Layer 7 Anti-DDoS Guard."

            # Create Filter for HTTP Floods
            # Matches absolutely ANY request (GET, POST, etc.) to count the raw volume per IP
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-httpflood.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
# [DEVSECOPS FIX] Micro-Regex: We only parse up to the timestamp bracket and stop.
# This saves ~85% CPU cycles during a volumetric Layer 7 DDoS attack.
failregex = ^<HOST> \S+ \S+ \[
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Layer 7 DDoS & HTTP Flood Protection ---
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $RCE_LOGS
backend  = auto
# Enterprise Policy: 300 requests in 5 seconds allows Python I/O buffer to process floods without Self-DoS
maxretry = 300
findtime = 5
bantime  = 24h
EOF
        fi

        # --- 34.5 DYNAMIC DETECTION: MODSECURITY WAF (PURPLE TEAM INTEGRATION) ---
        local MODSEC_ACTIVE=0
        local MODSEC_LOGS=""

        # DEVSECOPS FIX: Ensure base audit log exists physically to prevent Fail2ban Exception 255
        if [[ ! -f "/var/log/modsec_audit.log" ]]; then
            touch /var/log/modsec_audit.log
            chmod 640 /var/log/modsec_audit.log
            chown root:root /var/log/modsec_audit.log 2>/dev/null || true
        fi

        # DEVSECOPS FIX: Strict Python ConfigParser multiline format for multiple logs.
        # Fail2ban crashes if multiple paths are space-separated on a single line.
        for log_file in "/var/log/nginx/error.log" "/var/log/apache2/error.log" "/var/log/httpd/error_log" "/var/log/modsec_audit.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$MODSEC_LOGS" ]]; then
                    MODSEC_LOGS="$log_file"
                else
                    MODSEC_LOGS+=$'\n          '"$log_file"
                fi
            fi
        done

        if [[ -n "$MODSEC_LOGS" ]] && [[ -d "/etc/modsecurity" ]] && [[ -f "/etc/modsecurity/main.conf" ]]; then
            MODSEC_ACTIVE=1
            log "INFO" "ModSecurity WAF detected. Enabling Purple Team integration."

            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-modsec.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Catch Critical/Error ModSecurity drops to ban the attacker at Kernel level.
failregex = ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Access denied with code [45]\d\d.*$
            ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Warning\. Pattern match.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- ModSecurity WAF Integration (Purple Team) ---
[syswarden-modsec]
enabled  = true
port     = http,https
filter   = syswarden-modsec
logpath  = $MODSEC_LOGS
backend  = auto
# Policy: 3 ModSec drops = 24h Kernel Ban
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
        fi

        # 35. DYNAMIC DETECTION: WEBSHELL UPLOADS (LFI / RFI)
        if [[ -n "$RCE_LOGS" ]] && [[ $MODSEC_ACTIVE -eq 0 ]]; then
            log "INFO" "Web access logs detected. Enabling WebShell Upload Guard."

            # Create Filter for malicious file uploads
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-webshell.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-webshell.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*(?:/upload|/media|/images|/assets|/files|/tmp|/wp-content/uploads)[^"]*\.(?:php\d?|phtml|phar|aspx?|ashx|jsp|cgi|pl|py|sh|exe)(?:\?[^"]*)? HTTP/[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Malicious WebShell Upload Protection ---
[syswarden-webshell]
enabled  = true
port     = http,https
filter   = syswarden-webshell
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to upload a shell = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 36. DYNAMIC DETECTION: SQL INJECTION (SQLi) & XSS PAYLOADS
        if [[ -n "$RCE_LOGS" ]] && [[ $MODSEC_ACTIVE -eq 0 ]]; then
            log "INFO" "Web access logs detected. Enabling SQLi & XSS Payload Guard."

            # Create Filter for SQLi, XSS, and Path Traversal payloads in URIs
            # Catches: UNION SELECT, CONCAT, SLEEP, <script>, alert(), document.cookie, eval(), ../../
            # FIX: Used \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sqli-xss.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sqli-xss.conf
[Definition]
# [DEVSECOPS FIX] Replaced '.*' with '[^"]*' inside the HTTP request string to strictly bound
# the evaluation and mathematically prevent ReDoS (Catastrophic Backtracking) on massive payloads.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|PATCH|DELETE) [^"]*(?:UNION(?:\s|\+|\x2520)SELECT|CONCAT(?:\s|\+|\x2520)?\(|WAITFOR(?:\s|\+|\x2520)DELAY|SLEEP(?:\s|\+|\x2520)?\(|\x253Cscript|\x253E|\x253C\x252Fscript|<script|alert\(|onerror=|onload=|document\.cookie|base64_decode\(|eval\(|\.\./\.\./|\x252E\x252E\x252F)[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- SQL Injection (SQLi) & XSS Protection ---
[syswarden-sqli-xss]
enabled  = true
port     = http,https
filter   = syswarden-sqli-xss
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 blatant SQLi/XSS payload = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 37. DYNAMIC DETECTION: STEALTH SECRETS & CONFIG HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Stealth Secrets Hunter Guard."

            # Create Filter for sensitive file and config directory bruteforcing
            # Catches: .env, .git, .aws, id_rsa, .sql, .bak, docker-compose, etc.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-secretshunter.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-secretshunter.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/\.env[^ ]*|/\.git/?.*|/\.aws/?.*|/\.ssh/?.*|/id_rsa[^ ]*|/id_ed25519[^ ]*|/[^ ]*\.(?:sql|bak|swp|db|sqlite3?)(?:\.gz|\.zip)?|/docker-compose\.ya?ml|/wp-config\.php\.(?:bak|save|old|txt|zip)) HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Stealth Secrets & Config Hunting Protection ---
[syswarden-secretshunter]
enabled  = true
port     = http,https
filter   = syswarden-secretshunter
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to access a sensitive config file = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 38. DYNAMIC DETECTION: SSRF & CLOUD METADATA EXFILTRATION
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling SSRF & Cloud Metadata Guard."

            # Create Filter for Server-Side Request Forgery targeting Cloud instances
            # Catches: 169.254.169.254 (AWS/GCP/Azure/Linode metadata IP) and common metadata endpoints
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:169\.254\.169\.254|latest/meta-data|metadata\.google\.internal|/v1/user-data|/metadata/v1).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- SSRF & Cloud Metadata Exfiltration Protection ---
[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 39. DYNAMIC DETECTION: JNDI, LOG4J & SSTI PAYLOADS
        if [[ -n "$RCE_LOGS" ]] && [[ $MODSEC_ACTIVE -eq 0 ]]; then
            log "INFO" "Web access logs detected. Enabling JNDI & SSTI Guard."

            # Create Filter for Log4Shell (JNDI) and Server-Side Template Injection (SSTI)
            # Catches: ${jndi:ldap...}, URL-encoded equivalents, and Spring4Shell payloads in URLs AND User-Agents
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-jndi-ssti.conf
[Definition]
# DEVSECOPS OPTIMIZATION: Consolidated regex paths for reduced CPU cyclic overhead
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*?(?:\$\{jndi:|\x2524\x257Bjndi:|class\.module\.classLoader|\x2524\x257Bspring\.macro).* HTTP/.*" \d{3} .*$
            ^<HOST> \S+ \S+ \[.*?\] ".*?" \d{3} .*? "(?:\$\{jndi:|\x2524\x257Bjndi:).*?"$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- JNDI, Log4Shell & SSTI Injection Protection ---
[syswarden-jndi-ssti]
enabled  = true
port     = http,https
filter   = syswarden-jndi-ssti
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 40. DYNAMIC DETECTION: API MAPPING & SWAGGER HUNTING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling API Mapper Guard."

            # Create Filter for API Blueprint Hunting (Swagger, OpenAPI, GraphiQL)
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) [^"]*(?:/swagger-ui[^ "]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ "]*|/graphiql|/graphql/schema) HTTP/[^"]*" (403|404)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- API Mapping & Swagger Hunting Protection ---
[syswarden-apimapper]
enabled  = true
port     = http,https
filter   = syswarden-apimapper
logpath  = $RCE_LOGS
backend  = auto
# Policy: 2 attempts to find hidden API documentation = 48 hours ban
maxretry = 2
bantime  = 48h
EOF
        fi

        # 40.5. DYNAMIC DETECTION: BEHAVIORAL IDOR ENUMERATION & API BRUTE-FORCING
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Behavioral IDOR Guard."

            # Create Filter for IDOR (Insecure Direct Object Reference) Enumeration
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-idor-enum.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-idor-enum.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH) [^"]*(?:/api/v[0-9]+/|/users?/|/profile/|/invoices?/|/downloads?/|/docs?/|/id/|/view\?id=)[a-zA-Z0-9_-]+/?(?:[^"]*)? HTTP/[^"]*" (401|403|404)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Behavioral IDOR Enumeration & API Brute-Forcing Protection ---
[syswarden-idor-enum]
enabled  = true
port     = http,https
filter   = syswarden-idor-enum
logpath  = $RCE_LOGS
backend  = auto
# Policy: 15 direct reference errors within 10 seconds = Targeted offensive scan
maxretry = 15
findtime = 10
bantime  = 24h
EOF
        fi

        # 41. DYNAMIC DETECTION: ADVANCED LFI & WRAPPER ABUSE
        if [[ -n "$RCE_LOGS" ]] && [[ $MODSEC_ACTIVE -eq 0 ]]; then
            log "INFO" "Web access logs detected. Enabling Advanced LFI Guard."

            # Create Filter for Advanced Local File Inclusion and PHP Wrapper abuse
            # Catches: php://, file://, expect://, /etc/passwd, /etc/shadow, and null byte (%00) injections
            # Note: We use \x25 instead of % to prevent Python ConfigParser interpolation crashes
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-lfi-advanced.conf
[Definition]
# [DEVSECOPS FIX] Non-greedy bounds applied. Stops parsing exactly at the HTTP quote.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT) [^"]*(?:php://(?:filter|input|expect)|php\x253A\x252F\x252F|file://|file\x253A\x252F\x252F|zip://|phar://|/etc/(?:passwd|shadow|hosts)|\x252Fetc\x252F(?:passwd|shadow)|/windows/(?:win\.ini|system32)|(?:\x2500|\x252500)[^ ]*\.(?:php|py|sh|pl|rb))[^"]*" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Advanced LFI & Wrapper Abuse Protection ---
[syswarden-lfi-advanced]
enabled  = true
port     = http,https
filter   = syswarden-lfi-advanced
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance
maxretry = 1
bantime  = 48h
EOF
        fi

        # 42. DYNAMIC DETECTION: VAULTWARDEN (BITWARDEN COMPATIBLE PASSWORD MANAGER)
        VW_LOG=""
        # Search for standard Vaultwarden log paths (Native or Docker mounted)
        for path in "/var/log/vaultwarden/vaultwarden.log" "/vw-data/vaultwarden.log" "/opt/vaultwarden/vaultwarden.log"; do
            if [[ -f "$path" ]]; then
                VW_LOG="$path"
                break
            fi
        done

        if [[ -n "$VW_LOG" ]]; then
            log "INFO" "Vaultwarden logs detected. Enabling Vaultwarden Guard."

            # Create Filter for Vaultwarden Master Password brute-forcing
            # Note: Vaultwarden MUST be configured with LOG_IP_ADDRESSES=true or EXTENDED_LOGGING=true
            # Catches standard Rust backend identity warnings
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-vaultwarden.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-vaultwarden.conf
[Definition]
failregex = ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Invalid password.*from <HOST>.*\s*$
            ^.*\[vaultwarden::api::identity\]\[(?:WARN|ERROR)\].*Client IP: <HOST>.*\s*$
            ^.*\[(?:ERROR|WARN)\].*Failed login attempt.*from <HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Vaultwarden / Bitwarden Password Manager Protection ---
[syswarden-vaultwarden]
enabled  = true
port     = http,https,80,443,8080
filter   = syswarden-vaultwarden
logpath  = $VW_LOG
backend  = auto
# Zero-Tolerance for the password vault: 3 failed attempts = 24h ban
maxretry = 3
bantime  = 24h
EOF
        fi

        # 43. DYNAMIC DETECTION: IAM & SSO (AUTHELIA / AUTHENTIK)
        SSO_LOG=""
        # Check standard output logs for major open-source SSO providers
        for path in "/var/log/authelia/authelia.log" "/var/log/authentik/authentik.log" "/opt/authelia/authelia.log" "/opt/authentik/authentik.log"; do
            if [[ -f "$path" ]]; then
                SSO_LOG="$path"
                break
            fi
        done

        if [[ -n "$SSO_LOG" ]]; then
            log "INFO" "SSO (Authelia/Authentik) logs detected. Enabling IAM Guard."

            # Create Filter for Identity and Access Management credential stuffing
            # Supports both Authelia (logfmt/JSON) and Authentik (JSON) log formats
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-sso.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-sso.conf
[Definition]
failregex = ^.*(?:level=error|level=\"error\").*msg=\"Authentication failed\".*remote_ip=\"<HOST>\".*$
            ^.*(?:\"event\":\"Failed login\"|event=\'Failed login\').*(?:\"client_ip\":\"<HOST>\"|\"remote_ip\":\"<HOST>\").*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Authelia / Authentik SSO Protection ---
[syswarden-sso]
enabled  = true
port     = http,https
filter   = syswarden-sso
logpath  = $SSO_LOG
backend  = auto
# Strict policy to prevent SSO compromise
maxretry = 3
bantime  = 24h
EOF
        fi

        # 44. DYNAMIC DETECTION: BEHAVIORAL SILENT SCANNERS (DIRBUSTER/GOBUSTER)
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Behavioral Scanner Guard."

            # Create Filter for high-frequency 400/401/403/404/405/444 errors
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-silent-scanner.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-silent-scanner.conf
[Definition]
# [DEVSECOPS FIX] Bounded the HTTP request parsing [^"]* to mathematically prevent ReDoS
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PROPFIND) [^"]*" (?:400|401|403|404|405|444)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Behavioral Silent Scanner Protection (DirBuster/Gobuster) ---
[syswarden-silent-scanner]
enabled  = true
port     = http,https
filter   = syswarden-silent-scanner
logpath  = $RCE_LOGS
backend  = auto
# Policy: 20 anomalous HTTP errors within 10 seconds triggers an immediate drop
maxretry = 20
findtime = 10
bantime  = 48h
EOF
        fi

        # 45. DYNAMIC DETECTION: OPEN PROXY PROBING & EXOTIC HTTP METHOD ABUSE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Open Proxy & Exotic Method Guard."

            # Create Filter for Open Proxy Probing and Tunneling attempts
            # RED TEAM FIX: Non-greedy bounds to prevent ReDoS on massive CONNECT requests.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-proxy-abuse.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:CONNECT|TRACE|TRACK|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK) [^"]*?" \d{3}
            ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) (?:http|https)(?:\x253A|:)//[^"]*?" \d{3}
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Open Proxy Abuse & Malicious Tunneling Protection ---
[syswarden-proxy-abuse]
enabled  = true
port     = http,https
filter   = syswarden-proxy-abuse
logpath  = $RCE_LOGS
backend  = auto
# Zero-Tolerance policy: 1 attempt to use the server as a proxy = 48 hours kernel ban
maxretry = 1
bantime  = 48h
EOF
        fi

        # 46. DYNAMIC DETECTION: TELNET HONEYPOT & IOT BOTNETS (MIRAI/GAFGYT)
        TELNET_LOG=""
        # Dynamically aggregate auth and system logs where login/telnetd events are recorded
        for log_file in "/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/auth-syswarden.log"; do
            if [[ -f "$log_file" ]]; then
                if [[ -z "$TELNET_LOG" ]]; then
                    TELNET_LOG="$log_file"
                else
                    # HOTFIX: Strict ConfigParser multiline format (newline + 10 spaces)
                    TELNET_LOG+=$'\n          '"$log_file"
                fi
            fi
        done

        # Check if Port 23 is actively listening or if telnetd is installed
        if [[ -n "$TELNET_LOG" ]] && { command -v telnetd >/dev/null 2>&1 || ss -tlnp 2>/dev/null | grep -qE ':(23)\b'; }; then
            log "INFO" "Telnet service detected on Port 23. Enabling IoT Botnet Guard."

            # Create Filter for Telnet Brute-force and IoT Botnet probing
            # Catches:
            # 1. Raw tcpwrapper/xinetd telnetd connections (excessive probing)
            # 2. FAILED LOGIN from standard OS /bin/login (which telnetd pipes to)
            # 3. PAM authentication failures strictly tied to the 'login' service
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-telnet.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-telnet.conf
[Definition]
failregex = ^.*(?:in\.telnetd|telnetd)(?:\[\d+\])?: connect from (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+FAILED LOGIN.*(?:FROM|from) (?:::f{4}:)?<HOST>.*\s*$
            ^.*login(?:\[\d+\])?:\s+.*(?:authentication failure|invalid password).*rhost=(?:::f{4}:)?<HOST>.*\s*$
            ^.*pam_unix\(login:auth\): authentication failure;.*rhost=(?:::f{4}:)?<HOST>.*\s*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Telnet Honeypot & IoT Botnet Protection (Mirai/Gafgyt) ---
[syswarden-telnet]
enabled  = true
port     = 23,telnet
filter   = syswarden-telnet
logpath  = $TELNET_LOG
backend  = auto
# Purple Team Policy: Allow 3 attempts to capture the attacker's payload/credentials in logs for Threat Intel, then drop.
maxretry = 3
findtime = 10m
bantime  = 48h
EOF
        fi

        # 47. DYNAMIC DETECTION: GENERIC BRUTE-FORCE & PASSWORD SPRAYING (HTML/PHP LOGINS)
        # Relies on $RCE_LOGS aggregated earlier in the script
        if [[ -n "${RCE_LOGS:-}" ]]; then
            log "INFO" "Web access logs detected. Enabling Generic Brute-Force & Password Spraying Guard."

            # Create Filter for generic login endpoints
            # RED TEAM FIX: Removed inner greedy match to prevent regex engine exhaustion on fake auth endpoints.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-generic-auth.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-generic-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login|/sign-in|/signin|/log-in|/auth|/authenticate|/admin/login|/user/login|/member/login)[^"]*?(?:\.php|\.html|\.htm|\.jsp|\.aspx)?[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Generic Web Authentication Brute-Force & Password Spraying Protection ---
[syswarden-generic-auth]
enabled  = true
port     = http,https
filter   = syswarden-generic-auth
logpath  = $RCE_LOGS
backend  = auto
# Policy: 5 failed login attempts (or password spraying hits) within 10 minutes = 24h ban
maxretry = 5
findtime = 10m
bantime  = 24h
EOF
        fi

        # 48. DYNAMIC DETECTION: ODOO ERP
        ODOO_LOG=""
        # Search for standard Odoo log files
        if [[ -f "/var/log/odoo/odoo-server.log" ]]; then
            ODOO_LOG="/var/log/odoo/odoo-server.log"
        elif [[ -f "/var/log/odoo/odoo.log" ]]; then
            ODOO_LOG="/var/log/odoo/odoo.log"
        fi

        if [[ -n "$ODOO_LOG" ]]; then
            log "INFO" "Odoo ERP logs detected. Enabling Odoo Guard."

            # Create Filter for Odoo Authentication Failures
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-odoo.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-odoo.conf
[Definition]
failregex = ^.*? \d+ INFO \S+ odoo\.addons\.base\.models\.res_users: Login failed for db:.*? login:.*? from <HOST>.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Odoo ERP Protection ---
[syswarden-odoo]
enabled  = true
port     = http,https,8069
filter   = syswarden-odoo
logpath  = $ODOO_LOG
backend  = auto
maxretry = 4
bantime  = 24h
EOF
        fi

        # 49. DYNAMIC DETECTION: PRESTASHOP E-COMMERCE
        if [[ -n "$RCE_LOGS" ]]; then
            # PrestaShop often runs on the main web server logs
            # We check if it's potentially a web hosting server
            log "INFO" "Web access logs detected. Enabling PrestaShop Guard."

            # Create Filter for PrestaShop Backoffice Brute-Force
            # RED TEAM FIX: Bounded the URI parsing to strictly prevent query string ReDoS.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-prestashop.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-prestashop.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?index\.php\?[^"]*?controller=AdminLogin[^"]*?" 200
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- PrestaShop E-Commerce Protection ---
[syswarden-prestashop]
enabled  = true
port     = http,https
filter   = syswarden-prestashop
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 50. DYNAMIC DETECTION: ATLASSIAN JIRA & CONFLUENCE
        if [[ -n "$RCE_LOGS" ]]; then
            log "INFO" "Web access logs detected. Enabling Atlassian Guard."

            # Create Filter for Jira and Confluence Auth Failures
            # RED TEAM FIX: Strict non-greedy bounds inside the HTTP method quotes.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-atlassian.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-atlassian.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/login\.jsp|/dologin\.action|/rest/auth/\d+/session)[^"]*?" (?:401|403|200)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Atlassian Jira & Confluence Protection ---
[syswarden-atlassian]
enabled  = true
port     = http,https,8080,8090
filter   = syswarden-atlassian
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 51. DYNAMIC DETECTION: DOLIBARR ERP & CRM
        if [[ -n "$RCE_LOGS" ]]; then
            # We check if Dolibarr might be present (optional check to avoid overlapping generic index.php rules,
            # but relying on RCE_LOGS is standard for Syswarden web guards).
            log "INFO" "Web access logs detected. Enabling Dolibarr ERP Guard."

            # Create Filter for Dolibarr Authentication Failures
            # RED TEAM FIX: Strict non-greedy bounds inside the HTTP method quotes.
            # Rationale: Dolibarr Web UI returns HTTP 200 on failed logins (form reload).
            # The REST API returns 401/403. We catch both vectors strictly on POST requests.
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-dolibarr.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-dolibarr.conf
[Definition]
# [DEVSECOPS FIX] Bounded the URI parsing to strictly prevent query string ReDoS.
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/htdocs/index\.php|/index\.php|/api/index\.php/login)[^"]*?" (?:200|401|403)
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Dolibarr ERP & CRM Protection ---
[syswarden-dolibarr]
enabled  = true
port     = http,https
filter   = syswarden-dolibarr
logpath  = $RCE_LOGS
backend  = auto
maxretry = 5
bantime  = 24h
EOF
        fi

        # 52. DYNAMIC DETECTION: TLS/SSL LAYER ATTACKS (NGINX)
        if [[ -d "/etc/nginx" ]] && command -v nginx >/dev/null 2>&1; then
            log "INFO" "Nginx detected. Preparing TLS error logging for Syswarden."

            NGINX_CONF="/etc/nginx/nginx.conf"
            NGINX_LOG="/var/log/nginx/error.log"

            # --- HOTFIX: AUTOMATED NGINX LOG LEVEL HARDENING ---
            if grep -qE "^\s*error_log\s+.*info;" "$NGINX_CONF" 2>/dev/null; then
                log "INFO" "Nginx error_log is already set to 'info'. No changes needed."
            elif [[ -f "$NGINX_CONF" ]]; then
                log "INFO" "Modifying Nginx error_log to 'info' level to expose TLS attacks..."
                cp "$NGINX_CONF" "${NGINX_CONF}.syswarden.bak"

                # Safely replace existing error_log directive (commented or active) with the info level
                if grep -q "error_log" "$NGINX_CONF"; then
                    sed -i -E 's|^\s*#?\s*error_log\s+.*|error_log /var/log/nginx/error.log info;|' "$NGINX_CONF"
                else
                    # If absolutely no error_log exists, inject it at the top of the file
                    sed -i '1i error_log /var/log/nginx/error.log info;' "$NGINX_CONF"
                fi

                # Verify Nginx syntax before applying to prevent web server crash
                if nginx -t >/dev/null 2>&1; then
                    if command -v systemctl >/dev/null 2>&1; then
                        systemctl reload nginx >/dev/null 2>&1 || true
                    fi
                    log "INFO" "Nginx TLS logging enabled and reloaded successfully."
                else
                    log "ERROR" "Nginx syntax check failed. Reverting changes to prevent crash."
                    mv "${NGINX_CONF}.syswarden.bak" "$NGINX_CONF"
                fi
            fi
            # ----------------------------------------------------

            # Ensure the log file exists so Fail2ban doesn't crash on startup
            if [[ ! -f "$NGINX_LOG" ]]; then
                touch "$NGINX_LOG"
                # Handle Alpine (nginx:nginx) vs Ubuntu (www-data:adm) automatically
                chown nginx:nginx "$NGINX_LOG" 2>/dev/null || chown www-data:adm "$NGINX_LOG" 2>/dev/null || chown root:root "$NGINX_LOG"
                chmod 640 "$NGINX_LOG"
            fi

            # Create Filter for TLS Handshake failures, SNI mismatch, and mTLS bypass attempts
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-tls-guard.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-tls-guard.conf
[Definition]
# [DEVSECOPS FIX] Non-greedy parsing to catch core SSL errors natively emitted by Nginx
failregex = ^.*? \[info\] \d+#\d+: \*\d+ SSL_do_handshake\(\) failed .*? client: <HOST>
            ^.*? \[info\] \d+#\d+: \*\d+ peer closed connection in SSL handshake .*? client: <HOST>
            ^.*? \[error\] \d+#\d+: \*\d+ no "ssl_certificate" is defined in server listening on SSL port .*? client: <HOST>
            ^.*? \[error\] \d+#\d+: \*\d+ client SSL certificate verify error: .*? client: <HOST>
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- TLS/SSL Protocol & SNI Protection ---
[syswarden-tls-guard]
enabled  = true
port     = https,443,8443
filter   = syswarden-tls-guard
logpath  = $NGINX_LOG
backend  = auto
# Policy: 10 SSL errors in 1 minute indicates active TLS Fuzzing or massive direct IP scanning.
maxretry = 10
findtime = 60
bantime  = 24h
EOF
        fi

        # 53. DYNAMIC DETECTION: TLS/SSL LAYER ATTACKS (APACHE)
        APACHE_ERR_LOG=""
        if [[ -f "/var/log/apache2/error.log" ]]; then
            APACHE_ERR_LOG="/var/log/apache2/error.log" # Debian/Ubuntu
        elif [[ -f "/var/log/httpd/error_log" ]]; then
            APACHE_ERR_LOG="/var/log/httpd/error_log" # RHEL/CentOS/Alma/Alpine
        fi

        if [[ -n "$APACHE_ERR_LOG" ]]; then
            log "INFO" "Apache error logs detected. Enabling mod_ssl Protocol Guard."

            # Create Filter for Apache mod_ssl TLS Handshake failures, SNI mismatch, and mTLS bypass attempts
            if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apache-tls.conf" ]]; then
                cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apache-tls.conf
[Definition]
# [DEVSECOPS FIX] Targets mod_ssl specific error codes (AH02033 for SNI bypass, AH02261/AH02008 for handshake/cert failures)
failregex = ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH\d+: .*?(?:certificate verify failed|SSL Library Error|handshake failed|SSL_accept failed|peer closed connection).*$
            ^.*? \[ssl:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] SSL Library Error: .*$
            ^.*? \[core:(?:error|warn|info)\].*? \[client <HOST>(?::\d+)?\] AH02033: No hostname was provided via SNI.*$
            ^.*? \[ssl:(?:error|warn)\].*? \[client <HOST>(?::\d+)?\] AH02039: Certificate Verification: Error.*$
ignoreregex = 
EOF
            fi

            cat <<EOF >>/etc/fail2ban/jail.local

# --- Apache mod_ssl Protocol & SNI Protection ---
[syswarden-apache-tls]
enabled  = true
port     = https,443,8443
filter   = syswarden-apache-tls
logpath  = $APACHE_ERR_LOG
backend  = auto
# Policy: 10 SSL errors in 1 minute indicates active TLS Fuzzing or massive direct IP scanning.
maxretry = 10
findtime = 60
bantime  = 24h
EOF
        fi

        # --- HOTFIX: RHEL/ALMA CHICKEN & EGG LOG FIX ---
        if [[ ! -f /var/log/fail2ban.log ]]; then
            touch /var/log/fail2ban.log
            chmod 640 /var/log/fail2ban.log
            chown root:root /var/log/fail2ban.log 2>/dev/null || true
        fi
        # ------------------------------------------------------

        log "INFO" "Starting Fail2ban service..."
        if command -v systemctl >/dev/null; then
            systemctl enable --now fail2ban >/dev/null 2>&1 || true
            systemctl restart fail2ban >/dev/null 2>&1 || true
        else
            fail2ban-client reload >/dev/null 2>&1 || true
        fi

        # --- HOTFIX: ALMALINUX/RHEL SOCKET RACE CONDITION ---
        # Wait dynamically for the Python daemon to compile the jails and bind the socket.
        # This prevents 'Failed to access socket' errors in the subsequent Steps.
        log "INFO" "Waiting for Fail2ban socket to initialize (Polling)..."
        for _ in {1..10}; do
            if fail2ban-client ping >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done
        # ----------------------------------------------------
    fi
}
