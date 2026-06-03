setup_telemetry_backend() {
    log "INFO" "Installation of the advanced telemetry engine (Backend)..."

    local BIN_PATH="/usr/local/bin/syswarden-telemetry.sh"
    local UI_DIR="/etc/syswarden/ui"

    # 1. Writing the Telemetry Bash script
    cat <<'EOF' >"$BIN_PATH"
#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# --- SECURITY FIX: ZOMBIE PROCESS PREVENTION (CWE-400: Uncontrolled Resource Consumption) ---
trap 'wait' EXIT

# --- HOTFIX: ABSOLUTE MUTEX LOCK (ANTI-OVERLAP) ---
LOCK_DIR="/var/run/syswarden"
mkdir -p "$LOCK_DIR"
chmod 700 "$LOCK_DIR"

exec 9>"$LOCK_DIR/telemetry.lock"
if ! flock -n 9; then
    exit 0
fi
# ---------------------------------------------------------

# --- DEVSECOPS FIX: CRON PATH ISOLATION ---
# Cron executes with a highly restricted PATH (/usr/bin:/bin). System binaries like
# nginx, apache2, and iptables reside in /usr/sbin. We must expand the PATH globally 
# BEFORE any command or package manager is invoked.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# --- Configuration Paths ---
SYSWARDEN_DIR="/etc/syswarden"
UI_DIR="/etc/syswarden/ui"
TMP_FILE="$UI_DIR/data.json.tmp"
DATA_FILE="$UI_DIR/data.json"

mkdir -p "$UI_DIR"

# --- HOTFIX: UNIVERSAL PACKAGE MANAGER ---
if ! command -v jq >/dev/null; then
    if [[ -f /etc/debian_version ]]; then apt-get install -y jq >/dev/null 2>&1 || true
    elif [[ -f /etc/redhat-release ]]; then dnf install -y jq >/dev/null 2>&1 || true; fi
fi

# --- System Metrics Gathering ---
SYS_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SYS_HOSTNAME=$(hostname)
SYS_UPTIME=$(awk '{d=int($1/86400); h=int(($1%86400)/3600); m=int(($1%3600)/60); if(d>0) printf "%dd %dh %dm", d, h, m; else printf "%dh %dm", h, m}' /proc/uptime 2>/dev/null || echo "Unknown")
SYS_LOAD=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}' || echo "0, 0, 0")

SYS_RAM_USED=$(free -m 2>/dev/null | awk '/^Mem:/{print $3}')
SYS_RAM_USED=${SYS_RAM_USED:-0}
SYS_RAM_TOTAL=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
SYS_RAM_TOTAL=${SYS_RAM_TOTAL:-0}
# --- System Storage Gathering (Root) ---
SYS_DISK_USED=$(df -m / 2>/dev/null | awk 'NR==2 {print $3}' || echo 0)
SYS_DISK_TOTAL=$(df -m / 2>/dev/null | awk 'NR==2 {print $2}' || echo 1)

# NEW: Hardware and OS specifications
SYS_CORES=$(nproc 2>/dev/null || echo "1")
SYS_ARCH=$(uname -m 2>/dev/null || echo "Unknown")
SYS_OS=$(grep -P '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Linux")
SYS_CPU=$(grep -m 1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed -e 's/^[[:space:]]*//' || echo "Unknown")

# --- Layer 3 Metrics ---
L3_GLOBAL=0; L3_GEOIP=0; L3_ASN=0
[[ -f "$SYSWARDEN_DIR/active_global_blocklist.txt" ]] && L3_GLOBAL=$(wc -l < "$SYSWARDEN_DIR/active_global_blocklist.txt")
[[ -f "$SYSWARDEN_DIR/geoip.txt" ]] && L3_GEOIP=$(wc -l < "$SYSWARDEN_DIR/geoip.txt")
[[ -f "$SYSWARDEN_DIR/asn.txt" ]] && L3_ASN=$(wc -l < "$SYSWARDEN_DIR/asn.txt")

# --- System Services Tracking (Universal Pgrep) ---
SRV_F2B=$(pgrep -f fail2ban-server >/dev/null && echo "active" || echo "offline")
SRV_CRON=$(pgrep -f "cron|crond" >/dev/null && echo "active" || echo "offline")

# --- DEVSECOPS FIX: SMART ACTIVE WEB SERVER TRACKING ---
# Replaced static XOR 'command -v' which failed if dual binaries (e.g. Apache + Nginx) 
# were installed. Now dynamically checks the running process state first to prioritize 
# the genuinely active daemon.
if pgrep "nginx" >/dev/null 2>&1; then
    WEB_NAME="nginx (worker)"
    WEB_PATH=$(command -v nginx || echo "/usr/sbin/nginx")
    WEB_STATUS="active"
elif pgrep "apache2|httpd" >/dev/null 2>&1; then
    WEB_NAME="apache (worker)"
    WEB_PATH=$(command -v apache2 || command -v httpd || echo "/usr/sbin/apache2")
    WEB_STATUS="active"
elif command -v nginx >/dev/null 2>&1; then
    WEB_NAME="nginx (worker)"
    WEB_PATH=$(command -v nginx)
    WEB_STATUS="offline"
elif command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
    WEB_NAME="apache (worker)"
    WEB_PATH=$(command -v apache2 || command -v httpd)
    WEB_STATUS="offline"
else
    WEB_NAME="web-server (none)"
    WEB_PATH="none"
    WEB_STATUS="skipped"
fi

# --- ModSecurity WAF Tracking (Module embedded in Web Server) ---
# We check if SysWarden integrated it or if the default config folder exists.
if [[ -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]] || [[ -d "/etc/modsecurity" ]]; then
    # Since ModSecurity runs inside the web server, its state matches the web worker
    if [[ "$WEB_STATUS" == "active" ]]; then
        SRV_MODSEC="active"
    elif [[ "$WEB_STATUS" == "skipped" ]]; then
        SRV_MODSEC="skipped"
    else
        SRV_MODSEC="offline"
    fi
else
    SRV_MODSEC="skipped"
fi

# AbuseIPDB Reporter Tracking (3 States)
if [[ -f "/usr/local/bin/syswarden_reporter.py" ]]; then
    if pgrep -f "syswarden_reporter" >/dev/null; then
        SRV_REP="active"
    else
        SRV_REP="offline"
    fi
else
    SRV_REP="skipped"
fi

# --- DEVSECOPS: Advanced Dynamic Firewall Backend Detection ---
FW_NAME="Unknown Firewall"
FW_PATH="unknown"
FW_STATUS="offline"

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qw "active"; then
    FW_NAME="ufw (Uncomplicated Firewall)"
    FW_PATH=$(command -v ufw)
    FW_STATUS="active"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qw "running"; then
    FW_NAME="firewalld"
    FW_PATH=$(command -v firewalld || command -v firewall-cmd)
    FW_STATUS="active"
elif command -v nft >/dev/null 2>&1 && { nft list ruleset 2>/dev/null | grep -qE "(table|chain)" || systemctl is-active --quiet nftables 2>/dev/null || rc-service nftables status 2>/dev/null | grep -q "started"; }; then
    FW_NAME="netfilter/nftables"
    FW_PATH=$(command -v nft)
    FW_STATUS="active"
elif command -v iptables >/dev/null 2>&1 && { iptables -nL 2>/dev/null | grep -q "Chain" || systemctl is-active --quiet iptables 2>/dev/null || rc-service iptables status 2>/dev/null | grep -q "started"; }; then
    FW_NAME="iptables"
    FW_PATH=$(command -v iptables)
    FW_STATUS="active"
fi

SERVICES_JSON=$(jq -n \
  --arg f2b "$SRV_F2B" --arg crn "$SRV_CRON" --arg web_name "$WEB_NAME" --arg web_path "$WEB_PATH" --arg web_status "$WEB_STATUS" --arg rep "$SRV_REP" \
  --arg fw_name "$FW_NAME" --arg fw_path "$FW_PATH" --arg fw_status "$FW_STATUS" --arg modsec "$SRV_MODSEC" \
  '[
    {"name":"fail2ban-server","path":"/usr/bin/fail2ban-server","status":$f2b},
    {"name":$fw_name,"path":$fw_path,"status":$fw_status},
    {"name":$web_name,"path":$web_path,"status":$web_status},
    {"name":"modsecurity (waf)","path":"web-server-module","status":$modsec},
    {"name":"cron/crond","path":"/usr/sbin/cron","status":$crn},
    {"name":"syswarden-reporter","path":"/usr/local/bin/syswarden_reporter.py","status":$rep},
    {"name":"syswarden-telemetry","path":"/usr/local/bin/syswarden-telemetry.sh","status":"active"}
  ]')

# --- Network Ports Gathering (ss) ---
PORTS_JSON="[]"
if command -v ss >/dev/null; then
    # DEVSECOPS FIX: Bulletproof awk parsing. Finds the exact IP:Port column regardless of OS shifting (Recv-Q/Send-Q).
    while IFS=" " read -r proto state local_addr; do
        [[ -z "$proto" || -z "$state" || -z "$local_addr" ]] && continue
        
        # Standardize protocol nomenclature
        proto=$(echo "$proto" | tr 'a-z' 'A-Z')
        [[ "$proto" == "TCPV6" ]] && proto="TCP (v6)"
        [[ "$proto" == "UDPV6" ]] && proto="UDP (v6)"
        
        # Fallback if 'ss' omits the State column and shifts an integer (Recv-Q) into the State variable
        if [[ "$state" =~ ^[0-9]+$ ]]; then
            state="ACTIVE"
        fi
        
        # Parse Local IP and Port dynamically (Strict matching via last colon)
        port="${local_addr##*:}"
        ip="${local_addr%:*}"
        
        # Strip IPv6 brackets and kernel interface bindings (e.g. ::1%lo)
        ip="${ip//\[/}"
        ip="${ip//\]/}"
        ip="${ip%%%*}"
        
        # We exclusively track globally exposed ports (0.0.0.0 or ::) for the security dashboard
        if [[ "$ip" == "*" || "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
            ip="0.0.0.0 (Any)"
            
            # Inject securely into the JSON Array
            PORTS_JSON=$(echo "$PORTS_JSON" | jq --arg ip "$ip" --arg s "$state" --arg po "$port" --arg pt "$proto" '. + [{"ip": $ip, "state": $s, "port": $po, "protocol": $pt}]')
        fi
    done <<< "$(ss -tulpn 2>/dev/null | awk 'NR>1 {addr=""; for(i=3;i<=NF;i++){if($i~/:/ && $i!~/users:/){addr=$i; break}}; if(addr!="") print $1, $2, addr}' || true)"
fi

# --- Layer 7 Metrics & IP Registry (SECURE JSON ARRAYS) ---
L7_TOTAL_BANNED=0; L7_ACTIVE_JAILS=0
JAILS_JSON="[]"
BANNED_IPS_JSON="[]"
ACTIVE_BANNED_IPS=" "

# --- Risk Radar Vectors ---
R_EXP=0; R_BF=0; R_REC=0; R_DOS=0; R_ABU=0

if command -v fail2ban-client >/dev/null && timeout 2 fail2ban-client ping >/dev/null 2>&1; then
    JAIL_LIST=$(timeout 2 fail2ban-client status 2>/dev/null | awk -F'Jail list:[ \t]*' '/Jail list:/ {print $2}' | tr -d ' ' | tr ',' '\n' || true)
    
    for JAIL in $JAIL_LIST; do
        [[ -z "$JAIL" ]] && continue
        L7_ACTIVE_JAILS=$((L7_ACTIVE_JAILS + 1))
        
        STATUS_OUT=$(timeout 3 fail2ban-client status "$JAIL" 2>/dev/null || echo "")
        
        if [[ -n "$STATUS_OUT" ]]; then
            BANNED_COUNT=$(echo "$STATUS_OUT" | grep -i 'Currently banned:' | head -n 1 | grep -oE '[0-9]+' || echo "0")
            BANNED_COUNT=${BANNED_COUNT:-0}
            L7_TOTAL_BANNED=$((L7_TOTAL_BANNED + BANNED_COUNT))
            
            if [[ "$BANNED_COUNT" -gt 0 ]]; then
                # --- THREAT INTEL: MITRE ATT&CK MAPPING ---
                MITRE_ID="T1499" # Default
                MITRE_NAME="Endpoint DoS"
                
                case "${JAIL,,}" in
                    *webshell*) MITRE_ID="T1505.003"; MITRE_NAME="Server Software Component: Web Shell" ;;
                    *revshell*|*rce*) MITRE_ID="T1059"; MITRE_NAME="Command and Scripting Interpreter" ;;
                    *sqli*|*xss*|*lfi*|*ssti*|*jndi*|*haproxy*|*modsec*) MITRE_ID="T1190"; MITRE_NAME="Exploit Public-Facing Application" ;;
                    *homoglyph*) MITRE_ID="T1027"; MITRE_NAME="Obfuscated Files or Information" ;;
                    *privesc*|*auditd*) MITRE_ID="T1068"; MITRE_NAME="Exploitation for Privilege Escalation" ;;
                    *secretshunter*|*hunter*|*ssrf*|*idor*) MITRE_ID="T1552"; MITRE_NAME="Unsecured Credentials / Cloud Discovery" ;;
                    *proxy-abuse*|*squid*) MITRE_ID="T1090"; MITRE_NAME="Connection Proxy" ;;
                    *portscan*) MITRE_ID="T1046"; MITRE_NAME="Network Service Discovery" ;;
                    *scanner*|*bot*|*mapper*|*enum*|*tls*|*honeypot*) MITRE_ID="T1595"; MITRE_NAME="Active Scanning / TLS Fuzzing" ;;
                    *flood*|*dos*) MITRE_ID="T1498.001"; MITRE_NAME="Direct Network Flood" ;;
                    *slowloris*) MITRE_ID="T1498.002"; MITRE_NAME="Resource Exhaustion Flood" ;;
                    *wireguard*|*openvpn*) MITRE_ID="T1136"; MITRE_NAME="External Remote Services" ;;
                    *ssh*|*auth*|*telnet*|*ftp*|*mail*|*postfix*|*dovecot*|*mysql*|*mariadb*|*redis*|*rabbitmq*|*zabbix*|*grafana*|*vaultwarden*|*sso*|*odoo*|*prestashop*|*atlassian*|*jenkins*|*gitlab*|*proxmox*|*cockpit*|*nextcloud*) MITRE_ID="T1110"; MITRE_NAME="Brute Force / Password Guessing" ;;
                    *recidive*) MITRE_ID="T1133"; MITRE_NAME="External Remote Services / Repeat Offender" ;;
                esac
                MITRE_PAYLOAD="${MITRE_ID}: ${MITRE_NAME}"

                JAILS_JSON=$(echo "$JAILS_JSON" | jq --arg n "$JAIL" --argjson c "$BANNED_COUNT" --arg ttp "$MITRE_PAYLOAD" '. + [{"name": $n, "count": $c, "mitre": $ttp}]')
                
                # --- RISK RADAR CALCULATION ---
                if [[ "$JAIL" =~ (sqli|xss|lfi|revshell|webshell|ssti|ssrf|jndi|modsec|homoglyph) ]]; then R_EXP=$((R_EXP + BANNED_COUNT))
                elif [[ "$JAIL" =~ (ssh|auth|privesc|prestashop) ]]; then R_BF=$((R_BF + BANNED_COUNT))
                elif [[ "$JAIL" =~ (scan|bot|mapper|enum|hunter|tls|honeypot) ]]; then R_REC=$((R_REC + BANNED_COUNT))
                elif [[ "$JAIL" =~ (flood|slowloris) ]]; then R_DOS=$((R_DOS + BANNED_COUNT))
                else R_ABU=$((R_ABU + BANNED_COUNT)); fi
                
                BANNED_IPS=$(echo "$STATUS_OUT" | grep -i 'Banned IP list:' | head -n 1 | sed 's/.*Banned IP list://I' | tr -d ',' | tr -s ' \t' '\n' | grep -vE '^\s*$' | tail -n 50 || true)
                for IP in $BANNED_IPS; do
                    if [[ -n "$IP" ]]; then
                        L7_PAYLOAD=""
                        if [[ "$JAIL" =~ (recidive) ]]; then
                            L7_PAYLOAD="Repeat Offender (Recidive Module)"
                        else
                            # --- DEVSECOPS FIX: CONTEXT-AWARE LOG TARGETING & WILDARD EXPANSION ---
                            LOG_TARGETS="/var/log/kern-firewall.log* /var/log/kern.log* /var/log/messages* /var/log/syslog* /var/log/nginx/*.log* /var/log/apache2/*.log* /var/log/httpd/*log* /var/log/auth-syswarden.log* /var/log/secure* /var/log/auth.log* /var/log/maillog* /var/log/mail.log* /var/log/daemon.log* /var/log/audit/audit.log*"
                            
                            case "${JAIL,,}" in
                                *ssh*|*auth*|*telnet*|*cockpit*|*privesc*) LOG_TARGETS="/var/log/auth.log* /var/log/secure* /var/log/auth-syswarden.log* /var/log/daemon.log* /var/log/syslog* /var/log/messages* /var/log/kern.log*" ;;
                                *portscan*|*flood*|*dos*|*wireguard*|*openvpn*) LOG_TARGETS="/var/log/kern-firewall.log* /var/log/kern.log* /var/log/syslog* /var/log/messages* /var/log/openvpn/openvpn.log* /var/log/openvpn.log* /var/log/daemon.log*" ;;
                                *nginx*|*apache*|*web*|*http*|*sqli*|*xss*|*lfi*|*ssti*|*jndi*|*modsec*|*hunter*|*proxy*|*scan*|*enum*|*bot*|*prestashop*|*atlassian*|*webshell*|*homoglyph*|*tls*|*dolibarr*|*phpmyadmin*|*apimapper*|*drupal*|*wordpress*|*honeypot*|*slowloris*) LOG_TARGETS="/var/log/nginx/*.log* /var/log/apache2/*.log* /var/log/httpd/*log* /var/log/syslog* /var/log/messages* /var/log/daemon.log* /var/log/kern-firewall.log* /var/log/kern.log*" ;;
                                *mail*|*postfix*|*dovecot*|*exim*|*sendmail*) LOG_TARGETS="/var/log/maillog* /var/log/mail.log* /var/log/syslog* /var/log/messages* /var/log/daemon.log*" ;;
                                *mysql*|*mariadb*|*redis*|*mongodb*|*rabbitmq*) LOG_TARGETS="/var/log/mysql/*.log* /var/log/mariadb/*.log* /var/log/redis/*.log* /var/log/mongodb/*.log* /var/log/rabbitmq/*.log* /var/log/syslog* /var/log/messages* /var/log/daemon.log*" ;;
                                *vsftpd*|*ftp*) LOG_TARGETS="/var/log/vsftpd.log* /var/log/auth.log* /var/log/secure* /var/log/messages* /var/log/syslog*" ;;
                                *auditd*) LOG_TARGETS="/var/log/audit/audit.log* /var/log/auth.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *proxmox*) LOG_TARGETS="/var/log/daemon.log* /var/log/syslog* /var/log/auth.log* /var/log/messages*" ;;
                                *asterisk*) LOG_TARGETS="/var/log/asterisk/messages* /var/log/asterisk/full* /var/log/syslog* /var/log/messages*" ;;
                                *zabbix*) LOG_TARGETS="/var/log/zabbix/zabbix_server.log* /var/log/syslog* /var/log/messages*" ;;
                                *haproxy*) LOG_TARGETS="/var/log/haproxy.log* /var/log/syslog* /var/log/messages* /var/log/daemon.log*" ;;
                                *squid*) LOG_TARGETS="/var/log/squid/*.log* /var/log/syslog* /var/log/messages*" ;;
                                *gitea*|*forgejo*) LOG_TARGETS="/var/log/gitea/gitea.log* /var/log/forgejo/forgejo.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *jenkins*) LOG_TARGETS="/var/log/jenkins/jenkins.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *gitlab*) LOG_TARGETS="/var/log/gitlab/gitlab-rails/application.log* /var/log/gitlab/gitlab-rails/auth.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *vaultwarden*) LOG_TARGETS="/var/log/vaultwarden/vaultwarden.log* /vw-data/vaultwarden.log* /opt/vaultwarden/vaultwarden.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *sso*|*authelia*|*authentik*) LOG_TARGETS="/var/log/authelia/authelia.log* /var/log/authentik/authentik.log* /opt/authelia/authelia.log* /opt/authentik/authentik.log* /var/log/syslog* /var/log/daemon.log*" ;;
                                *odoo*) LOG_TARGETS="/var/log/odoo/odoo-server.log* /var/log/odoo/odoo.log* /var/log/syslog*" ;;
                                *nextcloud*) LOG_TARGETS="/var/www/nextcloud/data/nextcloud.log* /var/www/html/nextcloud/data/nextcloud.log* /var/www/html/data/nextcloud.log* /var/log/syslog*" ;;
                                *laravel*) LOG_TARGETS="/var/www/html/storage/logs/laravel.log* /var/www/storage/logs/laravel.log* /var/log/syslog*" ;;
                                *grafana*) LOG_TARGETS="/var/log/grafana/grafana.log* /var/log/syslog* /var/log/daemon.log*" ;;
                            esac

                            # --- DEVSECOPS FIX: THE I/O DEATH SPIRAL & CHRONOLOGICAL SYNC ---
                            # FIX: We restore `ls -1t` (NEWEST to OLDEST) and iterate file by file. 
                            # We use `tail -n 1` to get the most recent entry within the file, and `break` INSTANTLY 
                            # the moment a payload is found, completely skipping older archives. O(1) efficiency restored.
                            OIFS="$IFS"
                            IFS=$' \n\t'
                            
                            # Safely expand all wildcard paths and sort strictly from newest to oldest
                            SORTED_TARGETS=$(ls -1t $LOG_TARGETS 2>/dev/null || true)
                            IFS="$OIFS"
                            
                            L7_PAYLOAD=""
                            if [[ -n "$SORTED_TARGETS" ]]; then
                                while IFS= read -r log_file; do
                                    [[ ! -f "$log_file" ]] && continue
                                    
                                    # Forward search restricted to ONE file at a time.
                                    # Extract specifically HTTP methodologies to bypass post-ban TCP connection noise.
                                    MATCH=$(timeout 2 zgrep -h -a -F "$IP" "$log_file" 2>/dev/null | grep -E '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PROPFIND)' | awk '!/\[SysWarden-(GEO|ASN)\]/ && !(/\[SysWarden-BLOCK\]/ && !/\[Catch-All\]/)' | head -n 1 | LC_ALL=C tr -c '\40-\176' '.' || true)
                                    
                                    if [[ -n "$MATCH" ]]; then
                                        L7_PAYLOAD="$MATCH"
                                        break # CRITICAL: Stop reading older archives instantly. Saves 95% CPU/IO.
                                    fi
                                done <<< "$SORTED_TARGETS"
                            fi
                            
                            # Phase 2: systemd-journald fallback (if native flat files are missing)
                            if [[ -z "$L7_PAYLOAD" ]] && command -v journalctl >/dev/null 2>&1; then
                                L7_PAYLOAD=$(timeout 2 journalctl -q --no-pager -n 500000 2>/dev/null | grep -a -F "$IP" | grep -E '"(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PROPFIND)' | awk '!/\[SysWarden-(GEO|ASN)\]/ && !(/\[SysWarden-BLOCK\]/ && !/\[Catch-All\]/)' | head -n 1 | LC_ALL=C tr -c '\40-\176' '.' || true)
                            fi
                        fi
                        
                        L7_PAYLOAD=$(echo "$L7_PAYLOAD" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)

                        # --- DEVSECOPS FIX: CACHE POISONING PREVENTION & STATEFUL RETENTION ---
                        if [[ -z "$L7_PAYLOAD" ]] && [[ -f "$DATA_FILE" ]]; then
                            CACHE_PAYLOAD=$(jq -r --arg ip "$IP" --arg j "$JAIL" '.layer7.banned_ips[]? | select(.ip == $ip and .jail == $j) | .payload' "$DATA_FILE" 2>/dev/null | head -n 1 || true)
                            if [[ "$CACHE_PAYLOAD" != "null" ]] && [[ -n "$CACHE_PAYLOAD" ]] && [[ "$CACHE_PAYLOAD" != *"Payload context unavailable"* ]] && [[ "$CACHE_PAYLOAD" != *"Manual ban"* ]]; then
                                L7_PAYLOAD="$CACHE_PAYLOAD"
                            fi
                        fi
                        
                        # --- DEVSECOPS FIX: PREVENT ORPHANED IPS DESYNC (ULTIMATE FALLBACK) ---
                        if [[ -z "$L7_PAYLOAD" ]]; then
                            L7_PAYLOAD="Payload context unavailable (Manual ban via CLI or absolute log purge)"
                        fi
                        
                        # --- REQUIREMENT 1: RAW LOGS RETENTION (0.0% CPU) ---
                        # [DEVSECOPS FIX] Ultimate Forensic Sanitization: Purifies BOTH new extracts and legacy cached payloads.
                        # printf ensures literal handling. tr replaces all newlines, carriage returns, and binary fuzzing bytes with dots.
                        P_CLEAN=$(printf '%s' "$L7_PAYLOAD" | LC_ALL=C tr -c '\40-\176' '.')
                        
                        BANNED_IPS_JSON=$(echo "$BANNED_IPS_JSON" | jq --arg ip "$IP" --arg j "$JAIL" --arg p "$P_CLEAN" --arg ttp "$MITRE_PAYLOAD" '. + [{"ip": $ip, "jail": $j, "payload": $p, "mitre": $ttp}]')
                        ACTIVE_BANNED_IPS+="${IP} "
                    fi
                done
            fi
        fi
    done
fi

# --- DEVSECOPS: Top 10 Historical Attacking IPs (Aggregated & Bulletproof) ---
TOP_ATTACKERS_JSON="[]"
TOP_STATS=""

# --- ENTERPRISE OSINT CACHE (PERMANENT & OFFLINE) ---
# We maintain a persistent local file to guarantee we NEVER hit API rate limits.
# An IP is queried exactly once in the server's lifetime.
OSINT_CACHE="$UI_DIR/osint_cache.txt"
[[ ! -f "$OSINT_CACHE" ]] && touch "$OSINT_CACHE"

declare -A CACHE_COUNTRY
declare -A CACHE_ASN
declare -A CACHE_ISP
while IFS='|' read -r c_ip c_ctry c_asn c_isp; do
    [[ -z "$c_ip" || "$c_ip" == "null" ]] && continue
    CACHE_COUNTRY["$c_ip"]="$c_ctry"
    CACHE_ASN["$c_ip"]="$c_asn"
    CACHE_ISP["$c_ip"]="${c_isp:-N/A}"
done < "$OSINT_CACHE"

# --- DEVSECOPS FIX: PREVENT MIDNIGHT LOGROTATE WIPEOUT ---
# The default logrotate moves fail2ban.log to fail2ban.log.1 at 00:00.
# Reading only the active file causes the Top Attackers UI to reset to zero every night.
# FIX: We dynamically read the 4 most recent archives (flat or compressed) using zcat, 
# ensuring a stable rolling history across midnight boundaries. 
# (Unbanned IPs are filtered out automatically by REQUIREMENT 1 below).
TOP_STATS=$(zcat -f $(ls -1t /var/log/fail2ban.log* 2>/dev/null | head -n 4) 2>/dev/null | grep -aE "\] Ban " | sed -E 's/.*\[([^]]+)\].*Ban ([0-9.]+)/\2 \1/' | sort | uniq -c | sort -nr || true)

if [[ -n "$TOP_STATS" ]]; then
    TOP_COUNT=0
    SEEN_IPS=" "
    while IFS=" " read -r count ip jail; do
        if [[ -n "$ip" && -n "$count" ]]; then
            # --- REQUIREMENT 1: PURGE UNBANNED IPS FROM HISTORY ---
            if [[ "$ACTIVE_BANNED_IPS" != *" $ip "* ]]; then
                continue
            fi
            
            # --- REQUIREMENT 3: DEDUPLICATE IPS ACROSS MULTIPLE JAILS ---
            # Prevents an IP banned by multiple distinct jails from appearing multiple times in the Top Attackers JSON
            if [[ "$SEEN_IPS" == *" $ip "* ]]; then
                continue
            fi
            SEEN_IPS+="$ip "
            
            # 5 attackers limit API OSINT
            if (( TOP_COUNT >= 5 )); then break; fi

            PORT="Unknown"
            EXACT_PORT=$(timeout 2 grep -h -F "$ip" /var/log/kern-firewall.log /var/log/kern.log /var/log/syslog /var/log/messages 2>/dev/null | grep -oE 'DPT=[0-9]+' | cut -d= -f2 | sort | uniq -c | sort -nr | awk 'NR==1 {print $2}' || true)
            
            if [[ -n "$EXACT_PORT" ]]; then
                PORT="$EXACT_PORT"
            else
                case "${jail,,}" in
                    *ssh*) PORT="22" ;;
                    *http*|*web*|*nginx*|*apache*|*prestashop*|*sqli*|*xss*|*lfi*|*tls*) PORT="443" ;;
                    *ftp*) PORT="21" ;;
                    *mail*|*postfix*|*exim*|*dovecot*) PORT="25/143" ;;
                    *mysql*|*mariadb*) PORT="3306" ;;
                    *recidive*) PORT="Multiple" ;;
                    *scan*|*portscan*|*syswarden*) PORT="Network" ;;
                    *) PORT="Unknown" ;;
                esac
            fi
            
            # --- REQUIREMENT 2: SECURE HTTPS OSINT ENRICHMENT WITH SMART CACHING ---
            COUNTRY="${CACHE_COUNTRY["$ip"]:-N/A}"
            ASN="${CACHE_ASN["$ip"]:-N/A}"
            ISP="${CACHE_ISP["$ip"]:-N/A}"
            
            if [[ "$COUNTRY" == "N/A" || "$COUNTRY" == "null" ]]; then
                # Switch to ipwho.is (No API key, Generous Quota) + Permanent caching
                IP_INFO=$(timeout 1.5 curl -s "https://ipwho.is/${ip}" 2>/dev/null || true)
                COUNTRY=$(echo "$IP_INFO" | jq -r '.country_code // "N/A"' 2>/dev/null || echo "N/A")
                
                ASN_NUM=$(echo "$IP_INFO" | jq -r '.connection.asn // "N/A"' 2>/dev/null || echo "N/A")
                if [[ "$ASN_NUM" != "N/A" && "$ASN_NUM" != "null" ]]; then
                    ASN="AS${ASN_NUM}"
                else
                    ASN="N/A"
                fi
                
                ISP=$(echo "$IP_INFO" | jq -r '.connection.isp // "N/A"' 2>/dev/null || echo "N/A")
                
                # Permanent write-through cache: Never query this IP again across reboots/upgrades
                if [[ "$COUNTRY" != "N/A" && "$COUNTRY" != "null" ]]; then
                    CACHE_COUNTRY["$ip"]="$COUNTRY"
                    CACHE_ASN["$ip"]="$ASN"
                    CACHE_ISP["$ip"]="$ISP"
                    echo "${ip}|${COUNTRY}|${ASN}|${ISP}" >> "$OSINT_CACHE"
                fi
            fi
            
            TOP_ATTACKERS_JSON=$(echo "$TOP_ATTACKERS_JSON" | jq --arg ip "$ip" --arg p "$PORT" --arg ctry "$COUNTRY" --arg asn "$ASN" --arg isp "$ISP" '. + [{"ip": $ip, "port": $p, "country": $ctry, "asn": $asn, "isp": $isp}]')
            TOP_COUNT=$((TOP_COUNT + 1))
        fi
    done <<< "$TOP_STATS"
fi

# --- Whitelist Registry Extraction ---
WHITELIST_COUNT=0
WL_JSON="[]"

if [[ -f "$SYSWARDEN_DIR/whitelist.txt" ]]; then
    WHITELIST_COUNT=$(grep -cvE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    WL_IPS=$(grep -vE '^\s*(#|$)' "$SYSWARDEN_DIR/whitelist.txt" || true)
    for IP in $WL_IPS; do
        if [[ -n "$IP" ]]; then
            WL_JSON=$(echo "$WL_JSON" | jq --arg ip "$IP" '. + [$ip]')
        fi
    done
fi

# --- Generate Atomic JSON Payload ---
RADAR_JSON=$(jq -n --argjson e "$R_EXP" --argjson b "$R_BF" --argjson r "$R_REC" --argjson d "$R_DOS" --argjson a "$R_ABU" '[$e, $b, $r, $d, $a]')

jq -n \
  --arg ts "$SYS_TIMESTAMP" \
  --arg host "$SYS_HOSTNAME" \
  --arg up "$SYS_UPTIME" \
  --arg load "$SYS_LOAD" \
  --argjson ru "$SYS_RAM_USED" \
  --argjson rt "$SYS_RAM_TOTAL" \
  --argjson du "$SYS_DISK_USED" \
  --argjson dt "$SYS_DISK_TOTAL" \
  --arg cores "$SYS_CORES" \
  --arg arch "$SYS_ARCH" \
  --arg os "$SYS_OS" \
  --arg cpu "$SYS_CPU" \
  --argjson lg "$L3_GLOBAL" \
  --argjson lgeo "$L3_GEOIP" \
  --argjson lasn "$L3_ASN" \
  --argjson ltb "$L7_TOTAL_BANNED" \
  --argjson laj "$L7_ACTIVE_JAILS" \
  --argjson jj "$JAILS_JSON" \
  --argjson bip "$BANNED_IPS_JSON" \
  --argjson top "$TOP_ATTACKERS_JSON" \
  --argjson wlc "$WHITELIST_COUNT" \
  --argjson wlip "$WL_JSON" \
  --argjson srv "$SERVICES_JSON" \
  --argjson pts "$PORTS_JSON" \
  --argjson rad "$RADAR_JSON" \
'{
  timestamp: $ts,
  system: { hostname: $host, uptime: $up, load_average: $load, ram_used_mb: $ru, ram_total_mb: $rt, disk_used_mb: $du, disk_total_mb: $dt, services: $srv, cores: $cores, arch: $arch, os: $os, cpu_model: $cpu, ports: $pts },
  layer3: { global_blocked: $lg, geoip_blocked: $lgeo, asn_blocked: $lasn },
  layer7: { total_banned: $ltb, active_jails: $laj, jails_data: $jj, banned_ips: $bip, top_attackers: $top, risk_radar: $rad },
  whitelist: { active_ips: $wlc, ips: $wlip }
}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$DATA_FILE"
# [DEVSECOPS FIX] TUI Architecture: data.json is strictly owned by root, no web-server permissions needed
chown root:root "$DATA_FILE" 2>/dev/null || true
chmod 600 "$DATA_FILE"
EOF

    # 2. Make executable
    chmod +x "$BIN_PATH"

    # 3. Injection into CRON tasks
    if ! crontab -l 2>/dev/null | grep "$BIN_PATH" >/dev/null; then
        (
            crontab -l 2>/dev/null || true
            echo "* * * * * $BIN_PATH >/dev/null 2>&1"
        ) | crontab -
    fi

    # 4. First immediate run
    if ! "$BIN_PATH"; then
        log "WARN" "Initial telemetry run failed, but script will continue."
    fi
}
