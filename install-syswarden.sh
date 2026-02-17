#!/bin/bash

# --- SAFETY FIRST ---
set -euo pipefail
IFS=$'\n\t'

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"
TMP_DIR=$(mktemp -d)
VERSION="v4.03"
SYSWARDEN_DIR="/etc/syswarden"
WHITELIST_FILE="$SYSWARDEN_DIR/whitelist.txt"
BLOCKLIST_FILE="$SYSWARDEN_DIR/blocklist.txt"

# --- LIST URLS ---
declare -A URLS_STANDARD
URLS_STANDARD[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt"

declare -A URLS_CRITICAL
URLS_CRITICAL[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}ERROR: This script must be run as root.${NC}"
       exit 1
    fi
}

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

detect_os_backend() {
    log "INFO" "Detecting Operating System and Firewall Backend..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        OS_ID=$ID
    else
        OS="Unknown"
        OS_ID="unknown"
    fi

    # Logic to select the best firewall for the OS
    if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
        FIREWALL_BACKEND="ufw"
    elif [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]]; then
        FIREWALL_BACKEND="nftables"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FIREWALL_BACKEND="firewalld" # RHEL/Alma default
    elif command -v nft >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="ipset" # Fallback
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Checking dependencies..."
    local missing_common=""

    if [[ -f /etc/debian_version ]]; then
        log "INFO" "Updating apt repositories..."
        apt-get update -qq
    fi

    if ! command -v curl >/dev/null; then missing_common="$missing_common curl"; fi
    if ! command -v python3 >/dev/null; then missing_common="$missing_common python3"; fi
    
    if [[ -n "$missing_common" ]]; then
        if [[ -f /etc/debian_version ]]; then apt-get install -y $missing_common; 
        elif [[ -f /etc/redhat-release ]]; then dnf install -y $missing_common; fi
    fi

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

    if ! command -v ipset >/dev/null; then
        log "WARN" "Installing package: ipset"
        if [[ -f /etc/debian_version ]]; then apt-get install -y ipset
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
        if [[ -f /etc/debian_version ]]; then apt-get install -y nftables;
        elif [[ -f /etc/redhat-release ]]; then dnf install -y nftables; fi
    fi

    log "INFO" "All dependencies check complete."
}

define_ssh_port() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SSH_PORT:-}" ]]; then SSH_PORT=22; fi
        log "INFO" "Update Mode: Preserving SSH Port $SSH_PORT"
        return
    fi

    echo -e "\n${BLUE}=== Step: SSH Configuration ===${NC}"
    read -p "Please enter your current SSH Port [Default: 22]: " input_port
    SSH_PORT=${input_port:-22}

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        log "WARN" "Invalid port detected. Defaulting to 22."
        SSH_PORT=22
    fi

    echo "SSH_PORT='$SSH_PORT'" >> "$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"
}

define_docker_integration() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${USE_DOCKER:-}" ]]; then USE_DOCKER="n"; fi
        log "INFO" "Update Mode: Preserving Docker integration setting ($USE_DOCKER)"
        return
    fi

    echo -e "\n${BLUE}=== Step: Docker Integration ===${NC}"
    read -p "Do you use Docker on this server? (y/N): " input_docker
    if [[ "$input_docker" =~ ^[Yy]$ ]]; then
        USE_DOCKER="y"
        log "INFO" "Docker integration ENABLED."
    else
        USE_DOCKER="n"
        log "INFO" "Docker integration DISABLED."
    fi
    echo "USE_DOCKER='$USE_DOCKER'" >> "$CONF_FILE"
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

select_list_type() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log "INFO" "Update Mode: Loaded configuration (Type: $LIST_TYPE)"
        return
    fi

    echo -e "\n${BLUE}=== Step 1: Select Blocklist Type ===${NC}"
    echo "1) Standard List (~85,000 IPs) - Recommended for Web Servers"
    echo "2) Critical List (~100,000 IPs) - Recommended for High Security"
    echo "3) Custom List"
    echo "4) No List (Geo-Blocking / Local rules only)"
    read -p "Enter choice [1/2/3/4]: " choice

    case "$choice" in
        1) LIST_TYPE="Standard";;
        2) LIST_TYPE="Critical";;
        3) 
           LIST_TYPE="Custom"
           read -p "Enter the full URL: " CUSTOM_URL
           ;;
        4) LIST_TYPE="None";;
        *) log "ERROR" "Invalid choice. Exiting."; exit 1;;
    esac
    
    echo "LIST_TYPE='$LIST_TYPE'" > "$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >> "$CONF_FILE"; fi
    log "INFO" "User selected: $LIST_TYPE Blocklist"
}

measure_latency() {
    local url="$1"
    local time_sec
    time_sec=$(curl -o /dev/null -s -w '%{time_connect}\n' --connect-timeout 2 "$url" || echo "error")
    
    if [[ "$time_sec" == "error" ]] || [[ -z "$time_sec" ]]; then
        echo "9999"
    else
        echo "$time_sec" | awk '{print int($1 * 1000)}' 2>/dev/null || echo "9999"
    fi
}

select_mirror() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log "INFO" "Update Mode: keeping mirror $SELECTED_URL"
        return
    fi

    if [[ "$LIST_TYPE" == "Custom" ]]; then
        SELECTED_URL="$CUSTOM_URL"
        echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
        return
    fi
	
	if [[ "$LIST_TYPE" == "None" ]]; then
        SELECTED_URL="none"
        echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
        return
    fi

    echo -e "\n${BLUE}=== Step 2: Selecting Fastest Mirror ===${NC}"
    log "INFO" "Benchmarking mirrors..."

    declare -n URL_MAP
    if [[ "$LIST_TYPE" == "Standard" ]]; then URL_MAP=URLS_STANDARD; else URL_MAP=URLS_CRITICAL; fi

    local fastest_time=10000
    local fastest_url=""
    local valid_mirror_found=false

    for name in "${!URL_MAP[@]}"; do
        url="${URL_MAP[$name]}"
        echo -n "Connecting to $name... "
        time=$(measure_latency "$url")
        
        if [[ "$time" -eq 9999 ]]; then
             echo "FAIL"
        else
             echo "${time} ms"
             if (( time < fastest_time )); then
                fastest_time=$time
                fastest_url=$url
                valid_mirror_found=true
             fi
        fi
    done

    if [[ "$valid_mirror_found" == "false" ]]; then
        SELECTED_URL="${URL_MAP[Codeberg]}"
    else
        SELECTED_URL="$fastest_url"
    fi

    echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
}

download_list() {
    echo -e "\n${BLUE}=== Step 3: Downloading Blocklist ===${NC}"
    log "INFO" "Fetching list from $SELECTED_URL..."
	
	if [[ "$SELECTED_URL" == "none" ]]; then
        log "INFO" "No global blocklist selected. Skipping download."
        touch "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        return
    fi
    
    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        tr -d '\r' < "$output_file" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' > "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        log "INFO" "Download success."
    else
        log "ERROR" "Failed to download blocklist."
        exit 1
    fi
}

apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules ($FIREWALL_BACKEND) ===${NC}"
	
	# --- LOCAL PERSISTENCE INJECTION ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE" "$BLOCKLIST_FILE"

    # 1. Inject local blocklist into the global list
    cat "$BLOCKLIST_FILE" >> "$FINAL_LIST"
    
    # 2. Clean duplicates to ensure firewall stability
    sort -u "$FINAL_LIST" -o "$FINAL_LIST"

    # 3. Exclude local whitelisted IPs from the final blocklist
    if [[ -s "$WHITELIST_FILE" ]]; then
        grep -vFf "$WHITELIST_FILE" "$FINAL_LIST" > "$TMP_DIR/clean_final.txt" || true
        mv "$TMP_DIR/clean_final.txt" "$FINAL_LIST"
    fi
    # -----------------------------------
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        log "INFO" "Configuring Nftables Set..."
        cat <<EOF > "$TMP_DIR/syswarden.nft"
table inet syswarden_table {
    set $SET_NAME {
        type ipv4_addr
        flags interval
        auto-merge
        elements = {
$(awk '{print $1 ","}' "$FINAL_LIST")
        }
    }
    chain input {
        type filter hook input priority filter - 10; policy accept;
        ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " flags all drop
        tcp dport { 23, 445, 1433, 3389, 5900 } log prefix "[SysWarden-BLOCK] " flags all drop
    }
}
EOF
        nft -f "$TMP_DIR/syswarden.nft"

    elif [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
        if ! systemctl is-active --quiet firewalld; then systemctl enable --now firewalld; fi
        
        if [[ -n "${SSH_PORT:-}" ]]; then
            firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" 2>/dev/null || true
            firewall-cmd --reload
        fi

        log "INFO" "Configuring Firewalld IPSet..."
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --reload
        firewall-cmd --permanent --delete-ipset="$SET_NAME" 2>/dev/null || true
        firewall-cmd --reload
        firewall-cmd --permanent --new-ipset="$SET_NAME" --type=hash:net --option=family=inet --option=maxelem=200000
        firewall-cmd --reload
        
        firewall-cmd --permanent --ipset="$SET_NAME" --add-entries-from-file="$FINAL_LIST"
        firewall-cmd --permanent --add-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop"
        
        for port in 23 445 1433 3389 5900; do
            firewall-cmd --permanent --add-rich-rule="rule port port=\"$port\" protocol=\"tcp\" log prefix=\"[SysWarden-BLOCK] \" level=\"info\" drop" 2>/dev/null || true
        done
        
        firewall-cmd --reload
        log "INFO" "Firewalld rules applied."
		
		elif [[ "$FIREWALL_BACKEND" == "ufw" ]]; then
        log "INFO" "Configuring UFW with IPSet..."
        
        # 1. Create IPSet (UFW uses iptables underneath)
        ipset create "$SET_NAME" hash:net maxelem 200000 -exist
        sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!

        # 2. Inject Rule into /etc/ufw/before.rules
        # We insert the rule right after the standard UFW header to ensure it runs first
        UFW_RULES="/etc/ufw/before.rules"
        
        # Remove old rules if present to avoid duplicates
        sed -i "/$SET_NAME/d" "$UFW_RULES"

        # Insert new rules after "# End required lines" marker
        if grep -q "# End required lines" "$UFW_RULES"; then
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j DROP" "$UFW_RULES"
            sed -i "/# End required lines/a -A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix '[SysWarden-BLOCK] '" "$UFW_RULES"
        else
            log "WARN" "Standard UFW marker not found. Appending to end of file."
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j LOG --log-prefix '[SysWarden-BLOCK] '" >> "$UFW_RULES"
            echo "-A ufw-before-input -m set --match-set $SET_NAME src -j DROP" >> "$UFW_RULES"
        fi

        ufw reload
        log "INFO" "UFW rules applied."

    else
        # Fallback IPSET / IPTABLES
        ipset create "${SET_NAME}_tmp" hash:net maxelem 200000 -exist
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore
        ipset create "$SET_NAME" hash:net maxelem 200000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"
        
        if ! iptables -C INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j DROP
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j LOG --log-prefix "[SysWarden-BLOCK] "
            
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
        fi
    fi
	
	# --- DOCKER HERMETIC FIREWALL BLOCK ---
    if [[ "${USE_DOCKER:-n}" == "y" ]]; then
        log "INFO" "Applying Global Blocklist to Docker (DOCKER-USER chain)..."
        
        # Docker exclusively uses iptables routing. 
        # Even if the host uses Nftables, we must load the IPSet for Docker.
        if ! ipset list "$SET_NAME" >/dev/null 2>&1; then
             ipset create "$SET_NAME" hash:net maxelem 200000 -exist
             sed "s/^/add $SET_NAME /" "$FINAL_LIST" | ipset restore -!
        fi

        # Check if Docker chain exists before injecting rules
        if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
            iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
            
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I DOCKER-USER 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] "
            
            # Persist rules if possible
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
            log "INFO" "Docker firewall rules applied successfully."
        else
            log "WARN" "DOCKER-USER chain not found. Docker might not be running yet."
        fi
    fi
}

configure_fail2ban() {
    # [UNIVERSAL MODE] Configures services ONLY if they exist to prevent crashes
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Universal Mode)..."
		
		# --- Add backup Fai2ban jail ---
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi
        # -------------------------------------------------------

        # 1. Syslog requirement
        cat <<EOF > /etc/fail2ban/fail2ban.local
[Definition]
logtarget = SYSLOG
EOF

        # 2. Backup
        if [[ -f /etc/fail2ban/jail.local ]]; then
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # 3. HEADER & SSH (Always Active)
        cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = systemd
# Default Action (Will be overwritten if AbuseIPDB is enabled)
banaction = firewallcmd-ipset

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = $SSH_PORT
logpath = %(sshd_log)s
backend = systemd
EOF

        # 4. DYNAMIC DETECTION: NGINX
        if [[ -f "/var/log/nginx/access.log" ]] || [[ -f "/var/log/nginx/error.log" ]]; then
            log "INFO" "Nginx logs detected. Enabling Nginx Jail."
            # Create Filter for 404/403 scanners
            if [[ ! -f "/etc/fail2ban/filter.d/nginx-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST>.*\"(GET|POST|HEAD).*\" (400|401|403|404|444) .*$\nignoreregex =" > /etc/fail2ban/filter.d/nginx-scanner.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Nginx Protection ---
[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
backend = auto

[nginx-botsearch]
enabled = true
port = http,https
logpath = /var/log/nginx/access.log
backend = auto

[nginx-scanner]
enabled = true
port    = http,https
filter  = nginx-scanner
logpath = /var/log/nginx/access.log
backend = auto
maxretry = 3
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
            APACHE_LOG="/var/log/httpd/error_log"   # RHEL/CentOS
            APACHE_ACCESS="/var/log/httpd/access_log"
        fi

        if [[ -n "$APACHE_LOG" ]]; then
            log "INFO" "Apache logs detected. Enabling Apache Jail."
            
            # Create Filter for 404/403 scanners (Apache specific)
            if [[ ! -f "/etc/fail2ban/filter.d/apache-scanner.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> .+\"(GET|POST|HEAD) .+\" (400|401|403|404) .+\$\nignoreregex =" > /etc/fail2ban/filter.d/apache-scanner.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

# --- Apache Protection ---
[apache-auth]
enabled = true
port = http,https
logpath = $APACHE_LOG
backend = auto

[apache-badbots]
enabled = true
port = http,https
logpath = $APACHE_ACCESS
backend = auto

[apache-scanner]
enabled = true
port    = http,https
filter  = apache-scanner
logpath = $APACHE_ACCESS
backend = auto
maxretry = 3
bantime  = 24h
EOF
        fi

        # 6. DYNAMIC DETECTION: MONGODB
        if [[ -f "/var/log/mongodb/mongod.log" ]]; then
            log "INFO" "MongoDB logs detected. Enabling Mongo Jail."

            # Create strict Filter for Auth failures & Unauthorized commands (Injection probing)
            # Catches: "Authentication failed", "SASL authentication failed", "unauthorized", "not authorized"
            if [[ ! -f "/etc/fail2ban/filter.d/mongodb-guard.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*(?:Authentication failed|SASL authentication \S+ failed|Command not found|unauthorized|not authorized).*\$\nignoreregex =" > /etc/fail2ban/filter.d/mongodb-guard.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
            if [[ ! -f "/etc/fail2ban/filter.d/mariadb-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*[Aa]ccess denied for user.*\$\nignoreregex =" > /etc/fail2ban/filter.d/mariadb-auth.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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

            cat <<EOF >> /etc/fail2ban/jail.local

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

            cat <<EOF >> /etc/fail2ban/jail.local

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
        if [[ -n "$APACHE_ACCESS" ]]; then WP_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then WP_LOG="/var/log/nginx/access.log"; fi

        if [[ -n "$WP_LOG" ]]; then
            log "INFO" "Web logs available. Configuring WordPress Jail."

            # Create specific filter for WP Login & XMLRPC
            if [[ ! -f "/etc/fail2ban/filter.d/wordpress-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^<HOST> .* \"POST .*(wp-login\.php|xmlrpc\.php) HTTP.*\" 200\nignoreregex =" > /etc/fail2ban/filter.d/wordpress-auth.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
		
		# 11. DYNAMIC DETECTION: NEXTCLOUD
        NC_LOG=""
        # Check common paths for Nextcloud log file
        for path in "/var/www/nextcloud/data/nextcloud.log" "/var/www/html/nextcloud/data/nextcloud.log" "/var/www/html/data/nextcloud.log"; do
            if [[ -f "$path" ]]; then NC_LOG="$path"; break; fi
        done

        if [[ -n "$NC_LOG" ]]; then
            log "INFO" "Nextcloud logs detected. Enabling Nextcloud Jail."

            # Create Filter (Supports both JSON and Legacy text logs)
            if [[ ! -f "/etc/fail2ban/filter.d/nextcloud.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^.*Login failed: .* \(Remote IP: '<HOST>'\).*$\nignoreregex =" > /etc/fail2ban/filter.d/nextcloud.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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

            cat <<EOF >> /etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^.*failed login of user .* from <HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/zabbix-auth.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^.* <HOST>:\d+ .+(400|403|404|429) .+\$\nignoreregex =" > /etc/fail2ban/filter.d/haproxy-guard.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
            if [[ -f "/var/log/kern.log" ]]; then WG_LOG="/var/log/kern.log"; # Debian/Ubuntu
            elif [[ -f "/var/log/messages" ]]; then WG_LOG="/var/log/messages"; fi # RHEL

            if [[ -n "$WG_LOG" ]]; then
                log "INFO" "WireGuard detected. Enabling UDP Jail."

                # Create Filter for Handshake Failures (Requires Kernel Logging)
                if [[ ! -f "/etc/fail2ban/filter.d/wireguard.conf" ]]; then
                    echo -e "[Definition]\nfailregex = ^.*wireguard: .* Handshake for peer .* did not complete.*\$\nignoreregex =" > /etc/fail2ban/filter.d/wireguard.conf
                fi

                cat <<EOF >> /etc/fail2ban/jail.local

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
        if [[ -n "$APACHE_ACCESS" ]]; then PMA_LOG="$APACHE_ACCESS";
        elif [[ -f "/var/log/nginx/access.log" ]]; then PMA_LOG="/var/log/nginx/access.log"; fi

        # Check if phpMyAdmin is installed (common paths)
        if [[ -d "/usr/share/phpmyadmin" ]] || [[ -d "/etc/phpmyadmin" ]] || [[ -d "/var/www/html/phpmyadmin" ]]; then
            if [[ -n "$PMA_LOG" ]]; then
                log "INFO" "phpMyAdmin detected. Enabling PMA Jail."

                # Create Filter for POST requests to PMA (Bruteforce usually returns 200 OK)
                if [[ ! -f "/etc/fail2ban/filter.d/phpmyadmin-custom.conf" ]]; then
                     echo -e "[Definition]\nfailregex = ^<HOST> -.*\"POST .*phpmyadmin.* HTTP.*\" 200\nignoreregex =" > /etc/fail2ban/filter.d/phpmyadmin-custom.conf
                fi

                cat <<EOF >> /etc/fail2ban/jail.local

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
            if [[ -f "$path" ]]; then LARAVEL_LOG="$path"; break; fi
        done

        # Fallback: search in /var/www (max depth 4)
        if [[ -z "$LARAVEL_LOG" ]] && [[ -d "/var/www" ]]; then
            LARAVEL_LOG=$(find /var/www -maxdepth 4 -name "laravel.log" 2>/dev/null | head -n 1)
        fi

        if [[ -n "$LARAVEL_LOG" ]]; then
            log "INFO" "Laravel log detected. Enabling Laravel Jail."

            # Create Filter (Matches: 'Failed login... ip: 1.2.3.4' or similar patterns)
            if [[ ! -f "/etc/fail2ban/filter.d/laravel-auth.conf" ]]; then
                echo -e "[Definition]\nfailregex = ^\\[.*\\] .*: (?:Failed login|Authentication failed|Login failed).*<HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/laravel-auth.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^.*(?:msg=\"Invalid username or password\"|status=401).*remote_addr=<HOST>.*\$\nignoreregex =" > /etc/fail2ban/filter.d/grafana-auth.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
        if [[ -f "/var/log/mail.log" ]]; then SM_LOG="/var/log/mail.log"; # Debian/Ubuntu
        elif [[ -f "/var/log/maillog" ]]; then SM_LOG="/var/log/maillog"; fi # RHEL/Alma

        # Check if Sendmail is installed to avoid conflict with Postfix
        if [[ -n "$SM_LOG" ]] && [[ -f "/usr/sbin/sendmail" ]]; then
            log "INFO" "Sendmail detected. Enabling Sendmail Jails."

            cat <<EOF >> /etc/fail2ban/jail.local

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
                echo -e "[Definition]\nfailregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*\$\nignoreregex =" > /etc/fail2ban/filter.d/squid-custom.conf
            fi

            cat <<EOF >> /etc/fail2ban/jail.local

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
            cat <<'EOF' > /etc/fail2ban/action.d/syswarden-docker.conf
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
    fi 
}

setup_abuse_reporting() {
    echo -e "\n${BLUE}=== Step 7: AbuseIPDB Reporting Setup ===${NC}"
    echo "Would you like to automatically report blocked IPs to AbuseIPDB?"
    read -p "Enable AbuseIPDB reporting? (y/N): " response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
        
        if [[ -z "$USER_API_KEY" ]]; then
            log "ERROR" "No API Key provided. Skipping reporting setup."
            return
        fi

        echo ""
        read -p "Report Fail2ban Bans (SSH/Web brute-force)? [Y/n]: " REPORT_F2B
        REPORT_F2B=${REPORT_F2B:-y}

        echo ""
        read -p "Report Firewall Drops (Port Scans/Blacklist)? [Y/n]: " REPORT_FW
        REPORT_FW=${REPORT_FW:-y}

        if [[ "$REPORT_F2B" =~ ^[Nn]$ ]] && [[ "$REPORT_FW" =~ ^[Nn]$ ]]; then
            log "INFO" "Both reporting options declined. Skipping."
            return
        fi

        log "INFO" "Configuring Unified SysWarden Reporter..."
        
        cat <<'EOF' > /usr/local/bin/syswarden_reporter.py
#!/usr/bin/env python3
import subprocess
import select
import re
import requests
import time
import ipaddress
import socket
import threading

# --- CONFIGURATION ---
API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900  # 15 minutes
ENABLE_F2B = PLACEHOLDER_F2B
ENABLE_FW = PLACEHOLDER_FW

# --- DEFINITIONS ---
reported_cache = {}

def send_report(ip, categories, comment):
    current_time = time.time()
    
    # --- Validation stricte de l'IP ---
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[SKIP] Invalid IP detected by Regex: '{ip}'", flush=True)
        return

    if ip in reported_cache:
        if current_time - reported_cache[ip] < REPORT_INTERVAL:
            return 
    
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    full_comment = f"[{socket.gethostname()}] {comment}"
    params = {'ip': ip, 'categories': categories, 'comment': full_comment}

    try:
        response = requests.post(url, params=params, headers=headers)
        if response.status_code == 200:
            print(f"[SUCCESS] Reported {ip} -> Cats [{categories}]", flush=True)
            reported_cache[ip] = current_time 
            clean_cache()
        else:
            print(f"[API ERROR] HTTP {response.status_code} : {response.text}", flush=True)
    except Exception as e:
        print(f"[FAIL] Error: {e}", flush=True)

def clean_cache():
    current_time = time.time()
    to_delete = [ip for ip, ts in reported_cache.items() if current_time - ts > REPORT_INTERVAL]
    for ip in to_delete:
        del reported_cache[ip]

def monitor_logs():
    print("🚀 Monitoring logs (Unified SysWarden Reporter)...", flush=True)
    # Securisation de journalctl pour forcer la sortie brute
    f = subprocess.Popen(['journalctl', '-f', '-n', '0', '-o', 'cat'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    regex_fw = re.compile(r"\[SysWarden-(BLOCK|DOCKER)\].*SRC=([\d\.]+).*DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            if not line: continue

            # --- FIREWALL LOGIC ---
            if ENABLE_FW:
                match_fw = regex_fw.search(line)
                if match_fw:
                    ip = match_fw.group(2)
                    try:
                        port = int(match_fw.group(3))
                    except ValueError:
                        port = 0
                    
                    cats = ["14"]
                    attack_type = "Port Scan"

                    if port in [80, 443, 4443, 8080, 8443]: cats.extend(["20", "21"]); attack_type = "Web Attack"
                    elif port in [22, 2222, 22222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                    elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT Attack"
                    elif port == 88: cats.extend(["15", "20"]); attack_type = "Kerberos Attack"
                    elif port in [139, 445]: cats.extend(["15", "18"]); attack_type = "SMB/Possible Ransomware Attack"
                    elif port in [389, 636]: cats.extend(["15", "20"]); attack_type = "LDAP/LDAPS Attack"
                    elif port == 1433: cats.extend(["18", "15"]); attack_type = "MSSQL Attack"
                    elif port == 3000: cats.extend(["15", "20"]); attack_type = "Possible Vulns Exploit"
                    elif port == 4444: cats.extend(["15", "20"]); attack_type = "Possible C2 Host"
                    elif port in [3389, 5900]: cats.extend(["18"]); attack_type = "RDP/VNC Attack"
                    elif port == 21: cats.extend(["5", "18"]); attack_type = "FTP Attack"
                    elif port in [25, 110, 143, 465, 587, 993, 995]: cats.extend(["18"]); attack_type = "Mail Service Attack"
                    elif port in [1080, 3128, 8118]: cats.extend(["9", "15"]); attack_type = "Open Proxy Probe"
                    elif port in [2375, 2376]: cats.extend(["15", "20"]); attack_type = "Docker API Attack"
                    elif port in [3306, 5432, 27017]: cats.extend(["15", "18"]); attack_type = "DB Attack (MySQL/PgSQL/Mongo)"
                    elif port in [5060, 5061]: cats.extend(["8", "18"]); attack_type = "SIP/VoIP Attack"
                    elif port in [6379, 9200, 11211]: cats.extend(["15", "20"]); attack_type = "NoSQL/Cache Attack"

                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type} Port {port})")).start()
                    continue

            # --- FAIL2BAN LOGIC ---
            if ENABLE_F2B:
                match_f2b = regex_f2b.search(line)
                if match_f2b and "SysWarden-BLOCK" not in line:
                    jail = match_f2b.group(1)
                    ip = match_f2b.group(2)
                    
                    cats = ["18"] # General Abuse
                    if "ssh" in jail.lower(): cats.extend(["22"])
                    elif "nginx" in jail.lower() or "apache" in jail.lower() or "wordpress" in jail.lower(): cats.extend(["21"])
                    elif "postfix" in jail.lower() or "sendmail" in jail.lower(): cats.extend(["5", "11"])
                    elif "mariadb" in jail.lower() or "mongodb" in jail.lower(): cats.extend(["15"])

                    threading.Thread(target=send_report, args=(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {jail})")).start()

if __name__ == "__main__":
    monitor_logs()
EOF

        # Replace placeholders based on user choices
        local PY_F2B="False"; if [[ "$REPORT_F2B" =~ ^[Yy]$ ]]; then PY_F2B="True"; fi
        local PY_FW="False"; if [[ "$REPORT_FW" =~ ^[Yy]$ ]]; then PY_FW="True"; fi

        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_F2B/$PY_F2B/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_FW/$PY_FW/" /usr/local/bin/syswarden_reporter.py
        
        chmod +x /usr/local/bin/syswarden_reporter.py

        log "INFO" "Creating systemd service for Reporter..."
        cat <<EOF > /etc/systemd/system/syswarden-reporter.service
[Unit]
Description=SysWarden Unified Reporter
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/syswarden_reporter.py
Restart=always

# --- SECURITY & LEAST PRIVILEGE ---
DynamicUser=yes
SupplementaryGroups=systemd-journal adm
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
# ----------------------------------

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now syswarden-reporter
        log "INFO" "AbuseIPDB Unified Reporter is ACTIVE."
        
    else
        log "INFO" "Skipping AbuseIPDB reporting setup."
    fi
}

detect_protected_services() {
    echo -e "\n${BLUE}=== Step 5: Service Integration Check ===${NC}"
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list://g')
        log "INFO" "Fail2ban is ACTIVE. Jails: ${JAILS}"
    else
        log "WARN" "Fail2ban not active."
    fi
}

setup_siem_logging() {
    echo -e "\n${BLUE}=== Step 6: SIEM Logging Status ===${NC}"
    log "INFO" "Logs are ready in journalctl and /var/log/."
}

setup_cron_autoupdate() {
    if [[ "${1:-}" != "update" ]]; then
        local script_path=$(realpath "$0")
        local cron_file="/etc/cron.d/syswarden-update"
        local random_min=$((RANDOM % 60))
        echo "$random_min * * * * root $script_path update >/dev/null 2>&1" > "$cron_file"
        chmod 644 "$cron_file"
        log "INFO" "Automatic updates enabled."

        cat <<EOF > /etc/logrotate.d/syswarden
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

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation..."

    # Charger la conf pour récupérer les variables (Wazuh IP, etc.)
    if [[ -f "$CONF_FILE" ]]; then source "$CONF_FILE"; fi

    # 1. Stop & Remove Reporter Service
    log "INFO" "Removing SysWarden Reporter..."
    systemctl disable --now syswarden-reporter 2>/dev/null || true
    rm -f /etc/systemd/system/syswarden-reporter.service /usr/local/bin/syswarden_reporter.py
    systemctl daemon-reload

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    rm -f "/etc/cron.d/syswarden-update"
    rm -f "/etc/logrotate.d/syswarden"

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."
    
    # Nftables
    if command -v nft >/dev/null; then 
        nft delete table inet syswarden_table 2>/dev/null || true
    fi
	
	# UFW
    if [[ -f "/etc/ufw/before.rules" ]]; then
        sed -i "/$SET_NAME/d" /etc/ufw/before.rules
        if command -v ufw >/dev/null; then ufw reload; fi
    fi
    
    # Firewalld
    if command -v firewall-cmd >/dev/null; then
        # Remove Blocklist Rules
        firewall-cmd --permanent --remove-rich-rule="rule source ipset='$SET_NAME' log prefix='[SysWarden-BLOCK] ' level='info' drop" 2>/dev/null || true
        firewall-cmd --permanent --delete-ipset="$SET_NAME" 2>/dev/null || true
        
        # Remove Wazuh Whitelist Rules (if they exist)
        if [[ -n "${WAZUH_IP:-}" ]]; then
             firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1514' protocol='tcp' accept" 2>/dev/null || true
             firewall-cmd --permanent --remove-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='1515' protocol='tcp' accept" 2>/dev/null || true
        fi
        
        firewall-cmd --reload 2>/dev/null || true
    fi
    
	# Docker (DOCKER-USER chain)
    if command -v iptables >/dev/null && iptables -n -L DOCKER-USER >/dev/null 2>&1; then
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null || true
        iptables -D DOCKER-USER -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-DOCKER] " 2>/dev/null || true
        
        if command -v netfilter-persistent >/dev/null; then netfilter-persistent save 2>/dev/null || true; 
        elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save 2>/dev/null || true; fi
    fi
	
    # IPSet / Iptables (Legacy)
    if command -v ipset >/dev/null; then 
        ipset destroy "$SET_NAME" 2>/dev/null || true
        # Note: iptables rules in RAM are cleared by reboot or manual flush, 
        # but persistent rules (netfilter-persistent) should be manually reviewed if used.
    fi

    # 4. Revert Fail2ban Configuration
    if [[ -f /etc/fail2ban/jail.local.bak ]]; then
        log "INFO" "Restoring original Fail2ban configuration..."
        mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
        systemctl restart fail2ban
    elif [[ -f /etc/fail2ban/jail.local ]]; then
        # Si pas de backup, c'est que jail.local n'existait pas avant (Install propre).
        # On le supprime pour revenir à l'état par défaut de l'OS.
        log "INFO" "No backup found (was a clean install). Removing SysWarden jail.local..."
        rm /etc/fail2ban/jail.local
        systemctl restart fail2ban
    else
        log "WARN" "No Fail2ban configuration found to revert."
    fi
	
	# Remove custom Docker banaction
    rm -f /etc/fail2ban/action.d/syswarden-docker.conf

    # 5. Remove Wazuh Agent (Optional but cleaner)
    if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q wazuh-agent; then
        read -p "Do you also want to UNINSTALL the Wazuh Agent? (y/N): " rm_wazuh
        if [[ "$rm_wazuh" =~ ^[Yy]$ ]]; then
            log "INFO" "Removing Wazuh Agent..."
            systemctl disable --now wazuh-agent 2>/dev/null || true
            
            if [[ -f /etc/debian_version ]]; then
                apt-get remove --purge -y wazuh-agent
                rm -f /etc/apt/sources.list.d/wazuh.list
                rm -f /usr/share/keyrings/wazuh.gpg
                apt-get update -qq
            elif [[ -f /etc/redhat-release ]]; then
                dnf remove -y wazuh-agent
                rm -f /etc/yum.repos.d/wazuh.repo
            fi
            log "INFO" "Wazuh Agent removed."
        else
            log "INFO" "Keeping Wazuh Agent installed."
        fi
    fi

    # 6. Remove Config File
    rm -f "$CONF_FILE"
	
	# 7. Remove All logs
	rm -f "$LOG_FILE"
    
    log "INFO" "Cleanup complete. Logs at $LOG_FILE are kept for reference."
    echo -e "${GREEN}Uninstallation complete.${NC}"
    exit 0
}

setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (Custom) ===${NC}"
    
    # 1. Ask for confirmation
    read -p "Install Wazuh Agent? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping Wazuh Agent installation."
        return
    fi

    # 2. Gather Configuration Data
    # IP Serveur
    read -p "Enter Wazuh Manager IP: " WAZUH_IP
    if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing IP. Skipping."; return; fi

    # Hostname (Agent Name)
    read -p "Agent Name [Press Enter for '$(hostname)']: " W_NAME
    W_NAME=${W_NAME:-$(hostname)}

    # Group
    read -p "Agent Group [Press Enter for 'default']: " W_GROUP
    W_GROUP=${W_GROUP:-default}

    # Agent Port (Communication)
    read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
    W_PORT_COMM=${W_PORT_COMM:-1514}

    # Enrollment Port (Registration)
    read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
    W_PORT_ENROLL=${W_PORT_ENROLL:-1515}

    # Protocol (Default TCP)
    W_PROTO="TCP"

    # 3. Whitelist Wazuh Manager (Universal Firewall)
    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on ports $W_PORT_COMM & $W_PORT_ENROLL..."
    
    if [[ "$FIREWALL_BACKEND" == "firewalld" ]]; then
         # RHEL / Alma / Rocky
         # Rules for Custom Ports
         firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_COMM' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
         firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WAZUH_IP' port port='$W_PORT_ENROLL' protocol='${W_PROTO,,}' accept" >/dev/null 2>&1 || true
         firewall-cmd --reload

    elif [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
         # Debian / Ubuntu (Modern)
         # We accept all traffic from Manager IP (Highest Priority) to ensure connectivity & Active Response
         nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
         log "INFO" "Nftables rule added for Wazuh Manager (Full Trust)."
		 
		 # ### PERSISTENCE FIX ###
         # Save current RAM ruleset to disk so it survives reboot
         log "INFO" "Saving Nftables ruleset to /etc/nftables.conf for persistence..."
         nft list ruleset > /etc/nftables.conf
         # Enable service just in case
         systemctl enable nftables >/dev/null 2>&1 || true

    else
         # Fallback Iptables / IPSet
         if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
             iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT
             
             if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
             elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
         fi
    fi

    log "INFO" "Starting Wazuh Agent installation..."

    # 4. OS-Specific Installation Logic with EXPORTS
    # These variables are automatically read by the Wazuh package installer
    export WAZUH_MANAGER="$WAZUH_IP"
    export WAZUH_AGENT_NAME="$W_NAME"
    export WAZUH_AGENT_GROUP="$W_GROUP"
    export WAZUH_MANAGER_PORT="$W_PORT_COMM"       # Custom Agent Port
    export WAZUH_REGISTRATION_PORT="$W_PORT_ENROLL" # Custom Enrollment Port
    export WAZUH_PROTOCOL="$W_PROTO"

    if [[ -f /etc/debian_version ]]; then
        # --- DEBIAN / UBUNTU ---
        log "INFO" "Detected Debian/Ubuntu system."
        apt-get install -y gnupg apt-transport-https
        
        if curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import; then
            chmod 644 /usr/share/keyrings/wazuh.gpg
        else
            log "ERROR" "Failed to import GPG key."
            return
        fi
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
        
        apt-get update -qq
        apt-get install -y wazuh-agent

    elif [[ -f /etc/redhat-release ]]; then
        # --- RHEL / ALMA / ROCKY ---
        log "INFO" "Detected RHEL/Alma/Rocky system."
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
priority=1
EOF
        dnf install -y wazuh-agent
    else
        log "ERROR" "Unsupported OS."
        return
    fi

    # 5. Enable and Persistence
    if systemctl list-unit-files | grep -q wazuh-agent; then
        systemctl daemon-reload
        systemctl enable --now wazuh-agent
        
        # Save config for uninstall reference
        echo "WAZUH_IP='$WAZUH_IP'" >> "$CONF_FILE"
        echo "WAZUH_AGENT_NAME='$W_NAME'" >> "$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >> "$CONF_FILE"
        echo "WAZUH_ENROLL_PORT='$W_PORT_ENROLL'" >> "$CONF_FILE"
        
        log "INFO" "Wazuh Agent '$W_NAME' installed (Group: $W_GROUP, Ports: $W_PORT_COMM/$W_PORT_ENROLL)."
    else
        log "ERROR" "Wazuh Agent installation seemed to fail."
    fi
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    # Validation simple de l'IP
    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi
	
	# --- LOCAL PERSISTENCE ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$WHITELIST_FILE"
    if ! grep -q "^${WL_IP}$" "$WHITELIST_FILE" 2>/dev/null; then
        echo "$WL_IP" >> "$WHITELIST_FILE"
    fi
    # -------------------------

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            # Insert Rule at position 1 (Pre-Filter)
            nft insert rule inet syswarden_table input ip saddr "$WL_IP" accept
            # Persistence
            nft list ruleset > /etc/nftables.conf
            log "INFO" "Rule added to Nftables and saved."
            ;;
        
        "firewalld")
            # Add Rich Rule with ACCEPT action
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$WL_IP' accept"
            firewall-cmd --reload
            log "INFO" "Rule added to Firewalld."
            ;;
        
        "ufw")
            # 1. Add UFW Allow Rule (High priority on user chain)
            ufw insert 1 allow from "$WL_IP"
            # 2. Remove from Blacklist IPSet immediately (in case it was blocked there)
            ipset del "$SET_NAME" "$WL_IP" 2>/dev/null || true
            ufw reload
            log "INFO" "Rule added to UFW (and removed from current blocklist)."
            ;;
        
        *)
            # Fallback IPSet / Iptables
            iptables -I INPUT 1 -s "$WL_IP" -j ACCEPT
            # Persistence
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
            log "INFO" "Rule added to IPTables."
            ;;
    esac
}

blocklist_ip() {
    echo -e "\n${RED}=== SysWarden Manual Blocklist Manager ===${NC}"
    read -p "Enter IP to Block: " BL_IP

    # Validation simple de l'IP
    if [[ ! "$BL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi
	
	# --- LOCAL PERSISTENCE ---
    mkdir -p "$SYSWARDEN_DIR"
    touch "$BLOCKLIST_FILE"
    if ! grep -q "^${BL_IP}$" "$BLOCKLIST_FILE" 2>/dev/null; then
        echo "$BL_IP" >> "$BLOCKLIST_FILE"
    fi
    # -------------------------

    log "INFO" "Blocking IP: $BL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            # Insert Rule at position 1 (Immediate Drop)
            nft insert rule inet syswarden_table input ip saddr "$BL_IP" drop
            # Persistence
            nft list ruleset > /etc/nftables.conf
            log "INFO" "Drop rule added to Nftables and saved."
            ;;
        
        "firewalld")
            # Add Rich Rule with DROP action
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$BL_IP' drop"
            firewall-cmd --reload
            log "INFO" "Drop rule added to Firewalld."
            ;;
        
        "ufw")
            # Add UFW Deny Rule (High priority)
            ufw insert 1 deny from "$BL_IP"
            ufw reload
            log "INFO" "Deny rule added to UFW."
            ;;
        
        *)
            # Fallback IPSet / Iptables
            iptables -I INPUT 1 -s "$BL_IP" -j DROP
            # Persistence
            if command -v netfilter-persistent >/dev/null; then netfilter-persistent save; 
            elif command -v service >/dev/null && [ -f /etc/init.d/iptables ]; then service iptables save; fi
            log "INFO" "Drop rule added to IPTables."
            ;;
    esac
}

protect_docker_jail() {
    echo -e "\n${BLUE}=== SysWarden Docker Jail Protector ===${NC}"
    
    local jail_file="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_file" ]]; then
        log "ERROR" "Fail2ban configuration ($jail_file) not found."
        exit 1
    fi

    # Display active jails to help the user
    if command -v fail2ban-client >/dev/null && systemctl is-active --quiet fail2ban; then
        local active_jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*Jail list://g' || true)
        echo -e "Currently active Jails: ${YELLOW}${active_jails}${NC}"
    fi

    read -p "Enter the exact name of your custom Docker Jail (e.g. 'nginx-docker'): " jail_name
    
    # Trim whitespace
    jail_name=$(echo "$jail_name" | xargs)

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
    local temp_file=$(mktemp)
    local in_target_jail=0

    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ "$line" =~ ^\[.*\]$ ]]; then
            if [[ "$line" == "[${jail_name}]" ]]; then
                in_target_jail=1
                echo "$line" >> "$temp_file"
                echo "banaction = syswarden-docker" >> "$temp_file"
                continue
            else
                in_target_jail=0
            fi
        fi

        # If inside the target block, skip any pre-existing 'banaction' line to avoid duplicates
        if [[ $in_target_jail -eq 1 ]] && [[ "$line" =~ ^banaction[[:space:]]*= ]]; then
            continue
        fi

        echo "$line" >> "$temp_file"
    done < "$jail_file"

    mv "$temp_file" "$jail_file"
    chmod 644 "$jail_file"

    log "INFO" "Jail [${jail_name}] successfully configured to route bans to Docker (DOCKER-USER)."
    
    if command -v systemctl >/dev/null; then
        systemctl restart fail2ban
        log "INFO" "Fail2ban service restarted to apply changes."
    fi
}

check_upgrade() {
    echo -e "\n${BLUE}=== SysWarden Upgrade Checker ===${NC}"
    log "INFO" "Checking for updates on GitHub API..."

    local api_url="https://api.github.com/repos/duggytuxy/syswarden/releases/latest"
    local response
    
    # Fetch API response quietly (Timeout 5s to avoid hanging)
    response=$(curl -sS --connect-timeout 5 "$api_url") || {
        log "ERROR" "Failed to connect to GitHub API."
        exit 1
    }

    # Extract tag_name (e.g., "v3.00") using standard POSIX grep/cut (no external dependencies needed)
    local latest_version
    latest_version=$(echo "$response" | grep -o '"tag_name": "[^"]*"' | head -n 1 | cut -d'"' -f4)
    
    if [[ -z "$latest_version" ]]; then
        log "ERROR" "Could not parse latest version from GitHub."
        exit 1
    fi

    # Extract download URL for the .sh script from the release assets
    local download_url
    download_url=$(echo "$response" | grep -o '"browser_download_url": "[^"]*\.sh"' | head -n 1 | cut -d'"' -f4)

    echo -e "Current Version : ${YELLOW}${VERSION}${NC}"
    echo -e "Latest Version  : ${GREEN}${latest_version}${NC}\n"

    if [[ "$VERSION" == "$latest_version" ]]; then
        echo -e "${GREEN}You are already using the latest version of SysWarden!${NC}"
    else
        echo -e "${YELLOW}A new version ($latest_version) is available!${NC}"
        echo -e "To upgrade safely, please run the following commands:\n"
        
        # If the API returned a direct .sh link, provide the wget shortcut
        if [[ -n "$download_url" ]]; then
            echo -e "  wget -qO install-syswarden.sh \"$download_url\""
            echo -e "  chmod +x install-syswarden.sh"
            echo -e "  ./install-syswarden.sh\n"
        else
            # Fallback to the main releases page if no .sh asset is directly found
            echo -e "  Please download the new release manually from:"
            echo -e "  https://github.com/duggytuxy/syswarden/releases/latest\n"
        fi
        
        echo -e "Note: Running the updated script will cleanly overwrite old configurations if necessary."
    fi
}

show_alerts_dashboard() {
    # Trap Ctrl+C/Exit to restore cursor
    trap "tput cnorm; clear; exit 0" INT TERM
    tput civis # Hide cursor for cleaner UI

    while true; do
        clear
        local NOW=$(date "+%H:%M:%S")
        
        echo -e "${BLUE}====================================================================================================${NC}"
        echo -e "${BLUE}   SysWarden Live Attack Dashboard (Last Update: $NOW)        ${NC}"
        echo -e "${BLUE}====================================================================================================${NC}"
        # HEADER: 6 Columns (DATE / HOUR aligned to max 19 characters)
        printf "${YELLOW}%-19s | %-10s | %-16s | %-20s | %-12s | %-8s${NC}\n" "DATE / HOUR" "SOURCE" "IP ADDRESS" "RULES" "PORT" "DECISION"
        echo "----------------------------------------------------------------------------------------------------"

        # Regex to cleanly extract the date: "Feb 14 10:05:10" OR "2026-02-14 10:05:10"
        local date_regex="^([A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+[0-9:]+|[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9:]+)"

        # 1. FAIL2BAN ENTRIES (Via Journalctl)
        if command -v journalctl >/dev/null; then
            journalctl -u fail2ban -n 50 --no-pager 2>/dev/null | { grep " Ban " || true; } | tail -n 8 | while read -r line; do
                if [[ $line =~ \[([a-zA-Z0-9_-]+)\][[:space:]]+Ban[[:space:]]+([0-9.]+) ]]; then
                    jail="${BASH_REMATCH[1]}"
                    ip="${BASH_REMATCH[2]}"
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Fail2ban" "$ip" "$jail" "Dynamic" "BAN"
                fi
            done
        elif [[ -f "/var/log/fail2ban.log" ]]; then
             { grep " Ban " "/var/log/fail2ban.log" || true; } | tail -n 8 | while read -r line; do
                if [[ $line =~ \[([a-zA-Z0-9_-]+)\][[:space:]]+Ban[[:space:]]+([0-9.]+) ]]; then
                    jail="${BASH_REMATCH[1]}"
                    ip="${BASH_REMATCH[2]}"
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Fail2ban" "$ip" "$jail" "Dynamic" "BAN"
                fi
            done
        fi

        # 2. FIREWALL ENTRIES (Via Journalctl)
        # Increased journalctl to -n 100 to ensure enough lines are found
        if command -v journalctl >/dev/null; then
            journalctl -k -n 100 --no-pager 2>/dev/null | { grep "SysWarden-BLOCK" || true; } | tail -n 12 | while read -r line; do
                if [[ $line =~ SRC=([0-9.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    rule="SysWarden-BLOCK"
                    port="Global"
                    if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
                fi
            done
        elif [[ -f "/var/log/kern.log" ]]; then
             { grep "SysWarden-BLOCK" "/var/log/kern.log" || true; } | tail -n 12 | while read -r line; do
                if [[ $line =~ SRC=([0-9.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    rule="SysWarden-BLOCK"
                    port="Global"
                    if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
                fi
             done
        fi
        
        echo "----------------------------------------------------------------------------------------------------"
        echo -e "Press [ESC] to Quit."
        
        read -t 10 -n 1 -s -r key || true
        if [[ $key == $'\e' ]]; then
            break
        fi
    done
    tput cnorm # Restore cursor
    clear
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

MODE="${1:-install}"

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

if [[ "$MODE" == "protect-docker" ]]; then
    check_root
    protect_docker_jail
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
    uninstall_syswarden
fi

if [[ "$MODE" != "update" ]]; then
    clear
    echo -e "${GREEN}#############################################################"
    echo -e "#     SysWarden Tool Installer (Universal v4.03)     #"
    echo -e "#############################################################${NC}"
fi

check_root
detect_os_backend

if [[ "$MODE" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi

if [[ "$MODE" != "update" ]]; then
    install_dependencies
    define_ssh_port "$MODE"
    define_docker_integration "$MODE"
    configure_fail2ban
fi

select_list_type "$MODE"
select_mirror "$MODE"
download_list
apply_firewall_rules
detect_protected_services

if command -v systemctl >/dev/null && systemctl is-active --quiet syswarden-reporter; then
    systemctl restart syswarden-reporter
fi

if [[ "$MODE" != "update" ]]; then
    setup_siem_logging
    setup_abuse_reporting
    setup_wazuh_agent
    setup_cron_autoupdate "$MODE"
    
    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> List loaded: $LIST_TYPE"
    echo -e " -> Mode: Universal (Auto-Detection)"
    echo -e " -> Protection: Active"
fi