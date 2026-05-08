#!/bin/bash

# SysWarden WAF - Enterprise ModSecurity v3 & OWASP CRS Deployment Module
# Designed for SysWarden v0.30.1 Architecture
# Compatibility: Ubuntu, Debian, RHEL, AlmaLinux, Rocky, CentOS, Alpine Linux

# --- SAFETY FIRST ---
set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-waf-install.log"
MODSEC_VERSION="v3.0.15"
MODSEC_DIR="/etc/modsecurity"
CRS_DIR="/etc/modsecurity/owasp-crs"
AUDIT_LOG="/var/log/modsec_audit.log"

# --- SECURE TMP DIR (CWE-377 & STORAGE OPTIMIZATION) ---
# DEVSECOPS FIX: ModSecurity recursive submodules require massive storage (>1GB).
# We explicitly map the temporary directory to /var/tmp instead of /tmp
# to bypass 'tmpfs' RAM limits that cause "No space left on device" crashes.
TMP_DIR=$(mktemp -d /var/tmp/syswarden-waf-XXXXXX)
chmod 0700 "$TMP_DIR"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root.${NC}"
        exit 1
    fi
}

detect_os() {
    log "INFO" "Detecting Operating System for WAF compilation..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
        OS_VERSION=$VERSION_ID
    else
        log "ERROR" "Cannot determine OS. /etc/os-release missing."
        exit 1
    fi
    log "INFO" "OS Detected: $OS_ID $OS_VERSION"
}

# ==============================================================================
# DEPENDENCIES INJECTION
# ==============================================================================

install_dependencies() {
    log "INFO" "Installing compilation dependencies for ModSecurity $MODSEC_VERSION..."

    if [[ "$OS_ID" == "ubuntu" ]] || [[ "$OS_ID" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        # DEVSECOPS FIX: Removed deprecated libpcre++-dev. Added libxslt1-dev, libgd-dev,
        # and libperl-dev to satisfy strict Nginx ABI --with-compat requirements.
        apt-get install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev \
            libgeoip-dev liblmdb-dev libpcre2-dev libtool libxml2-dev libyajl-dev \
            pkgconf wget zlib1g-dev flex bison doxygen ruby python3 \
            libxslt1-dev libgd-dev libperl-dev apache2-dev

    elif [[ "$OS_ID" =~ ^(rhel|almalinux|rocky|centos)$ ]]; then
        dnf install -y dnf-plugins-core || yum install -y yum-utils
        dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled PowerTools 2>/dev/null || true
        dnf install -y epel-release || true
        dnf install -y gcc-c++ flex bison yajl yajl-devel curl-devel curl GeoIP-devel doxygen \
            zlib-devel pcre-devel pcre2-devel libxml2-devel lmdb-devel autoconf automake libtool \
            wget git pkgconf python3 libxslt-devel gd-devel perl-devel httpd-devel

    elif [[ "$OS_ID" == "alpine" ]]; then
        # Alpine 3.21+ specific compilation headers (musl libc compatible)
        apk add --no-cache gcc g++ make automake autoconf libtool pcre-dev pcre2-dev \
            libxml2-dev curl-dev geoip-dev yajl-dev lmdb-dev linux-headers git wget \
            flex bison python3 ruby doxygen coreutils libxslt-dev gd-dev perl-dev apache2-dev
    else
        log "ERROR" "Unsupported OS for automated ModSecurity compilation: $OS_ID"
        exit 1
    fi
}

# ==============================================================================
# CORE LIBMODSECURITY COMPILATION
# ==============================================================================

compile_libmodsecurity() {
    log "INFO" "Cloning and compiling libmodsecurity ($MODSEC_VERSION)..."

    cd "$TMP_DIR"
    # DEVSECOPS FIX: Added --recurse-submodules directly during the clone phase
    # to guarantee that Mbed TLS and ssdeep are fetched successfully.
    git clone --depth 1 -b "$MODSEC_VERSION" --recurse-submodules https://github.com/owasp-modsecurity/ModSecurity.git
    cd ModSecurity

    log "INFO" "Ensuring all nested Git Submodules (Mbed TLS) are strictly initialized..."
    # DEVSECOPS FIX: Forced recursive initialization for nested cryptographic libraries
    git submodule update --init --recursive

    log "INFO" "Building environment..."
    ./build.sh

    # Alpine requires strict prefixing for musl
    if [[ "$OS_ID" == "alpine" ]]; then
        ./configure --prefix=/usr --enable-standalone-module
    else
        ./configure
    fi

    log "INFO" "Compiling C++ Source (This may take several minutes)..."
    # Utilize all available CPU cores for compilation speed
    make -j"$(nproc)"
    make install

    log "SUCCESS" "libmodsecurity $MODSEC_VERSION compiled and installed."
}

# ==============================================================================
# NGINX CONNECTOR COMPILATION (DYNAMIC MODULE)
# ==============================================================================

compile_nginx_connector() {
    if ! command -v nginx >/dev/null 2>&1; then
        log "WARN" "Nginx not found. Skipping dynamic module compilation."
        return
    fi

    # Extract exact Nginx version installed on the host
    NGINX_VERSION=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
    log "INFO" "Detected Nginx version: $NGINX_VERSION. Preparing dynamic module build..."

    cd "$TMP_DIR"

    # Fetch Nginx source code matching the exact binary version
    wget -qO "nginx-${NGINX_VERSION}.tar.gz" "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
    tar -xzf "nginx-${NGINX_VERSION}.tar.gz"

    # Clone the ModSecurity-nginx connector
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git

    cd "nginx-${NGINX_VERSION}"

    log "INFO" "Configuring Nginx module for compatibility..."
    # Extract existing Nginx configure arguments to ensure ABI compatibility
    NGINX_ARGS=$(nginx -V 2>&1 | grep "configure arguments:" | sed 's/configure arguments://')

    # DEVSECOPS FIX: Safely evaluate the configure arguments using eval to expand quoted strings properly
    eval "./configure --with-compat --add-dynamic-module=../ModSecurity-nginx $NGINX_ARGS"

    log "INFO" "Compiling Nginx ModSecurity Connector..."
    make modules

    # Inject the compiled module into the system
    local MODULE_DIR="/etc/nginx/modules"
    mkdir -p "$MODULE_DIR"
    cp objs/ngx_http_modsecurity_module.so "$MODULE_DIR/"
    chmod 644 "$MODULE_DIR/ngx_http_modsecurity_module.so"

    log "SUCCESS" "Nginx ModSecurity dynamic module created."

    # Configure Nginx to load the module
    local NGINX_CONF="/etc/nginx/nginx.conf"
    if ! grep -q "load_module.*ngx_http_modsecurity_module.so" "$NGINX_CONF"; then
        log "INFO" "Injecting load_module directive into $NGINX_CONF..."
        # Safely insert at the very top of the config file
        sed -i "1i load_module $MODULE_DIR/ngx_http_modsecurity_module.so;" "$NGINX_CONF"
    fi
}

# ==============================================================================
# APACHE CONNECTOR COMPILATION (MODSECURITY V3)
# ==============================================================================
compile_apache_connector() {
    if ! command -v apache2 >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
        log "WARN" "Apache not found. Skipping dynamic module compilation."
        return
    fi

    log "INFO" "Preparing Apache ModSecurity v3 connector..."
    cd "$TMP_DIR"

    # Clone the official ModSecurity-apache connector
    git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-apache.git
    cd ModSecurity-apache

    log "INFO" "Compiling Apache ModSecurity Connector..."
    ./autogen.sh
    ./configure
    make

    # 'make install' relies on apxs to automatically place the .so in the correct Apache modules directory
    make install

    # Identify the Apache daemon and configuration directory
    local APACHE_MOD_DIR="/etc/apache2/mods-available"
    if command -v httpd >/dev/null 2>&1 || [[ -d "/etc/httpd" ]]; then
        APACHE_MOD_DIR="/etc/httpd/conf.modules.d"
    fi

    mkdir -p "$APACHE_MOD_DIR"
    local LOAD_CONF="$APACHE_MOD_DIR/modsecurity3.load"

    # Create the module load directive
    cat <<EOF >"$LOAD_CONF"
LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so
EOF

    # Enable the module natively on Debian/Ubuntu
    if command -v a2enmod >/dev/null 2>&1; then
        a2enmod modsecurity3 >/dev/null 2>&1 || true
    fi

    log "SUCCESS" "Apache ModSecurity v3 dynamic module created and enabled."
}

# ==============================================================================
# OWASP CORE RULE SET (CRS) CONFIGURATION
# ==============================================================================

configure_owasp_crs() {
    log "INFO" "Deploying OWASP Core Rule Set and ModSecurity configuration..."

    mkdir -p "$MODSEC_DIR"
    cd "$MODSEC_DIR"

    # Fetch default unicode mapping and recommended config from the repo we just cloned
    cp "$TMP_DIR/ModSecurity/modsecurity.conf-recommended" "$MODSEC_DIR/modsecurity.conf"
    cp "$TMP_DIR/ModSecurity/unicode.mapping" "$MODSEC_DIR/"

    # --- DEVSECOPS: MODSECURITY HARDENING ---
    log "INFO" "Hardening modsecurity.conf for SysWarden Telemetry..."

    # 1. Enable Rule Engine (Switch from DetectionOnly to On)
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$MODSEC_DIR/modsecurity.conf"

    # 2. Configure Audit Log path to match SysWarden Fail2ban Jails
    sed -i "s|^SecAuditLog .*|SecAuditLog $AUDIT_LOG|" "$MODSEC_DIR/modsecurity.conf"

    # 3. Create the log file securely
    touch "$AUDIT_LOG"
    chown root:root "$AUDIT_LOG"
    chmod 640 "$AUDIT_LOG"

    # Fetch OWASP CRS (v4.0 is the modern standard, cloning main branch)
    log "INFO" "Cloning OWASP CRS..."
    rm -rf "$CRS_DIR"
    git clone https://github.com/coreruleset/coreruleset.git "$CRS_DIR"

    cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"

    # Create the master config inclusion file
    cat <<EOF >"$MODSEC_DIR/main.conf"
# SysWarden - ModSecurity Master Configuration
Include /etc/modsecurity/modsecurity.conf
Include /etc/modsecurity/owasp-crs/crs-setup.conf
Include /etc/modsecurity/owasp-crs/rules/*.conf
EOF

    # Configure Nginx to activate ModSecurity in its server blocks
    local NGINX_MAIN_CONF="/etc/nginx/nginx.conf"
    if grep -q "http {" "$NGINX_MAIN_CONF"; then
        if ! grep -q "modsecurity on;" "$NGINX_MAIN_CONF"; then
            log "INFO" "Enabling ModSecurity globally in Nginx HTTP block..."
            sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /etc/modsecurity/main.conf;' "$NGINX_MAIN_CONF"
        fi
    fi

    # --- APACHE WAF CONFIGURATION INJECTION ---
    if command -v apache2 >/dev/null 2>&1 || command -v httpd >/dev/null 2>&1; then
        local APACHE_CONF_DIR="/etc/apache2/conf-available"
        local APACHE_DAEMON="apache2"

        if command -v httpd >/dev/null 2>&1 || [[ -d "/etc/httpd" ]]; then
            APACHE_CONF_DIR="/etc/httpd/conf.d"
            APACHE_DAEMON="httpd"
        fi

        mkdir -p "$APACHE_CONF_DIR"
        local APACHE_WAF_CONF="$APACHE_CONF_DIR/syswarden-waf.conf"

        log "INFO" "Enabling ModSecurity globally for Apache..."
        cat <<EOF >"$APACHE_WAF_CONF"
<IfModule security2_module>
    SecRuleEngine On
    Include /etc/modsecurity/main.conf
</IfModule>
EOF

        if [[ "$APACHE_DAEMON" == "apache2" ]] && command -v a2enconf >/dev/null 2>&1; then
            a2enconf syswarden-waf >/dev/null 2>&1 || true
        fi

        log "INFO" "Validating Apache configuration..."
        if $APACHE_DAEMON -t >/dev/null 2>&1; then
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart $APACHE_DAEMON
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service $APACHE_DAEMON restart
            fi
            log "SUCCESS" "WAF Active. Apache successfully restarted with ModSecurity enabled."
        else
            log "ERROR" "Apache configuration test failed. WAF integration requires manual review."
        fi
    fi

    # Verify Nginx configuration and restart
    if command -v nginx >/dev/null 2>&1; then
        log "INFO" "Validating Nginx configuration..."
        if nginx -t >/dev/null 2>&1; then
            if command -v systemctl >/dev/null 2>&1; then
                systemctl restart nginx
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service nginx restart
            fi
            log "SUCCESS" "WAF Active. Nginx successfully restarted with ModSecurity enabled."
        else
            log "ERROR" "Nginx configuration test failed. WAF integration might require manual adjustments."
        fi
    fi
}

# ==============================================================================
# WAF SIGNATURES AUTO-UPDATE (OWASP CRS) - UNIVERSAL (NGINX/APACHE)
# ==============================================================================

update_waf_signatures() {
    log "INFO" "Checking for OWASP Core Rule Set (CRS) signature updates..."

    if [[ ! -d "$CRS_DIR/.git" ]]; then
        log "ERROR" "CRS directory ($CRS_DIR) is not a Git repository. Cannot perform update."
        exit 1
    fi

    cd "$CRS_DIR" || exit 1

    # 1. Capture current state (For Rollback)
    local LOCAL_HASH
    LOCAL_HASH=$(git rev-parse HEAD)

    # 2. Silently fetch metadata from the remote repository
    git fetch origin main >/dev/null 2>&1
    local REMOTE_HASH
    REMOTE_HASH=$(git rev-parse origin/main)

    if [[ "$LOCAL_HASH" == "$REMOTE_HASH" ]]; then
        log "INFO" "OWASP CRS signatures are already up to date. No action required."
        return
    fi

    log "INFO" "New WAF signatures detected. Pulling updates from upstream..."

    # 3. Apply the update
    if ! git pull origin main >/dev/null 2>&1; then
        log "ERROR" "Failed to pull CRS updates. Network issue or Git conflict."
        return
    fi

    # --- DEVSECOPS: DYNAMIC WEB SERVER DETECTION ---
    local WEB_DAEMON=""
    local TEST_CMD=""

    if command -v apache2 >/dev/null 2>&1; then
        WEB_DAEMON="apache2"
        TEST_CMD="apache2 -t"
    elif command -v httpd >/dev/null 2>&1; then
        WEB_DAEMON="httpd"
        TEST_CMD="httpd -t"
    elif command -v nginx >/dev/null 2>&1; then
        WEB_DAEMON="nginx"
        TEST_CMD="nginx -t"
    else
        log "ERROR" "No supported web server found for validation. Aborting update and rolling back."
        git reset --hard "$LOCAL_HASH" >/dev/null 2>&1
        return
    fi

    # 4. SAFEGUARD: Validate target web server syntax (Anti-Crash)
    log "INFO" "Validating $WEB_DAEMON configuration with new WAF rules..."

    if $TEST_CMD >/dev/null 2>&1; then
        # Hot reload (Zero-Downtime)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl reload "$WEB_DAEMON"
        elif command -v rc-service >/dev/null 2>&1; then
            rc-service "$WEB_DAEMON" reload
        fi
        log "SUCCESS" "WAF signatures updated successfully. $WEB_DAEMON reloaded."
    else
        # 5. ROLLBACK: Reject the update if it breaks the web server
        log "ERROR" "CRITICAL: New WAF signatures broke $WEB_DAEMON configuration! Initiating automated rollback..."
        git reset --hard "$LOCAL_HASH" >/dev/null 2>&1

        # Confirm successful rollback
        if $TEST_CMD >/dev/null 2>&1; then
            if command -v systemctl >/dev/null 2>&1; then
                systemctl reload "$WEB_DAEMON"
            elif command -v rc-service >/dev/null 2>&1; then
                rc-service "$WEB_DAEMON" reload
            fi
            log "INFO" "Rollback successful. WAF is running on previous stable signatures."
        else
            log "ERROR" "Rollback failed! $WEB_DAEMON configuration is deeply corrupted."
        fi
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

MODE="${1:-install}"

if [[ "$MODE" == "update" ]] || [[ "$MODE" == "cron-update" ]]; then
    check_root
    update_waf_signatures
    exit 0
fi

clear
echo -e "${BLUE}===================================================================================${NC}"
echo -e "${GREEN}                  SysWarden WAF - ModSecurity v3 Orchestrator                      ${NC}"
echo -e "${BLUE}===================================================================================${NC}"

check_root
detect_os
install_dependencies
compile_libmodsecurity
compile_nginx_connector
compile_apache_connector
configure_owasp_crs

# Configuration de la tâche automatisée CRON pour les signatures WAF (Toutes les nuits à 03:00)
CRON_FILE="/etc/cron.d/syswarden-waf-update"
if [[ ! -f "$CRON_FILE" ]]; then
    log "INFO" "Installing automated daily CRON job for WAF signatures..."
    SCRIPT_PATH=$(realpath "$0" 2>/dev/null || readlink -f "$0" 2>/dev/null || echo "${PWD}/${0#./}")
    echo "0 3 * * * root $SCRIPT_PATH cron-update >/dev/null 2>&1" >"$CRON_FILE"
    chmod 644 "$CRON_FILE"
fi

echo -e "\n${GREEN}[+] ModSecurity v3.0.15 and OWASP CRS deployed successfully!${NC}"
echo -e "${YELLOW}[i] The WAF is strictly linked to SysWarden's Fail2ban [syswarden-modsec] jail via $AUDIT_LOG.${NC}"
exit 0
