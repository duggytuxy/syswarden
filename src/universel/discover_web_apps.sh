discover_web_apps() {
    log "INFO" "Discovering active Web Servers and underlying applications..."

    # Reset global state to prevent persistence across reloads
    export SYSW_RCE_LOGS=""
    export SYSW_HAS_DOLIBARR=false
    export SYSW_HAS_PRESTASHOP=false
    export SYSW_HAS_WORDPRESS=false
    export SYSW_HAS_DRUPAL=false
    export SYSW_HAS_NEXTCLOUD=false
    export SYSW_HAS_PHPMYADMIN=false
    export SYSW_HAS_LARAVEL=false

    local web_conf_dirs=""
    local web_logs=""

    # PYTHON CONFIGPARSER FIX: Multi-line indentation for multiple log files
    # This ensures Fail2ban parses each log path strictly as a file, avoiding the 'head/tail' ValueError
    local nl=$'\n          '

    # 1. Native detection of active Web Servers (Multi-line formatted)
    if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
        web_logs="/var/log/nginx/*access.log${nl}/var/log/nginx/*error.log"
        web_conf_dirs="/etc/nginx"
        touch /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null || true
        # --- SELINUX FIX ---
        command -v restorecon >/dev/null 2>&1 && restorecon -F -R /var/log/nginx/ 2>/dev/null || true
    fi

    if command -v apache2 >/dev/null 2>&1 && systemctl is-active --quiet apache2 2>/dev/null; then
        web_logs="${web_logs:+$web_logs$nl}/var/log/apache2/*access.log${nl}/var/log/apache2/*error.log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/apache2"
        touch /var/log/apache2/access.log /var/log/apache2/error.log 2>/dev/null || true
        # --- SELINUX FIX ---
        command -v restorecon >/dev/null 2>&1 && restorecon -F -R /var/log/apache2/ 2>/dev/null || true
    elif command -v httpd >/dev/null 2>&1 && systemctl is-active --quiet httpd 2>/dev/null; then
        web_logs="${web_logs:+$web_logs$nl}/var/log/httpd/*access.log${nl}/var/log/httpd/*error_log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/httpd"
        touch /var/log/httpd/access_log /var/log/httpd/error_log 2>/dev/null || true
        # --- SELINUX FIX ---
        command -v restorecon >/dev/null 2>&1 && restorecon -F -R /var/log/httpd/ 2>/dev/null || true
    fi

    export SYSW_RCE_LOGS="${web_logs}"

    # 2. Application Heuristic Discovery (Only if a Web Server runs)
    if [[ -n "$web_conf_dirs" ]]; then
        # Fast configuration parsing (Reverse lookup, strictly ignoring commented lines)
        grep -rhIEi 'dolibarr' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_DOLIBARR=true || true
        grep -rhIEi 'prestashop' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_PRESTASHOP=true || true
        grep -rhIEi 'wp-config|wordpress' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_WORDPRESS=true || true
        grep -rhIEi 'drupal' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_DRUPAL=true || true
        grep -rhIEi 'nextcloud' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_NEXTCLOUD=true || true
        grep -rhIEi 'phpmyadmin' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_PHPMYADMIN=true || true
        grep -rhIEi 'laravel|artisan' $web_conf_dirs 2>/dev/null | grep -vE '^\s*#' | grep -q . && SYSW_HAS_LARAVEL=true || true

        # Shallow filesystem probing (Depth 4 max for strict I/O optimization)
        for root in /var/www /usr/share/nginx/html /opt; do
            if [[ -d "$root" ]]; then
                find "$root" -maxdepth 4 -type f -name "wp-config.php" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_WORDPRESS=true || true
                find "$root" -maxdepth 4 -type f -name "artisan" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_LARAVEL=true || true
                find "$root" -maxdepth 4 -type d -name "phpmyadmin" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_PHPMYADMIN=true || true
                find "$root" -maxdepth 4 -type d -name "drupal" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_DRUPAL=true || true
                find "$root" -maxdepth 4 -type f -name "status.php" -path "*/nextcloud/*" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_NEXTCLOUD=true || true
            fi
        done
    fi

    return 0
}
